/*
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file incorporates work originally licensed under the
 * BSD 3-Clause License:
 *
 *   Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
 *
 * Modifications and additional work:
 *
 *   Copyright (c) 2026 Damian Peckett <damian@pecke.tt>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

pub mod errors;
pub mod handshake;
pub mod rate_limiter;

pub(crate) mod relay;
pub(crate) mod session;
pub(crate) mod timers;

use core::{
    convert::{TryFrom, TryInto},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use defmt_or_log::{debug, trace, warn};
#[cfg(not(feature = "std"))]
use embassy_time::{Duration, Instant};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "std")]
use tokio::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    ip_packet::src_address,
    noise::{
        errors::WireGuardError,
        handshake::Handshake,
        timers::{PENDING_PACKET_TTL, TimerName, Timers},
    },
    packet_pool::{PacketHandle, PacketPool},
    timestamper::TimeStamper,
};

/// Number of recent sessions retained across key rotations.
pub(crate) const N_SESSIONS: usize = 3;

/// Maximum number of outbound packets buffered while waiting for
/// a usable encrypted session.
const MAX_PENDING_PACKETS: usize = 8;

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;
const IPV4_IHL_MASK: u8 = 0x0f;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_LEN_OFF: usize = 4;

const IP_LEN_SZ: usize = 2;

#[derive(Debug)]
pub enum TunnResult<'a> {
    Done,
    Err(WireGuardError),
    WriteToNetwork(&'a mut [u8]),
    WriteToInterfaceV4(&'a mut [u8], Ipv4Addr),
    WriteToInterfaceV6(&'a mut [u8], Ipv6Addr),
}

impl<'a> From<WireGuardError> for TunnResult<'a> {
    fn from(err: WireGuardError) -> TunnResult<'a> {
        TunnResult::Err(err)
    }
}

#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Stats {
    /// Elapsed time since the last successful handshake.
    pub time_since_last_handshake: Option<Duration>,
    /// Total transmitted payload bytes.
    pub tx_bytes: usize,
    /// Total received payload bytes.
    pub rx_bytes: usize,
    /// Total transmitted packets, including keepalives and handshake/control packets.
    pub tx_packets: usize,
    /// Total received packets, including keepalives and handshake/control packets.
    pub rx_packets: usize,
    /// Estimated packet loss ratio in the range `0.0..=1.0`.
    pub packet_loss: f32,
    /// Most recently measured round-trip time in milliseconds.
    pub rtt_ms: Option<u32>,
}

/// Tunnel represents a point-to-point WireGuard connection
pub struct Tunn<'a> {
    /// Device-owned timestamper.
    stamper: &'a TimeStamper,
    /// The handshake currently in progress
    handshake: handshake::Handshake,
    /// The N_SESSIONS most recent sessions.
    sessions: [Option<session::Session>; N_SESSIONS],
    /// Index of most recently used session.
    current: usize,
    /// Head of this peer's intrusive pending-packet queue in the shared pool.
    packet_queue_head: Option<PacketHandle>,
    /// Tail of this peer's intrusive pending-packet queue in the shared pool.
    packet_queue_tail: Option<PacketHandle>,
    /// Number of shared-pool packets currently queued for this peer.
    packet_queue_len: usize,
    /// Keeps tabs on the expiring timers
    timers: timers::Timers,
    tx_bytes: usize,
    rx_bytes: usize,
    tx_packets: usize,
    rx_packets: usize,
}

pub(crate) type MessageType = u32;
pub(crate) const HANDSHAKE_INIT: MessageType = 1;
pub(crate) const HANDSHAKE_RESP: MessageType = 2;
pub(crate) const COOKIE_REPLY: MessageType = 3;
pub(crate) const DATA: MessageType = 4;
/// Non-standard extension for explicit relay data packets.
pub(crate) const RELAY_DATA: MessageType = 5;

pub(crate) const HANDSHAKE_INIT_SZ: usize = 148;
pub(crate) const HANDSHAKE_RESP_SZ: usize = 92;
pub(crate) const COOKIE_REPLY_SZ: usize = 64;
pub(crate) const DATA_OVERHEAD_SZ: usize = 32;

#[derive(Debug)]
pub struct HandshakeInit<'a> {
    sender_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_static: &'a [u8],
    encrypted_timestamp: &'a [u8],
}

#[derive(Debug)]
pub struct HandshakeResponse<'a> {
    sender_idx: u32,
    pub receiver_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_nothing: &'a [u8],
}

#[derive(Debug)]
pub struct CookieReply<'a> {
    pub receiver_idx: u32,
    nonce: &'a [u8],
    encrypted_cookie: &'a [u8],
}

#[derive(Debug)]
pub struct Data<'a> {
    pub receiver_idx: u32,
    counter: u64,
    encrypted_encapsulated_packet: &'a [u8],
}

/// Describes a packet from network
#[derive(Debug)]
pub enum Packet<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    CookieReply(CookieReply<'a>),
    Data(Data<'a>),
    RelayData(Data<'a>),
}

#[inline(always)]
pub(crate) fn parse_incoming_packet(src: &[u8]) -> Result<Packet<'_>, WireGuardError> {
    if src.len() < 4 {
        trace!("Rejecting incoming packet: too short len={}", src.len());
        return Err(WireGuardError::InvalidPacket);
    }

    let packet_type = u32::from_le_bytes(src[0..4].try_into().unwrap());

    Ok(match (packet_type, src.len()) {
        (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ) => {
            trace!(
                "Received handshake initiation: sender_idx={}",
                u32::from_le_bytes(src[4..8].try_into().unwrap())
            );
            Packet::HandshakeInit(HandshakeInit {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[8..40])
                    .expect("length already checked above"),
                encrypted_static: &src[40..88],
                encrypted_timestamp: &src[88..116],
            })
        }
        (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ) => {
            trace!(
                "Received handshake response: sender_idx={}, receiver_idx={}",
                u32::from_le_bytes(src[4..8].try_into().unwrap()),
                u32::from_le_bytes(src[8..12].try_into().unwrap())
            );
            Packet::HandshakeResponse(HandshakeResponse {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                receiver_idx: u32::from_le_bytes(src[8..12].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[12..44])
                    .expect("length already checked above"),
                encrypted_nothing: &src[44..60],
            })
        }
        (COOKIE_REPLY, COOKIE_REPLY_SZ) => {
            trace!(
                "Received cookie reply: receiver_idx={}",
                u32::from_le_bytes(src[4..8].try_into().unwrap())
            );
            Packet::CookieReply(CookieReply {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                nonce: &src[8..32],
                encrypted_cookie: &src[32..64],
            })
        }
        (DATA, DATA_OVERHEAD_SZ..=core::usize::MAX) => {
            trace!(
                "Received data packet: receiver_idx={}",
                u32::from_le_bytes(src[4..8].try_into().unwrap())
            );
            Packet::Data(Data {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                counter: u64::from_le_bytes(src[8..16].try_into().unwrap()),
                encrypted_encapsulated_packet: &src[16..],
            })
        }
        (RELAY_DATA, DATA_OVERHEAD_SZ..=core::usize::MAX) => {
            trace!(
                "Received relay data packet: receiver_idx={}",
                u32::from_le_bytes(src[4..8].try_into().unwrap())
            );
            Packet::RelayData(Data {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                counter: u64::from_le_bytes(src[8..16].try_into().unwrap()),
                encrypted_encapsulated_packet: &src[16..],
            })
        }
        _ => {
            trace!(
                "Rejecting incoming packet: invalid type={} len={}",
                packet_type,
                src.len()
            );
            return Err(WireGuardError::InvalidPacket);
        }
    })
}

impl<'a> Tunn<'a> {
    pub fn is_expired(&self) -> bool {
        self.handshake.is_expired()
    }

    /// Create a new tunnel using own private key and the peer public key
    pub fn new(
        static_private: StaticSecret,
        peer_static_public: PublicKey,
        persistent_keepalive: Option<u16>,
        index: u32,
        stamper: &'a TimeStamper,
    ) -> Self {
        let static_public = PublicKey::from(&static_private);

        Tunn {
            stamper,
            handshake: Handshake::new(static_private, static_public, peer_static_public, index),
            sessions: core::array::from_fn(|_| None),
            current: Default::default(),
            tx_bytes: Default::default(),
            rx_bytes: Default::default(),
            tx_packets: Default::default(),
            rx_packets: Default::default(),

            packet_queue_head: None,
            packet_queue_tail: None,
            packet_queue_len: 0,
            timers: Timers::new(persistent_keepalive),
        }
    }

    /// Encapsulate a single packet from the tunnel interface.
    /// Returns TunnResult.
    ///
    /// # Panics
    /// Panics if dst buffer is too small.
    /// Size of dst should be at least src.len() + 32, and no less than 148 bytes.
    pub async fn encapsulate<'d, R, const N: usize, const B: usize>(
        &mut self,
        pool: &mut PacketPool<N, B>,
        src: &[u8],
        dst: &'d mut [u8],
        rng: &mut R,
    ) -> TunnResult<'d>
    where
        R: RngCore + CryptoRng,
    {
        self.encapsulate_with_type(pool, DATA, src, dst, rng).await
    }

    /// Encapsulate relay plaintext as explicit relay data packet type 5.
    pub async fn encapsulate_relay<'d, R, const N: usize, const B: usize>(
        &mut self,
        pool: &mut PacketPool<N, B>,
        src: &[u8],
        dst: &'d mut [u8],
        rng: &mut R,
    ) -> TunnResult<'d>
    where
        R: RngCore + CryptoRng,
    {
        self.encapsulate_with_type(pool, RELAY_DATA, src, dst, rng)
            .await
    }

    async fn encapsulate_with_type<'d, R, const N: usize, const B: usize>(
        &mut self,
        pool: &mut PacketPool<N, B>,
        packet_type: MessageType,
        src: &[u8],
        dst: &'d mut [u8],
        rng: &mut R,
    ) -> TunnResult<'d>
    where
        R: RngCore + CryptoRng,
    {
        let current = self.current;
        // Encrypt into dst using the current session, if any. We keep only
        // the resulting length so the borrow on dst is released here, which
        // lets us reuse dst for a fresh handshake on the exhausted-session
        // path below.
        let written = self.sessions[current % N_SESSIONS]
            .as_ref()
            .and_then(|session| {
                session
                    .format_packet_data_with_type(packet_type, src, dst)
                    .map(|p| p.len())
            });
        if let Some(written) = written {
            self.timer_tick(TimerName::TimeLastPacketSent);
            // Exclude Keepalive packets from timer update.
            if !src.is_empty() {
                self.timer_tick(TimerName::TimeLastDataPacketSent);
            }
            self.tx_bytes += src.len();
            self.tx_packets += 1;
            return TunnResult::WriteToNetwork(&mut dst[..written]);
        }

        // Either no session is established or the current session has
        // exhausted its REJECT_AFTER_MESSAGES nonce budget. Either way,
        // queue the packet and trigger a fresh handshake.
        self.queue_packet(pool, packet_type, src);
        self.format_handshake_initiation(dst, false, rng).await
    }

    pub async fn handle_verified_packet<'d, R>(
        &mut self,
        packet: Packet<'_>,
        dst: &'d mut [u8],
        rng: &mut R,
    ) -> TunnResult<'d>
    where
        R: RngCore + CryptoRng,
    {
        match packet {
            Packet::HandshakeInit(p) => self.handle_handshake_init(p, dst, rng).await,
            Packet::HandshakeResponse(p) => self.handle_handshake_response(p, dst).await,
            Packet::CookieReply(p) => self.handle_cookie_reply(p),
            Packet::Data(p) => self.handle_data(p, dst).await,
            Packet::RelayData(_) => Err(WireGuardError::InvalidPacket),
        }
        .unwrap_or_else(TunnResult::from)
    }

    /// Decrypt an explicit relay data packet and return its raw plaintext.
    ///
    /// The plaintext is intentionally not validated as an IP packet. Relay
    /// plaintext is the device-level relay envelope header followed by the
    /// inner WireGuard packet.
    pub async fn handle_verified_relay_packet<'d>(
        &mut self,
        packet: Packet<'_>,
        dst: &'d mut [u8],
    ) -> Result<&'d mut [u8], WireGuardError> {
        let Packet::RelayData(p) = packet else {
            return Err(WireGuardError::InvalidPacket);
        };

        self.decrypt_raw_data(p, dst).await
    }

    async fn handle_handshake_init<'d, R>(
        &mut self,
        p: HandshakeInit<'_>,
        dst: &'d mut [u8],
        rng: &mut R,
    ) -> Result<TunnResult<'d>, WireGuardError>
    where
        R: RngCore + CryptoRng,
    {
        trace!("Received handshake_initiation: remote_idx={}", p.sender_idx);

        let (packet, session) = self
            .handshake
            .receive_handshake_initialization(p, dst, rng)
            .await?;

        // Store new session in ring buffer.
        let index = session.local_index();
        self.sessions[index % N_SESSIONS] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeLastPacketSent);
        self.rx_packets += 1;
        self.tx_packets += 1;
        self.timer_tick_session_established(false, index); // New session established, we are not the initiator
        self.set_current_session(index);

        trace!("Sending handshake_response: local_idx={}", index);

        Ok(TunnResult::WriteToNetwork(packet))
    }

    async fn handle_handshake_response<'d>(
        &mut self,
        p: HandshakeResponse<'_>,
        dst: &'d mut [u8],
    ) -> Result<TunnResult<'d>, WireGuardError> {
        trace!(
            "Received handshake_response: local_idx={}, remote_idx={}",
            p.receiver_idx, p.sender_idx
        );

        let session = self.handshake.receive_handshake_response(p)?;

        // A freshly established session always has counter 0, well below
        // REJECT_AFTER_MESSAGES, so format_packet_data must succeed here.
        let keepalive_len = session
            .format_packet_data(&[], dst)
            .expect("freshly established session must accept the keepalive")
            .len();
        // Store new session in ring buffer.
        let l_idx = session.local_index();
        let index = l_idx % N_SESSIONS;
        self.sessions[index] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.rx_packets += 1;
        self.tx_packets += 1;
        self.timer_tick_session_established(true, index); // New session established, we are the initiator
        self.set_current_session(l_idx);

        trace!("Sending keepalive");

        Ok(TunnResult::WriteToNetwork(&mut dst[..keepalive_len])) // Send a keepalive as a response
    }

    fn handle_cookie_reply<'d>(
        &mut self,
        p: CookieReply,
    ) -> Result<TunnResult<'d>, WireGuardError> {
        trace!("Received cookie_reply: local_idx={}", p.receiver_idx);

        self.handshake.receive_cookie_reply(p)?;
        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.rx_packets += 1;
        self.timer_tick(TimerName::TimeCookieReceived);

        trace!("Did set cookie");

        Ok(TunnResult::Done)
    }

    /// Update the index of the currently used session, if needed.
    fn set_current_session(&mut self, new_idx: usize) {
        let cur_idx = self.current;
        if cur_idx == new_idx {
            return;
        }
        if self.sessions[cur_idx % N_SESSIONS].is_none()
            || self.timers.session_timers[new_idx % N_SESSIONS]
                >= self.timers.session_timers[cur_idx % N_SESSIONS]
        {
            self.current = new_idx;
            trace!("New session: session={}", new_idx);
        }
    }

    /// Decrypts a data packet, and stores the decapsulated packet in dst.
    async fn handle_data<'d>(
        &mut self,
        packet: Data<'_>,
        dst: &'d mut [u8],
    ) -> Result<TunnResult<'d>, WireGuardError> {
        let decapsulated_packet = self.decrypt_raw_data(packet, dst).await?;

        trace!(
            "Decrypted data packet: plaintext_len={}",
            decapsulated_packet.len()
        );

        Ok(self.validate_decapsulated_packet(decapsulated_packet))
    }

    /// Decrypts a data-like packet and returns the raw plaintext without
    /// interpreting it as IP. Used by explicit relay packet type 5.
    async fn decrypt_raw_data<'d>(
        &mut self,
        packet: Data<'_>,
        dst: &'d mut [u8],
    ) -> Result<&'d mut [u8], WireGuardError> {
        let r_idx = packet.receiver_idx as usize;
        let idx = r_idx % N_SESSIONS;

        let plaintext = {
            let session = self.sessions[idx].as_ref().ok_or_else(|| {
                trace!("No current session available: remote_idx={}", r_idx);
                WireGuardError::NoCurrentSession
            })?;
            session.receive_packet_data(packet, dst).await?
        };

        trace!(
            "Decrypted raw data packet: session={} remote_idx={} plaintext_len={}",
            idx,
            r_idx,
            plaintext.len()
        );

        self.set_current_session(r_idx);
        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.rx_packets += 1;

        Ok(plaintext)
    }

    /// Formats a new handshake initiation message and store it in dst. If force_resend is true will send
    /// a new handshake, even if a handshake is already in progress (for example when a handshake times out)
    pub async fn format_handshake_initiation<'d, R>(
        &mut self,
        dst: &'d mut [u8],
        force_resend: bool,
        rng: &mut R,
    ) -> TunnResult<'d>
    where
        R: RngCore + CryptoRng,
    {
        if self.handshake.is_in_progress() && !force_resend {
            trace!("Skipping handshake initiation: handshake already in progress");
            return TunnResult::Done;
        }

        if self.handshake.is_expired() {
            trace!("Clearing timers before handshake initiation: tunnel expired");
            self.timers.clear();
        }

        let starting_new_handshake = !self.handshake.is_in_progress();

        match self
            .handshake
            .format_handshake_initiation(dst, self.stamper, rng)
            .await
        {
            Ok(packet) => {
                trace!(
                    "Sending handshake_initiation: len={} force_resend={}",
                    packet.len(),
                    force_resend
                );

                if starting_new_handshake {
                    self.timer_tick(TimerName::TimeLastHandshakeStarted);
                }
                self.timer_tick(TimerName::TimeLastPacketSent);
                self.tx_packets += 1;
                TunnResult::WriteToNetwork(packet)
            }
            Err(e) => TunnResult::Err(e),
        }
    }

    /// Check if an IP packet is v4 or v6, truncate to the length indicated by the length field
    /// Returns the truncated packet and the source IP as TunnResult
    fn validate_decapsulated_packet<'d>(&mut self, packet: &'d mut [u8]) -> TunnResult<'d> {
        if packet.is_empty() {
            trace!("Received keepalive data packet");
            return TunnResult::Done; // This is keepalive, and not an error
        }

        let Some(src_ip_address) = src_address(packet) else {
            debug!(
                "Rejecting decapsulated packet: invalid source IP len={}",
                packet.len()
            );
            return TunnResult::Err(WireGuardError::InvalidPacket);
        };

        let computed_len = match packet[0] >> 4 {
            4 => {
                if packet.len() < IPV4_MIN_HEADER_SIZE {
                    debug!(
                        "Rejecting decapsulated IPv4 packet: too short len={}",
                        packet.len()
                    );
                    return TunnResult::Err(WireGuardError::InvalidPacket);
                }

                let header_len = ((packet[0] & IPV4_IHL_MASK) as usize) * 4;
                if header_len < IPV4_MIN_HEADER_SIZE || packet.len() < header_len {
                    debug!(
                        "Rejecting decapsulated IPv4 packet: invalid header length ihl={} len={}",
                        packet[0] & IPV4_IHL_MASK,
                        packet.len()
                    );
                    return TunnResult::Err(WireGuardError::InvalidPacket);
                }

                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV4_LEN_OFF..IPV4_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();

                let total_len = u16::from_be_bytes(len_bytes) as usize;
                if total_len < header_len {
                    debug!(
                        "Rejecting decapsulated IPv4 packet: declared_len={} header_len={}",
                        total_len, header_len
                    );
                    return TunnResult::Err(WireGuardError::InvalidPacket);
                }

                total_len
            }

            6 => {
                if packet.len() < IPV6_MIN_HEADER_SIZE {
                    debug!(
                        "Rejecting decapsulated IPv6 packet: too short len={}",
                        packet.len()
                    );
                    return TunnResult::Err(WireGuardError::InvalidPacket);
                }

                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV6_LEN_OFF..IPV6_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();

                u16::from_be_bytes(len_bytes) as usize + IPV6_MIN_HEADER_SIZE
            }

            _ => {
                debug!(
                    "Rejecting decapsulated packet: unknown IP version len={}",
                    packet.len()
                );
                return TunnResult::Err(WireGuardError::InvalidPacket);
            }
        };

        if computed_len > packet.len() {
            debug!(
                "Rejecting decapsulated packet: declared_len={} actual_len={}",
                computed_len,
                packet.len()
            );
            return TunnResult::Err(WireGuardError::InvalidPacket);
        }

        self.timer_tick(TimerName::TimeLastDataPacketReceived);
        self.rx_bytes += computed_len;

        trace!(
            "Validated decapsulated packet: src={} len={}",
            src_ip_address, computed_len
        );

        match src_ip_address {
            IpAddr::V4(addr) => TunnResult::WriteToInterfaceV4(&mut packet[..computed_len], addr),

            IpAddr::V6(addr) => TunnResult::WriteToInterfaceV6(&mut packet[..computed_len], addr),
        }
    }

    /// Get a packet from the queue, and try to encapsulate it.
    pub async fn flush_queued_packet<'d, R, const N: usize, const B: usize>(
        &mut self,
        pool: &mut PacketPool<N, B>,
        dst: &'d mut [u8],
        _rng: &mut R,
    ) -> TunnResult<'d>
    where
        R: RngCore + CryptoRng,
    {
        if let Some(handle) = self.dequeue_packet(pool) {
            let current = self.current;
            let (written, packet_len) = {
                let packet = pool.get(handle);
                trace!(
                    "Flushing queued packet from tunnel queue: len={}",
                    packet.data.len()
                );

                let written = self.sessions[current % N_SESSIONS]
                    .as_ref()
                    .and_then(|session| {
                        session
                            .format_packet_data_with_type(packet.packet_type, packet.data, dst)
                            .map(|p| p.len())
                    });

                (written, packet.data.len())
            };

            if let Some(written) = written {
                self.timer_tick(TimerName::TimeLastPacketSent);
                if packet_len != 0 {
                    self.timer_tick(TimerName::TimeLastDataPacketSent);
                }
                self.tx_bytes += packet_len;
                self.tx_packets += 1;
                pool.free(handle);
                return TunnResult::WriteToNetwork(&mut dst[..written]);
            }

            debug!("Requeueing packet: no current session while flushing");
            self.requeue_packet(pool, handle);
        }
        TunnResult::Done
    }

    /// Push packet to the back of this peer's queue in the shared pool.
    fn queue_packet<const N: usize, const B: usize>(
        &mut self,
        pool: &mut PacketPool<N, B>,
        packet_type: MessageType,
        packet: &[u8],
    ) {
        if packet.len() > crate::MAX_PACKET_SIZE {
            warn!(
                "Dropping queued packet: packet too large len={}",
                packet.len()
            );
            return;
        }

        let now = Instant::now();
        let dropped = self.drop_expired_queued_packets(pool, now);
        if dropped != 0 {
            debug!(
                "Dropped expired queued packets before queueing: count={}",
                dropped
            );
        }

        if self.packet_queue_len >= MAX_PENDING_PACKETS {
            warn!(
                "Dropping queued packet: peer queue full len={}",
                packet.len()
            );
            return;
        }

        let Some(handle) = pool.alloc(packet_type, packet, now) else {
            warn!(
                "Dropping queued packet: shared packet pool full len={}",
                packet.len()
            );
            return;
        };

        if let Some(tail) = self.packet_queue_tail {
            pool.set_next(tail, Some(handle));
        } else {
            self.packet_queue_head = Some(handle);
        }

        self.packet_queue_tail = Some(handle);
        self.packet_queue_len += 1;
        trace!("Queued packet pending handshake: len={}", packet.len());
    }

    /// Drop packets in this peer's queue that have exceeded the pending-packet TTL.
    pub(crate) fn drop_expired_queued_packets<const N: usize, const B: usize>(
        &mut self,
        pool: &mut PacketPool<N, B>,
        now: Instant,
    ) -> usize {
        let mut dropped = 0;
        let mut prev = None;
        let mut current = self.packet_queue_head;

        while let Some(handle) = current {
            let next = pool.next(handle);

            if now.duration_since(pool.queued_at(handle)) >= PENDING_PACKET_TTL {
                if let Some(prev) = prev {
                    pool.set_next(prev, next);
                } else {
                    self.packet_queue_head = next;
                }

                if self.packet_queue_tail == Some(handle) {
                    self.packet_queue_tail = prev;
                }

                pool.set_next(handle, None);
                pool.free(handle);
                self.packet_queue_len -= 1;
                dropped += 1;
            } else {
                prev = Some(handle);
            }

            current = next;
        }

        dropped
    }

    /// Push packet to the front of this peer's queue.
    fn requeue_packet<const N: usize, const B: usize>(
        &mut self,
        pool: &mut PacketPool<N, B>,
        handle: PacketHandle,
    ) {
        if self.packet_queue_len >= MAX_PENDING_PACKETS {
            pool.free(handle);
            return;
        }

        pool.set_next(handle, self.packet_queue_head);
        self.packet_queue_head = Some(handle);
        if self.packet_queue_tail.is_none() {
            self.packet_queue_tail = Some(handle);
        }
        self.packet_queue_len += 1;
    }

    fn dequeue_packet<const N: usize, const B: usize>(
        &mut self,
        pool: &mut PacketPool<N, B>,
    ) -> Option<PacketHandle> {
        let handle = self.packet_queue_head?;
        let next = pool.take_next(handle);
        self.packet_queue_head = next;
        if next.is_none() {
            self.packet_queue_tail = None;
        }
        self.packet_queue_len -= 1;
        Some(handle)
    }

    pub(crate) fn clear_packet_queue<const N: usize, const B: usize>(
        &mut self,
        pool: &mut PacketPool<N, B>,
    ) {
        pool.free_chain(self.packet_queue_head.take());
        self.packet_queue_tail = None;
        self.packet_queue_len = 0;
    }

    async fn estimate_loss(&self) -> f32 {
        let session_idx = self.current;

        let mut weight = 9.0;
        let mut cur_avg = 0.0;
        let mut total_weight = 0.0;

        for i in 0..N_SESSIONS {
            if let Some(ref session) = self.sessions[(session_idx.wrapping_sub(i)) % N_SESSIONS] {
                let (expected, received) = session.current_packet_cnt().await;

                let loss = if expected == 0 {
                    0.0
                } else {
                    (1.0 - received as f32 / expected as f32).clamp(0.0, 1.0)
                };

                cur_avg += loss * weight;
                total_weight += weight;
                weight /= 3.0;
            }
        }

        if total_weight == 0.0 {
            0.0
        } else {
            cur_avg / total_weight
        }
    }

    /// Return stats from the tunnel:
    pub async fn stats(&self) -> Stats {
        Stats {
            time_since_last_handshake: self.time_since_last_handshake(),
            tx_bytes: self.tx_bytes,
            rx_bytes: self.rx_bytes,
            tx_packets: self.tx_packets,
            rx_packets: self.rx_packets,
            packet_loss: self.estimate_loss().await,
            rtt_ms: self.handshake.last_rtt,
        }
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;

    fn create_two_tuns<'a>(stamper: &'a TimeStamper) -> (Tunn<'a>, Tunn<'a>) {
        let mut rng = OsRng;

        let my_secret_key = StaticSecret::random_from_rng(&mut rng);
        let my_public_key = PublicKey::from(&my_secret_key);

        let their_secret_key = StaticSecret::random_from_rng(&mut rng);
        let their_public_key = PublicKey::from(&their_secret_key);

        let my_tun = Tunn::new(my_secret_key, their_public_key, None, 1, stamper);

        let their_tun = Tunn::new(their_secret_key, my_public_key, None, 2, stamper);

        (my_tun, their_tun)
    }

    async fn create_handshake_init(tun: &mut Tunn<'_>) -> Vec<u8> {
        let mut rng = OsRng;
        let mut dst = vec![0u8; 2048];

        let handshake_init = tun
            .format_handshake_initiation(&mut dst, false, &mut rng)
            .await;

        assert!(matches!(handshake_init, TunnResult::WriteToNetwork(_)));

        if let TunnResult::WriteToNetwork(packet) = handshake_init {
            packet.to_vec()
        } else {
            panic!("unexpected result");
        }
    }

    async fn create_handshake_response(tun: &mut Tunn<'_>, handshake_init: &[u8]) -> Vec<u8> {
        let mut rng = OsRng;
        let mut dst = vec![0u8; 2048];

        let packet = parse_incoming_packet(handshake_init).expect("parse failed");
        let handshake_resp = tun.handle_verified_packet(packet, &mut dst, &mut rng).await;

        assert!(matches!(handshake_resp, TunnResult::WriteToNetwork(_)));

        if let TunnResult::WriteToNetwork(packet) = handshake_resp {
            packet.to_vec()
        } else {
            panic!("unexpected result");
        }
    }

    async fn parse_handshake_resp(tun: &mut Tunn<'_>, handshake_resp: &[u8]) -> Vec<u8> {
        let mut rng = OsRng;
        let mut dst = vec![0u8; 2048];

        let packet = parse_incoming_packet(handshake_resp).expect("parse failed");
        let keepalive = tun.handle_verified_packet(packet, &mut dst, &mut rng).await;

        assert!(matches!(keepalive, TunnResult::WriteToNetwork(_)));

        if let TunnResult::WriteToNetwork(packet) = keepalive {
            packet.to_vec()
        } else {
            panic!("unexpected result");
        }
    }

    async fn parse_keepalive(tun: &mut Tunn<'_>, keepalive: &[u8]) {
        let mut rng = OsRng;
        let mut dst = vec![0u8; 2048];

        let packet = parse_incoming_packet(keepalive).expect("parse failed");
        let result = tun.handle_verified_packet(packet, &mut dst, &mut rng).await;

        assert!(matches!(result, TunnResult::Done));
    }

    async fn create_two_tuns_and_handshake<'a>(stamper: &'a TimeStamper) -> (Tunn<'a>, Tunn<'a>) {
        let (mut my_tun, mut their_tun) = create_two_tuns(stamper);

        let init = create_handshake_init(&mut my_tun).await;

        let resp = create_handshake_response(&mut their_tun, &init).await;

        let keepalive = parse_handshake_resp(&mut my_tun, &resp).await;

        parse_keepalive(&mut their_tun, &keepalive).await;

        (my_tun, their_tun)
    }

    fn create_ipv4_udp_packet() -> Vec<u8> {
        let header =
            etherparse::PacketBuilder::ipv4([192, 168, 1, 2], [192, 168, 1, 3], 5).udp(5678, 23);
        let payload = [0, 1, 2, 3];
        let mut packet = Vec::<u8>::with_capacity(header.size(payload.len()));
        header.write(&mut packet, &payload).unwrap();
        packet
    }

    #[test]
    fn rejects_decapsulated_ipv4_total_length_below_header_length() {
        let stamper = TimeStamper::new(0);
        let (mut tun, _) = create_two_tuns(&stamper);
        let mut packet = create_ipv4_udp_packet();
        packet[2..4].copy_from_slice(&19u16.to_be_bytes());

        assert!(matches!(
            tun.validate_decapsulated_packet(&mut packet),
            TunnResult::Err(WireGuardError::InvalidPacket)
        ));
    }

    #[test]
    fn rejects_decapsulated_ipv4_invalid_ihl() {
        let stamper = TimeStamper::new(0);
        let (mut tun, _) = create_two_tuns(&stamper);
        let mut packet = create_ipv4_udp_packet();
        packet[0] = 0x44; // IPv4, invalid IHL = 4
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());

        assert!(matches!(
            tun.validate_decapsulated_packet(&mut packet),
            TunnResult::Err(WireGuardError::InvalidPacket)
        ));
    }

    #[test]
    fn rejects_decapsulated_ipv4_total_length_below_options_header_length() {
        let stamper = TimeStamper::new(0);
        let (mut tun, _) = create_two_tuns(&stamper);
        let mut packet = create_ipv4_udp_packet();
        packet.resize(24, 0);
        packet[0] = 0x46; // IPv4, IHL = 6
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());

        assert!(matches!(
            tun.validate_decapsulated_packet(&mut packet),
            TunnResult::Err(WireGuardError::InvalidPacket)
        ));
    }

    #[tokio::test]
    async fn create_two_tunnels_linked_to_eachother() {
        let stamper = TimeStamper::new(0);
        let (_my_tun, _their_tun) = create_two_tuns(&stamper);
    }

    #[tokio::test]
    async fn handshake_init() {
        let stamper = TimeStamper::new(0);
        let (mut my_tun, _their_tun) = create_two_tuns(&stamper);

        let init = create_handshake_init(&mut my_tun).await;

        let parsed = parse_incoming_packet(&init).expect("parse failed");

        match parsed {
            Packet::HandshakeInit(p) => {
                assert_ne!(p.sender_idx, 0);
            }
            _ => panic!("expected handshake init"),
        }
    }

    #[tokio::test]
    async fn handshake_init_and_response() {
        let stamper = TimeStamper::new(0);
        let (mut my_tun, mut their_tun) = create_two_tuns(&stamper);

        let init = create_handshake_init(&mut my_tun).await;

        let resp = create_handshake_response(&mut their_tun, &init).await;

        let parsed = parse_incoming_packet(&resp).expect("parse failed");

        match parsed {
            Packet::HandshakeResponse(p) => {
                assert_ne!(p.sender_idx, 0);
                assert_ne!(p.receiver_idx, 0);
            }
            _ => panic!("expected handshake response"),
        }
    }

    #[tokio::test]
    async fn full_handshake() {
        let stamper = TimeStamper::new(0);
        let (mut my_tun, mut their_tun) = create_two_tuns(&stamper);

        let init = create_handshake_init(&mut my_tun).await;

        let resp = create_handshake_response(&mut their_tun, &init).await;

        let keepalive = parse_handshake_resp(&mut my_tun, &resp).await;

        parse_keepalive(&mut their_tun, &keepalive).await;
    }

    #[tokio::test]
    async fn full_handshake_plus_timers() {
        let mut rng = OsRng;

        let stamper = TimeStamper::new(0);
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake(&stamper).await;

        let mut dst1 = vec![0u8; 2048];
        let mut dst2 = vec![0u8; 2048];

        let mut pool = PacketPool::<4, 8192>::new();

        let r1 = my_tun.update_timers(&mut pool, &mut dst1, &mut rng).await;

        let r2 = their_tun
            .update_timers(&mut pool, &mut dst2, &mut rng)
            .await;

        assert!(matches!(r1, TunnResult::Done));
        assert!(matches!(r2, TunnResult::Done));
    }

    #[tokio::test]
    async fn one_ip_packet() {
        let mut rng = OsRng;

        let stamper = TimeStamper::new(0);
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake(&stamper).await;

        let sent_packet_buf = create_ipv4_udp_packet();

        let mut my_dst = vec![0u8; 2048];

        let mut pool = PacketPool::<4, 8192>::new();
        let encapsulated = my_tun
            .encapsulate(&mut pool, &sent_packet_buf, &mut my_dst, &mut rng)
            .await;

        assert!(matches!(encapsulated, TunnResult::WriteToNetwork(_)));

        let encrypted_packet = if let TunnResult::WriteToNetwork(packet) = encapsulated {
            packet.to_vec()
        } else {
            panic!("expected encrypted packet");
        };

        let mut their_dst = vec![0u8; 2048];

        let packet = parse_incoming_packet(&encrypted_packet).expect("parse failed");
        let decapsulated = their_tun
            .handle_verified_packet(packet, &mut their_dst, &mut rng)
            .await;

        match decapsulated {
            TunnResult::WriteToInterfaceV4(packet, addr) => {
                assert_eq!(addr.octets(), [192, 168, 1, 2]);
                assert_eq!(packet, sent_packet_buf.as_slice());
            }
            other => panic!("expected WriteToInterfaceV4, got {other:?}"),
        }
    }
}
