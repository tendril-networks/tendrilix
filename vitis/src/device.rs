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

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec, vec::Vec};
#[cfg(feature = "std")]
use core::marker::PhantomData;
use core::{
    future::Future,
    net::{IpAddr, SocketAddr},
    option::Option,
};
#[cfg(feature = "std")]
use std::sync::Arc;

use defmt_or_log::{debug, error, trace, warn};
use embassy_futures::select::{Either4, select4};
#[cfg(not(feature = "std"))]
use embassy_net::IpEndpoint;
#[cfg(not(feature = "std"))]
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex, signal::Signal};
#[cfg(not(feature = "std"))]
use embassy_time::{Duration, Instant, Ticker};
#[cfg(feature = "alloc")]
use hashbrown::{HashMap, HashSet};
#[cfg(not(feature = "alloc"))]
use heapless::{Vec as HVec, index_map::FnvIndexMap, index_set::FnvIndexSet};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "std")]
use tokio::sync::{
    Mutex,
    watch::{self, Receiver, Sender},
};
#[cfg(feature = "std")]
use tokio::time::{Duration, Instant};

#[cfg(not(feature = "alloc"))]
use crate::limits::{MAX_ALLOWED_IPS_PER_PEER, MAX_PEERS};
pub use crate::noise::Stats as PeerStats;
use crate::{
    MAX_PACKET_SIZE, MTU,
    allowed_ips::AllowedIPs,
    authz::ForwardingAuthorizer,
    bounded::{CapacityError, TryInsert, TryInsertKey},
    index::IndexGenerator,
    ip_packet,
    ipnet::IpNet,
    nic::{InboundPacketMeta, NetworkInterface},
    noise::{
        Packet, Tunn, TunnResult,
        errors::WireGuardError,
        handshake::parse_handshake_anon,
        rate_limiter::RateLimiter,
        relay::{self, Error as RelayError},
    },
    packet_pool::DevicePacketPool,
    serialization::KeyBytes,
    timestamper::TimeStamper,
    x25519::{PublicKey, StaticSecret},
};

#[cfg(feature = "std")]
type PacketPoolMutex = Mutex<DevicePacketPool>;
#[cfg(not(feature = "std"))]
type PacketPoolMutex = Mutex<CriticalSectionRawMutex, DevicePacketPool>;

#[cfg(feature = "std")]
type UdpSocket<'a> = tokio::net::UdpSocket;
#[cfg(not(feature = "std"))]
type UdpSocket<'a> = embassy_net::udp::UdpSocket<'a>;

#[cfg(feature = "alloc")]
type PeerKeySet = HashSet<PublicKey>;
#[cfg(not(feature = "alloc"))]
type PeerKeySet = FnvIndexSet<PublicKey, MAX_PEERS>;

#[cfg(feature = "alloc")]
type PeerRoutes = AllowedIPs<PublicKey>;
#[cfg(not(feature = "alloc"))]
type PeerRoutes = AllowedIPs<PublicKey, { MAX_PEERS * MAX_ALLOWED_IPS_PER_PEER }>;

#[cfg(feature = "alloc")]
type PeerAllowedIPs = AllowedIPs<()>;
#[cfg(not(feature = "alloc"))]
type PeerAllowedIPs = AllowedIPs<(), MAX_ALLOWED_IPS_PER_PEER>;

#[cfg(not(feature = "std"))]
pub type PeerStateSubmissionChannel = Signal<CriticalSectionRawMutex, Command>;
#[cfg(not(feature = "std"))]
pub type PeerStateCompletionChannel = Signal<CriticalSectionRawMutex, CommandCompletion>;

/// Maximum handshake attempts accepted per peer before cookie rate limiting engages.
const HANDSHAKE_RATE_LIMIT: u64 = 100;

/// Maximum iterations when draining queued WireGuard packets after decapsulation.
const MAX_ITR: usize = 100;

/// Pending UDP send operation, this is used to allow us to
/// defer network operations until after we have released locks.
type PendingUdpSend<'a> = (&'a [u8], SocketAddr);

/// Caller-owned storage required by [`Device`].
///
/// Callers should create one `DeviceResources` value per device, usually in
/// static storage for embedded targets, and pass a reference to [`Device::new`].
/// This stores ordinary references to the caller-owned per-device index
/// generator and timestamper. On `no_std` targets, it also owns the command
/// queues so those queues do not require heap allocation.
pub struct DeviceResources {
    #[cfg(not(feature = "std"))]
    command_submissions: Signal<CriticalSectionRawMutex, Command>,
    #[cfg(not(feature = "std"))]
    command_completions: Signal<CriticalSectionRawMutex, CommandCompletion>,
    index_generator: IndexGenerator,
    stamper: TimeStamper,
}

impl DeviceResources {
    pub const fn new(index_generator: IndexGenerator, stamper: TimeStamper) -> Self {
        Self {
            #[cfg(not(feature = "std"))]
            command_submissions: Signal::new(),
            #[cfg(not(feature = "std"))]
            command_completions: Signal::new(),
            index_generator,
            stamper,
        }
    }
}

/// Serialized async peer-management client.
///
/// This owns both command mailboxes and turns the lower-level submit/complete
/// protocol into normal async functions. Keep running [`Device::run`] while
/// awaiting these methods; completion is produced by the device event loop.
///
/// Exposed as a trait to allow mocking devices in tests.
pub trait DeviceClient {
    fn add_peer(&self, config: PeerConfig) -> impl Future<Output = Result<(), Error>> + Send;

    fn update_peer(&self, config: PeerConfig) -> impl Future<Output = Result<(), Error>> + Send;

    fn remove_peer(&self, public_key: PublicKey) -> impl Future<Output = Result<(), Error>> + Send;

    fn get_peer(
        &self,
        public_key: PublicKey,
    ) -> impl Future<Output = Result<PeerInfo, Error>> + Send;

    fn list_peers(&self) -> impl Future<Output = Result<PeerKeySet, Error>> + Send;
}

/// Asynchronous command client for a [`Device`].
#[cfg_attr(feature = "std", derive(Clone))]
pub struct CommandClient<'q> {
    #[cfg(feature = "std")]
    inner: Arc<Mutex<CommandChannel<'q>>>,
    #[cfg(not(feature = "std"))]
    inner: Mutex<CriticalSectionRawMutex, CommandChannel<'q>>,
}

struct CommandChannel<'q> {
    #[cfg(feature = "std")]
    tx: Sender<Command>,
    #[cfg(feature = "std")]
    rx: Receiver<CommandCompletion>,
    #[cfg(feature = "std")]
    _queue_lifetime: PhantomData<&'q ()>,

    #[cfg(not(feature = "std"))]
    submissions: &'q Signal<CriticalSectionRawMutex, Command>,
    #[cfg(not(feature = "std"))]
    completions: &'q Signal<CriticalSectionRawMutex, CommandCompletion>,
}

#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// The peer's currently learned endpoint address, if known.
    pub endpoint: Option<SocketAddr>,
    /// The peer's current runtime statistics.
    pub stats: PeerStats,
}

#[derive(Clone, Debug)]
pub enum CommandOutput {
    None,
    PeerInfo(PeerInfo),
    PeerKeys(PeerKeySet),
}

pub type CommandCompletion = Result<CommandOutput, Error>;

#[derive(Clone, Debug)]
pub enum Command {
    #[cfg(feature = "std")]
    None,
    Add(PeerConfig),
    Update(PeerConfig),
    Remove(PublicKey),
    Get(PublicKey),
    List,
}

impl<'q> DeviceClient for CommandClient<'q> {
    async fn add_peer(&self, config: PeerConfig) -> Result<(), Error> {
        self.execute(Command::Add(config)).await.map(|_| ())
    }

    async fn update_peer(&self, config: PeerConfig) -> Result<(), Error> {
        self.execute(Command::Update(config)).await.map(|_| ())
    }

    async fn remove_peer(&self, public_key: PublicKey) -> Result<(), Error> {
        self.execute(Command::Remove(public_key)).await.map(|_| ())
    }

    async fn get_peer(&self, public_key: PublicKey) -> Result<PeerInfo, Error> {
        self.execute(Command::Get(public_key))
            .await
            .and_then(|output| match output {
                CommandOutput::PeerInfo(peer) => Ok(peer),
                _ => Err(Error::Io), // unreachable
            })
    }

    async fn list_peers(&self) -> Result<PeerKeySet, Error> {
        self.execute(Command::List)
            .await
            .and_then(|output| match output {
                CommandOutput::PeerKeys(keys) => Ok(keys),
                _ => Err(Error::Io), // unreachable
            })
    }
}

impl<'q> CommandClient<'q> {
    async fn execute(&self, command: Command) -> Result<CommandOutput, Error> {
        let mut channel = self.inner.lock().await;
        channel.discard_current();
        channel.submit(command).await?;
        channel.wait_next().await
    }
}

impl<'q> CommandChannel<'q> {
    #[cfg(feature = "std")]
    async fn submit(&self, command: Command) -> Result<(), Error> {
        self.tx.send(command).map_err(|_| Error::Io)
    }

    #[cfg(not(feature = "std"))]
    async fn submit(&self, command: Command) -> Result<(), Error> {
        self.submissions.signal(command);
        Ok(())
    }

    #[cfg(feature = "std")]
    fn discard_current(&mut self) {
        let _ = self.rx.borrow_and_update();
    }

    #[cfg(not(feature = "std"))]
    fn discard_current(&mut self) {
        let _ = self.completions.try_take();
    }

    #[cfg(feature = "std")]
    async fn wait_next(&mut self) -> Result<CommandOutput, Error> {
        self.rx.changed().await.map_err(|_| Error::Io)?;
        self.rx.borrow_and_update().clone()
    }

    #[cfg(not(feature = "std"))]
    async fn wait_next(&mut self) -> Result<CommandOutput, Error> {
        self.completions.wait().await
    }
}

/// Errors returned by device configuration and initialization operations.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    Io,
    PeerAlreadyExists,
    PeerNotFound,
    AllowedIPOverlap,
    Capacity,
}

impl From<CapacityError> for Error {
    fn from(_value: CapacityError) -> Self {
        Self::Capacity
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Io => write!(f, "I/O error"),
            Error::PeerAlreadyExists => write!(f, "Peer already exists"),
            Error::PeerNotFound => write!(f, "Peer not found"),
            Error::AllowedIPOverlap => write!(f, "Allowed IP overlap"),
            Error::Capacity => write!(f, "Capacity reached"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Runtime configuration for a [`Device`].
pub struct DeviceConfig<A>
where
    A: ForwardingAuthorizer,
{
    /// The device's static private key.
    pub private_key: StaticSecret,
    /// Policy used to authorize relay forwarding requests.
    ///
    /// The authorizer is invoked with the authenticated submitter's public key
    /// and the requested destination peer public key. Return `true` to allow
    /// forwarding, or `false` to drop the relay packet.
    pub forwarding_authorizer: A,
    /// Initial set of peers.
    #[cfg(feature = "alloc")]
    pub peers: Vec<PeerConfig>,
    /// Initial set of peers.
    #[cfg(not(feature = "alloc"))]
    pub peers: HVec<PeerConfig, MAX_PEERS>,
}

/// A WireGuard device that bridges an outer UDP socket with a caller-owned
/// pluggable source/sink of inner IP packets.
pub struct Device<'a, A>
where
    A: ForwardingAuthorizer,
{
    key_pair: (StaticSecret, PublicKey),
    rate_limiter: RateLimiter,
    peers: PeerState<'a>,
    #[cfg(feature = "std")]
    command_rx: Receiver<Command>,
    #[cfg(not(feature = "std"))]
    command_rx: &'a Signal<CriticalSectionRawMutex, Command>,
    #[cfg(feature = "std")]
    command_completion_tx: Sender<CommandCompletion>,
    #[cfg(not(feature = "std"))]
    command_completion_tx: &'a Signal<CriticalSectionRawMutex, CommandCompletion>,
    packet_pool: PacketPoolMutex,
    index_generator: &'a IndexGenerator,
    stamper: &'a TimeStamper,
    forwarding_authorizer: A,
}

impl<'a, A> Device<'a, A>
where
    A: ForwardingAuthorizer,
{
    /// Create a new WireGuard device.
    ///
    /// The caller owns any network stack, tunnel interface, and UDP socket.
    /// Pass those into [`Device::run`] using the pluggable [`NetworkInterface`] trait.
    ///
    /// Pass caller-owned [`DeviceResources`] storage so the device does not use
    /// process-wide singleton state for indexes or timestamps. On `no_std`
    /// targets, this storage also backs the command queues.
    pub fn new<R>(
        config: DeviceConfig<A>,
        resources: &'a DeviceResources,
        rng: &mut R,
    ) -> Result<(Self, CommandClient<'a>), Error>
    where
        R: RngCore + CryptoRng,
    {
        let public_key = PublicKey::from(&config.private_key);

        debug!("Initializing WireGuard device");

        let mut peers = PeerState::new();

        let index_generator = &resources.index_generator;
        index_generator.initialize(rng);
        let stamper = &resources.stamper;

        for peer in config.peers.into_iter() {
            Self::add_peer_to_state(
                &mut peers,
                peer,
                &config.private_key,
                index_generator,
                stamper,
            )?;
        }

        #[cfg(feature = "std")]
        let (command_tx, command_rx) = watch::channel(Command::None);
        #[cfg(feature = "std")]
        let (command_completion_tx, command_completion_rx) =
            watch::channel(Ok(CommandOutput::None));

        #[cfg(not(feature = "std"))]
        let command_tx = &resources.command_submissions;
        #[cfg(not(feature = "std"))]
        let command_rx = &resources.command_submissions;
        #[cfg(not(feature = "std"))]
        let command_completion_tx = &resources.command_completions;
        #[cfg(not(feature = "std"))]
        let command_completion_rx = &resources.command_completions;

        let device = Device {
            key_pair: (config.private_key, public_key),
            rate_limiter: RateLimiter::new(&public_key, HANDSHAKE_RATE_LIMIT, rng),
            peers,
            command_rx,
            command_completion_tx,
            packet_pool: PacketPoolMutex::new(DevicePacketPool::new()),
            index_generator,
            stamper,
            forwarding_authorizer: config.forwarding_authorizer,
        };

        let queues = CommandClient {
            #[cfg(feature = "std")]
            inner: Arc::new(Mutex::new(CommandChannel {
                #[cfg(feature = "std")]
                tx: command_tx,
                #[cfg(feature = "std")]
                rx: command_completion_rx,
                #[cfg(feature = "std")]
                _queue_lifetime: PhantomData,

                #[cfg(not(feature = "std"))]
                submissions: command_tx,
                #[cfg(not(feature = "std"))]
                completions: command_completion_rx,
            })),

            #[cfg(not(feature = "std"))]
            inner: Mutex::new(CommandChannel {
                submissions: command_tx,
                completions: command_completion_rx,
            }),
        };

        Ok((device, queues))
    }
    /// Run the WireGuard event loop.
    ///
    /// Processes packets flowing between the UDP transport socket and the
    /// inner tunnel interface until an unrecoverable socket error occurs.
    pub async fn run<NI, R>(&mut self, nic: &mut NI, udp: &mut UdpSocket<'_>, rng: &mut R) -> !
    where
        NI: NetworkInterface,
        R: RngCore + CryptoRng,
    {
        #[cfg(feature = "alloc")]
        let mut tun_src_buf: Box<[u8]> = vec![0; MTU].into_boxed_slice();
        #[cfg(not(feature = "alloc"))]
        let mut tun_src_buf = [0u8; MTU];

        #[cfg(feature = "alloc")]
        let mut udp_src_buf: Box<[u8]> = vec![0; MAX_PACKET_SIZE].into_boxed_slice();
        #[cfg(not(feature = "alloc"))]
        let mut udp_src_buf = [0u8; MAX_PACKET_SIZE];

        #[cfg(feature = "alloc")]
        let mut dst_buf: Box<[u8]> = vec![0; MAX_PACKET_SIZE].into_boxed_slice();
        #[cfg(not(feature = "alloc"))]
        let mut dst_buf = [0u8; MAX_PACKET_SIZE];

        #[cfg(feature = "alloc")]
        let mut relay_forward_buf: Box<[u8]> = vec![0; MAX_PACKET_SIZE].into_boxed_slice();
        #[cfg(not(feature = "alloc"))]
        let mut relay_forward_buf = [0u8; MAX_PACKET_SIZE];

        #[cfg(feature = "std")]
        let mut ticker = tokio::time::interval(Duration::from_millis(250));

        #[cfg(not(feature = "std"))]
        let mut ticker = Ticker::every(Duration::from_millis(250));

        let mut tick_count: u8 = 0;

        debug!("WireGuard device event loop started");

        loop {
            match select4(
                nic.recv(&mut tun_src_buf),
                udp.recv_from(&mut udp_src_buf),
                tick(&mut ticker),
                self.receive_command(),
            )
            .await
            {
                Either4::First(recv_result) => {
                    let src_len = match recv_result {
                        Ok(packet) => packet.len(),
                        Err(e) => {
                            debug!("TUN recv error: {:?}", e);
                            continue;
                        }
                    };

                    trace!("Received inner tunnel packet: len={}", src_len);

                    self.handle_tun_packet(
                        udp,
                        &mut tun_src_buf,
                        src_len,
                        &mut dst_buf,
                        &mut udp_src_buf,
                        &mut relay_forward_buf,
                        rng,
                    )
                    .await;
                }

                Either4::Second(recv_result) => {
                    let (packet_len, metadata) = match recv_result {
                        Ok((n, metadata)) => (n, metadata),

                        Err(e) => {
                            error!("UDP recv error: {:?}", e);

                            continue;
                        }
                    };

                    #[cfg(feature = "std")]
                    let src_endpoint = metadata;
                    #[cfg(not(feature = "std"))]
                    let src_endpoint = metadata.endpoint;

                    let src_addr = endpoint_to_socket_addr(src_endpoint);

                    trace!(
                        "Received UDP packet: len={} src_ip={}",
                        packet_len,
                        src_addr.ip()
                    );

                    self.handle_udp_packet(
                        nic,
                        udp,
                        &mut udp_src_buf,
                        packet_len,
                        src_addr,
                        &mut dst_buf,
                        &mut relay_forward_buf,
                        rng,
                    )
                    .await;
                }

                Either4::Third(_) => {
                    self.handle_timer_tick(
                        udp,
                        &mut dst_buf,
                        &mut udp_src_buf,
                        &mut relay_forward_buf,
                        rng,
                    )
                    .await;

                    tick_count = tick_count.wrapping_add(1);

                    // Reset the handshake rate limiter every second.
                    if tick_count >= 4 {
                        tick_count = 0;

                        self.rate_limiter.reset_count().await;
                    }
                }

                Either4::Fourth(command) => {
                    self.handle_peer_update(command).await;
                }
            }
        }
    }

    async fn handle_peer_update(&mut self, command: Command) {
        let completion = match command {
            #[cfg(feature = "std")]
            Command::None => Ok(CommandOutput::None),
            Command::Add(config) => Self::add_peer_to_state(
                &mut self.peers,
                config,
                &self.key_pair.0,
                self.index_generator,
                self.stamper,
            ),
            Command::Update(config) => Self::update_peer_in_state(&mut self.peers, config),
            Command::Remove(public_key) => {
                Self::remove_peer_from_state(&mut self.peers, &public_key);
                Ok(CommandOutput::None)
            }
            Command::Get(public_key) => {
                let stats = match self.peers.peer_by_key(&public_key) {
                    Some(peer) => Some(peer.stats().await),
                    None => None,
                };

                let peer_info = self.peers.peer_by_key(&public_key).map(|peer| PeerInfo {
                    endpoint: peer.endpoint_addr(),
                    stats: stats.unwrap_or_default(),
                });

                peer_info
                    .map(CommandOutput::PeerInfo)
                    .ok_or(Error::PeerNotFound)
            }
            Command::List => Ok(CommandOutput::PeerKeys(self.peers.peer_keys())),
        };

        self.try_send_command_completion(completion);
    }

    #[cfg(feature = "std")]
    async fn receive_command(&mut self) -> Command {
        match self.command_rx.changed().await {
            Ok(()) => self.command_rx.borrow_and_update().clone(),
            Err(_) => Command::None,
        }
    }

    #[cfg(not(feature = "std"))]
    async fn receive_command(&self) -> Command {
        self.command_rx.wait().await
    }

    #[cfg(feature = "std")]
    fn try_send_command_completion(&self, completion: CommandCompletion) {
        let _ = self.command_completion_tx.send(completion);
    }

    #[cfg(not(feature = "std"))]
    fn try_send_command_completion(&self, completion: CommandCompletion) {
        self.command_completion_tx.signal(completion);
    }

    fn add_peer_to_state(
        peers: &mut PeerState<'a>,
        config: PeerConfig,
        private_key: &StaticSecret,
        index_generator: &'a IndexGenerator,
        stamper: &'a TimeStamper,
    ) -> Result<CommandOutput, Error> {
        if peers.peer_by_key(&config.public_key).is_some() {
            warn!("Peer add skipped: peer already exists");
            return Err(Error::PeerAlreadyExists);
        }

        let index = index_generator.new_index();
        let tunn = Tunn::new(
            private_key.clone(),
            config.public_key,
            config.keepalive,
            index,
            stamper,
        );
        let peer = Peer::new(
            tunn,
            index,
            config.endpoint,
            &config.allowed_ips,
            config.relay,
        )?;
        let public_key = config.public_key;
        let peers_by_ip = peers.rebuilt_peers_by_ip_with(public_key, &peer.allowed_ips)?;

        peers.insert_peer_storage(public_key, index, peer)?;
        peers.peers_by_ip = peers_by_ip;

        debug!(
            "Peer added: allowed_ips={} has_endpoint={} has_relay={} keepalive={}",
            config.allowed_ips.len(),
            config.endpoint.is_some(),
            config.relay.is_some(),
            config.keepalive.unwrap_or(0)
        );

        Ok(CommandOutput::None)
    }

    fn update_peer_in_state(
        peers: &mut PeerState<'a>,
        config: PeerConfig,
    ) -> Result<CommandOutput, Error> {
        if peers.peer_by_key(&config.public_key).is_none() {
            warn!("Peer update skipped: peer not found");
            return Err(Error::PeerNotFound);
        }

        let allowed_ips = Peer::allowed_ips_from_slice(&config.allowed_ips)?;
        let peers_by_ip = peers.rebuilt_peers_by_ip_with(config.public_key, &allowed_ips)?;

        {
            let peer = peers
                .peer_by_key_mut(&config.public_key)
                .expect("peer existence checked above");

            peer.endpoint = config.endpoint;
            peer.relay = config.relay;
            peer.tunnel.set_persistent_keepalive(config.keepalive);
            peer.allowed_ips = allowed_ips;
        }

        peers.peers_by_ip = peers_by_ip;

        debug!(
            "Peer updated: allowed_ips={} has_endpoint={} has_relay={} keepalive={}",
            config.allowed_ips.len(),
            config.endpoint.is_some(),
            config.relay.is_some(),
            config.keepalive.unwrap_or(0)
        );

        Ok(CommandOutput::None)
    }

    fn remove_peer_from_state(peers: &mut PeerState<'a>, pub_key: &PublicKey) {
        if peers.remove_peer_storage(pub_key) {
            peers.peers_by_ip.remove(&|p: &PublicKey| p == pub_key);
            debug!("Peer removed");
        } else {
            debug!("Peer remove skipped: peer not found");
        }
    }

    /// Return runtime statistics for a configured peer.
    pub async fn peer_stats(&self, pub_key: &PublicKey) -> Option<PeerStats> {
        let peers = &self.peers;

        let peer = peers.peer_by_key(pub_key)?;

        Some(peer.stats().await)
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_tun_packet<R>(
        &mut self,
        udp: &mut UdpSocket<'_>,
        src_buf: &mut [u8],
        src_len: usize,
        dst_buf: &mut [u8],
        relay_plain_buf: &mut [u8],
        relay_packet_buf: &mut [u8],
        rng: &mut R,
    ) where
        R: RngCore + CryptoRng,
    {
        let dst_addr = match ip_packet::dst_address(&src_buf[..src_len]) {
            Some(addr) => addr,
            None => {
                debug!(
                    "Dropping inner packet: unknown or truncated IP header len={}",
                    src_len
                );
                return;
            }
        };

        trace!("Routing inner packet: len={} dst={}", src_len, dst_addr);

        let peers = &mut self.peers;

        let public_key = match peers.peers_by_ip.find(dst_addr).copied() {
            Some(public_key) => public_key,
            None => {
                debug!("Dropping inner packet: no peer route for dst={}", dst_addr);
                return;
            }
        };

        let mut packet_pool = self.packet_pool.lock().await;
        peers.drop_expired_packet_queues(&mut packet_pool, Instant::now());

        let peer = match peers.peer_by_key_mut(&public_key) {
            Some(peer) => peer,
            None => return,
        };

        match peer
            .tunnel
            .encapsulate(&mut packet_pool, &src_buf[..src_len], dst_buf, rng)
            .await
        {
            TunnResult::Done => {}

            TunnResult::Err(e) => {
                error!("Encapsulate error: {:?}", e);
            }

            TunnResult::WriteToNetwork(packet) => {
                let len = packet.len();
                let pending = Self::prepare_packet_to_peer(
                    peers,
                    &mut packet_pool,
                    public_key,
                    packet,
                    relay_plain_buf,
                    relay_packet_buf,
                    rng,
                )
                .await;
                drop(packet_pool);
                Self::send_pending_packet(udp, pending).await;
                trace!("Handled encapsulated packet: len={}", len);
            }

            _ => panic!("Unexpected result from encapsulate"),
        }
    }

    async fn prepare_packet_to_peer<'b, R>(
        peers: &mut PeerState<'a>,
        packet_pool: &mut DevicePacketPool,
        destination_key: PublicKey,
        packet: &'b [u8],
        relay_plain_buf: &'b mut [u8],
        relay_packet_buf: &'b mut [u8],
        rng: &mut R,
    ) -> Option<PendingUdpSend<'b>>
    where
        R: RngCore + CryptoRng,
    {
        let (relay_key, endpoint_addr) = match peers.peer_by_key(&destination_key) {
            Some(peer) => (peer.relay, peer.endpoint_addr()),
            None => {
                debug!("Dropping packet: destination peer is not configured");
                return None;
            }
        };

        if let Some(relay_key) = relay_key {
            return Self::prepare_packet_to_peer_via_relay(
                peers,
                packet_pool,
                destination_key,
                relay_key,
                packet,
                relay_plain_buf,
                relay_packet_buf,
                rng,
            )
            .await;
        }

        if let Some(addr) = endpoint_addr {
            trace!(
                "Sending packet directly: len={} dst_ip={}",
                packet.len(),
                addr.ip()
            );

            return Some((packet, addr));
        } else {
            debug!("Dropping packet: destination peer has no endpoint");
        }

        None
    }

    #[allow(clippy::too_many_arguments)]
    async fn prepare_packet_to_peer_via_relay<'b, R>(
        peers: &mut PeerState<'a>,
        packet_pool: &mut DevicePacketPool,
        destination_key: PublicKey,
        relay_key: PublicKey,
        packet: &'b [u8],
        relay_plain_buf: &'b mut [u8],
        relay_packet_buf: &'b mut [u8],
        rng: &mut R,
    ) -> Option<PendingUdpSend<'b>>
    where
        R: RngCore + CryptoRng,
    {
        trace!(
            "Routing packet via relay: destination_key={} relay_key={} len={}",
            KeyBytes(*destination_key.as_bytes()),
            KeyBytes(*relay_key.as_bytes()),
            packet.len()
        );

        let relay_plaintext = match relay::build_envelope(relay_plain_buf, destination_key, packet)
        {
            Ok(relay_plaintext) => relay_plaintext,
            Err(RelayError::BufferTooSmall) => {
                error!("Relay plaintext buffer too small while sending packet");
                return None;
            }
            Err(e) => {
                error!(
                    "Relay envelope construction error while sending packet: {:?}",
                    e
                );
                return None;
            }
        };

        trace!(
            "Built relay envelope plaintext: len={}",
            relay_plaintext.len()
        );

        peers.drop_expired_packet_queues(packet_pool, Instant::now());

        let relay_peer = match peers.peer_by_key_mut(&relay_key) {
            Some(peer) => peer,
            None => {
                debug!("Dropping packet: relay peer is not configured");
                return None;
            }
        };

        match relay_peer
            .tunnel
            .encapsulate_relay(packet_pool, relay_plaintext, relay_packet_buf, rng)
            .await
        {
            TunnResult::WriteToNetwork(relay_packet) => {
                let endpoint_addr = relay_peer.endpoint_addr();

                if let Some(addr) = endpoint_addr {
                    trace!(
                        "Sending packet via relay: inner_len={} outer_len={} relay_ip={}",
                        packet.len(),
                        relay_packet.len(),
                        addr.ip()
                    );

                    return Some((relay_packet, addr));
                } else {
                    debug!("Dropping packet: relay peer has no endpoint");
                }
            }
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                error!(
                    "Outer relay encapsulate error while sending packet: {:?}",
                    e
                );
            }
            _ => panic!("Unexpected result from relay encapsulate"),
        }

        None
    }

    async fn send_pending_packet(udp: &mut UdpSocket<'_>, pending: Option<PendingUdpSend<'_>>) {
        if let Some((packet, addr)) = pending
            && let Err(e) = udp.send_to(packet, addr).await
        {
            error!("UDP send error while sending packet: {:?}", e);
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_udp_packet<N, R>(
        &mut self,
        nic: &mut N,
        udp_for_reply: &mut UdpSocket<'_>,
        recv_buf: &mut [u8],
        packet_len: usize,
        src_addr: SocketAddr,
        dst_buf: &mut [u8],
        relay_forward_buf: &mut [u8],
        rng: &mut R,
    ) where
        N: NetworkInterface,
        R: RngCore + CryptoRng,
    {
        let (private_key, public_key) = (self.key_pair.0.clone(), self.key_pair.1);

        trace!(
            "Handling UDP packet: len={} src_ip={}",
            packet_len,
            src_addr.ip()
        );

        let parsed_packet = {
            let packet = &recv_buf[..packet_len];
            match self
                .rate_limiter
                .verify_packet(Some(src_addr.ip()), packet, dst_buf)
            {
                Ok(p) => p,

                Err(TunnResult::WriteToNetwork(cookie)) => {
                    trace!(
                        "Sending cookie reply: len={} dst_ip={}",
                        cookie.len(),
                        src_addr.ip()
                    );
                    if let Err(e) = udp_for_reply.send_to(cookie, src_addr).await {
                        error!("UDP send error while sending cookie reply: {:?}", e);
                    }

                    return;
                }

                Err(_) => {
                    trace!("Dropping UDP packet during rate-limit verification");
                    return;
                }
            }
        };

        let peers = &mut self.peers;

        let peer_key = match &parsed_packet {
            Packet::HandshakeInit(p) => parse_handshake_anon(&private_key, &public_key, p)
                .ok()
                .map(|hh| PublicKey::from(hh.peer_static_public))
                .and_then(|key| peers.peer_by_key(&key).map(|_| key)),

            Packet::HandshakeResponse(p) => peers.peer_key_by_index(p.receiver_idx),

            Packet::CookieReply(p) => peers.peer_key_by_index(p.receiver_idx),

            Packet::Data(p) => peers.peer_key_by_index(p.receiver_idx),
            Packet::RelayData(p) => peers.peer_key_by_index(p.receiver_idx),
        };

        let peer_key = match peer_key {
            Some(peer_key) => peer_key,
            None => {
                debug!(
                    "Dropping UDP packet: no configured peer matched src_ip={}",
                    src_addr.ip()
                );
                return;
            }
        };

        let mut packet_pool = self.packet_pool.lock().await;
        peers.drop_expired_packet_queues(&mut packet_pool, Instant::now());

        let peer = match peers.peer_by_key_mut(&peer_key) {
            Some(peer) => peer,
            None => {
                debug!("Dropping UDP packet: peer disappeared before processing");
                return;
            }
        };

        if matches!(parsed_packet, Packet::RelayData(_)) {
            let relay_plaintext = match peer
                .tunnel
                .handle_verified_relay_packet(parsed_packet, dst_buf)
                .await
            {
                Ok(plaintext) => plaintext,
                Err(e) => {
                    debug!("Dropping relay packet: decapsulation failed: {:?}", e);
                    return;
                }
            };

            let relay_plaintext_len = relay_plaintext.len();
            let mut envelope = match relay::Envelope::parse(relay_plaintext) {
                Ok(envelope) => envelope,
                Err(RelayError::TooShort) => {
                    debug!(
                        "Dropping relay packet: envelope too short len={}",
                        relay_plaintext_len
                    );
                    return;
                }
                Err(RelayError::UnsupportedVersion(version)) => {
                    debug!(
                        "Dropping relay packet: unsupported envelope version={}",
                        version
                    );
                    return;
                }
                Err(RelayError::HopLimitExhausted) => {
                    debug!("Dropping relay packet: hop limit exhausted");
                    return;
                }
                Err(e) => {
                    debug!("Dropping relay packet: invalid envelope: {:?}", e);
                    return;
                }
            };

            // Reject inner payloads that aren't a plausible standard
            // WireGuard packet before we either re-wrap or UDP-send them.
            // Without this, an authenticated submitter chooses arbitrary
            // bytes to be UDP-delivered to the destination peer's endpoint.
            match relay::validate_inner_packet(envelope.inner_packet()) {
                Ok(()) => {}
                Err(RelayError::TooShortForType) => {
                    debug!("Dropping relay packet: inner packet too short for its message type");
                    return;
                }
                Err(RelayError::InvalidMessageType(t)) => {
                    debug!(
                        "Dropping relay packet: inner packet has invalid message type={}",
                        t
                    );
                    return;
                }
                Err(e) => {
                    debug!("Dropping relay packet: invalid inner packet: {:?}", e);
                    return;
                }
            }

            let destination_key = envelope.destination();
            let inner_packet_len = envelope.inner_packet_len();

            if !self
                .forwarding_authorizer
                .authorize(&peer_key, &destination_key)
            {
                debug!("Dropping relay packet: forwarding authorizer denied packet");
                return;
            }

            let (destination_relay, destination_endpoint) =
                match peers.peer_by_key(&destination_key) {
                    Some(destination_peer) => {
                        (destination_peer.relay, destination_peer.endpoint_addr())
                    }
                    None => (None, None),
                };

            let pending_relay_forward = if let Some(next_relay_key) = destination_relay {
                peers.drop_expired_packet_queues(&mut packet_pool, Instant::now());

                let relay_peer = match peers.peer_by_key_mut(&next_relay_key) {
                    Some(peer) => peer,
                    None => {
                        debug!("Dropping relay packet: destination relay peer is not configured");
                        return;
                    }
                };

                if let Err(RelayError::HopLimitExhausted) = envelope.decrement_hop_limit() {
                    debug!("Dropping relay packet: hop limit exhausted before next relay");
                    return;
                }

                match relay_peer
                    .tunnel
                    .encapsulate_relay(
                        &mut packet_pool,
                        envelope.bytes_mut(),
                        relay_forward_buf,
                        rng,
                    )
                    .await
                {
                    TunnResult::WriteToNetwork(next_hop_packet) => {
                        let next_hop_endpoint = relay_peer.endpoint_addr();

                        if let Some(addr) = next_hop_endpoint {
                            trace!(
                                "Forwarding relay packet via next relay: inner_len={} relay_ip={}",
                                inner_packet_len,
                                addr.ip()
                            );

                            Some((&*next_hop_packet, addr))
                        } else {
                            debug!("Dropping relay packet: next relay peer has no endpoint");
                            None
                        }
                    }
                    TunnResult::Done => None,
                    TunnResult::Err(e) => {
                        error!("Relay re-encapsulate error while forwarding: {:?}", e);
                        None
                    }
                    _ => panic!("Unexpected result from relay re-encapsulate"),
                }
            } else if let Some(addr) = destination_endpoint {
                let inner_packet = envelope.inner_packet();
                trace!(
                    "Forwarding relay packet: inner_len={} dst_ip={}",
                    inner_packet.len(),
                    addr.ip()
                );

                Some((inner_packet, addr))
            } else {
                debug!("Dropping relay packet: destination peer has no endpoint");
                None
            };

            drop(packet_pool);

            Self::send_pending_packet(udp_for_reply, pending_relay_forward).await;

            return;
        }

        let mut flush = false;
        let mut pending_response = None;

        let tunnel_result = peer
            .tunnel
            .handle_verified_packet(parsed_packet, dst_buf, rng)
            .await;

        if !matches!(tunnel_result, TunnResult::Err(_)) && peer.endpoint_addr() != Some(src_addr) {
            peer.set_endpoint(src_addr);

            trace!("Updated endpoint for peer {}", src_addr.ip());
        }

        match tunnel_result {
            TunnResult::Done => {}

            TunnResult::Err(e) => {
                trace!("Dropping verified packet: tunnel returned error: {:?}", e);
                return;
            }

            TunnResult::WriteToNetwork(pkt) => {
                flush = true;

                pending_response = Self::prepare_packet_to_peer(
                    peers,
                    &mut packet_pool,
                    peer_key,
                    pkt,
                    recv_buf,
                    relay_forward_buf,
                    rng,
                )
                .await;
            }

            TunnResult::WriteToInterfaceV4(pkt, addr) => {
                let allowed = peer.is_allowed_ip(addr);
                drop(packet_pool);

                if allowed {
                    let len = pkt.len();
                    match nic
                        .send(
                            pkt,
                            InboundPacketMeta {
                                peer_public_key: peer_key,
                            },
                        )
                        .await
                    {
                        Ok(()) => {
                            trace!(
                                "Delivered IPv4 packet to interface: len={} src={}",
                                len, addr
                            );
                        }
                        Err(e) => {
                            debug!("Dropping decrypted IPv4 packet: TUN send failed: {:?}", e);
                        }
                    }
                } else {
                    debug!(
                        "Dropping decrypted IPv4 packet: source not allowed src={}",
                        addr
                    );
                }

                return;
            }

            TunnResult::WriteToInterfaceV6(pkt, addr) => {
                let allowed = peer.is_allowed_ip(addr);
                drop(packet_pool);

                if allowed {
                    let len = pkt.len();
                    match nic
                        .send(
                            pkt,
                            InboundPacketMeta {
                                peer_public_key: peer_key,
                            },
                        )
                        .await
                    {
                        Ok(()) => {
                            trace!(
                                "Delivered IPv6 packet to interface: len={} src={}",
                                len, addr
                            );
                        }
                        Err(e) => {
                            debug!("Dropping decrypted IPv6 packet: TUN send failed: {:?}", e);
                        }
                    }
                } else {
                    debug!(
                        "Dropping decrypted IPv6 packet: source not allowed src={}",
                        addr
                    );
                }

                return;
            }
        }

        drop(packet_pool);

        Self::send_pending_packet(udp_for_reply, pending_response).await;

        if flush {
            self.flush_queued_packets(
                udp_for_reply,
                peer_key,
                dst_buf,
                recv_buf,
                relay_forward_buf,
                rng,
            )
            .await;
        }
    }

    async fn flush_queued_packets<R>(
        &mut self,
        udp: &mut UdpSocket<'_>,
        peer_key: PublicKey,
        dst_buf: &mut [u8],
        relay_plain_buf: &mut [u8],
        relay_packet_buf: &mut [u8],
        rng: &mut R,
    ) where
        R: RngCore + CryptoRng,
    {
        for _ in 0..MAX_ITR {
            let peers = &mut self.peers;
            let mut packet_pool = self.packet_pool.lock().await;

            let packet_to_send = {
                let peer = match peers.peer_by_key_mut(&peer_key) {
                    Some(peer) => peer,
                    None => return,
                };

                match peer
                    .tunnel
                    .flush_queued_packet(&mut packet_pool, dst_buf, rng)
                    .await
                {
                    TunnResult::WriteToNetwork(pkt) => Some(pkt),
                    _ => None,
                }
            };

            let pending = match packet_to_send {
                Some(pkt) => {
                    Self::prepare_packet_to_peer(
                        peers,
                        &mut packet_pool,
                        peer_key,
                        pkt,
                        relay_plain_buf,
                        relay_packet_buf,
                        rng,
                    )
                    .await
                }
                None => return,
            };

            drop(packet_pool);
            Self::send_pending_packet(udp, pending).await;
        }
    }

    async fn handle_timer_tick<R>(
        &mut self,
        udp: &mut UdpSocket<'_>,
        dst_buf: &mut [u8],
        relay_plain_buf: &mut [u8],
        relay_packet_buf: &mut [u8],
        rng: &mut R,
    ) where
        R: RngCore + CryptoRng,
    {
        let peer_keys = {
            let peers = &self.peers;
            peers.peer_keys()
        };

        for public_key in peer_keys.iter().copied() {
            let peers = &mut self.peers;

            let mut packet_pool = self.packet_pool.lock().await;
            peers.drop_expired_packet_queues(&mut packet_pool, Instant::now());

            let peer = match peers.peer_by_key_mut(&public_key) {
                Some(peer) => peer,
                None => continue,
            };

            match peer.update_timers(&mut packet_pool, dst_buf, rng).await {
                TunnResult::Done | TunnResult::Err(WireGuardError::ConnectionExpired) => {}

                TunnResult::Err(e) => {
                    error!("Timer error: {:?}", e);
                }

                TunnResult::WriteToNetwork(packet) => {
                    let pending = Self::prepare_packet_to_peer(
                        peers,
                        &mut packet_pool,
                        public_key,
                        packet,
                        relay_plain_buf,
                        relay_packet_buf,
                        rng,
                    )
                    .await;
                    drop(packet_pool);
                    Self::send_pending_packet(udp, pending).await;
                }

                _ => panic!("Unexpected result from update_timers"),
            }
        }
    }
}

struct PeerState<'q> {
    #[cfg(feature = "alloc")]
    peers: HashMap<PublicKey, Peer<'q>>,
    #[cfg(not(feature = "alloc"))]
    peers: FnvIndexMap<PublicKey, Peer<'q>, MAX_PEERS>,
    peers_by_ip: PeerRoutes,
    #[cfg(feature = "alloc")]
    peers_by_idx: HashMap<u32, PublicKey>,
    #[cfg(not(feature = "alloc"))]
    peers_by_idx: FnvIndexMap<u32, PublicKey, MAX_PEERS>,
}

impl<'q> PeerState<'q> {
    fn new() -> Self {
        PeerState {
            #[cfg(feature = "alloc")]
            peers: HashMap::new(),
            #[cfg(not(feature = "alloc"))]
            peers: FnvIndexMap::new(),
            peers_by_ip: AllowedIPs::new(),
            #[cfg(feature = "alloc")]
            peers_by_idx: HashMap::new(),
            #[cfg(not(feature = "alloc"))]
            peers_by_idx: FnvIndexMap::new(),
        }
    }

    fn peer_by_key(&self, public_key: &PublicKey) -> Option<&Peer<'q>> {
        self.peers.get(public_key)
    }

    fn peer_by_key_mut(&mut self, public_key: &PublicKey) -> Option<&mut Peer<'q>> {
        self.peers.get_mut(public_key)
    }

    fn peer_key_by_index(&self, index: u32) -> Option<PublicKey> {
        self.peers_by_idx.get(&(index >> 8)).copied()
    }

    fn insert_peer_storage(
        &mut self,
        public_key: PublicKey,
        index: u32,
        peer: Peer<'q>,
    ) -> Result<(), Error> {
        self.peers
            .try_insert_entry(public_key, peer, "peers")
            .map_err(Error::from)?;
        if let Err(err) = self
            .peers_by_idx
            .try_insert_entry(index, public_key, "peer indexes")
        {
            self.peers.remove(&public_key);
            return Err(err.into());
        }
        Ok(())
    }

    fn remove_peer_storage(&mut self, public_key: &PublicKey) -> bool {
        let Some(peer) = self.peers.remove(public_key) else {
            return false;
        };

        self.peers_by_idx.remove(&peer.index());
        true
    }

    fn rebuilt_peers_by_ip_with(
        &self,
        updated_public_key: PublicKey,
        updated_allowed_ips: &PeerAllowedIPs,
    ) -> Result<PeerRoutes, Error> {
        let mut found = false;
        let mut peers_by_ip = PeerRoutes::new();

        for (public_key, peer) in self.peers.iter() {
            let allowed_ips = if *public_key == updated_public_key {
                found = true;
                updated_allowed_ips
            } else {
                &peer.allowed_ips
            };

            for (_, allowed_ip) in allowed_ips.iter() {
                if peers_by_ip
                    .overlaps(allowed_ip)
                    .map_err(|_| Error::Capacity)?
                {
                    warn!("Peer route rejected: allowed IP overlaps an existing peer route");
                    return Err(Error::AllowedIPOverlap);
                }

                peers_by_ip
                    .insert(allowed_ip, *public_key)
                    .map_err(|_| Error::Capacity)?;
            }
        }

        if !found {
            for (_, allowed_ip) in updated_allowed_ips.iter() {
                if peers_by_ip
                    .overlaps(allowed_ip)
                    .map_err(|_| Error::Capacity)?
                {
                    warn!("Peer route rejected: allowed IP overlaps an existing peer route");
                    return Err(Error::AllowedIPOverlap);
                }

                peers_by_ip
                    .insert(allowed_ip, updated_public_key)
                    .map_err(|_| Error::Capacity)?;
            }
        }

        Ok(peers_by_ip)
    }

    fn drop_expired_packet_queues(&mut self, pool: &mut DevicePacketPool, now: Instant) -> usize {
        let mut dropped = 0;
        for (_, peer) in self.peers.iter_mut() {
            dropped += peer.tunnel.drop_expired_queued_packets(pool, now);
        }
        if dropped != 0 {
            debug!("Dropped expired queued packets: count={}", dropped);
        }
        dropped
    }

    fn peer_keys(&self) -> PeerKeySet {
        let mut peers = PeerKeySet::new();

        for public_key in self.peers.keys() {
            if peers.try_insert_key(*public_key, "peer keys").is_err() {
                break;
            }
        }

        peers
    }
}

/// Configuration used when adding or updating a peer in a [`Device`].
///
/// During an update, all runtime fields replace the peer's current runtime
/// configuration, so set `endpoint`, `keepalive`, or `relay` to `None` to clear
/// that setting. The `public_key` identifies the peer being added or updated.
#[derive(Clone, Debug, Hash)]
pub struct PeerConfig {
    /// The peer's static public key.
    pub public_key: PublicKey,
    /// The peer's endpoint address, if already known.
    pub endpoint: Option<SocketAddr>,
    /// The list of IP prefixes allowed to be routed to this peer.
    #[cfg(feature = "alloc")]
    pub allowed_ips: Vec<IpNet>,
    /// The list of IP prefixes allowed to be routed to this peer.
    #[cfg(not(feature = "alloc"))]
    pub allowed_ips: HVec<IpNet, MAX_ALLOWED_IPS_PER_PEER>,
    /// The persistent keepalive interval in seconds, if configured.
    pub keepalive: Option<u16>,
    /// Optional relay peer used to transport packets to this peer.
    pub relay: Option<PublicKey>,
}

/// Runtime state associated with a configured WireGuard peer.
pub struct Peer<'q> {
    tunnel: Tunn<'q>,
    index: u32,
    endpoint: Option<SocketAddr>,
    relay: Option<PublicKey>,
    allowed_ips: PeerAllowedIPs,
}

impl<'q> Peer<'q> {
    fn new(
        tunnel: Tunn<'q>,
        index: u32,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[IpNet],
        relay: Option<PublicKey>,
    ) -> Result<Peer<'q>, Error> {
        let allowed_ips = Self::allowed_ips_from_slice(allowed_ips)?;

        Ok(Peer {
            tunnel,
            index,
            endpoint,
            relay,
            allowed_ips,
        })
    }

    async fn update_timers<'d, R>(
        &mut self,
        pool: &mut DevicePacketPool,
        dst: &'d mut [u8],
        rng: &mut R,
    ) -> TunnResult<'d>
    where
        R: RngCore + CryptoRng,
    {
        self.tunnel.update_timers(pool, dst, rng).await
    }

    fn index(&self) -> u32 {
        self.index
    }

    /// Return the currently known peer endpoint address.
    pub fn endpoint_addr(&self) -> Option<SocketAddr> {
        self.endpoint
    }

    fn set_endpoint(&mut self, addr: SocketAddr) {
        self.endpoint = Some(addr);
    }

    fn allowed_ips_from_slice(allowed_ips: &[IpNet]) -> Result<PeerAllowedIPs, Error> {
        AllowedIPs::try_from_iter(allowed_ips.iter().map(|ip| (ip, ())))
            .map_err(|_| Error::Capacity)
    }

    fn is_allowed_ip<I: Into<IpAddr>>(&self, addr: I) -> bool {
        self.allowed_ips.find(addr.into()).is_some()
    }

    /// Iterate over all allowed IP prefixes assigned to this peer.
    pub fn allowed_ips(&self) -> impl Iterator<Item = (IpAddr, u8)> + '_ {
        self.allowed_ips
            .iter()
            .map(|(_, ip)| (ip.network(), ip.prefix_len()))
    }

    /// Returns the elapsed time since the last successful handshake.
    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        self.tunnel.time_since_last_handshake()
    }

    /// Returns the configured persistent keepalive interval in seconds.
    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.tunnel.persistent_keepalive()
    }

    /// Returns `true` if the peer session state has expired.
    pub fn is_expired(&self) -> bool {
        self.tunnel.is_expired()
    }

    /// Return runtime statistics for this peer.
    pub async fn stats(&self) -> PeerStats {
        self.tunnel.stats().await
    }
}

#[cfg(feature = "std")]
fn endpoint_to_socket_addr(endpoint: SocketAddr) -> SocketAddr {
    normalize_socket_addr(endpoint)
}

#[cfg(not(feature = "std"))]
fn endpoint_to_socket_addr(endpoint: IpEndpoint) -> SocketAddr {
    normalize_socket_addr(SocketAddr::new(endpoint.addr.into(), endpoint.port))
}

fn normalize_socket_addr(endpoint: SocketAddr) -> SocketAddr {
    match endpoint {
        SocketAddr::V6(addr) => match addr.ip().to_ipv4_mapped() {
            Some(ipv4) => SocketAddr::from((ipv4, addr.port())),
            None => SocketAddr::V6(addr),
        },
        SocketAddr::V4(_) => endpoint,
    }
}

#[cfg(feature = "std")]
async fn tick(ticker: &mut tokio::time::Interval) {
    ticker.tick().await;
}

#[cfg(not(feature = "std"))]
async fn tick(ticker: &mut Ticker) {
    ticker.next().await;
}
