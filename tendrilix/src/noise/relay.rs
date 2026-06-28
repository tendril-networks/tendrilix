/*
 * SPDX-License-Identifier: AGPL-3.0-only
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

use crate::{
    noise::{
        COOKIE_REPLY, COOKIE_REPLY_SZ, DATA, DATA_OVERHEAD_SZ, HANDSHAKE_INIT, HANDSHAKE_INIT_SZ,
        HANDSHAKE_RESP, HANDSHAKE_RESP_SZ,
    },
    x25519::PublicKey,
};

/// Relay envelope header version.
const ENVELOPE_VERSION: u8 = 0x01;

/// Default relay hop limit for newly-created relay envelopes.
const DEFAULT_HOP_LIMIT: u8 = 8;

/// Relay envelope layout:
///
/// - version: 1 byte (`0x01`)
/// - hop_limit: 1 byte, decremented by each relay-to-relay forwarder
/// - inner_len: 2 bytes, little-endian length of the inner WireGuard packet
/// - destination peer static public key: 32 bytes
pub(crate) const ENVELOPE_HEADER_SIZE: usize = 36;
const ENVELOPE_VERSION_OFFSET: usize = 0;
const ENVELOPE_HOP_LIMIT_OFFSET: usize = 1;
const ENVELOPE_INNER_LEN_OFFSET: usize = 2;
const ENVELOPE_INNER_LEN_SIZE: usize = 2;
const ENVELOPE_DESTINATION_OFFSET: usize = 4;
const ENVELOPE_DESTINATION_SIZE: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum Error {
    BufferTooSmall,
    TooShort,
    UnsupportedVersion(u8),
    HopLimitExhausted,
    InnerPacketTooLarge,
    TooShortForType,
    InvalidMessageType(u32),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Envelope<'a> {
    bytes: &'a mut [u8],
    inner_len: usize,
}

impl<'a> Envelope<'a> {
    pub(crate) fn parse(bytes: &'a mut [u8]) -> Result<Self, Error> {
        if bytes.len() < ENVELOPE_HEADER_SIZE {
            return Err(Error::TooShort);
        }

        let version = bytes[ENVELOPE_VERSION_OFFSET];
        if version != ENVELOPE_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }

        if bytes[ENVELOPE_HOP_LIMIT_OFFSET] == 0 {
            return Err(Error::HopLimitExhausted);
        }

        let inner_len = u16::from_le_bytes(
            bytes[ENVELOPE_INNER_LEN_OFFSET..ENVELOPE_INNER_LEN_OFFSET + ENVELOPE_INNER_LEN_SIZE]
                .try_into()
                .unwrap(),
        ) as usize;

        if ENVELOPE_HEADER_SIZE + inner_len > bytes.len() {
            return Err(Error::TooShort);
        }

        Ok(Self { bytes, inner_len })
    }

    pub(crate) fn destination(&self) -> PublicKey {
        let mut destination = [0u8; ENVELOPE_DESTINATION_SIZE];
        destination.copy_from_slice(&self.bytes[ENVELOPE_DESTINATION_OFFSET..ENVELOPE_HEADER_SIZE]);
        PublicKey::from(destination)
    }

    pub(crate) fn inner_packet(&self) -> &[u8] {
        &self.bytes[ENVELOPE_HEADER_SIZE..ENVELOPE_HEADER_SIZE + self.inner_len]
    }

    pub(crate) fn inner_packet_len(&self) -> usize {
        self.inner_len
    }

    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        self.bytes
    }

    pub(crate) fn decrement_hop_limit(&mut self) -> Result<(), Error> {
        if self.bytes[ENVELOPE_HOP_LIMIT_OFFSET] <= 1 {
            return Err(Error::HopLimitExhausted);
        }

        self.bytes[ENVELOPE_HOP_LIMIT_OFFSET] -= 1;
        Ok(())
    }
}

pub(crate) fn build_envelope<'a>(
    dst: &'a mut [u8],
    destination: PublicKey,
    inner_packet: &[u8],
) -> Result<&'a mut [u8], Error> {
    if inner_packet.len() > u16::MAX as usize {
        return Err(Error::InnerPacketTooLarge);
    }

    let envelope_len = ENVELOPE_HEADER_SIZE + inner_packet.len();
    if dst.len() < envelope_len {
        return Err(Error::BufferTooSmall);
    }

    dst[..ENVELOPE_HEADER_SIZE].fill(0);
    dst[ENVELOPE_VERSION_OFFSET] = ENVELOPE_VERSION;
    dst[ENVELOPE_HOP_LIMIT_OFFSET] = DEFAULT_HOP_LIMIT;
    dst[ENVELOPE_INNER_LEN_OFFSET..ENVELOPE_INNER_LEN_OFFSET + ENVELOPE_INNER_LEN_SIZE]
        .copy_from_slice(&(inner_packet.len() as u16).to_le_bytes());
    dst[ENVELOPE_DESTINATION_OFFSET..ENVELOPE_HEADER_SIZE].copy_from_slice(destination.as_bytes());
    dst[ENVELOPE_HEADER_SIZE..envelope_len].copy_from_slice(inner_packet);

    Ok(&mut dst[..envelope_len])
}

/// Validate that `inner` is wire-format-plausible as a standard WireGuard
/// packet that the relay is willing to forward.
///
/// Accepts only the four standard message types (HandshakeInit,
/// HandshakeResponse, CookieReply, Data). RELAY_DATA (type 5) is rejected
/// to prevent nested-relay constructions that would bypass per-hop
/// hop-limit decrement at this layer. Unknown types are rejected.
///
/// For each accepted type the inner buffer must be at least the
/// fixed-size minimum required by that type. This is a wire-format
/// sanity check, not an authentication check; the inner packet remains
/// end-to-end encrypted to the destination peer, which still performs
/// full cryptographic verification.
pub(crate) fn validate_inner_packet(inner: &[u8]) -> Result<(), Error> {
    if inner.len() < 4 {
        return Err(Error::TooShortForType);
    }

    let message_type = u32::from_le_bytes(inner[0..4].try_into().unwrap());

    match message_type {
        HANDSHAKE_INIT if inner.len() == HANDSHAKE_INIT_SZ => Ok(()),
        HANDSHAKE_RESP if inner.len() == HANDSHAKE_RESP_SZ => Ok(()),
        COOKIE_REPLY if inner.len() == COOKIE_REPLY_SZ => Ok(()),
        DATA if inner.len() >= DATA_OVERHEAD_SZ => Ok(()),
        HANDSHAKE_INIT | HANDSHAKE_RESP | COOKIE_REPLY | DATA => Err(Error::TooShortForType),
        // Reject RELAY_DATA (5) and all unknown types. Forwarding a
        // type-5 inner would let a submitter nest relay envelopes and
        // bypass the per-hop hop-limit decrement.
        other => Err(Error::InvalidMessageType(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_inner_data_packet() -> [u8; DATA_OVERHEAD_SZ] {
        let mut inner = [0u8; DATA_OVERHEAD_SZ];
        inner[..4].copy_from_slice(&DATA.to_le_bytes());
        inner
    }

    #[test]
    fn build_envelope_writes_inner_len() {
        let destination = PublicKey::from([0x42u8; ENVELOPE_DESTINATION_SIZE]);
        let inner = valid_inner_data_packet();
        let mut buf = [0xffu8; ENVELOPE_HEADER_SIZE + DATA_OVERHEAD_SZ];

        let envelope = build_envelope(&mut buf, destination, &inner).unwrap();

        assert_eq!(
            u16::from_le_bytes(
                envelope[ENVELOPE_INNER_LEN_OFFSET
                    ..ENVELOPE_INNER_LEN_OFFSET + ENVELOPE_INNER_LEN_SIZE]
                    .try_into()
                    .unwrap(),
            ) as usize,
            inner.len()
        );
    }

    #[test]
    fn parse_uses_inner_len_and_ignores_padding() {
        let destination = PublicKey::from([0x42u8; ENVELOPE_DESTINATION_SIZE]);
        let mut inner = [0u8; HANDSHAKE_INIT_SZ];
        inner[..4].copy_from_slice(&HANDSHAKE_INIT.to_le_bytes());
        let mut buf = [0u8; ENVELOPE_HEADER_SIZE + HANDSHAKE_INIT_SZ + 8];
        let envelope = build_envelope(&mut buf, destination, &inner).unwrap();
        let envelope_len = envelope.len();
        let padded = &mut buf[..envelope_len + 8];
        padded[envelope_len..].fill(0xaa);

        let envelope = Envelope::parse(padded).unwrap();

        assert_eq!(envelope.inner_packet_len(), HANDSHAKE_INIT_SZ);
        assert_eq!(envelope.inner_packet(), &inner);
        validate_inner_packet(envelope.inner_packet()).unwrap();
    }

    #[test]
    fn parse_rejects_inner_len_past_buffer() {
        let destination = PublicKey::from([0x42u8; ENVELOPE_DESTINATION_SIZE]);
        let inner = valid_inner_data_packet();
        let mut buf = [0u8; ENVELOPE_HEADER_SIZE + DATA_OVERHEAD_SZ];
        let envelope = build_envelope(&mut buf, destination, &inner).unwrap();
        envelope[ENVELOPE_INNER_LEN_OFFSET..ENVELOPE_INNER_LEN_OFFSET + ENVELOPE_INNER_LEN_SIZE]
            .copy_from_slice(&((DATA_OVERHEAD_SZ + 1) as u16).to_le_bytes());

        assert_eq!(Envelope::parse(envelope), Err(Error::TooShort));
    }

    #[test]
    fn validate_rejects_padded_handshake_init() {
        let mut inner = [0u8; HANDSHAKE_INIT_SZ + 1];
        inner[..4].copy_from_slice(&HANDSHAKE_INIT.to_le_bytes());

        assert_eq!(validate_inner_packet(&inner), Err(Error::TooShortForType));
    }

    #[test]
    fn validate_accepts_data_with_payload() {
        let mut inner = [0u8; DATA_OVERHEAD_SZ + 16];
        inner[..4].copy_from_slice(&DATA.to_le_bytes());

        assert_eq!(validate_inner_packet(&inner), Ok(()));
    }
}
