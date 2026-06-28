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

use core::future::Future;

use defmt_or_log::debug;
use embassy_net_driver_channel::Runner as ChannelRunner;

use crate::{MTU, x25519::PublicKey};

/// Error returned by a network interface.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    /// The packet could not be read from or written to the network interface.
    Io,
    /// The destination network interface receive queue is full.
    Full,
    /// The supplied caller-owned buffer is too small for the packet.
    BufferTooSmall,
}

/// Metadata attached to an inbound inner IP packet after it has been
/// authenticated and decrypted by WireGuard.
#[derive(Clone, Copy, Debug)]
pub struct InboundPacketMeta {
    /// Public key of the WireGuard peer that originated the packet.
    pub peer_public_key: PublicKey,
}

/// Pluggable source and destination for inner IP packets.
///
/// Implement this trait for anything that behaves like a network interface:
/// an `embassy-net` channel runner, a userspace stack adapter, or a Linux TUN
/// device.
///
/// `recv` copies the next outbound inner IP packet into the caller-provided
/// buffer and returns the initialized packet slice. `send` delivers a
/// decrypted inner IP packet back to the local IP stack or TUN device.
pub trait NetworkInterface {
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = Result<&'a [u8], Error>> + 'a;

    fn send<'a>(
        &'a mut self,
        packet: &'a [u8],
        meta: InboundPacketMeta,
    ) -> impl Future<Output = Result<(), Error>> + 'a;
}

/// A network interface implementation backed by an `embassy-net` channel runner.
impl NetworkInterface for ChannelRunner<'static, MTU> {
    async fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let packet = self.tx_buf().await;

        if packet.len() > buf.len() {
            debug!(
                "Dropping inner stack packet: packet too large len={} buf_len={}",
                packet.len(),
                buf.len()
            );
            self.tx_done();
            return Err(Error::BufferTooSmall);
        }

        let len = packet.len();
        buf[..len].copy_from_slice(packet);
        self.tx_done();

        Ok(&buf[..len])
    }

    async fn send<'a>(
        &'a mut self,
        packet: &'a [u8],
        _meta: InboundPacketMeta,
    ) -> Result<(), Error> {
        let Some(buf) = self.try_rx_buf() else {
            debug!(
                "Dropping decrypted packet: receive buffer full len={}",
                packet.len()
            );
            return Err(Error::Full);
        };

        if packet.len() > buf.len() {
            debug!(
                "Dropping decrypted packet: packet too large len={} buf_len={}",
                packet.len(),
                buf.len()
            );
            return Err(Error::BufferTooSmall);
        }

        let len = packet.len();
        buf[..len].copy_from_slice(packet);
        self.rx_done(len);

        Ok(())
    }
}
