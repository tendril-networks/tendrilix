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

#![cfg_attr(not(any(test, feature = "std")), no_std)]

#[cfg(not(any(
    feature = "alloc",
    feature = "memory-tiny",
    feature = "memory-small",
    feature = "memory-medium",
    feature = "memory-large",
)))]
compile_error!("tendrilix requires either the `alloc` feature or one `memory-*` feature to be enabled");

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod allowed_ips;
pub mod authz;
pub mod control;
pub mod device;
pub mod index;
pub mod ipnet;
pub mod nic;
pub mod packet_pool;
pub mod serialization;
pub mod timestamper;
pub mod types;

pub(crate) mod bounded;
pub(crate) mod ip_packet;
pub(crate) mod noise;

/// Re-export of the x25519 types
pub mod x25519 {
    pub use x25519_dalek::{
        EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret,
    };
}

/// Overhead of WireGuard encapsulation in bytes.
pub const PACKET_OVERHEAD: usize = 32;

/// Inner MTU used for tunneled IP packets.
///
/// Chosen to satisfy the IPv6 minimum MTU requirement while leaving
/// room for WireGuard and UDP encapsulation overhead.
pub const MTU: usize = 1280;

/// Maximum total size of a WireGuard packet, including explicit relayed packets.
pub const MAX_PACKET_SIZE: usize =
    MTU + 2 * PACKET_OVERHEAD + crate::noise::relay::ENVELOPE_HEADER_SIZE;

#[cfg(feature = "memory-tiny")]
pub mod limits {
    /// Device-wide pending packet byte capacity shared by all peers.
    pub const MAX_PACKET_POOL_BYTES: usize = 1536;
    /// Maximum number of peers that can be configured simultaneously.
    pub const MAX_PEERS: usize = 4;
    /// Maximum number of allowed IP CIDR entries stored per peer.
    pub const MAX_ALLOWED_IPS_PER_PEER: usize = 2;
}

#[cfg(feature = "memory-small")]
pub mod limits {
    /// Device-wide pending packet byte capacity shared by all peers.
    pub const MAX_PACKET_POOL_BYTES: usize = 2048;
    /// Maximum number of peers that can be configured simultaneously.
    pub const MAX_PEERS: usize = 8;
    /// Maximum number of allowed IP CIDR entries stored per peer.
    pub const MAX_ALLOWED_IPS_PER_PEER: usize = 2;
}

#[cfg(feature = "memory-medium")]
pub mod limits {
    /// Device-wide pending packet byte capacity shared by all peers.
    pub const MAX_PACKET_POOL_BYTES: usize = 8192;
    /// Maximum number of peers that can be configured simultaneously.
    pub const MAX_PEERS: usize = 16;
    /// Maximum number of allowed IP CIDR entries stored per peer.
    pub const MAX_ALLOWED_IPS_PER_PEER: usize = 4;
}

#[cfg(feature = "memory-large")]
pub mod limits {
    /// Device-wide pending packet byte capacity shared by all peers.
    pub const MAX_PACKET_POOL_BYTES: usize = 32768;
    /// Maximum number of peers that can be configured simultaneously.
    pub const MAX_PEERS: usize = 32;
    /// Maximum number of allowed IP CIDR entries stored per peer.
    pub const MAX_ALLOWED_IPS_PER_PEER: usize = 8;
}

#[cfg(feature = "alloc")]
pub mod limits {
    /// Device-wide pending packet byte capacity shared by all peers.
    pub const MAX_PACKET_POOL_BYTES: usize = 65536;
}
