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

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use serde::Deserialize;
use tendrilix::{
    ipnet::IpNet,
    serialization::KeyBytes,
    types::v1alpha1::net_map::{Peer, RouteKind},
};

/// Configuration for the Tendril Networks desktop client.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// UDP listen port for WireGuard; 0 asks the OS for an ephemeral port.
    #[serde(default)]
    pub listen_port: u16,
    /// Private key for the local WireGuard interface.
    pub private_key: KeyBytes,
    /// IP prefix to assign to the local WireGuard interface.
    pub address: IpNet,
    /// Initial directory servers to use for fetching the network map.
    /// Once the client has successfully fetched a network map,
    /// it will ignore this list and use the directory selectors
    /// from the map instead.
    pub directories: Vec<Directory>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    /// WireGuard public key; the peer's stable identity.
    pub public_key: KeyBytes,
    /// Tunnel IPs that the directory server is reachable at.
    pub tunnel_ips: Vec<IpAddr>,
    /// Public IP/hostname and port to reach this directory server at.
    pub endpoint: String,
}

pub trait DirectoryPeer {
    fn public_key(&self) -> KeyBytes;
    fn tunnel_ips(&self) -> &[IpAddr];
    fn endpoint(&self) -> anyhow::Result<Option<SocketAddr>>;
}

impl DirectoryPeer for Directory {
    fn public_key(&self) -> KeyBytes {
        self.public_key
    }

    fn tunnel_ips(&self) -> &[IpAddr] {
        &self.tunnel_ips
    }

    fn endpoint(&self) -> anyhow::Result<Option<SocketAddr>> {
        let endpoint = self
            .endpoint
            .to_socket_addrs()
            .map_err(|error| {
                anyhow::anyhow!(
                    "failed to resolve directory endpoint {}: {error}",
                    self.endpoint
                )
            })?
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "directory endpoint {} resolved to no addresses",
                    self.endpoint
                )
            })?;

        Ok(Some(endpoint))
    }
}

impl DirectoryPeer for Peer {
    fn public_key(&self) -> KeyBytes {
        self.public_key
    }

    fn tunnel_ips(&self) -> &[IpAddr] {
        self.tunnel_ip
            .as_ref()
            .map(std::slice::from_ref)
            .unwrap_or(&[])
    }

    fn endpoint(&self) -> anyhow::Result<Option<SocketAddr>> {
        Ok(self.routes.iter().find_map(|path| match &path.kind {
            RouteKind::Direct { endpoint } => *endpoint,
            RouteKind::Relay { .. } => None,
        }))
    }
}
