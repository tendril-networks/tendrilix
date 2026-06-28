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

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};

use chrono::{DateTime, Utc};
#[cfg(not(feature = "alloc"))]
use heapless::Vec;
use serde::{Deserialize, Serialize};

#[cfg(not(feature = "alloc"))]
use crate::limits::MAX_PEERS;
use crate::serialization::KeyBytes;

#[cfg(not(feature = "alloc"))]
pub const MAX_ROUTES: usize = 4;

/// Unique identifier for a peer.
pub type PeerId = i64;

/// Full network map published by directory servers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkMap {
    /// Newest timestamp from database rows that contributed to this map.
    #[serde(with = "map_timestamp")]
    pub updated_at: DateTime<Utc>,
    /// Peers known to the control plane.
    #[cfg(feature = "alloc")]
    pub peers: Vec<Peer>,
    /// Peers known to the control plane.
    #[cfg(not(feature = "alloc"))]
    pub peers: Vec<Peer, MAX_PEERS>,
}

/// A WireGuard node in the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    /// Global unique identifier for this peer.
    pub id: PeerId,
    /// WireGuard public key; the peer's stable identity.
    pub public_key: KeyBytes,
    /// IP address this peer owns.
    pub tunnel_ip: Option<IpAddr>,
    /// Whether this peer is a directory server.
    pub is_directory: bool,
    /// Reachable routes to this peer.
    #[cfg(feature = "alloc")]
    pub routes: Vec<Route>,
    /// Reachable routes to this peer.
    #[cfg(not(feature = "alloc"))]
    pub routes: Vec<Route, MAX_ROUTES>,
}

/// Route for routing to a peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// Lower values have higher precedence. Routes with equal priority are candidates
    /// for client-side load distribution.
    pub priority: u16,
    /// The kind of route to this peer.
    pub kind: RouteKind,
}

/// The kind of route to a peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    /// Route directly to the destination peer.
    Direct {
        /// The destination peer's current endpoint.
        endpoint: Option<SocketAddr>,
    },
    /// Route through a specific relay peer.
    Relay {
        /// Relay peer id to route through.
        id: PeerId,
    },
}

mod map_timestamp {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

    pub fn serialize<S>(timestamp: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            timestamp.serialize(serializer)
        } else {
            serializer.serialize_i64(timestamp.timestamp())
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            DateTime::<Utc>::deserialize(deserializer)
        } else {
            let seconds = i64::deserialize(deserializer)?;
            DateTime::<Utc>::from_timestamp(seconds, 0)
                .ok_or_else(|| de::Error::custom("timestamp is outside chrono's supported range"))
        }
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use alloc::vec;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    #[test]
    fn network_map_round_trips_with_postcard() {
        let map = NetworkMap {
            updated_at: DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
            peers: vec![
                Peer {
                    id: 1,
                    public_key: KeyBytes([0x11; 32]),
                    tunnel_ip: Some(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
                    is_directory: true,
                    routes: vec![
                        Route {
                            priority: 0,
                            kind: RouteKind::Direct {
                                endpoint: Some(SocketAddr::from(([203, 0, 113, 10], 51820))),
                            },
                        },
                        Route {
                            priority: 10,
                            kind: RouteKind::Relay { id: 2 },
                        },
                    ],
                },
                Peer {
                    id: 2,
                    public_key: KeyBytes([0x22; 32]),
                    tunnel_ip: Some(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))),
                    is_directory: false,
                    routes: vec![],
                },
            ],
        };

        let encoded = postcard::to_allocvec(&map).expect("serialize network map");
        let decoded: NetworkMap = postcard::from_bytes(&encoded).expect("deserialize network map");

        assert_eq!(decoded, map);
    }
}
