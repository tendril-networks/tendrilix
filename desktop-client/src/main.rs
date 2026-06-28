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

#![cfg(target_os = "linux")]

mod config;
mod directory;
mod http_client;

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use clap::Parser;
use rand_core::{CryptoRng, OsRng, RngCore};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::UdpSocket;
use tracing_subscriber::EnvFilter;
use tun_rs::{AsyncDevice, DeviceBuilder};
use vitis::{
    MTU,
    authz::{ForwardingAuthorizer, GenericAuthorizer},
    control::reconciler::PeerReconciler,
    device::{Device, DeviceConfig, DeviceResources, PeerConfig},
    index::IndexGenerator,
    ipnet::IpNet,
    nic::{Error as TunError, InboundPacketMeta, NetworkInterface},
    serialization::KeyBytes,
    timestamper::TimeStamper,
    types::v1alpha1::net_map::{Peer, Route as NetRoute, RouteKind},
    x25519::StaticSecret,
};

use crate::{
    config::{Config, Directory, DirectoryPeer},
    directory::NetworkMapFetcher,
};

#[derive(Debug, Parser)]
#[command(about = "Linux desktop client for Tendril Networks")]
struct Args {
    /// Path to the JSON configuration file.
    #[arg(value_name = "CONFIG", default_value = "config.json")]
    config: PathBuf,

    /// Override the TUN interface name from the config file.
    #[arg(long = "tun-name", default_value = "wg0")]
    tun_name: String,

    /// Enable relay forwarding, overriding the config file.
    #[arg(long)]
    relay: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init()
        .map_err(|error| anyhow::anyhow!("failed to initialize tracing subscriber: {error}"))?;

    let args = Args::parse();
    let config = load_config(&args.config)?;

    let private_key = parse_private_key(config.private_key)?;

    let tun = LinuxTunDevice::new(&args.tun_name, config.address)?;
    let tun_name = tun.name();
    tracing::info!("created TUN interface {tun_name}");

    let udp = bind_udp_socket(config.listen_port).await?;
    tracing::info!(
        "listening for WireGuard UDP packets on {}",
        udp.local_addr()?,
    );

    let forwarding_authorizer = if args.relay {
        tracing::info!("relay forwarding enabled");
        GenericAuthorizer::AllowAll
    } else {
        GenericAuthorizer::RejectAll
    };

    let mut rng = OsRng;
    let unix_time_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs();

    // The WireGuard device runs in its own long-lived Tokio task.
    // DeviceResources are borrowed by Device for the lifetime of that task, so
    // allocate them for the process lifetime before spawning.
    let resources = Box::leak(Box::new(DeviceResources::new(
        IndexGenerator::new(),
        TimeStamper::new(unix_time_secs),
    )));

    let directory_peers = directory_peer_configs(&config.directories)?;

    let (device, commands) = Device::new(
        DeviceConfig {
            private_key,
            forwarding_authorizer,
            peers: directory_peers,
        },
        resources,
        &mut rng,
    )
    .map_err(|error| anyhow::anyhow!("failed to create WireGuard device: {error:?}"))?;

    tracing::debug!("WireGuard device initialized");

    tokio::spawn(run_wireguard(device, tun, udp, rng));

    let mut reconciler = PeerReconciler::new(
        commands,
        reconciler_directories_from_config(&config.directories)?,
    );

    let map_fetcher = NetworkMapFetcher::new(tun_name.clone());
    let mut rng = OsRng;

    reconciler.run(&map_fetcher, &mut rng).await
}

fn load_config(path: &Path) -> anyhow::Result<Config> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("failed to read config {}: {error}", path.display()))?;

    serde_json::from_str(&text)
        .map_err(|error| anyhow::anyhow!("failed to parse config {}: {error}", path.display()))
}

fn parse_private_key(input: KeyBytes) -> anyhow::Result<StaticSecret> {
    Ok(StaticSecret::from(input.0))
}

fn directory_peer_configs<D: DirectoryPeer>(directories: &[D]) -> anyhow::Result<Vec<PeerConfig>> {
    if directories.is_empty() {
        anyhow::bail!("no directory servers available");
    }

    directories
        .iter()
        .map(|directory| directory_peer_config(directory))
        .collect::<anyhow::Result<Vec<_>>>()
}

fn directory_peer_config<D: DirectoryPeer>(directory: &D) -> anyhow::Result<PeerConfig> {
    let allowed_ips = directory
        .tunnel_ips()
        .iter()
        .map(|ip| match ip {
            IpAddr::V4(v4) => IpNet::new((*v4).into(), 32),
            IpAddr::V6(v6) => IpNet::new((*v6).into(), 128),
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(PeerConfig {
        public_key: directory.public_key().into(),
        endpoint: Some(directory.endpoint()?.ok_or_else(|| {
            anyhow::anyhow!("directory {} has no endpoint", directory.public_key())
        })?),
        allowed_ips,
        keepalive: Some(25),
        relay: None,
    })
}

fn reconciler_directories_from_config(directories: &[Directory]) -> anyhow::Result<Vec<Peer>> {
    if directories.is_empty() {
        anyhow::bail!("no directory servers available");
    }

    directories
        .iter()
        .enumerate()
        .map(|(index, directory)| {
            Ok(Peer {
                id: i64::try_from(index)?,
                public_key: directory.public_key,
                tunnel_ip: directory.tunnel_ips.first().copied(),
                is_directory: true,
                routes: vec![NetRoute {
                    priority: 0,
                    kind: RouteKind::Direct {
                        endpoint: directory.endpoint()?,
                    },
                }],
            })
        })
        .collect()
}

async fn bind_udp_socket(listen_port: u16) -> anyhow::Result<UdpSocket> {
    let bind_addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, listen_port));
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;

    socket
        .set_only_v6(false)
        .context("failed to enable dual-stack IPv4/IPv6 UDP socket")?;

    socket.bind(&SockAddr::from(bind_addr))?;
    socket.set_nonblocking(true)?;

    Ok(UdpSocket::from_std(socket.into())?)
}

async fn run_wireguard<A, R>(
    mut device: Device<'static, A>,
    mut tun: LinuxTunDevice,
    mut udp: UdpSocket,
    mut rng: R,
) -> !
where
    A: ForwardingAuthorizer + Send + 'static,
    R: RngCore + CryptoRng + Send + 'static,
{
    device.run(&mut tun, &mut udp, &mut rng).await;
}

struct LinuxTunDevice {
    inner: AsyncDevice,
}

impl LinuxTunDevice {
    fn new(name: &str, address: IpNet) -> anyhow::Result<Self> {
        let mut builder = DeviceBuilder::new().name(name).mtu(MTU as u16);

        builder = match address.addr() {
            IpAddr::V4(addr) => builder.ipv4(addr, address.prefix_len(), None),
            IpAddr::V6(addr) => builder.ipv6(addr, address.prefix_len()),
        };

        Ok(Self {
            inner: builder.build_async()?,
        })
    }

    fn name(&self) -> String {
        self.inner.name().unwrap_or_else(|_| "unknown".to_string())
    }
}

impl NetworkInterface for LinuxTunDevice {
    async fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> Result<&'a [u8], TunError> {
        let len = self.inner.recv(buf).await.map_err(|error| {
            tracing::debug!("TUN recv failed: {error}");
            TunError::Io
        })?;

        Ok(&buf[..len])
    }

    async fn send<'a>(
        &'a mut self,
        packet: &'a [u8],
        _meta: InboundPacketMeta,
    ) -> Result<(), TunError> {
        let len = self.inner.send(packet).await.map_err(|error| {
            tracing::debug!("TUN send failed: {error}");
            TunError::Io
        })?;

        if len == packet.len() {
            Ok(())
        } else {
            tracing::debug!("short TUN send: sent {len} of {} bytes", packet.len());
            Err(TunError::Io)
        }
    }
}
