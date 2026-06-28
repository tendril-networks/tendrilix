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

use std::{
    ffi::CString,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    os::fd::AsRawFd,
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, Uri, client::conn::http1};
use hyper_util::rt::TokioIo;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::config::DirectoryPeer;

const DEFAULT_HTTP_PORT: u16 = 80;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const NETWORK_MAP_PATH: &str = "/v1alpha1/map";

#[derive(Debug, Clone)]
pub struct DirectoryMapEndpoint {
    host: String,
    port: u16,
    path: &'static str,
}

impl DirectoryMapEndpoint {
    pub fn from_directory<D: DirectoryPeer>(directory: &D) -> anyhow::Result<Self> {
        let tunnel_ip = directory.tunnel_ips().first().ok_or_else(|| {
            anyhow::anyhow!(
                "directory peer {} has no tunnel IPs",
                directory.public_key()
            )
        })?;

        Ok(Self {
            host: tunnel_ip.to_string(),
            port: DEFAULT_HTTP_PORT,
            path: NETWORK_MAP_PATH,
        })
    }

    pub fn uri(&self) -> anyhow::Result<Uri> {
        self.request_url()
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid directory map URL: {error}"))
    }

    pub fn request_url(&self) -> String {
        format!(
            "http://{}:{}{}",
            format_http_host(&self.host),
            self.port,
            self.path
        )
    }

    fn socket_addr(&self) -> anyhow::Result<SocketAddr> {
        (self.host.as_str(), self.port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow::anyhow!("could not resolve {}", self.host))
    }
}

pub struct DirectoryHttpClient {
    interface_name: String,
}

impl DirectoryHttpClient {
    pub fn new(interface_name: impl Into<String>) -> Self {
        Self {
            interface_name: interface_name.into(),
        }
    }

    pub async fn get_network_map_bytes(
        &self,
        endpoint: &DirectoryMapEndpoint,
    ) -> anyhow::Result<Vec<u8>> {
        let stream =
            connect_bound_to_device(endpoint.socket_addr()?, self.interface_name.clone()).await?;
        let io = TokioIo::new(stream);

        let (mut sender, connection) = http1::handshake(io).await.map_err(|error| {
            anyhow::anyhow!(
                "HTTP handshake with {} failed: {error}",
                endpoint.request_url()
            )
        })?;

        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!("directory HTTP connection failed: {error}");
            }
        });

        let request = Request::get(endpoint.uri()?)
            .header(hyper::header::ACCEPT, "application/vnd.postcard")
            .body(Empty::<Bytes>::new())?;

        let response = tokio::time::timeout(HTTP_TIMEOUT, sender.send_request(request))
            .await
            .map_err(|_| anyhow::anyhow!("timed out waiting for {}", endpoint.request_url()))?
            .map_err(|error| {
                anyhow::anyhow!("HTTP request to {} failed: {error}", endpoint.request_url())
            })?;

        if !response.status().is_success() {
            anyhow::bail!(
                "directory server {} returned {}",
                endpoint.request_url(),
                response.status()
            );
        }

        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "failed to read response from {}: {error}",
                    endpoint.request_url()
                )
            })?
            .to_bytes();

        Ok(body.to_vec())
    }
}

async fn connect_bound_to_device(
    address: SocketAddr,
    interface_name: String,
) -> anyhow::Result<tokio::net::TcpStream> {
    let stream = tokio::task::spawn_blocking(move || {
        let socket = Socket::new(domain_for(address), Type::STREAM, Some(Protocol::TCP))?;
        bind_socket_to_device(&socket, &interface_name)?;
        socket.set_read_timeout(Some(HTTP_TIMEOUT))?;
        socket.set_write_timeout(Some(HTTP_TIMEOUT))?;
        socket.connect_timeout(&SockAddr::from(address), HTTP_TIMEOUT)?;

        let stream: TcpStream = socket.into();
        stream.set_nonblocking(true)?;
        Ok::<_, anyhow::Error>(stream)
    })
    .await
    .map_err(|error| anyhow::anyhow!("directory connection task failed: {error}"))??;

    tokio::net::TcpStream::from_std(stream).map_err(Into::into)
}

fn format_http_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn domain_for(address: SocketAddr) -> Domain {
    if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    }
}

fn bind_socket_to_device<S: AsRawFd>(socket: &S, device_name: &str) -> anyhow::Result<()> {
    let device_name = CString::new(device_name)
        .map_err(|_| anyhow::anyhow!("interface name contains an interior NUL byte"))?;

    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            device_name.as_ptr().cast(),
            device_name.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };

    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
            .map_err(|error| anyhow::anyhow!("failed to bind socket to {device_name:?}: {error}"))
    }
}
