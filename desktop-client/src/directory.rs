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

use vitis::{
    control::reconciler::NetworkMapFetcher as ReconcilerNetworkMapFetcher,
    types::v1alpha1::net_map::NetworkMap,
};

use crate::{
    config::DirectoryPeer,
    http_client::{DirectoryHttpClient, DirectoryMapEndpoint},
};

pub struct NetworkMapFetcher {
    tun_name: String,
    client: DirectoryHttpClient,
}

impl NetworkMapFetcher {
    pub fn new(tun_name: impl Into<String>) -> Self {
        let tun_name = tun_name.into();
        Self {
            client: DirectoryHttpClient::new(tun_name.clone()),
            tun_name,
        }
    }

    pub async fn fetch<D: DirectoryPeer>(&self, directories: &[D]) -> anyhow::Result<NetworkMap> {
        if directories.is_empty() {
            anyhow::bail!("no directory servers available");
        }

        let mut last_error = None;

        for directory in directories {
            let endpoint = DirectoryMapEndpoint::from_directory(directory)?;
            tracing::info!(
                "fetching network map from {} via {}",
                endpoint.request_url(),
                self.tun_name
            );

            let fetch_result = self
                .client
                .get_network_map_bytes(&endpoint)
                .await
                .and_then(|body| postcard::from_bytes::<NetworkMap>(&body).map_err(Into::into));

            match fetch_result {
                Ok(map) => return Ok(map),
                Err(fetch_error) => {
                    tracing::warn!(
                        "failed to fetch network map from {}: {fetch_error}",
                        endpoint.request_url()
                    );
                    last_error = Some(fetch_error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("failed to fetch network map")))
    }
}

impl ReconcilerNetworkMapFetcher for NetworkMapFetcher {
    type Error = anyhow::Error;

    async fn fetch_network_map(
        &self,
        directories: &[vitis::types::v1alpha1::net_map::Peer],
    ) -> anyhow::Result<NetworkMap> {
        self.fetch(directories).await
    }
}
