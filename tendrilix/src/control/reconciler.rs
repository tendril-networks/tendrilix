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

//! Control-plane reconciler.
//!
//! The reconciler is the imperative shell around two pure cores: turning a
//! [`NetworkMap`] into the set of peers we want on the device, and the
//! [`PeerHealth`] state machine. Its job is to diff that desired state against
//! what the device is actually running, apply the difference, and periodically
//! sample peer health to drive route-policy failover and recovery.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::{
    hash::{Hash, Hasher},
    net::{IpAddr, SocketAddr},
};

use chrono::{DateTime, Utc};
use defmt_or_log::{debug, info, trace, warn};
#[cfg(not(feature = "std"))]
use embassy_futures::select::{Either, select};
#[cfg(not(feature = "std"))]
use embassy_time::{Duration, Instant, Ticker};
use hash32::FnvHasher;
#[cfg(feature = "alloc")]
use hashbrown::{HashMap, HashSet};
#[cfg(not(feature = "alloc"))]
use heapless::{Vec, index_map::FnvIndexMap, index_set::FnvIndexSet};
use rand_core::RngCore;
#[cfg(feature = "std")]
use tokio::time::{Duration, Instant};

#[cfg(not(feature = "alloc"))]
use crate::limits::{MAX_ALLOWED_IPS_PER_PEER, MAX_PEERS};
#[cfg(not(feature = "alloc"))]
use crate::types::v1alpha1::net_map::MAX_ROUTES;
use crate::{
    bounded::{CapacityError, TryInsert, TryPush},
    control::peer_health::{HealthDecision, PeerHealth, RouteKey, RouteKeyVec, SwitchReason},
    device::{DeviceClient, PeerConfig},
    ipnet::IpNet,
    serialization::KeyBytes,
    types::v1alpha1::net_map::{NetworkMap, Peer, RouteKind},
    x25519::PublicKey,
};

/// A list of peers, bounded by [`MAX_PEERS`] on no-alloc targets.
#[cfg(feature = "alloc")]
pub type PeerVec<T> = Vec<T>;
#[cfg(not(feature = "alloc"))]
pub type PeerVec<T> = Vec<T, MAX_PEERS>;

/// A peer's tunnel IPs, rendered as host-prefix allowed IPs on the device.
#[cfg(feature = "alloc")]
pub type AllowedIpVec = Vec<IpAddr>;
#[cfg(not(feature = "alloc"))]
pub type AllowedIpVec = Vec<IpAddr, MAX_ALLOWED_IPS_PER_PEER>;

/// A peer's route policies in preference order (index 0 most preferred).
#[cfg(feature = "alloc")]
pub type PolicyVec = Vec<RoutePolicy>;
// A peer's policies are derived one-to-one from its routes (then deduplicated),
// so the route bound is the right capacity here.
#[cfg(not(feature = "alloc"))]
pub type PolicyVec = Vec<RoutePolicy, MAX_ROUTES>;

/// A map keyed by peer public key, used for desired state, health, and
/// applied-config fingerprints.
#[cfg(feature = "alloc")]
pub type PeerMap<T> = HashMap<PublicKey, T>;
#[cfg(not(feature = "alloc"))]
pub type PeerMap<T> = FnvIndexMap<PublicKey, T, MAX_PEERS>;

/// A set of peer public keys, used to represent the peers currently on the device.
#[cfg(feature = "alloc")]
pub type PeerSet = HashSet<PublicKey>;
#[cfg(not(feature = "alloc"))]
pub type PeerSet = FnvIndexSet<PublicKey, MAX_PEERS>;

/// How often the reconciler fetches and applies network map updates. Peer
/// configuration changes infrequently, so this cadence is coarse; the cost of a
/// missed update is only that a config change lands up to one interval late.
pub const MAP_RECONCILE_INTERVAL: Duration = Duration::from_secs(60);

/// How often the reconciler samples peer health. This is the cadence at which
/// the [`PeerHealth`] state machine is fed fresh statistics, so it bounds how
/// quickly a dead path can be detected. It must stay well below the
/// inbound-silence window that gates failover so detection is not starved of
/// samples (see `peer_health`).
pub const PEER_HEALTH_INTERVAL: Duration = Duration::from_secs(5);

/// Human-readable label for a [`SwitchReason`], used only in log lines.
fn describe_switch_reason(reason: SwitchReason) -> &'static str {
    match reason {
        SwitchReason::Failover => "failover",
        SwitchReason::RecoveryProbe => "recovery probe",
        SwitchReason::RecoveryFailed => "recovery failed",
    }
}

/// Human-readable label for a route policy, used only in log lines. `None`
/// covers the case where the chosen index has no policy (logged as `missing`).
fn describe_route_policy(policy: Option<&RoutePolicy>) -> &'static str {
    match policy {
        Some(RoutePolicy::Direct { .. }) => "direct",
        Some(RoutePolicy::Relay { .. }) => "relay",
        None => "missing",
    }
}

/// A way to reach a peer, in descending order of preference (lower priority
/// value wins). Policy index 0 is the highest-priority path after normalization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoutePolicy {
    /// Send straight to one destination peer endpoint. Multiple direct policies
    /// with the same priority are load-balanced candidates.
    Direct {
        endpoint: Option<SocketAddr>,
        priority: u16,
    },
    /// Send via the named relay peer.
    Relay { relay: PublicKey, priority: u16 },
}

impl RoutePolicy {
    /// This policy's priority value (lower wins).
    fn priority(&self) -> u16 {
        match self {
            Self::Direct { priority, .. } | Self::Relay { priority, .. } => *priority,
        }
    }

    /// Overwrite this policy's priority, used when collapsing duplicate routes
    /// down to their best (lowest) priority.
    fn set_priority(&mut self, new_priority: u16) {
        match self {
            Self::Direct { priority, .. } | Self::Relay { priority, .. } => {
                *priority = new_priority
            }
        }
    }

    /// Two policies describe the same route if they go the same way, regardless
    /// of priority. Used to collapse duplicate routes.
    fn same_route(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Direct { endpoint: a, .. }, Self::Direct { endpoint: b, .. }) => a == b,
            (Self::Relay { relay: a, .. }, Self::Relay { relay: b, .. }) => a == b,
            _ => false,
        }
    }

    /// The stable [`RouteKey`] identity for this policy. Health is keyed by this
    /// rather than by policy index, so reordering the policy list preserves history.
    fn route_key(&self) -> RouteKey {
        match self {
            Self::Direct { endpoint, .. } => RouteKey::Direct(*endpoint),
            Self::Relay { relay, .. } => RouteKey::Relay(*relay),
        }
    }
}

/// The configuration we want on the device for a single peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesiredPeer {
    /// The peer's static public key, its identity on the device.
    pub public_key: PublicKey,
    /// Tunnel IPs to install as host-prefix allowed IPs for this peer.
    pub allowed_ips: AllowedIpVec,
    /// Persistent keepalive interval in seconds, set for directory servers so
    /// the control channel survives NAT and left unset for ordinary peers.
    pub keepalive: Option<u16>,
    /// Normalized route policies in preference order (index 0 most preferred).
    pub policies: PolicyVec,
    /// Semantic source of truth for the selected route. `active_policy` is kept
    /// as a resolved cache for existing callers and tests.
    pub active_route: Option<RouteKey>,
    /// Index into `policies` of the route currently programmed on the device.
    pub active_policy: usize,
}

impl DesiredPeer {
    /// The active policy index, clamped into range in case `policies` shrank
    /// since it was last set.
    fn active_policy_index(&self) -> usize {
        self.active_policy
            .min(self.policies.len().saturating_sub(1))
    }

    /// Select a new active policy, clamping the index and keeping the cached
    /// `active_route` identity in step with it.
    fn set_active_policy(&mut self, policy_index: usize) {
        self.active_policy = policy_index.min(self.policies.len().saturating_sub(1));
        self.active_route = self
            .policies
            .get(self.active_policy)
            .map(RoutePolicy::route_key);
    }

    /// Render this peer into a device [`PeerConfig`] for the active policy.
    pub fn config(&self) -> PeerConfig {
        self.config_for_policy(self.active_policy_index(), self.keepalive)
    }

    /// The best direct endpoint advertised for this peer, if any.
    ///
    /// Relay policies still program this endpoint hint so switching to a relay does
    /// not erase the destination endpoint learned from the map. This keeps direct
    /// recovery cheap and preserves the historical device behavior where endpoint
    /// state is independent from the selected relay.
    fn preferred_direct_endpoint(&self) -> Option<SocketAddr> {
        self.policies.iter().find_map(|policy| match policy {
            RoutePolicy::Direct {
                endpoint: Some(endpoint),
                ..
            } => Some(*endpoint),
            RoutePolicy::Direct { endpoint: None, .. } | RoutePolicy::Relay { .. } => None,
        })
    }

    /// Render this peer into a device [`PeerConfig`] for a specific policy.
    fn config_for_policy(&self, policy_index: usize, keepalive: Option<u16>) -> PeerConfig {
        let (endpoint, relay) = match self.policies.get(policy_index) {
            Some(RoutePolicy::Direct { endpoint, .. }) => (*endpoint, None),
            Some(RoutePolicy::Relay { relay, .. }) => {
                (self.preferred_direct_endpoint(), Some(*relay))
            }
            None => (None, None),
        };

        let allowed_ips = self
            .allowed_ips
            .iter()
            .map(|ip| {
                let host_prefix = if ip.is_ipv4() { 32 } else { 128 };
                IpNet::new(*ip, host_prefix).expect("host prefix length is always valid")
            })
            .collect();

        PeerConfig {
            public_key: self.public_key,
            endpoint,
            allowed_ips,
            keepalive,
            relay,
        }
    }
}

/// Stable fingerprint of the peer configuration rendered by the reconciler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PeerConfigFingerprint(u64);

impl PeerConfigFingerprint {
    /// Fingerprint a rendered [`PeerConfig`] so the reconciler can tell whether a
    /// peer's installed configuration actually changed and skip no-op device writes.
    fn from_config(config: &PeerConfig) -> Self {
        let mut hasher = FnvHasher::default();
        config.hash(&mut hasher);
        Self(hasher.finish())
    }
}

/// Anything that can go wrong while reconciling desired state onto the device.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ReconcileError {
    /// A device operation (add/update/remove/query) failed.
    Device(crate::device::Error),
    /// A bounded collection ran out of room; the context names which one.
    CapacityExceeded(&'static str),
    /// Fetching a fresh network map from the client failed.
    FetchNetworkMap,
}

impl From<crate::device::Error> for ReconcileError {
    fn from(value: crate::device::Error) -> Self {
        Self::Device(value)
    }
}

impl From<CapacityError> for ReconcileError {
    fn from(value: CapacityError) -> Self {
        Self::CapacityExceeded(value.context())
    }
}

/// Fetches fresh network maps for the reconciler to apply.
pub trait NetworkMapFetcher {
    /// Transport- or cache-specific failure returned by a fetch attempt.
    type Error;

    /// Fetch the next network map.
    fn fetch_network_map(
        &self,
        directories: &[Peer],
    ) -> impl core::future::Future<Output = Result<NetworkMap, Self::Error>>;
}

/// Owns the reconciler's view of the world and drives it toward the network map.
///
/// It holds the directory peers to fetch maps from, the desired peer set derived
/// from the most recent map, the per-peer [`PeerHealth`] state machines, a cache
/// of applied-config fingerprints to suppress redundant device writes, and the
/// timestamp of the last map it accepted.
pub struct PeerReconciler<C> {
    /// Device client used to read and write the running peer set.
    client: C,
    /// Directory peers consulted when fetching the next map.
    directories: PeerVec<Peer>,
    /// Desired configuration per peer, derived from the last applied map.
    desired: PeerMap<DesiredPeer>,
    /// Per-peer route-health state machines driving failover and recovery.
    health: PeerMap<PeerHealth>,
    /// Fingerprint of the config last written for each peer, so unchanged peers
    /// are not rewritten to the device.
    applied_config_fingerprints: PeerMap<PeerConfigFingerprint>,
    /// `updated_at` of the most recently applied map, used to reject stale maps.
    last_applied_map_updated_at: Option<DateTime<Utc>>,
}

impl<C> PeerReconciler<C>
where
    C: DeviceClient,
{
    /// Build an empty reconciler around a device client and a starting set of
    /// directory peers. Desired state, health, and fingerprints are populated by
    /// the first map reconciliation.
    pub fn new(client: C, directories: PeerVec<Peer>) -> Self {
        Self {
            client,
            directories,
            desired: PeerMap::new(),
            health: PeerMap::new(),
            applied_config_fingerprints: PeerMap::new(),
            last_applied_map_updated_at: None,
        }
    }

    /// The directory peers currently used to fetch maps.
    pub fn directories(&self) -> &[Peer] {
        &self.directories
    }

    /// The `updated_at` of the last map applied, or `None` if none has been.
    pub fn last_applied_map_updated_at(&self) -> Option<DateTime<Utc>> {
        self.last_applied_map_updated_at
    }

    /// Run the control-plane reconciler forever.
    ///
    /// Two independent timers drive the loop: one fetches and applies map updates
    /// every [`MAP_RECONCILE_INTERVAL`], the other samples peer health every
    /// [`PEER_HEALTH_INTERVAL`]. Errors from either pass are logged and swallowed
    /// rather than propagated, so a transient failure never tears down the loop.
    #[cfg(feature = "std")]
    pub async fn run<F, R>(&mut self, fetcher: &F, rng: &mut R) -> !
    where
        F: NetworkMapFetcher,
        R: RngCore + ?Sized,
    {
        let mut map_interval = tokio::time::interval(MAP_RECONCILE_INTERVAL);
        let mut health_interval = tokio::time::interval(PEER_HEALTH_INTERVAL);

        loop {
            tokio::select! {
                _ = map_interval.tick() => {
                    if let Err(err) = self.fetch_and_reconcile_network_map(fetcher, rng).await {
                        warn!("network map reconciliation failed: {:?}", err);
                    }
                }
                _ = health_interval.tick() => {
                    if let Err(err) = self.reconcile_peer_health(rng).await {
                        warn!("peer health reconciliation failed: {:?}", err);
                    }
                }
            }
        }
    }

    /// Run the control-plane reconciler forever.
    ///
    /// The no-std counterpart of the `std` loop above: the same two cadences,
    /// driven by embassy tickers and `select` instead of tokio intervals, with
    /// errors from either pass logged and swallowed.
    #[cfg(not(feature = "std"))]
    pub async fn run<F, R>(&mut self, fetcher: &F, rng: &mut R) -> !
    where
        F: NetworkMapFetcher,
        R: RngCore + ?Sized,
    {
        // Embassy's first tick is delayed unlike tokio.
        if let Err(err) = self.fetch_and_reconcile_network_map(fetcher, rng).await {
            warn!("initial network map reconciliation failed: {:?}", err);
        }

        let mut map_ticker = Ticker::every(MAP_RECONCILE_INTERVAL);
        let mut health_ticker = Ticker::every(PEER_HEALTH_INTERVAL);

        loop {
            match select(map_ticker.next(), health_ticker.next()).await {
                Either::First(_) => {
                    if let Err(err) = self.fetch_and_reconcile_network_map(fetcher, rng).await {
                        warn!("network map reconciliation failed: {:?}", err);
                    }
                }
                Either::Second(_) => {
                    if let Err(err) = self.reconcile_peer_health(rng).await {
                        warn!("peer health reconciliation failed: {:?}", err);
                    }
                }
            }
        }
    }

    async fn fetch_and_reconcile_network_map<F, R>(
        &mut self,
        fetcher: &F,
        rng: &mut R,
    ) -> Result<(), ReconcileError>
    where
        F: NetworkMapFetcher,
        R: RngCore + ?Sized,
    {
        info!("fetching network map");

        let map = fetcher
            .fetch_network_map(&self.directories)
            .await
            .map_err(|_| ReconcileError::FetchNetworkMap)?;

        if self.reconcile_network_map(&map, rng).await? {
            info!("applied network map");
        }

        Ok(())
    }

    /// Bring the running device configuration in line with a network map.
    ///
    /// The pipeline: reject stale maps, compute the desired peer set, carry
    /// forward any in-flight failover decision that is still valid, diff against
    /// the device (add/update/remove), and record the applied state.
    pub async fn reconcile_network_map<R>(
        &mut self,
        map: &NetworkMap,
        rng: &mut R,
    ) -> Result<bool, ReconcileError>
    where
        R: RngCore + ?Sized,
    {
        if let Some(last_applied) = self.last_applied_map_updated_at
            && map.updated_at <= last_applied
        {
            debug!(
                "rejecting stale network map: received={} last_applied={}",
                map.updated_at, last_applied,
            );
            return Ok(false);
        }

        debug!(
            "reconciling network map: updated_at={} peers={}",
            map.updated_at,
            map.peers.len(),
        );

        let mut desired = desired_peers_from_map(map, rng)?;
        self.carry_forward_active_policies(&mut desired);

        let actual = self.client.list_peers().await?;
        self.remove_vanished_peers(&actual, &desired).await?;
        self.apply_desired_peers(&actual, &desired, Instant::now(), rng)
            .await?;

        self.directories = directory_servers_from_map(map)?;
        self.desired = desired;
        self.last_applied_map_updated_at = Some(map.updated_at);
        Ok(true)
    }

    /// Preserve a peer's already-selected failover policy across a map update by
    /// matching route identity, not the vector index. Health state is also kept
    /// by route identity, so path reordering no longer discards useful history.
    fn carry_forward_active_policies(&mut self, desired: &mut PeerMap<DesiredPeer>) {
        for (key, peer) in desired.iter_mut() {
            let Some(health) = self.health.get_mut(key) else {
                continue;
            };

            let old_active_policy = health.active_policy();
            // Recover the route identity the peer was last on, most authoritative
            // source first: the health machine's own active route, then the
            // previously-desired peer's cached identity, and finally resolving the
            // old index against the old policy vector. Identity (not index) is what
            // lets the selection survive a reordered policy list.
            let old_active_route = health
                .active_route()
                .or_else(|| {
                    self.desired
                        .get(key)
                        .and_then(|old_peer| old_peer.active_route)
                })
                .or_else(|| {
                    self.desired
                        .get(key)
                        .and_then(|old_peer| old_peer.policies.get(old_active_policy))
                        .map(RoutePolicy::route_key)
                });
            let new_active_policy = old_active_route
                .and_then(|route| peer.policies.iter().position(|policy| policy.route_key() == route))
                .unwrap_or_else(|| {
                    debug!(
                        "resetting peer {} to highest-priority policy: active route no longer exists in network map",
                        KeyBytes::from(*key),
                    );
                    0
                });

            peer.set_active_policy(new_active_policy);
            let preserve_result = route_keys_for_policies(&peer.policies).map(|routes| {
                health.sync_policies(new_active_policy, &routes);
            });
            if let Err(err) = preserve_result {
                warn!(
                    "could not preserve route health for peer {} across map update: {:?}",
                    KeyBytes::from(*key),
                    err,
                );
                health.reset_policy_state();
                health.sync_active_policy(new_active_policy);
            }
        }
    }

    /// Remove any peer present on the device but absent from the desired set,
    /// dropping its health and fingerprint bookkeeping along with it.
    async fn remove_vanished_peers(
        &mut self,
        actual: &PeerSet,
        desired: &PeerMap<DesiredPeer>,
    ) -> Result<(), ReconcileError> {
        for key in actual.iter().copied() {
            if !desired.contains_key(&key) {
                debug!(
                    "removing peer absent from network map: {}",
                    KeyBytes::from(key)
                );
                self.client.remove_peer(key).await?;
                self.health.remove(&key);
                self.applied_config_fingerprints.remove(&key);
            }
        }
        Ok(())
    }

    /// Add or update every desired peer on the device and ensure each has a
    /// tracked health entry. An existing peer is rewritten only when its config
    /// fingerprint differs from the one last applied, so an unchanged peer costs
    /// no device write.
    async fn apply_desired_peers<R>(
        &mut self,
        actual: &PeerSet,
        desired: &PeerMap<DesiredPeer>,
        now: Instant,
        rng: &mut R,
    ) -> Result<(), ReconcileError>
    where
        R: RngCore + ?Sized,
    {
        for (key, peer) in desired.iter() {
            let config = peer.config();
            let fingerprint = PeerConfigFingerprint::from_config(&config);

            if actual.contains(key) {
                if self.applied_config_fingerprints.get(key) != Some(&fingerprint) {
                    trace!("updating peer {}", KeyBytes::from(*key));
                    self.client.update_peer(config).await?;
                    self.applied_config_fingerprints.try_insert_entry(
                        *key,
                        fingerprint,
                        "peer config fingerprints",
                    )?;
                } else {
                    trace!(
                        "peer {} already matches desired config fingerprint",
                        KeyBytes::from(*key)
                    );
                }
            } else {
                trace!("adding peer {}", KeyBytes::from(*key));
                self.client.add_peer(config).await?;
                self.applied_config_fingerprints.try_insert_entry(
                    *key,
                    fingerprint,
                    "peer config fingerprints",
                )?;
            }
            let routes = route_keys_for_policies(&peer.policies)?;
            self.track_active_policy(*key, peer.active_policy_index(), &routes, now, rng)?;
        }
        Ok(())
    }

    /// Ensure a health entry exists for `key` and reflects the current route
    /// identities, without disturbing the switch cooldown of an existing entry.
    fn track_active_policy<R>(
        &mut self,
        key: PublicKey,
        active_policy: usize,
        routes: &[RouteKey],
        now: Instant,
        rng: &mut R,
    ) -> Result<(), ReconcileError>
    where
        R: RngCore + ?Sized,
    {
        match self.health.get_mut(&key) {
            Some(health) => {
                health.sync_policies(active_policy, routes);
                Ok(())
            }
            None => {
                let mut health = PeerHealth::new_with_rng(active_policy, now, rng);
                health.sync_policies(active_policy, routes);
                Ok(self.health.try_insert_entry(key, health, "peer health")?)
            }
        }
    }

    /// Sample the health of every multi-policy peer and apply any failover or
    /// recovery the [`PeerHealth`] state machine decides on.
    pub async fn reconcile_peer_health<R>(&mut self, rng: &mut R) -> Result<(), ReconcileError>
    where
        R: RngCore + ?Sized,
    {
        self.reconcile_peer_health_at(Instant::now(), rng).await
    }

    /// The testable core of [`reconcile_peer_health`](Self::reconcile_peer_health),
    /// taking an explicit `now`. For each multi-policy peer it samples device
    /// stats, folds them into the peer's health, and acts on the resulting
    /// [`HealthDecision`] — logging the inactive/no-viable-policy cases and
    /// applying a switch. On a failed device write the in-memory health and
    /// desired state are rolled back so the three views never diverge.
    async fn reconcile_peer_health_at<R>(
        &mut self,
        now: Instant,
        rng: &mut R,
    ) -> Result<(), ReconcileError>
    where
        R: RngCore + ?Sized,
    {
        // Snapshot the keys so we can mutate `self.health` / the device while
        // iterating without holding a borrow on `self.desired`.
        let mut keys = PeerVec::new();
        for key in self.desired.keys().copied() {
            keys.try_push(key, "peer health keys")?;
        }

        for key in keys {
            let Some((policy_count, active_policy, routes)) = self
                .desired
                .get(&key)
                .map(|peer| {
                    Ok::<_, ReconcileError>((
                        peer.policies.len(),
                        peer.active_policy_index(),
                        route_keys_for_policies(&peer.policies)?,
                    ))
                })
                .transpose()?
            else {
                continue;
            };

            // Single-policy peers have nothing to fail over to.
            if policy_count <= 1 {
                continue;
            }

            let info = self.client.get_peer(key).await?;
            self.track_active_policy(key, active_policy, &routes, now, rng)?;
            let previous_health = self
                .health
                .get(&key)
                .expect("health entry tracked above")
                .clone();
            let decision = self
                .health
                .get_mut(&key)
                .expect("health entry tracked above")
                .observe(&info.stats, &routes, now);

            match decision {
                HealthDecision::Stay => {}
                HealthDecision::PeerInactive => {
                    warn!(
                        "peer {} appears inactive; suppressing further route failover until inbound traffic is observed",
                        KeyBytes::from(key),
                    );
                }
                HealthDecision::NoViablePolicy => {
                    let active = self
                        .health
                        .get(&key)
                        .map(|health| health.active_policy())
                        .unwrap_or(active_policy);
                    warn!(
                        "peer {} has no viable failover policy; staying on policy {}",
                        KeyBytes::from(key),
                        active,
                    );
                }
                HealthDecision::Switch {
                    next_policy,
                    reason,
                } => {
                    let policy = self
                        .desired
                        .get(&key)
                        .and_then(|peer| peer.policies.get(next_policy));
                    debug!(
                        "switching peer {} to policy {} ({}) for {}",
                        KeyBytes::from(key),
                        next_policy,
                        describe_route_policy(policy),
                        describe_switch_reason(reason),
                    );

                    if let Err(err) = self.apply_active_policy(key, next_policy).await {
                        // The health checker updates its in-memory state when it proposes
                        // a switch. Restore that snapshot if the device update fails so
                        // the reconciler, desired state, and device do not diverge.
                        self.health
                            .try_insert_entry(key, previous_health, "peer health")?;
                        if let Some(peer) = self.desired.get_mut(&key) {
                            peer.set_active_policy(active_policy);
                        }
                        return Err(err);
                    }
                }
            }
        }

        Ok(())
    }

    /// Install a newly selected policy for one peer: update the desired state,
    /// render its config, push it to the device, and refresh the fingerprint
    /// cache. A peer that has since vanished from the desired set is a no-op.
    async fn apply_active_policy(
        &mut self,
        key: PublicKey,
        policy_index: usize,
    ) -> Result<(), ReconcileError> {
        let Some(peer) = self.desired.get_mut(&key) else {
            return Ok(());
        };
        peer.set_active_policy(policy_index);
        let config = peer.config();
        let fingerprint = PeerConfigFingerprint::from_config(&config);
        self.client.update_peer(config).await?;
        self.applied_config_fingerprints.try_insert_entry(
            key,
            fingerprint,
            "peer config fingerprints",
        )?;
        Ok(())
    }
}

/// Collect the directory peers out of a map, used to seed the fetcher for the
/// next round.
fn directory_servers_from_map(map: &NetworkMap) -> Result<PeerVec<Peer>, ReconcileError> {
    let mut directories = PeerVec::new();
    for peer in map.peers.iter().filter(|peer| peer.is_directory) {
        directories.try_push(peer.clone(), "directory peers")?;
    }
    Ok(directories)
}

/// Build the desired peer set from a network map: expand each peer's routes into
/// route policies, attach its tunnel IPs as allowed IPs, and pick an initial
/// active policy.
pub fn desired_peers_from_map<R>(
    map: &NetworkMap,
    rng: &mut R,
) -> Result<PeerMap<DesiredPeer>, ReconcileError>
where
    R: RngCore + ?Sized,
{
    let mut desired = PeerMap::new();

    for peer in &map.peers {
        let mut allowed_ips = AllowedIpVec::new();
        if let Some(tunnel_ip) = peer.tunnel_ip {
            allowed_ips.try_push(tunnel_ip, "allowed IPs")?;
        }

        let policies = route_policies_for_peer(map, peer)?;
        if policies.is_empty() {
            continue;
        }
        let active_policy = initial_policy_index(&policies, rng);

        desired.try_insert_entry(
            peer.public_key.into(),
            DesiredPeer {
                public_key: peer.public_key.into(),
                allowed_ips,
                // Directory servers get keepalives so the control channel stays
                // reachable through NAT; ordinary peers stay quiet.
                keepalive: if peer.is_directory { Some(25) } else { None },
                active_route: policies.get(active_policy).map(RoutePolicy::route_key),
                policies,
                active_policy,
            },
            "desired peers",
        )?;
    }

    Ok(desired)
}

/// Project a policy list to its route-key identities, preserving order. Used to
/// keep [`PeerHealth`] aligned with the current policy vector by identity.
fn route_keys_for_policies(policies: &PolicyVec) -> Result<RouteKeyVec, ReconcileError> {
    let mut routes = RouteKeyVec::new();
    for policy in policies {
        routes.try_push(policy.route_key(), "route keys")?;
    }
    Ok(routes)
}

/// Expand a peer's routes into a normalized policy list: relays resolved to
/// concrete peers, duplicates collapsed to their best priority, sorted with the
/// most-preferred path first. An empty path list means a single direct route.
fn route_policies_for_peer(
    map: &NetworkMap,
    destination: &Peer,
) -> Result<PolicyVec, ReconcileError> {
    let mut policies = PolicyVec::new();

    for route in &destination.routes {
        let priority = route.priority;
        match route.kind {
            RouteKind::Direct { endpoint } => {
                policies.try_push(RoutePolicy::Direct { endpoint, priority }, "route policies")?
            }
            RouteKind::Relay { id } => {
                let Some(relay) = map.peers.iter().find(|peer| peer.id == id) else {
                    debug!(
                        "dropping relay route for {}: relay id {} not in map",
                        destination.public_key, id,
                    );
                    continue;
                };
                if relay.public_key == destination.public_key {
                    debug!(
                        "dropping relay route for {}: relay points at the destination itself",
                        destination.public_key,
                    );
                    continue;
                }
                policies.try_push(
                    RoutePolicy::Relay {
                        relay: relay.public_key.into(),
                        priority,
                    },
                    "route policies",
                )?;
            }
        }
    }

    if policies.is_empty() {
        // No explicit direct endpoint was advertised. Keep the peer installed without
        // clearing any endpoint the device may learn from authenticated traffic.
        policies.try_push(
            RoutePolicy::Direct {
                endpoint: None,
                priority: 0,
            },
            "route policies",
        )?;
    }

    dedupe_and_sort_policies(policies)
}

/// Pick the starting policy: the most-preferred (lowest priority value). When
/// several share that priority, choose one at random to spread load across
/// equal routes.
fn initial_policy_index<R>(policies: &PolicyVec, rng: &mut R) -> usize
where
    R: RngCore + ?Sized,
{
    let Some(best_priority) = policies.iter().map(RoutePolicy::priority).min() else {
        return 0;
    };

    let candidate_count = policies
        .iter()
        .filter(|policy| policy.priority() == best_priority)
        .count();
    let chosen = random_below(rng, candidate_count);

    policies
        .iter()
        .enumerate()
        .filter(|(_, policy)| policy.priority() == best_priority)
        .nth(chosen)
        .map(|(index, _)| index)
        .unwrap_or(0)
}

/// A uniformly random index in `0..modulo` (returns 0 for an empty range).
fn random_below<R>(rng: &mut R, modulo: usize) -> usize
where
    R: RngCore + ?Sized,
{
    if modulo == 0 {
        0
    } else {
        (rng.next_u64() as usize) % modulo
    }
}

/// Collapse duplicate routes (keeping the best priority of each) and return the
/// result sorted by ascending priority.
fn dedupe_and_sort_policies(policies: PolicyVec) -> Result<PolicyVec, ReconcileError> {
    let mut deduped = PolicyVec::new();
    for policy in policies {
        match deduped
            .iter_mut()
            .find(|existing| existing.same_route(&policy))
        {
            Some(existing) if policy.priority() < existing.priority() => {
                existing.set_priority(policy.priority());
            }
            Some(_) => {}
            None => deduped.try_push(policy, "route policies")?,
        }
    }

    deduped.sort_unstable_by_key(RoutePolicy::priority);

    Ok(deduped)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    #[cfg(not(feature = "std"))]
    use embassy_time::Duration;
    use rand_core::OsRng;
    #[cfg(feature = "std")]
    use tokio::time::Duration;

    use super::*;
    #[cfg(not(feature = "alloc"))]
    use crate::types::v1alpha1::net_map;
    use crate::{
        bounded::TryInsertKey,
        device::{PeerInfo, PeerStats},
        types::v1alpha1::net_map::Route,
    };

    #[cfg(feature = "alloc")]
    type Ops = Vec<DeviceOp>;
    #[cfg(not(feature = "alloc"))]
    type Ops = heapless::Vec<DeviceOp, 64>;

    fn key(value: u8) -> PublicKey {
        PublicKey::from([value; 32])
    }

    fn key_id(public_key: PublicKey) -> u8 {
        KeyBytes::from(public_key).0[0]
    }

    fn ip(value: u8) -> IpAddr {
        IpAddr::V4(core::net::Ipv4Addr::new(10, 0, value, 1))
    }

    fn endpoint(value: u8) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 10_000 + u16::from(value)))
    }

    fn timestamp(seconds: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(seconds, 0).unwrap()
    }

    fn direct(priority: u16) -> Route {
        direct_endpoint(priority, endpoint(2))
    }

    fn direct_endpoint(priority: u16, endpoint: SocketAddr) -> Route {
        Route {
            kind: RouteKind::Direct {
                endpoint: Some(endpoint),
            },
            priority,
        }
    }

    fn relay(target: PublicKey, priority: u16) -> Route {
        Route {
            kind: RouteKind::Relay {
                id: i64::from(key_id(target)),
            },
            priority,
        }
    }

    fn peer(public_key: PublicKey, is_directory: bool, routes: &[Route]) -> Peer {
        let tunnel_ip = Some(ip(key_id(public_key)));

        let mut owned_routes = Routes::new();
        for route in routes {
            owned_routes.try_push(route.clone(), "routes").unwrap();
        }

        Peer {
            id: i64::from(key_id(public_key)),
            public_key: public_key.into(),
            tunnel_ip,
            is_directory,
            routes: owned_routes,
        }
    }

    #[cfg(feature = "alloc")]
    type Routes = Vec<Route>;

    #[cfg(not(feature = "alloc"))]
    type Routes = heapless::Vec<Route, { net_map::MAX_ROUTES }>;

    fn network_map<const P: usize>(peers: [Peer; P]) -> NetworkMap {
        let mut map = NetworkMap {
            updated_at: timestamp(1),
            peers: Default::default(),
        };
        for p in peers {
            map.peers.try_push(p, "map peers").unwrap();
        }
        map
    }

    fn no_directories() -> PeerVec<Peer> {
        PeerVec::new()
    }

    fn peer_info(tx_packets: usize, rx_packets: usize) -> PeerInfo {
        let mut info = peer_info_with_endpoint(None);
        info.stats.tx_bytes = tx_packets;
        info.stats.rx_bytes = rx_packets;
        info.stats.tx_packets = tx_packets;
        info.stats.rx_packets = rx_packets;
        info
    }

    fn peer_info_with_endpoint(endpoint: Option<SocketAddr>) -> PeerInfo {
        PeerInfo {
            endpoint,
            stats: PeerStats::default(),
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum DeviceOp {
        Add {
            key: PublicKey,
            relay: Option<PublicKey>,
            keepalive: Option<u16>,
        },
        Update {
            key: PublicKey,
            relay: Option<PublicKey>,
            endpoint: Option<SocketAddr>,
            keepalive: Option<u16>,
        },
        Remove(PublicKey),
        Get(PublicKey),
        ListPeers,
    }

    #[derive(Default)]
    struct MockDevice {
        peers: Mutex<PeerSet>,
        ops: Mutex<Ops>,
        peer_info: Mutex<PeerMap<PeerInfo>>,
    }

    impl MockDevice {
        fn with_peer(public_key: PublicKey) -> Self {
            let device = Self::default();
            device
                .peers
                .lock()
                .unwrap()
                .try_insert_key(public_key, "peers")
                .unwrap();
            device
        }

        fn ops(&self) -> Ops {
            self.ops.lock().unwrap().clone()
        }

        fn clear_ops(&self) {
            self.ops.lock().unwrap().clear();
        }

        fn record(&self, op: DeviceOp) {
            self.ops.lock().unwrap().try_push(op, "ops").unwrap();
        }

        fn set_peer_info(&self, public_key: PublicKey, info: PeerInfo) {
            self.peer_info
                .lock()
                .unwrap()
                .try_insert_entry(public_key, info, "peer info")
                .unwrap();
        }
    }

    impl DeviceClient for MockDevice {
        async fn add_peer(&self, config: PeerConfig) -> Result<(), crate::device::Error> {
            let key = PublicKey::from(config.public_key);
            self.peers
                .lock()
                .unwrap()
                .try_insert_key(key, "peers")
                .unwrap();
            self.peer_info
                .lock()
                .unwrap()
                .try_insert_entry(key, peer_info_with_endpoint(config.endpoint), "peer info")
                .unwrap();
            self.record(DeviceOp::Add {
                key,
                relay: config.relay.map(PublicKey::from),
                keepalive: config.keepalive,
            });
            Ok(())
        }

        async fn update_peer(&self, config: PeerConfig) -> Result<(), crate::device::Error> {
            let key = PublicKey::from(config.public_key);
            self.peers
                .lock()
                .unwrap()
                .try_insert_key(key, "peers")
                .unwrap();
            self.peer_info
                .lock()
                .unwrap()
                .try_insert_entry(key, peer_info_with_endpoint(config.endpoint), "peer info")
                .unwrap();
            self.record(DeviceOp::Update {
                key,
                relay: config.relay.map(PublicKey::from),
                endpoint: config.endpoint,
                keepalive: config.keepalive,
            });
            Ok(())
        }

        async fn remove_peer(&self, public_key: PublicKey) -> Result<(), crate::device::Error> {
            self.peers.lock().unwrap().remove(&public_key);
            self.record(DeviceOp::Remove(public_key));
            Ok(())
        }

        async fn get_peer(&self, public_key: PublicKey) -> Result<PeerInfo, crate::device::Error> {
            self.record(DeviceOp::Get(public_key));
            self.peer_info
                .lock()
                .unwrap()
                .get(&public_key)
                .cloned()
                .ok_or(crate::device::Error::PeerNotFound)
        }

        async fn list_peers(&self) -> Result<PeerSet, crate::device::Error> {
            self.record(DeviceOp::ListPeers);
            Ok(self.peers.lock().unwrap().clone())
        }
    }

    /// Route expansion is the heart of `desired_peers_from_map`: duplicate routes
    /// collapse to their best priority, the list sorts most-preferred first,
    /// directories get a keepalive, and `config()` selects the relay for the
    /// active policy.
    #[test]
    fn desired_peers_normalize_routes_and_render_config() {
        let dest = key(2);
        let relay_a = key(3);
        let relay_b = key(4);
        // relay_a appears twice at priorities 20 and 5 -> collapses to 5.
        let map = network_map([
            peer(
                dest,
                false,
                &[
                    relay(relay_a, 20),
                    direct(1),
                    relay(relay_b, 10),
                    relay(relay_a, 5),
                ],
            ),
            peer(relay_a, true, &[direct(0)]),
            peer(relay_b, false, &[direct(0)]),
        ]);

        let mut desired = desired_peers_from_map(&map, &mut OsRng).unwrap();
        let peer = desired.get(&dest).unwrap();

        assert_eq!(
            peer.policies.as_slice(),
            &[
                RoutePolicy::Direct {
                    endpoint: Some(endpoint(2)),
                    priority: 1
                },
                RoutePolicy::Relay {
                    relay: relay_a,
                    priority: 5
                },
                RoutePolicy::Relay {
                    relay: relay_b,
                    priority: 10
                },
            ],
        );
        // The unique best-priority path (direct@1) is the deterministic highest-priority policy.
        assert_eq!(peer.active_policy, 0);

        let config = peer.config();
        assert_eq!(config.relay, None);
        assert_eq!(config.endpoint, Some(endpoint(2)));
        assert_eq!(
            config.allowed_ips.as_slice(),
            &[IpNet::new(ip(2), 32).unwrap()]
        );

        // Selecting the relay policy threads through to the device config.
        desired.get_mut(&dest).unwrap().active_policy = 1;
        assert_eq!(
            desired
                .get(&dest)
                .unwrap()
                .config()
                .relay
                .unwrap()
                .as_bytes(),
            &KeyBytes::from(relay_a).0,
        );

        // Directories carry a keepalive; ordinary peers do not.
        assert_eq!(desired.get(&relay_a).unwrap().keepalive, Some(25));
        assert_eq!(desired.get(&relay_b).unwrap().keepalive, None);
    }

    #[test]
    fn direct_routes_with_distinct_endpoints_are_load_balanced_candidates() {
        let dest = key(2);
        let endpoint_a = endpoint(10);
        let endpoint_b = endpoint(11);
        let map = network_map([peer(
            dest,
            false,
            &[
                direct_endpoint(0, endpoint_a),
                direct_endpoint(0, endpoint_b),
            ],
        )]);

        let policies = route_policies_for_peer(&map, &map.peers[0]).unwrap();

        assert_eq!(
            policies.as_slice(),
            &[
                RoutePolicy::Direct {
                    endpoint: Some(endpoint_a),
                    priority: 0,
                },
                RoutePolicy::Direct {
                    endpoint: Some(endpoint_b),
                    priority: 0,
                },
            ]
        );

        let route_keys = route_keys_for_policies(&policies).unwrap();
        assert_eq!(
            route_keys.as_slice(),
            &[
                RouteKey::Direct(Some(endpoint_a)),
                RouteKey::Direct(Some(endpoint_b))
            ]
        );
    }

    /// One reconcile removes unknown device peers and adds the desired ones; a
    /// second reconcile updates in place and preserves a failover decision that
    /// is still valid under the new map.
    #[tokio::test]
    async fn reconcile_diffs_device_and_preserves_active_policy() {
        let stale = key(9);
        let dest = key(2);
        let relay_peer = key(3);
        let directory = key(4);
        let mut map = network_map([
            peer(dest, false, &[direct(0), relay(relay_peer, 1)]),
            peer(relay_peer, false, &[direct(0)]),
            peer(directory, true, &[direct(0)]),
        ]);

        let mut reconciler = PeerReconciler::new(MockDevice::with_peer(stale), no_directories());
        reconciler
            .reconcile_network_map(&map, &mut OsRng)
            .await
            .unwrap();

        let ops = reconciler.client.ops();
        assert_eq!(ops.first(), Some(&DeviceOp::ListPeers));
        assert!(ops.contains(&DeviceOp::Remove(stale)));
        // dest's highest-priority path is the unique direct@0, so it is added without a relay.
        assert!(ops.contains(&DeviceOp::Add {
            key: dest,
            relay: None,
            keepalive: None
        }));
        assert!(ops.contains(&DeviceOp::Add {
            key: directory,
            relay: None,
            keepalive: Some(25)
        }));
        assert_eq!(reconciler.directories().len(), 1);
        assert_eq!(reconciler.directories()[0].public_key, directory.into());

        // Simulate an in-flight failover to the relay policy, then feed a newer
        // map that still offers that policy.
        reconciler
            .health
            .get_mut(&dest)
            .unwrap()
            .sync_active_policy(1);
        reconciler.client.clear_ops();
        map.updated_at = timestamp(2);
        reconciler
            .reconcile_network_map(&map, &mut OsRng)
            .await
            .unwrap();

        let ops = reconciler.client.ops();
        assert!(ops.contains(&DeviceOp::Update {
            key: dest,
            relay: Some(relay_peer),
            endpoint: Some(endpoint(2)),
            keepalive: None,
        }));
        assert_eq!(reconciler.desired.get(&dest).unwrap().active_policy, 1);
    }

    /// Existing peers are updated when the rendered config fingerprint changes.
    #[tokio::test]
    async fn reconcile_updates_existing_peer_when_endpoint_changes() {
        let dest = key(2);
        let mut map = network_map([peer(dest, false, &[direct(0)])]);

        let mut reconciler = PeerReconciler::new(MockDevice::default(), no_directories());
        reconciler
            .reconcile_network_map(&map, &mut OsRng)
            .await
            .unwrap();

        map.peers[0].routes[0] = direct_endpoint(0, endpoint(42));
        reconciler.client.clear_ops();
        map.updated_at = timestamp(2);

        reconciler
            .reconcile_network_map(&map, &mut OsRng)
            .await
            .unwrap();

        assert!(reconciler.client.ops().contains(&DeviceOp::Update {
            key: dest,
            relay: None,
            endpoint: Some(endpoint(42)),
            keepalive: None,
        }));
    }

    /// Reconciling the same map twice produces no second device write: an
    /// unchanged rendered config has an unchanged fingerprint, which suppresses
    /// the redundant update.
    #[tokio::test]
    async fn reconcile_skips_update_when_rendered_config_is_unchanged() {
        let dest = key(2);
        let mut map = network_map([peer(dest, false, &[direct(0)])]);

        let mut reconciler = PeerReconciler::new(MockDevice::default(), no_directories());
        reconciler
            .reconcile_network_map(&map, &mut OsRng)
            .await
            .unwrap();
        reconciler.client.clear_ops();
        map.updated_at = timestamp(2);

        reconciler
            .reconcile_network_map(&map, &mut OsRng)
            .await
            .unwrap();

        assert!(
            !reconciler
                .client
                .ops()
                .iter()
                .any(|op| matches!(op, DeviceOp::Update { .. }))
        );
    }

    /// When the directory reports no endpoint for a peer, reconciliation must not
    /// clear an endpoint the device has already learned from traffic.
    #[tokio::test]
    async fn reconcile_preserves_learned_endpoint_when_map_reports_none() {
        let dest = key(2);
        let learned = endpoint(99);
        let endpointless = peer(dest, false, &[]);
        let mut map = network_map([endpointless]);

        let mut reconciler = PeerReconciler::new(MockDevice::default(), no_directories());
        reconciler
            .reconcile_network_map(&map, &mut OsRng)
            .await
            .unwrap();

        // The device subsequently learns an endpoint for the peer from traffic.
        reconciler
            .client
            .set_peer_info(dest, peer_info_with_endpoint(Some(learned)));
        reconciler.client.clear_ops();
        map.updated_at = timestamp(2);

        reconciler
            .reconcile_network_map(&map, &mut OsRng)
            .await
            .unwrap();

        // No update is needed: omitting an endpoint means "preserve the device-learned
        // endpoint", so leaving the existing device state untouched is sufficient.
        assert!(
            !reconciler
                .client
                .ops()
                .iter()
                .any(|op| matches!(op, DeviceOp::Update { .. }))
        );
    }

    /// End to end through the health path: repeated unanswered sends fail the
    /// peer over to its relay. Recovery to a higher-priority path is attempted
    /// only when real outbound traffic is present; no idle keepalive probe is sent.
    #[tokio::test]
    async fn health_sampling_fails_over_then_tries_recovery_with_real_traffic() {
        let dest = key(2);
        let relay_peer = key(3);
        let map = network_map([
            peer(dest, false, &[direct(0), relay(relay_peer, 1)]),
            peer(relay_peer, false, &[direct(0)]),
        ]);

        let mut reconciler = PeerReconciler::new(MockDevice::default(), no_directories());
        reconciler
            .reconcile_network_map(&map, &mut OsRng)
            .await
            .unwrap();
        reconciler.client.clear_ops();

        let base = Instant::now();
        let after_cooldown = base + Duration::from_secs(200);

        for sample in [peer_info(0, 0), peer_info(100, 0), peer_info(200, 0)] {
            reconciler.client.set_peer_info(dest, sample);
            reconciler
                .reconcile_peer_health_at(after_cooldown, &mut OsRng)
                .await
                .unwrap();
        }

        assert!(reconciler.client.ops().contains(&DeviceOp::Update {
            key: dest,
            relay: Some(relay_peer),
            endpoint: Some(endpoint(2)),
            keepalive: None,
        }));
        assert_eq!(reconciler.desired.get(&dest).unwrap().active_policy, 1);

        // Relay-path inbound traffic alone must not restore the highest-priority policy.
        reconciler.client.clear_ops();
        let later = base + Duration::from_secs(400);
        reconciler.client.set_peer_info(dest, peer_info(200, 1));
        reconciler
            .reconcile_peer_health_at(later, &mut OsRng)
            .await
            .unwrap();

        assert!(!reconciler.client.ops().contains(&DeviceOp::Update {
            key: dest,
            relay: None,
            endpoint: Some(endpoint(2)),
            keepalive: None,
        }));
        assert_eq!(reconciler.desired.get(&dest).unwrap().active_policy, 1);

        // Idle after the recovery interval still samples device stats but does
        // not change the installed route policy.
        reconciler.client.clear_ops();
        let after_idle = later + Duration::from_secs(136);
        reconciler.client.set_peer_info(dest, peer_info(200, 1));
        reconciler
            .reconcile_peer_health_at(after_idle, &mut OsRng)
            .await
            .unwrap();

        assert!(
            !reconciler
                .client
                .ops()
                .iter()
                .any(|op| matches!(op, DeviceOp::Update { .. }))
        );
        assert_eq!(reconciler.desired.get(&dest).unwrap().active_policy, 1);

        // Real outbound traffic is the recovery probe; it switches to direct
        // without installing a temporary keepalive override.
        reconciler.client.clear_ops();
        reconciler.client.set_peer_info(dest, peer_info(201, 1));
        reconciler
            .reconcile_peer_health_at(after_idle + Duration::from_secs(1), &mut OsRng)
            .await
            .unwrap();

        assert!(reconciler.client.ops().contains(&DeviceOp::Update {
            key: dest,
            relay: None,
            endpoint: Some(endpoint(2)),
            keepalive: None,
        }));
        assert_eq!(reconciler.desired.get(&dest).unwrap().active_policy, 0);
    }

    /// A map update that reorders a peer's routes must keep the peer on the same
    /// route: because health and selection are tracked by route identity, the
    /// active policy follows its [`RouteKey`] to its new index rather than
    /// staying pinned to the old one.
    #[tokio::test]
    async fn active_policy_survives_path_reordering_by_route_identity() {
        let dest = key(2);
        let relay_peer = key(3);
        let initial = network_map([
            peer(dest, false, &[direct(0), relay(relay_peer, 1)]),
            peer(relay_peer, false, &[direct(0)]),
        ]);
        let mut updated = network_map([
            peer(dest, false, &[relay(relay_peer, 0), direct(1)]),
            peer(relay_peer, false, &[direct(0)]),
        ]);
        updated.updated_at = timestamp(2);

        let mut reconciler = PeerReconciler::new(MockDevice::default(), no_directories());
        reconciler
            .reconcile_network_map(&initial, &mut OsRng)
            .await
            .unwrap();
        reconciler
            .health
            .get_mut(&dest)
            .unwrap()
            .sync_active_policy(1);
        reconciler.desired.get_mut(&dest).unwrap().active_policy = 1;
        reconciler.client.clear_ops();

        reconciler
            .reconcile_network_map(&updated, &mut OsRng)
            .await
            .unwrap();

        let peer = reconciler.desired.get(&dest).unwrap();
        assert_eq!(peer.active_policy, 0);
        assert!(
            matches!(peer.policies.get(0), Some(RoutePolicy::Relay { relay, .. }) if *relay == relay_peer)
        );
        assert!(reconciler.client.ops().contains(&DeviceOp::Update {
            key: dest,
            relay: Some(relay_peer),
            endpoint: Some(endpoint(2)),
            keepalive: None,
        }));
    }
}
