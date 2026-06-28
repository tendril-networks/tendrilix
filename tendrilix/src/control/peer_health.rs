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

//! Per-peer route-health state machine.
//!
//! The reconciler samples each peer's traffic statistics on a fixed cadence and
//! folds every sample into a [`PeerHealth`]. The state machine decides whether
//! the peer should fail over to another route policy, probe a higher-priority
//! policy using real traffic, or stay put. All I/O lives in the reconciler.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(not(feature = "std"))]
use embassy_time::{Duration, Instant};
#[cfg(not(feature = "alloc"))]
use heapless::Vec;
use rand_core::RngCore;
#[cfg(feature = "std")]
use tokio::time::{Duration, Instant};

#[cfg(not(feature = "alloc"))]
use crate::types::v1alpha1::net_map::MAX_ROUTES;
use crate::{bounded::TryPush, device::PeerStats, x25519::PublicKey};

/// Suspicion score at which a policy is considered failed.
const POLICY_FAILURE_SCORE: i8 = 4;
/// Amount added by an unanswered outbound sample.
const UNHEALTHY_SCORE_DELTA: i8 = 2;
/// Amount removed by a successful inbound sample.
const HEALTHY_SCORE_DELTA: i8 = 1;
/// Base time between ordinary route-policy switches for a single peer. The
/// effective cooldown grows from this base as a peer keeps flapping (see
/// [`PeerHealth::current_switch_cooldown`]).
const MIN_POLICY_SWITCH_INTERVAL: Duration = Duration::from_secs(120);
/// Cooldown applied before a peer's *first* switch. A brand-new peer should be
/// allowed to fail away from a dead path quickly rather than waiting a full
/// [`MIN_POLICY_SWITCH_INTERVAL`]; this only needs to outlast a startup
/// transient (a couple of health samples).
const INITIAL_FAILOVER_GRACE: Duration = Duration::from_secs(15);
/// Maximum left-shift applied to [`MIN_POLICY_SWITCH_INTERVAL`] by switch
/// backoff, bounding the cooldown at `MIN_POLICY_SWITCH_INTERVAL << 3` (~16 min).
const MAX_SWITCH_BACKOFF_SHIFT: u32 = 3;
/// Once a peer holds a single policy for this long, its flap backoff resets so
/// an isolated future blip is again treated as a first switch.
const SWITCH_BACKOFF_RESET_INTERVAL: Duration = Duration::from_secs(600);
/// Minimum time on a fallback policy before trying a higher-priority path using real traffic.
const RECOVERY_PROBE_INTERVAL: Duration = Duration::from_secs(120);
/// How long a route stays `Failed` before its suspicion is aged back down one
/// step. A non-active route receives no success samples, so without this a
/// route marked failed would never become eligible again even after it has
/// physically recovered. Set comfortably above the recovery/cooldown intervals
/// so deliberate failover hysteresis is unaffected.
const POLICY_FAILURE_DECAY_INTERVAL: Duration = Duration::from_secs(600);
/// Maximum jitter added to recovery attempts and switch cooldowns.
const MAX_HEALTH_JITTER: Duration = Duration::from_secs(15);
/// How long the active route may go without *any* inbound traffic, while we are
/// actively sending, before it is implicated as unhealthy.
///
/// The WireGuard data plane guarantees that a peer which is receiving our
/// packets emits at least a passive keepalive within one keepalive interval
/// (`KEEPALIVE_TIMEOUT`, 10 s in the Noise timers) of falling silent. A working
/// route therefore produces inbound traffic on that cadence even for a purely
/// outbound flow. This threshold is set to a comfortable multiple of that
/// guarantee (2 keepalive intervals plus sampling slack) so that a single lost
/// keepalive does not implicate a healthy route.
///
/// Crucially, blame is gated on a *silence window* rather than on a single empty
/// sample. The previous per-sample `rx`-delta test aliased against the keepalive
/// period — at a 5 s sample cadence roughly every other sample on a healthy
/// unidirectional flow saw no inbound, and with the asymmetric `+2 / -1` scoring
/// that accumulated to a spurious failover. A silence window makes the signal
/// independent of the sampling cadence: as long as one keepalive lands inside
/// the window, the route is never blamed, regardless of how often we sample.
///
/// This value also bounds how quickly a genuinely dead route (or a failed
/// recovery probe) is detected: detection takes this window plus the couple of
/// scoring samples needed to reach [`POLICY_FAILURE_SCORE`], i.e. ~30 s.
const INBOUND_SILENCE_TIMEOUT: Duration = Duration::from_secs(25);

/// Per-route health entries, one per current policy, in policy order.
#[cfg(feature = "alloc")]
type PolicyHealthVec = Vec<PolicyHealthEntry>;
#[cfg(not(feature = "alloc"))]
type PolicyHealthVec = Vec<PolicyHealthEntry, MAX_ROUTES>;

/// A list of route identities in policy-preference order (index 0 most
/// preferred). The reconciler builds these from a peer's normalized policies.
#[cfg(feature = "alloc")]
pub type RouteKeyVec = Vec<RouteKey>;
#[cfg(not(feature = "alloc"))]
pub type RouteKeyVec = Vec<RouteKey, MAX_ROUTES>;

/// Stable identity for a route policy. Health is keyed by this, not by the
/// current policy vector index, so map reordering preserves useful history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteKey {
    /// Send straight to a destination peer endpoint. `None` is the legacy/default
    /// direct route whose endpoint may be learned by the device.
    Direct(Option<core::net::SocketAddr>),
    /// Send via the named relay peer.
    Relay(PublicKey),
}

/// Why the health checker is asking the reconciler to switch policies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchReason {
    /// The active route reached the failure threshold and another viable route exists.
    Failover,
    /// A higher-priority route is due to be tested using real outbound traffic.
    RecoveryProbe,
    /// A recovery probe saw unanswered outbound traffic and should return to its fallback.
    RecoveryFailed,
}

/// The action the reconciler should take after folding in a sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthDecision {
    /// Keep the currently active route policy.
    Stay,
    /// Switch to the given policy index.
    Switch {
        next_policy: usize,
        reason: SwitchReason,
    },
    /// The peer itself currently appears unreachable, so further route blame is
    /// suppressed until inbound traffic proves the peer is alive again.
    PeerInactive,
    /// The active route failed, but there is no non-failed alternate route.
    NoViablePolicy,
}

/// Peer-level liveness, distinct from route-policy health. This prevents a
/// dead/offline peer from being treated purely as a set of failed routes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerLiveness {
    /// No inbound traffic has been observed yet.
    Unknown,
    /// Recent history proves the peer can receive and reply on at least one route.
    Reachable,
    /// Outbound traffic has gone unanswered and no route currently proves the
    /// peer is reachable.
    LikelyInactive,
}

/// Coarse lifecycle label for a single route, kept in step with its numeric
/// suspicion score. Advisory only: [`PolicyHealth::is_failed`] trusts either the
/// score crossing [`POLICY_FAILURE_SCORE`] or this reaching `Failed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PolicyState {
    /// No sample has been recorded for this route yet.
    Unknown,
    /// The most recent sample on this route saw return traffic.
    Healthy,
    /// Some unanswered outbound traffic, but not yet past the failure threshold.
    Suspect,
    /// Suspicion reached [`POLICY_FAILURE_SCORE`]; disqualified as a target until
    /// it recovers (active route) or decays (idle alternate).
    Failed,
}

/// Health history for a single route. Updated from live samples only while that
/// route is active; non-active routes are aged by [`PolicyHealth::decay`]
/// instead. `suspicion` is the source of truth — the rest support decay,
/// recovery eligibility, and peer-liveness decisions.
#[derive(Clone, Copy, Debug)]
struct PolicyHealth {
    /// Failure score in `0..=POLICY_FAILURE_SCORE`. Rises by
    /// [`UNHEALTHY_SCORE_DELTA`] per unanswered sample and falls by
    /// [`HEALTHY_SCORE_DELTA`] per success or decay step.
    suspicion: i8,
    /// Unanswered samples in a row on this route; cleared by any success.
    consecutive_failures: u8,
    /// When this route last saw return traffic. Gates recovery-probe
    /// eligibility: a fallback must have succeeded since the last switch.
    last_success: Option<Instant>,
    /// When this route last went unanswered. Doubles as the decay anchor.
    last_failure: Option<Instant>,
    /// Coarse lifecycle label, kept consistent with `suspicion`.
    state: PolicyState,
}

impl PolicyHealth {
    /// A fresh route with no history: zero suspicion, `Unknown` state.
    fn new() -> Self {
        Self {
            suspicion: 0,
            consecutive_failures: 0,
            last_success: None,
            last_failure: None,
            state: PolicyState::Unknown,
        }
    }

    /// Fold in a sample that saw return traffic: shed one suspicion step
    /// (floored at zero), clear the failure streak, and mark the route healthy.
    fn record_success(&mut self, now: Instant) {
        self.suspicion = self.suspicion.saturating_sub(HEALTHY_SCORE_DELTA).max(0);
        self.consecutive_failures = 0;
        self.last_success = Some(now);
        self.state = PolicyState::Healthy;
    }

    /// Fold in an unanswered outbound sample: add [`UNHEALTHY_SCORE_DELTA`]
    /// (capped at [`POLICY_FAILURE_SCORE`]) and mark the route `Suspect`, or
    /// `Failed` once the cap is reached. The `+2 / -1` asymmetry with
    /// [`record_success`](Self::record_success) is deliberate — evidence of
    /// failure accrues faster than it is shed, so a route must clearly prove
    /// itself to recover.
    fn record_failure(&mut self, now: Instant) {
        self.suspicion = self
            .suspicion
            .saturating_add(UNHEALTHY_SCORE_DELTA)
            .min(POLICY_FAILURE_SCORE);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_failure = Some(now);
        self.state = if self.suspicion >= POLICY_FAILURE_SCORE {
            PolicyState::Failed
        } else {
            PolicyState::Suspect
        };
    }

    /// Whether this route is currently disqualified as a failover or recovery
    /// target.
    fn is_failed(&self) -> bool {
        self.suspicion >= POLICY_FAILURE_SCORE || self.state == PolicyState::Failed
    }

    /// Age suspicion downward for a route that has not failed recently.
    ///
    /// Only the active route earns its way out of failure via `record_success`,
    /// so an idle alternate that was marked `Failed` would otherwise stay failed
    /// forever and never be retried even if it has physically recovered. One
    /// suspicion step is shed per elapsed [`POLICY_FAILURE_DECAY_INTERVAL`],
    /// which is enough to make a `Failed` route a viable candidate again while
    /// keeping deliberate failover hysteresis intact. `last_failure` doubles as
    /// the decay anchor and is advanced as steps are shed.
    fn decay(&mut self, now: Instant) {
        let Some(mut anchor) = self.last_failure else {
            return;
        };
        if self.suspicion == 0 {
            return;
        }

        while self.suspicion > 0
            && now.saturating_duration_since(anchor) >= POLICY_FAILURE_DECAY_INTERVAL
        {
            self.suspicion = self.suspicion.saturating_sub(HEALTHY_SCORE_DELTA).max(0);
            anchor += POLICY_FAILURE_DECAY_INTERVAL;
        }

        if self.suspicion == 0 {
            self.last_failure = None;
            self.state = PolicyState::Unknown;
        } else {
            self.last_failure = Some(anchor);
            self.state = if self.suspicion >= POLICY_FAILURE_SCORE {
                PolicyState::Failed
            } else {
                PolicyState::Suspect
            };
        }
    }
}

/// A route's stable identity paired with its accumulated health. Stored as a
/// list (not a map) so the order can mirror the policy vector, while health is
/// still matched by [`RouteKey`] across map updates.
#[derive(Clone, Copy, Debug)]
struct PolicyHealthEntry {
    /// Stable identity of the route this health belongs to.
    route: RouteKey,
    /// Accumulated health for the route.
    health: PolicyHealth,
}

impl PolicyHealthEntry {
    /// A new entry for `route` with empty health.
    fn new(route: RouteKey) -> Self {
        Self {
            route,
            health: PolicyHealth::new(),
        }
    }
}

/// Per-peer health history used to decide whether to switch route policies.
#[derive(Clone, Debug)]
pub struct PeerHealth {
    /// Index into the current policy vector of the route programmed on the
    /// device right now.
    active_policy: usize,
    /// Peer-level reachability, distinct from any single route's health.
    liveness: PeerLiveness,
    /// Unanswered samples in a row across the peer (not per route); cleared by
    /// any success. Gates the `PeerInactive` verdict.
    consecutive_peer_failures: u8,
    /// When the active policy last changed. Anchors the switch cooldown and,
    /// absent any inbound packet, the inbound-silence clock.
    last_switch: Instant,
    /// Number of switches in the current unstable run. Drives switch backoff and
    /// is reset once the peer has held one policy for [`SWITCH_BACKOFF_RESET_INTERVAL`].
    /// Zero means the peer has not switched yet, so its first failover is only
    /// gated by [`INITIAL_FAILOVER_GRACE`].
    switch_count: u32,
    /// Earliest time the peer may probe a higher-priority route. Pushed forward
    /// on observed activity and after every switch.
    next_recovery_attempt_at: Instant,
    /// Transmit packet counter from the previous sample, for per-interval deltas.
    last_tx_packets: usize,
    /// Receive packet counter from the previous sample, for per-interval deltas.
    last_rx_packets: usize,
    /// When inbound traffic was last observed on the *current* active route.
    /// Reset on every switch, since a freshly selected route has not yet proven
    /// it can receive. Drives the inbound-silence health signal (see
    /// [`INBOUND_SILENCE_TIMEOUT`]).
    last_inbound_at: Option<Instant>,
    /// Whether at least one sample has been folded in. The very first sample
    /// only seeds the packet counters and returns `Stay`.
    has_observed_stats: bool,
    /// Per-route health, one entry per current policy, matched by [`RouteKey`].
    policy_health: PolicyHealthVec,
    /// When set, the active policy is a tentative higher-priority recovery probe.
    /// One healthy sample commits it; one unanswered outbound sample returns to
    /// this fallback policy immediately.
    recovery_fallback: Option<usize>,
    /// Per-peer randomized offset (`0..=MAX_HEALTH_JITTER`) added to cooldowns
    /// and recovery scheduling, so many peers recovering from one correlated
    /// outage do not act in lockstep.
    jitter: Duration,
}

impl PeerHealth {
    /// Construct health for a peer, drawing its de-sync jitter from `rng`.
    pub fn new_with_rng<R>(active_policy: usize, now: Instant, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new_with_jitter(active_policy, now, jitter_from_rng(rng))
    }

    /// Construct health with an explicit jitter. Used by tests for determinism;
    /// production code uses [`new_with_rng`](Self::new_with_rng).
    pub fn new_with_jitter(active_policy: usize, now: Instant, jitter: Duration) -> Self {
        Self {
            active_policy,
            liveness: PeerLiveness::Unknown,
            consecutive_peer_failures: 0,
            last_switch: now,
            switch_count: 0,
            next_recovery_attempt_at: now + RECOVERY_PROBE_INTERVAL + jitter,
            last_tx_packets: 0,
            last_rx_packets: 0,
            last_inbound_at: None,
            has_observed_stats: false,
            policy_health: PolicyHealthVec::new(),
            recovery_fallback: None,
            jitter,
        }
    }

    /// The currently selected policy index.
    pub fn active_policy(&self) -> usize {
        self.active_policy
    }

    /// The [`RouteKey`] of the currently selected policy, if one exists.
    pub fn active_route(&self) -> Option<RouteKey> {
        self.policy_health
            .get(self.active_policy)
            .map(|entry| entry.route)
    }

    /// The peer's current liveness estimate.
    pub fn liveness(&self) -> PeerLiveness {
        self.liveness
    }

    /// Align active policy and route-health entries with the current policy list.
    /// Existing health is preserved by [`RouteKey`] whenever possible.
    pub fn sync_policies(&mut self, active_policy: usize, routes: &[RouteKey]) {
        let mut next = PolicyHealthVec::new();
        for route in routes {
            let entry = self
                .policy_health
                .iter()
                .find(|entry| entry.route == *route)
                .copied()
                .unwrap_or_else(|| PolicyHealthEntry::new(*route));
            next.try_push(entry, "policy health").ok();
        }
        self.policy_health = next;
        self.active_policy = active_policy.min(routes.len().saturating_sub(1));
        if self
            .recovery_fallback
            .is_some_and(|fallback| fallback >= routes.len())
        {
            self.recovery_fallback = None;
        }
    }

    /// Backwards-compatible index sync for tests and callers that do not care
    /// about preserving route identity.
    pub fn sync_active_policy(&mut self, active_policy: usize) {
        self.active_policy = active_policy;
    }

    /// Clear all route health. Kept for explicit administrative resets.
    pub fn reset_policy_state(&mut self) {
        self.policy_health.clear();
        self.recovery_fallback = None;
    }

    /// Fold one statistics sample into the peer's health and return the action
    /// the reconciler should take. The pipeline: align to the current routes,
    /// seed counters on the first call, classify the sample from packet deltas
    /// and the inbound-silence window, decay idle alternates, record the sample
    /// against the active route, then branch — a healthy sample may trigger a
    /// recovery probe, an unhealthy one may fail over (see
    /// [`decide_after_unhealthy`](Self::decide_after_unhealthy)), and an idle one
    /// does nothing. Single-policy peers always `Stay`.
    pub fn observe(
        &mut self,
        stats: &PeerStats,
        routes: &[RouteKey],
        now: Instant,
    ) -> HealthDecision {
        self.sync_policies(self.active_policy, routes);
        if routes.len() <= 1 {
            return HealthDecision::Stay;
        }

        if !self.has_observed_stats {
            self.has_observed_stats = true;
            self.last_tx_packets = stats.tx_packets;
            self.last_rx_packets = stats.rx_packets;
            // A peer that has already exchanged inbound traffic is treated as
            // recently reachable, so we do not start a silence clock against a
            // peer that is plainly alive the moment we begin observing it.
            if stats.rx_packets > 0 {
                self.last_inbound_at = Some(now);
            }
            if Self::has_activity(stats) {
                self.record_activity(now);
            }
            return HealthDecision::Stay;
        }

        let received_more = stats.rx_packets > self.last_rx_packets;
        let sent_more = stats.tx_packets > self.last_tx_packets;
        let recovery_was_due = self.recovery_attempt_due(now);
        let sample = self.classify(stats, now);
        if received_more {
            self.last_inbound_at = Some(now);
        }
        self.last_tx_packets = stats.tx_packets;
        self.last_rx_packets = stats.rx_packets;

        // Age any route that has not failed recently back toward eligibility, so
        // an idle alternate that was marked `Failed` can be retried once it has
        // had time to physically recover. Done after classifying this sample but
        // before recording it, so a route failing again this interval is not
        // decayed in the same step.
        for entry in self.policy_health.iter_mut() {
            entry.health.decay(now);
        }

        let active_policy = self.active_policy;
        self.record_sample(active_policy, sample, now);

        match sample {
            Sample::Healthy => {
                self.recovery_fallback = None;
                self.decide_recovery_probe(active_policy, sent_more, recovery_was_due, now)
            }
            Sample::Idle => HealthDecision::Stay,
            Sample::Unhealthy => self.decide_after_unhealthy(
                active_policy,
                routes.len(),
                sent_more,
                recovery_was_due,
                now,
            ),
        }
    }

    fn classify(&self, stats: &PeerStats, now: Instant) -> Sample {
        let received_more = stats.rx_packets > self.last_rx_packets;
        let sent_more = stats.tx_packets > self.last_tx_packets;

        if received_more {
            Sample::Healthy
        } else if sent_more && self.inbound_silence(now) >= INBOUND_SILENCE_TIMEOUT {
            // We are actively sending but have heard nothing back for longer
            // than the data plane's keepalive guarantee. A working route would
            // have produced at least a passive keepalive by now, so the active
            // route is implicated. Gating on the silence window rather than a
            // single empty sample is what makes this robust to the sampling
            // cadence (see `INBOUND_SILENCE_TIMEOUT`).
            Sample::Unhealthy
        } else {
            // Either nothing was sent this interval (no information), or we sent
            // but inbound has not been silent long enough to blame the route.
            Sample::Idle
        }
    }

    /// How long the current active route has gone without inbound traffic.
    /// Measured from the last inbound packet seen on this route, or from the
    /// last switch if none has been seen since the route became active.
    fn inbound_silence(&self, now: Instant) -> Duration {
        let anchor = self.last_inbound_at.unwrap_or(self.last_switch);
        now.saturating_duration_since(anchor)
    }

    /// Apply a classified sample to the active route's health and the
    /// peer-level liveness counters. The failover/recovery *decision* is made by
    /// the callers (`observe` and its helpers), not here.
    fn record_sample(&mut self, policy: usize, sample: Sample, now: Instant) {
        match sample {
            Sample::Healthy => {
                if let Some(entry) = self.policy_health.get_mut(policy) {
                    entry.health.record_success(now);
                }
                self.liveness = PeerLiveness::Reachable;
                self.consecutive_peer_failures = 0;
                self.record_activity(now);
            }
            Sample::Unhealthy => {
                self.consecutive_peer_failures = self.consecutive_peer_failures.saturating_add(1);
                // An unanswered outbound sample always counts against the active
                // route. Whether the *peer* is treated as inactive (as opposed to
                // the route being at fault) is decided separately in
                // `decide_after_unhealthy`, which gates `PeerInactive` on the peer
                // never having had a successful route.
                if let Some(entry) = self.policy_health.get_mut(policy) {
                    entry.health.record_failure(now);
                }
            }
            Sample::Idle => {}
        }
    }

    /// Decide what to do after an unanswered sample on the active route, in
    /// strict priority order: abort an in-flight recovery probe back to its
    /// fallback; otherwise respect the switch cooldown; otherwise attempt a due
    /// recovery probe; otherwise, if the active route is failed, fail over to the
    /// best alternate, or report the peer dead ([`HealthDecision::PeerInactive`])
    /// or out of options ([`HealthDecision::NoViablePolicy`]).
    fn decide_after_unhealthy(
        &mut self,
        active_policy: usize,
        policy_count: usize,
        sent_more: bool,
        recovery_due: bool,
        now: Instant,
    ) -> HealthDecision {
        if let Some(fallback) = self.recovery_fallback.take()
            && fallback < policy_count
            && fallback != active_policy
        {
            self.switch_to(fallback, now, false);
            return HealthDecision::Switch {
                next_policy: fallback,
                reason: SwitchReason::RecoveryFailed,
            };
        }

        if !self.cooldown_elapsed(now) {
            return HealthDecision::Stay;
        }

        let recovery_decision =
            self.decide_recovery_probe(active_policy, sent_more, recovery_due, now);
        if !matches!(recovery_decision, HealthDecision::Stay) {
            return recovery_decision;
        }

        if self.policy_failed(active_policy) {
            if let Some(next_policy) = self.best_failover_policy(active_policy, policy_count) {
                self.switch_to(next_policy, now, false);
                return HealthDecision::Switch {
                    next_policy,
                    reason: SwitchReason::Failover,
                };
            }

            if !self.has_any_route_success() && self.consecutive_peer_failures > 2 {
                self.liveness = PeerLiveness::LikelyInactive;
                return HealthDecision::PeerInactive;
            }

            return HealthDecision::NoViablePolicy;
        }

        HealthDecision::Stay
    }

    /// If a recovery attempt is due and there is real outbound traffic to ride,
    /// switch up to the best higher-priority route as a tentative probe. Probes
    /// use real traffic only — no synthetic packets are ever injected.
    fn decide_recovery_probe(
        &mut self,
        active_policy: usize,
        sent_more: bool,
        recovery_due: bool,
        now: Instant,
    ) -> HealthDecision {
        if !sent_more || !recovery_due {
            return HealthDecision::Stay;
        }

        if let Some(next_policy) = self.best_recovery_policy(active_policy) {
            self.switch_to(next_policy, now, true);
            return HealthDecision::Switch {
                next_policy,
                reason: SwitchReason::RecoveryProbe,
            };
        }

        HealthDecision::Stay
    }

    /// The best higher-priority route to probe for recovery, or `None`. Only
    /// routes more preferred than the active fallback are considered; a failed
    /// one becomes eligible only once the active fallback has itself proven it
    /// can receive (see the validation check below). Ties break toward lower
    /// suspicion, then lower index.
    fn best_recovery_policy(&self, active_policy: usize) -> Option<usize> {
        if active_policy == 0 {
            return None;
        }

        // A failed higher-priority route is eligible for a real-traffic
        // recovery probe only after the active fallback has proven it can
        // receive traffic. Use last_success rather than current state so a
        // validated fallback remains eligible even if the current outbound
        // sample was unanswered. This avoids probing a known-failed route when
        // both the active fallback and all alternatives are already failed.
        let active_fallback_validated = self
            .policy_health
            .get(active_policy)
            .and_then(|entry| entry.health.last_success)
            .is_some_and(|last_success| last_success >= self.last_switch);

        (0..active_policy)
            .filter(|&idx| {
                let target = self.policy_health.get(idx);
                let target_failed = target.is_some_and(|entry| entry.health.is_failed());
                !target_failed || active_fallback_validated
            })
            .min_by_key(|&idx| {
                let suspicion = self
                    .policy_health
                    .get(idx)
                    .map(|p| p.health.suspicion)
                    .unwrap_or(0);
                (suspicion, idx)
            })
    }

    /// The best non-failed alternate to the active route — lowest suspicion,
    /// ties broken by index — or `None` if every other route is failed.
    fn best_failover_policy(&self, active_policy: usize, policy_count: usize) -> Option<usize> {
        (0..policy_count)
            .filter(|&idx| idx != active_policy)
            .filter(|&idx| {
                self.policy_health
                    .get(idx)
                    .is_none_or(|p| !p.health.is_failed())
            })
            .min_by_key(|&idx| {
                let suspicion = self
                    .policy_health
                    .get(idx)
                    .map(|p| p.health.suspicion)
                    .unwrap_or(0);
                (suspicion, idx)
            })
    }

    /// Whether the policy at `policy` is currently marked failed.
    fn policy_failed(&self, policy: usize) -> bool {
        self.policy_health
            .get(policy)
            .is_some_and(|entry| entry.health.is_failed())
    }

    /// Whether any route has *ever* seen return traffic. Distinguishes a peer
    /// whose current route just broke from a peer that has never been reachable,
    /// which is what separates a failover from a `PeerInactive` verdict.
    fn has_any_route_success(&self) -> bool {
        self.policy_health
            .iter()
            .any(|entry| entry.health.last_success.is_some())
    }

    /// Whether the recovery-probe timer has elapsed.
    fn recovery_attempt_due(&self, now: Instant) -> bool {
        now >= self.next_recovery_attempt_at
    }

    /// Note that the peer is actively communicating, deferring the next
    /// recovery probe so probes are timed from the last activity, not boot.
    fn record_activity(&mut self, now: Instant) {
        self.schedule_next_recovery_attempt(now);
    }

    /// Push the next recovery-probe time out by one interval plus jitter.
    fn schedule_next_recovery_attempt(&mut self, now: Instant) {
        self.next_recovery_attempt_at = now + RECOVERY_PROBE_INTERVAL + self.jitter;
    }

    /// Whether the peer has any traffic at all, used only to seed recovery
    /// timing on the first sample.
    fn has_activity(stats: &PeerStats) -> bool {
        stats.tx_packets > 0 || stats.rx_packets > 0
    }

    /// The cooldown that must elapse since the last switch before another switch
    /// is allowed. Grows with the number of recent switches so a flapping peer is
    /// damped harder, while the first switch only has to outlast a startup
    /// transient.
    fn current_switch_cooldown(&self) -> Duration {
        if self.switch_count == 0 {
            return INITIAL_FAILOVER_GRACE + self.jitter;
        }
        let shift = (self.switch_count - 1).min(MAX_SWITCH_BACKOFF_SHIFT);
        MIN_POLICY_SWITCH_INTERVAL * (1u32 << shift) + self.jitter
    }

    /// Whether enough time has passed since the last switch to allow another.
    fn cooldown_elapsed(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_switch) >= self.current_switch_cooldown()
    }

    /// Move the active policy, updating flap backoff (resetting it if the peer
    /// had been stable past [`SWITCH_BACKOFF_RESET_INTERVAL`]), the recovery
    /// schedule, the inbound-silence clock, and — for a probe — the fallback to
    /// revert to if it fails.
    fn switch_to(&mut self, policy: usize, now: Instant, recovery_probe: bool) {
        let previous = self.active_policy;
        // A peer that held one policy beyond the reset interval is considered
        // stable, so an isolated future switch starts the backoff over.
        if now.saturating_duration_since(self.last_switch) >= SWITCH_BACKOFF_RESET_INTERVAL {
            self.switch_count = 0;
        }
        self.switch_count = self.switch_count.saturating_add(1);
        self.active_policy = policy;
        self.last_switch = now;
        // A newly selected route has not yet proven it can receive; restart the
        // silence clock so blame is measured from this switch.
        self.last_inbound_at = None;
        self.recovery_fallback = if recovery_probe { Some(previous) } else { None };
        self.schedule_next_recovery_attempt(now);
    }
}

/// The classification of one health sample, derived from packet-count deltas
/// and — for `Unhealthy` — the inbound-silence window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sample {
    /// Inbound traffic was seen this interval: the active route works.
    Healthy,
    /// We sent, but inbound has been silent past [`INBOUND_SILENCE_TIMEOUT`].
    Unhealthy,
    /// No information: nothing was sent, or silence is not yet long enough.
    Idle,
}

/// Draw a uniform per-peer de-sync jitter in `0..=MAX_HEALTH_JITTER`.
fn jitter_from_rng<R>(rng: &mut R) -> Duration
where
    R: RngCore + ?Sized,
{
    let max_secs = MAX_HEALTH_JITTER.as_secs();
    if max_secs == 0 {
        Duration::from_secs(0)
    } else {
        Duration::from_secs(rng.next_u64() % (max_secs + 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(tx_packets: usize, rx_packets: usize) -> PeerStats {
        PeerStats {
            tx_bytes: tx_packets,
            rx_bytes: rx_packets,
            tx_packets,
            rx_packets,
            ..Default::default()
        }
    }

    fn routes(count: usize) -> RouteKeyVec {
        let mut routes = RouteKeyVec::new();
        routes.try_push(RouteKey::Direct(None), "routes").unwrap();
        for n in 1..count {
            routes
                .try_push(RouteKey::Relay(PublicKey::from([n as u8; 32])), "routes")
                .unwrap();
        }
        routes
    }

    struct Clock {
        now: Instant,
    }

    impl Clock {
        fn new() -> Self {
            Self {
                now: Instant::now(),
            }
        }

        fn tick(&mut self) -> Instant {
            self.tick_by(MIN_POLICY_SWITCH_INTERVAL + Duration::from_secs(1))
        }

        fn tick_by(&mut self, duration: Duration) -> Instant {
            self.now = self.now + duration;
            self.now
        }
    }

    #[test]
    fn idle_and_quiet_peers_never_switch_policies() {
        let mut clock = Clock::new();
        let mut health = PeerHealth::new_with_jitter(0, clock.now, Duration::from_secs(0));
        let routes = routes(2);

        for _ in 0..10 {
            assert_eq!(
                health.observe(&stats(0, 0), &routes, clock.tick()),
                HealthDecision::Stay,
            );
        }
        assert_eq!(health.active_policy(), 0);
    }

    #[test]
    fn repeated_unanswered_sends_fail_over_once_threshold_and_cooldown_met() {
        let mut clock = Clock::new();
        let mut health = PeerHealth::new_with_jitter(0, clock.now, Duration::from_secs(0));
        let routes = routes(2);

        assert_eq!(
            health.observe(&stats(0, 0), &routes, clock.tick()),
            HealthDecision::Stay
        );
        assert_eq!(
            health.observe(&stats(100, 0), &routes, clock.tick()),
            HealthDecision::Stay
        );
        assert_eq!(
            health.observe(&stats(200, 0), &routes, clock.tick()),
            HealthDecision::Switch {
                next_policy: 1,
                reason: SwitchReason::Failover
            },
        );
        assert_eq!(health.active_policy(), 1);
    }

    #[test]
    fn inbound_packets_mark_current_policy_healthy() {
        let mut clock = Clock::new();
        let mut health = PeerHealth::new_with_jitter(0, clock.now, Duration::from_secs(0));
        let routes = routes(2);

        health.observe(&stats(0, 0), &routes, clock.tick());
        assert_eq!(
            health.observe(&stats(100, 1), &routes, clock.tick()),
            HealthDecision::Stay
        );
        assert_eq!(
            health.observe(&stats(200, 1), &routes, clock.tick()),
            HealthDecision::Stay
        );
        assert_eq!(health.active_policy(), 0);
    }

    #[test]
    fn failover_is_suppressed_until_the_cooldown_elapses() {
        let start = Instant::now();
        let mut health = PeerHealth::new_with_jitter(0, start, Duration::from_secs(0));
        let routes = routes(2);

        health.observe(&stats(0, 0), &routes, start);
        for tx in [100, 200, 300, 400] {
            assert_eq!(
                health.observe(&stats(tx, 0), &routes, start),
                HealthDecision::Stay
            );
        }
        assert_eq!(health.active_policy(), 0);
    }

    #[test]
    fn fallback_recovery_only_happens_with_real_outbound_traffic() {
        let mut clock = Clock::new();
        let mut health = PeerHealth::new_with_jitter(0, clock.now, Duration::from_secs(0));
        let routes = routes(2);

        health.observe(&stats(0, 0), &routes, clock.tick());
        health.observe(&stats(100, 0), &routes, clock.tick());
        assert_eq!(
            health.observe(&stats(200, 0), &routes, clock.tick()),
            HealthDecision::Switch {
                next_policy: 1,
                reason: SwitchReason::Failover
            },
        );

        assert_eq!(
            health.observe(
                &stats(200, 0),
                &routes,
                clock.tick_by(RECOVERY_PROBE_INTERVAL + Duration::from_secs(1)),
            ),
            HealthDecision::Stay,
        );
        assert_eq!(health.active_policy(), 1);

        assert_eq!(
            health.observe(&stats(201, 0), &routes, clock.tick()),
            HealthDecision::Stay,
        );
        assert_eq!(health.active_policy(), 1);
    }

    #[test]
    fn recovery_probe_requires_success_or_returns_to_fallback() {
        let mut clock = Clock::new();
        let mut health = PeerHealth::new_with_jitter(0, clock.now, Duration::from_secs(0));
        let route_keys = routes(2);

        health.observe(&stats(0, 0), &route_keys, clock.tick());
        health.observe(&stats(100, 0), &route_keys, clock.tick());
        health.observe(&stats(200, 0), &route_keys, clock.tick());
        assert_eq!(health.active_policy(), 1);

        assert_eq!(
            health.observe(
                &stats(201, 0),
                &route_keys,
                clock.tick_by(RECOVERY_PROBE_INTERVAL + Duration::from_secs(1)),
            ),
            HealthDecision::Stay,
        );
        assert_eq!(health.active_policy(), 1);

        // Mark policy 0 as no longer failed so recovery may be attempted later.
        let reordered = routes(2);
        health.reset_policy_state();
        health.sync_policies(1, &reordered);
        assert_eq!(
            health.observe(
                &stats(202, 0),
                &reordered,
                clock.tick_by(
                    RECOVERY_PROBE_INTERVAL + MIN_POLICY_SWITCH_INTERVAL + Duration::from_secs(2)
                ),
            ),
            HealthDecision::Switch {
                next_policy: 0,
                reason: SwitchReason::RecoveryProbe
            },
        );
        // The probed higher-priority route black-holes traffic. It is returned
        // to the fallback once inbound silence proves it dead — deliberately not
        // on the first empty sample, which would also bounce off a healthy route
        // whose keepalive simply had not arrived yet.
        assert_eq!(
            health.observe(
                &stats(203, 0),
                &reordered,
                clock.tick_by(INBOUND_SILENCE_TIMEOUT + Duration::from_secs(1)),
            ),
            HealthDecision::Switch {
                next_policy: 1,
                reason: SwitchReason::RecoveryFailed
            },
        );
    }

    #[test]
    fn failover_chooses_best_viable_policy_instead_of_round_robin_wrap() {
        let mut clock = Clock::new();
        let mut health = PeerHealth::new_with_jitter(0, clock.now, Duration::from_secs(0));
        let routes = routes(3);

        health.observe(&stats(0, 0), &routes, clock.tick());
        health.observe(&stats(100, 0), &routes, clock.tick());
        assert_eq!(
            health.observe(&stats(200, 0), &routes, clock.tick()),
            HealthDecision::Switch {
                next_policy: 1,
                reason: SwitchReason::Failover
            },
        );

        health.observe(&stats(300, 0), &routes, clock.tick());
        assert_eq!(
            health.observe(&stats(400, 0), &routes, clock.tick()),
            HealthDecision::Switch {
                next_policy: 2,
                reason: SwitchReason::Failover
            },
        );
        assert_eq!(health.active_policy(), 2);
    }

    #[test]
    fn unanswered_traffic_to_never_reachable_peer_marks_peer_inactive() {
        let mut clock = Clock::new();
        let mut health = PeerHealth::new_with_jitter(0, clock.now, Duration::from_secs(0));
        let routes = routes(2);

        health.observe(&stats(0, 0), &routes, clock.tick());
        health.observe(&stats(100, 0), &routes, clock.tick());
        health.observe(&stats(200, 0), &routes, clock.tick());
        health.observe(&stats(300, 0), &routes, clock.tick());
        assert_eq!(
            health.observe(&stats(400, 0), &routes, clock.tick()),
            HealthDecision::PeerInactive,
        );
        assert_eq!(health.liveness(), PeerLiveness::LikelyInactive);
    }

    #[test]
    fn no_viable_policy_remains_explicit_for_previously_reachable_peer() {
        let mut clock = Clock::new();
        let mut health = PeerHealth::new_with_jitter(0, clock.now, Duration::from_secs(0));
        let routes = routes(2);

        health.observe(&stats(0, 0), &routes, clock.tick());
        assert_eq!(
            health.observe(&stats(100, 1), &routes, clock.tick()),
            HealthDecision::Stay
        );
        assert_eq!(health.liveness(), PeerLiveness::Reachable);
        health.observe(&stats(200, 1), &routes, clock.tick());
        assert_eq!(
            health.observe(&stats(300, 1), &routes, clock.tick()),
            HealthDecision::Switch {
                next_policy: 1,
                reason: SwitchReason::Failover
            },
        );
        health.observe(&stats(400, 1), &routes, clock.tick());
        assert_eq!(
            health.observe(&stats(500, 1), &routes, clock.tick()),
            HealthDecision::NoViablePolicy,
        );
    }

    #[test]
    fn route_identity_preserves_health_across_reordering() {
        let mut clock = Clock::new();
        let mut health = PeerHealth::new_with_jitter(0, clock.now, Duration::from_secs(0));
        let original = routes(2);

        health.observe(&stats(0, 0), &original, clock.tick());
        health.observe(&stats(100, 0), &original, clock.tick());
        health.observe(&stats(200, 0), &original, clock.tick());
        assert_eq!(health.active_policy(), 1);

        let mut reordered = RouteKeyVec::new();
        reordered
            .try_push(RouteKey::Relay(PublicKey::from([1; 32])), "routes")
            .unwrap();
        reordered
            .try_push(RouteKey::Direct(None), "routes")
            .unwrap();
        health.sync_policies(0, &reordered);

        // The direct route moved from index 0 to index 1, and its accumulated
        // failure health moved with the route identity rather than sticking to
        // the old vector index.
        assert_eq!(
            health.policy_health.get(1).unwrap().route,
            RouteKey::Direct(None)
        );
        assert!(health.policy_health.get(1).unwrap().health.suspicion > 0);
        assert_eq!(
            health.policy_health.get(0).unwrap().route,
            RouteKey::Relay(PublicKey::from([1; 32])),
        );
        assert_eq!(health.policy_health.get(0).unwrap().health.suspicion, 0);
    }

    #[test]
    fn healthy_bidirectional_fallback_traffic_can_trigger_recovery_probe() {
        let mut clock = Clock::new();
        let mut health = PeerHealth::new_with_jitter(1, clock.now, Duration::from_secs(0));
        let routes = routes(2);

        health.observe(&stats(0, 0), &routes, clock.now);
        assert_eq!(
            health.observe(
                &stats(1, 1),
                &routes,
                clock.tick_by(RECOVERY_PROBE_INTERVAL + Duration::from_secs(1)),
            ),
            HealthDecision::Switch {
                next_policy: 0,
                reason: SwitchReason::RecoveryProbe
            },
        );
        assert_eq!(health.active_policy(), 0);
    }

    #[test]
    fn failed_higher_priority_policy_requires_validated_fallback_before_recovery_probe() {
        let mut clock = Clock::new();
        let mut health = PeerHealth::new_with_jitter(0, clock.now, Duration::from_secs(0));
        let routes = routes(2);

        health.observe(&stats(0, 0), &routes, clock.tick());
        health.observe(&stats(100, 0), &routes, clock.tick());
        assert_eq!(
            health.observe(&stats(200, 0), &routes, clock.tick()),
            HealthDecision::Switch {
                next_policy: 1,
                reason: SwitchReason::Failover
            },
        );

        assert_eq!(
            health.observe(
                &stats(201, 0),
                &routes,
                // Minimum age of a failed higher-priority policy before it may be retried
                // even if the current fallback has not yet observed a successful inbound sample.
                clock.tick_by(Duration::from_secs(301)),
            ),
            HealthDecision::Stay,
        );

        assert_eq!(
            health.observe(&stats(202, 1), &routes, clock.tick()),
            HealthDecision::Switch {
                next_policy: 0,
                reason: SwitchReason::RecoveryProbe
            },
        );
        assert_eq!(health.active_policy(), 0);
    }

    #[test]
    fn jitter_delays_real_traffic_recovery_attempt() {
        let start = Instant::now();
        let mut health = PeerHealth::new_with_jitter(1, start, Duration::from_secs(7));
        let routes = routes(2);

        health.observe(&stats(0, 0), &routes, start);
        assert_eq!(
            health.observe(
                &stats(1, 0),
                &routes,
                start + RECOVERY_PROBE_INTERVAL + Duration::from_secs(6),
            ),
            HealthDecision::Stay,
        );
        assert_eq!(
            health.observe(
                &stats(2, 0),
                &routes,
                start + RECOVERY_PROBE_INTERVAL + Duration::from_secs(7),
            ),
            HealthDecision::Switch {
                next_policy: 0,
                reason: SwitchReason::RecoveryProbe
            },
        );
    }

    #[test]
    fn first_failover_is_not_delayed_by_full_switch_interval() {
        // A brand-new peer whose only evidence is unanswered outbound traffic
        // should fail away from a dead path once inbound silence has proven the
        // route dead — well under a full MIN_POLICY_SWITCH_INTERVAL, but not
        // before the silence threshold rules out a merely-quiet healthy route.
        let start = Instant::now();
        let mut health = PeerHealth::new_with_jitter(0, start, Duration::from_secs(0));
        let routes = routes(2);

        health.observe(&stats(0, 0), &routes, start);
        // Sending every 5s with nothing coming back. No blame accrues until the
        // inbound-silence window elapses.
        for sample in 1..=4 {
            assert_eq!(
                health.observe(
                    &stats(100 * sample, 0),
                    &routes,
                    start + Duration::from_secs(5 * sample as u64),
                ),
                HealthDecision::Stay,
                "no failover before the silence threshold (sample {sample})",
            );
        }
        // Past the silence threshold the route is implicated, and one further
        // scoring sample tips it over the failure threshold and fails over —
        // at ~30s, far below MIN_POLICY_SWITCH_INTERVAL.
        health.observe(&stats(500, 0), &routes, start + Duration::from_secs(25));
        let decision = health.observe(&stats(600, 0), &routes, start + Duration::from_secs(30));
        assert_eq!(
            decision,
            HealthDecision::Switch {
                next_policy: 1,
                reason: SwitchReason::Failover
            },
        );
        assert_eq!(health.active_policy(), 1);
    }

    #[test]
    fn repeated_switches_widen_the_cooldown() {
        // The first switch is gated only by the short initial grace; the second
        // must wait a full base MIN_POLICY_SWITCH_INTERVAL. Detection of each
        // dead route is gated by the inbound-silence window, so samples are
        // spaced to cross it.
        let start = Instant::now();
        let mut health = PeerHealth::new_with_jitter(0, start, Duration::from_secs(0));
        let routes = routes(3);

        // First failover: route 0 black-holes traffic; fails over once silence
        // proves it dead (~30s), well under MIN_POLICY_SWITCH_INTERVAL.
        health.observe(&stats(0, 0), &routes, start);
        health.observe(&stats(100, 0), &routes, start + Duration::from_secs(25));
        assert_eq!(
            health.observe(&stats(200, 0), &routes, start + Duration::from_secs(30)),
            HealthDecision::Switch {
                next_policy: 1,
                reason: SwitchReason::Failover
            },
        );
        // last_switch is now start+30, switch_count == 1.

        // Route 1 also dies. Suspicion reaches the failure threshold quickly,
        // but the second switch is suppressed until the base cooldown (120s)
        // elapses since the previous switch.
        health.observe(&stats(300, 0), &routes, start + Duration::from_secs(55));
        assert_eq!(
            health.observe(&stats(400, 0), &routes, start + Duration::from_secs(60)),
            HealthDecision::Stay,
        );
        // Just past last_switch + MIN_POLICY_SWITCH_INTERVAL the switch is allowed.
        assert_eq!(
            health.observe(&stats(500, 0), &routes, start + Duration::from_secs(151)),
            HealthDecision::Switch {
                next_policy: 2,
                reason: SwitchReason::Failover
            },
        );
    }

    #[test]
    fn failed_alternate_route_decays_back_to_eligible_after_interval() {
        // A non-active route marked Failed must stop being treated as failed once
        // it has had time to recover, even though it receives no success samples
        // while another route is active. Without decay it would stay wedged.
        let mut clock = Clock::new();
        let mut health = PeerHealth::new_with_jitter(0, clock.now, Duration::from_secs(0));
        let routes = routes(2);

        // Drive the direct route (policy 0) to Failed and fail over to policy 1.
        health.observe(&stats(0, 0), &routes, clock.tick());
        health.observe(&stats(100, 0), &routes, clock.tick());
        assert_eq!(
            health.observe(&stats(200, 0), &routes, clock.tick()),
            HealthDecision::Switch {
                next_policy: 1,
                reason: SwitchReason::Failover
            },
        );
        assert!(health.policy_health.get(0).unwrap().health.is_failed());

        // Stay on policy 1 with inbound-only traffic (tx flat, so no recovery
        // probe is attempted): policy 0 just sits there, failed and idle.
        assert_eq!(
            health.observe(&stats(200, 1), &routes, clock.tick()),
            HealthDecision::Stay,
        );
        assert!(health.policy_health.get(0).unwrap().health.is_failed());

        // After the decay interval, an observe ages policy 0's suspicion below
        // the failure threshold, making it a viable target once again.
        assert_eq!(
            health.observe(
                &stats(200, 2),
                &routes,
                clock.tick_by(POLICY_FAILURE_DECAY_INTERVAL + Duration::from_secs(1)),
            ),
            HealthDecision::Stay,
        );
        assert!(!health.policy_health.get(0).unwrap().health.is_failed());
    }

    #[test]
    fn healthy_unidirectional_flow_does_not_fail_over() {
        // Regression for the sampling/keepalive aliasing pathology. A healthy
        // outbound-only stream whose only return traffic is the peer's periodic
        // passive keepalive must never be mistaken for a failing route. The old
        // per-sample rx-delta test, sampling every 5s against a ~10s keepalive,
        // saw ~half its samples as "unhealthy" and (with +2/-1 scoring) forced a
        // spurious failover.
        let start = Instant::now();
        let mut health = PeerHealth::new_with_jitter(0, start, Duration::from_secs(0));
        let routes = routes(2);

        health.observe(&stats(0, 0), &routes, start); // seed

        let mut tx = 0usize;
        let mut rx = 0usize;
        for sample in 1..=120u64 {
            let now = start + Duration::from_secs(5 * sample);
            tx += 10; // outbound climbs every 5s sample
            if sample % 2 == 0 {
                rx += 1; // passive keepalive lands on a ~10s cadence
            }
            assert_eq!(
                health.observe(&stats(tx, rx), &routes, now),
                HealthDecision::Stay,
                "healthy unidirectional flow must not switch (sample {sample})",
            );
        }
        assert_eq!(health.active_policy(), 0);
        assert!(!health.policy_health.get(0).unwrap().health.is_failed());
    }

    #[test]
    fn genuinely_dead_route_still_fails_over_after_silence_threshold() {
        // The flip side of the regression: a route that black-holes outbound
        // traffic (no inbound at all) must still fail over — just only after the
        // inbound-silence window proves it dead rather than merely quiet, and
        // still well under a minute.
        let start = Instant::now();
        let mut health = PeerHealth::new_with_jitter(0, start, Duration::from_secs(0));
        let routes = routes(2);

        health.observe(&stats(0, 0), &routes, start); // seed

        let mut tx = 0usize;
        let mut switched_at = None;
        for sample in 1..=12u64 {
            tx += 10;
            let elapsed = 5 * sample;
            let decision =
                health.observe(&stats(tx, 0), &routes, start + Duration::from_secs(elapsed));
            if decision != HealthDecision::Stay {
                assert_eq!(
                    decision,
                    HealthDecision::Switch {
                        next_policy: 1,
                        reason: SwitchReason::Failover
                    },
                );
                switched_at = Some(elapsed);
                break;
            }
        }

        let elapsed = switched_at.expect("dead route must eventually fail over");
        assert!(
            (INBOUND_SILENCE_TIMEOUT.as_secs()..=45).contains(&elapsed),
            "failover at {elapsed}s should be past the silence window but under ~45s",
        );
        assert_eq!(health.active_policy(), 1);
    }
}
