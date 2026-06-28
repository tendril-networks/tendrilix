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

use crate::x25519::PublicKey;

/// Pluggable policy used to decide whether an authenticated peer may
/// relay-forward a packet to a requested destination peer.
///
/// The callback is invoked after the relay envelope has been authenticated,
/// but before the relay forwards or re-wraps the packet for the destination
/// peer. Return `true` to allow forwarding or `false` to drop the relay packet.
pub trait ForwardingAuthorizer: Sync {
    fn authorize(&self, source: &PublicKey, destination: &PublicKey) -> bool;
}

/// A `ForwardingAuthorizer` that allows or rejects all relay forwarding attempts.
#[derive(Debug, Clone, Copy)]
pub enum GenericAuthorizer {
    AllowAll,
    RejectAll,
}

impl ForwardingAuthorizer for GenericAuthorizer {
    fn authorize(&self, _source: &PublicKey, _destination: &PublicKey) -> bool {
        matches!(self, GenericAuthorizer::AllowAll)
    }
}
