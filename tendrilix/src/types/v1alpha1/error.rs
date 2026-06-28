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
use alloc::string::String;

#[cfg(not(feature = "alloc"))]
use heapless::String;
use serde::{Deserialize, Serialize};

/// Structured error response returned by v1alpha1 directory endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Error {
    /// Stable machine-readable error code.
    pub code: ErrorCode,
    /// Human-readable diagnostic message.
    #[cfg(feature = "alloc")]
    pub message: String,
    /// Human-readable diagnostic message.
    #[cfg(not(feature = "alloc"))]
    pub message: String<128>,
}

impl Error {
    /// Create a peer-limit error for a generated map that is too large.
    pub fn too_many_peers(actual: usize, max: usize) -> Self {
        Self {
            code: ErrorCode::TooManyPeers,
            message: format_message(actual, max),
        }
    }
}

/// Stable machine-readable v1alpha1 error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The generated peer list exceeded the caller-provided `max_peers` limit.
    TooManyPeers,
}

#[cfg(feature = "alloc")]
fn format_message(actual: usize, max: usize) -> String {
    alloc::format!("found {actual} peers, exceeds max of {max} peers")
}

#[cfg(not(feature = "alloc"))]
fn format_message(actual: usize, max: usize) -> String<128> {
    use core::fmt::Write;

    let mut message = String::<128>::new();
    let _ = write!(
        &mut message,
        "found {} peers, exceeds max of {} peers",
        actual, max
    );
    message
}
