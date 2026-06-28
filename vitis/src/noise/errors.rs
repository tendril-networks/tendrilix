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

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum WireGuardError {
    DestinationBufferTooSmall,
    UnexpectedPacket,
    WrongIndex,
    WrongKey,
    WrongTimestamp,
    InvalidMac,
    InvalidAeadTag,
    InvalidCounter,
    DuplicateCounter,
    InvalidPacket,
    NoCurrentSession,
    ConnectionExpired,
    UnderLoad,
}
