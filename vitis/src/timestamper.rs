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

use core::convert::TryInto;

#[cfg(not(feature = "std"))]
use embassy_time::Instant;
#[cfg(feature = "std")]
use tokio::time::Instant;

use crate::noise::errors::WireGuardError;

/// Computes WireGuard-compatible TAI64N timestamps.
#[derive(Debug)]
pub struct TimeStamper {
    instant_at_start: Instant,
    unix_time_secs_at_start: u64,
}

impl TimeStamper {
    /// TAI64 base corresponding to the Unix epoch.
    const TAI64_BASE: u64 = 0x4000_0000_0000_000a;

    /// Mask used by WireGuard to whiten/truncate nanoseconds.
    const WHITENER_MASK: u32 = 0x0100_0000 - 1;

    /// Create a new TimeStamper anchored to the given Unix wall-clock time.
    ///
    /// `unix_time_secs` is seconds since the Unix epoch.
    pub fn new(unix_time_secs: u64) -> TimeStamper {
        TimeStamper {
            instant_at_start: Instant::now(),
            unix_time_secs_at_start: unix_time_secs,
        }
    }

    /// Generate a 12-byte WireGuard-compatible TAI64N timestamp.
    pub fn stamp(&self) -> [u8; 12] {
        let elapsed = Instant::now().duration_since(self.instant_at_start);

        let seconds = Self::TAI64_BASE + self.unix_time_secs_at_start + elapsed.as_secs();
        let nanoseconds = ((elapsed.as_nanos() % 1_000_000_000) as u32) & !Self::WHITENER_MASK;

        let mut timestamp = [0u8; 12];
        timestamp[0..8].copy_from_slice(&seconds.to_be_bytes());
        timestamp[8..12].copy_from_slice(&nanoseconds.to_be_bytes());

        timestamp
    }
}

/// Represents a 12-byte TAI64N timestamp.
#[derive(Debug)]
pub(crate) struct Tai64N {
    secs: u64,
    nano: u32,
}

impl Tai64N {
    /// A zeroed-out timestamp.
    pub(crate) fn zero() -> Tai64N {
        Tai64N { secs: 0, nano: 0 }
    }

    /// Parse a timestamp from a 12-byte slice.
    pub(crate) fn parse(buf: &[u8; 12]) -> Result<Tai64N, WireGuardError> {
        let (seconds_bytes, nanoseconds_bytes) = buf.split_at(core::mem::size_of::<u64>());

        let seconds = u64::from_be_bytes(seconds_bytes.try_into().unwrap());

        let nanoseconds = u32::from_be_bytes(nanoseconds_bytes.try_into().unwrap());

        Ok(Tai64N {
            secs: seconds,
            nano: nanoseconds,
        })
    }

    /// Returns true if this timestamp is chronologically after `other`.
    pub fn after(&self, other: &Tai64N) -> bool {
        (self.secs > other.secs) || ((self.secs == other.secs) && (self.nano > other.nano))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tai64n_bytes(secs: u64, nano: u32) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..8].copy_from_slice(&secs.to_be_bytes());
        out[8..12].copy_from_slice(&nano.to_be_bytes());
        out
    }

    #[test]
    fn zero_is_not_after_zero() {
        let a = Tai64N::zero();
        let b = Tai64N::zero();

        assert!(!a.after(&b));
    }

    #[test]
    fn parse_reads_big_endian_seconds_and_nanoseconds() {
        let bytes = tai64n_bytes(0x4000_0000_0000_000a, 0x1234_5678);

        let parsed = Tai64N::parse(&bytes).unwrap();

        assert_eq!(parsed.secs, 0x4000_0000_0000_000a);
        assert_eq!(parsed.nano, 0x1234_5678);
    }

    #[test]
    fn timestamp_with_larger_seconds_is_after() {
        let earlier = Tai64N {
            secs: 100,
            nano: u32::MAX,
        };

        let later = Tai64N { secs: 101, nano: 0 };

        assert!(later.after(&earlier));
        assert!(!earlier.after(&later));
    }

    #[test]
    fn timestamp_with_same_seconds_and_larger_nanoseconds_is_after() {
        let earlier = Tai64N {
            secs: 100,
            nano: 0x0100_0000,
        };

        let later = Tai64N {
            secs: 100,
            nano: 0x0200_0000,
        };

        assert!(later.after(&earlier));
        assert!(!earlier.after(&later));
    }

    #[test]
    fn identical_timestamps_are_not_after_each_other() {
        let a = Tai64N {
            secs: 100,
            nano: 0x0200_0000,
        };

        let b = Tai64N {
            secs: 100,
            nano: 0x0200_0000,
        };

        assert!(!a.after(&b));
        assert!(!b.after(&a));
    }

    #[test]
    fn tai64_base_matches_wireguard_unix_epoch_offset() {
        assert_eq!(TimeStamper::TAI64_BASE, (1u64 << 62) + 10);
    }

    #[test]
    fn whitener_mask_clears_lower_24_bits() {
        let nanos = 0x1234_5678u32;
        let whitened = nanos & !TimeStamper::WHITENER_MASK;

        assert_eq!(whitened, 0x1200_0000);
        assert_eq!(whitened & TimeStamper::WHITENER_MASK, 0);
    }

    #[cfg(feature = "std")]
    #[test]
    fn stamp_returns_parseable_tai64n_with_expected_shape() {
        let unix_time_secs = 1_700_000_000;
        let stamper = TimeStamper::new(unix_time_secs);

        let raw = stamper.stamp();
        let parsed = Tai64N::parse(&raw).unwrap();

        assert_eq!(raw.len(), 12);
        assert!(parsed.secs >= TimeStamper::TAI64_BASE);
        assert!(parsed.nano < 1_000_000_000);

        assert_eq!(parsed.nano & TimeStamper::WHITENER_MASK, 0);
    }

    #[cfg(feature = "std")]
    #[test]
    fn subsequent_stamps_do_not_go_backwards() {
        let unix_time_secs = 1_700_000_000;
        let stamper = TimeStamper::new(unix_time_secs);

        let first = Tai64N::parse(&stamper.stamp()).unwrap();
        let second = Tai64N::parse(&stamper.stamp()).unwrap();

        assert!(second.after(&first) || (second.secs == first.secs && second.nano == first.nano));
    }
}
