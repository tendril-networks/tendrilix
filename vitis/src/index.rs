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
 */

use portable_atomic::{AtomicU32, Ordering};
use rand_core::{CryptoRng, RngCore};

/// Collision-free 24-bit peer-index generator backed by a Galois LFSR.
///
/// The upper 24 bits of every WireGuard receiver index identify the peer. The
/// lower byte is rotated per-session by `Handshake`, so the device only needs a
/// single peer-index lookup entry per peer.
pub struct IndexGenerator {
    lfsr: AtomicU32,
    remaining: AtomicU32,
    mask: AtomicU32,
}

impl IndexGenerator {
    const LFSR_MAX: u32 = 0x00ff_ffff;
    const LFSR_POLY: u32 = 0x00d8_0000;

    pub const fn new() -> Self {
        Self {
            lfsr: AtomicU32::new(0),
            remaining: AtomicU32::new(Self::LFSR_MAX),
            mask: AtomicU32::new(0),
        }
    }

    fn random_index<R>(rng: &mut R) -> u32
    where
        R: RngCore + CryptoRng,
    {
        loop {
            let value = rng.next_u32() & Self::LFSR_MAX;
            if value != 0 {
                return value;
            }
        }
    }

    pub fn initialize<R>(&self, rng: &mut R)
    where
        R: RngCore + CryptoRng,
    {
        if self.lfsr.load(Ordering::Acquire) != 0 {
            return;
        }

        let seed = Self::random_index(rng);
        let mask = Self::random_index(rng);

        if self
            .lfsr
            .compare_exchange(0, seed, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.mask.store(mask, Ordering::Release);
        }
    }

    #[inline]
    fn step(state: u32) -> u32 {
        (state >> 1) ^ ((0u32.wrapping_sub(state & 1u32)) & Self::LFSR_POLY)
    }

    /// Returns the next unique non-zero 24-bit peer index.
    pub fn new_index(&self) -> u32 {
        if self.lfsr.load(Ordering::Acquire) == 0 {
            panic!("IndexGenerator used before initialization");
        }

        self.remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .unwrap_or_else(|_| panic!("Too many peers created"));

        loop {
            let current = self.lfsr.load(Ordering::Acquire);
            debug_assert_ne!(current, 0);

            let next = Self::step(current);

            match self.lfsr.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let mask = self.mask.load(Ordering::Acquire);
                    let index = ((current - 1) ^ mask) & Self::LFSR_MAX;

                    return if index == 0 {
                        Self::LFSR_MAX ^ mask
                    } else {
                        index
                    };
                }
                Err(_) => core::hint::spin_loop(),
            }
        }
    }
}

impl Default for IndexGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use rand_core::OsRng;

    use super::*;

    #[tokio::test]
    async fn generated_indices_are_24_bit_non_zero_and_unique_for_large_sample() {
        let generator = IndexGenerator::new();
        let mut rng = OsRng;
        let mut seen = HashSet::with_capacity(20_000);

        generator.initialize(&mut rng);

        for _ in 0..20_000 {
            let index = generator.new_index();

            assert_ne!(index, 0);
            assert!(index <= 0x00ff_ffff);
            assert!(seen.insert(index), "duplicate index: {index:#08x}");
        }
    }
}
