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

use aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Tag};
#[cfg(not(feature = "std"))]
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};
use portable_atomic::{AtomicU64, Ordering};
#[cfg(feature = "std")]
use tokio::sync::Mutex;

use super::Data;
use crate::noise::errors::WireGuardError;

#[cfg(not(feature = "std"))]
type SessionMutex<T> = Mutex<CriticalSectionRawMutex, T>;
#[cfg(feature = "std")]
type SessionMutex<T> = Mutex<T>;

pub struct Session {
    pub(crate) receiving_index: u32,
    sending_index: u32,
    receiver: ChaCha20Poly1305,
    sender: ChaCha20Poly1305,
    sending_key_counter: AtomicU64,
    receiving_key_counter: SessionMutex<ReceivingKeyCounterValidator>,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "Session: {}<- ->{}",
            self.receiving_index, self.sending_index
        )
    }
}

/// Where encrypted data resides in a data packet
const DATA_OFFSET: usize = 16;
/// The overhead of the AEAD
const AEAD_SIZE: usize = 16;

/// Initiator should rekey after sending this many messages on a session.
/// Per the WireGuard whitepaper section 5.2.
#[allow(dead_code)]
pub(crate) const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
/// Both initiator and responder must refuse to send or receive on a session
/// once this many messages have been processed. Per the WireGuard whitepaper
/// section 5.2.
pub(crate) const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 16) - 1;

// Receiving buffer constants
const WORD_SIZE: u64 = 64;
const N_WORDS: u64 = 4; // Suffice to reorder 64*4 = 256 packets; can be increased at will
const N_BITS: u64 = WORD_SIZE * N_WORDS;

#[derive(Debug, Clone, Default)]
struct ReceivingKeyCounterValidator {
    /// In order to avoid replays while allowing for some reordering of the packets, we keep a
    /// bitmap of received packets, and the value of the highest counter
    next: u64,
    /// Used to estimate packet loss
    receive_cnt: u64,
    bitmap: [u64; N_WORDS as usize],
}

impl ReceivingKeyCounterValidator {
    #[inline(always)]
    fn set_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] |= 1 << bit;
    }

    #[inline(always)]
    fn clear_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] &= !(1u64 << bit);
    }

    /// Clear the word that contains idx
    #[inline(always)]
    fn clear_word(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        self.bitmap[word] = 0;
    }

    /// Returns true if bit is set, false otherwise
    #[inline(always)]
    fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        ((self.bitmap[word] >> bit) & 1) == 1
    }

    /// Returns true if the counter was not yet received, and is not too far back
    #[inline(always)]
    fn will_accept(&self, counter: u64) -> Result<(), WireGuardError> {
        if counter >= self.next {
            // As long as the counter is growing no replay took place for sure
            return Ok(());
        }
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if !self.check_bit(counter) {
            Ok(())
        } else {
            Err(WireGuardError::DuplicateCounter)
        }
    }

    /// Marks the counter as received, and returns true if it is still good (in case during
    /// decryption something changed)
    #[inline(always)]
    fn mark_did_receive(&mut self, counter: u64) -> Result<(), WireGuardError> {
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if counter == self.next {
            // Usually the packets arrive in order, in that case we simply mark the bit and
            // increment the counter
            self.set_bit(counter);
            self.next += 1;
            return Ok(());
        }
        if counter < self.next {
            // A packet arrived out of order, check if it is valid, and mark
            if self.check_bit(counter) {
                return Err(WireGuardError::InvalidCounter);
            }
            self.set_bit(counter);
            return Ok(());
        }
        // Packets where dropped, or maybe reordered, skip them and mark unused
        if counter - self.next >= N_BITS {
            // Too far ahead, clear all the bits
            for c in self.bitmap.iter_mut() {
                *c = 0;
            }
        } else {
            let mut i = self.next;
            while !i.is_multiple_of(WORD_SIZE) && i < counter {
                // Clear until i aligned to word size
                self.clear_bit(i);
                i += 1;
            }
            while i + WORD_SIZE < counter {
                // Clear whole word at a time
                self.clear_word(i);
                i = (i + WORD_SIZE) & 0u64.wrapping_sub(WORD_SIZE);
            }
            while i < counter {
                // Clear any remaining bits
                self.clear_bit(i);
                i += 1;
            }
        }
        self.set_bit(counter);
        self.next = counter + 1;
        Ok(())
    }
}

impl Session {
    pub(super) fn new(
        local_index: u32,
        peer_index: u32,
        receiving_key: [u8; 32],
        sending_key: [u8; 32],
    ) -> Session {
        Session {
            receiving_index: local_index,
            sending_index: peer_index,
            receiver: ChaCha20Poly1305::new_from_slice(&receiving_key).unwrap(),
            sender: ChaCha20Poly1305::new_from_slice(&sending_key).unwrap(),
            sending_key_counter: AtomicU64::new(0),
            receiving_key_counter: SessionMutex::new(Default::default()),
        }
    }

    pub(super) fn local_index(&self) -> usize {
        self.receiving_index as usize
    }

    /// Returns true if receiving counter is good to use
    async fn receiving_counter_quick_check(&self, counter: u64) -> Result<(), WireGuardError> {
        let counter_validator = self.receiving_key_counter.lock().await;
        counter_validator.will_accept(counter)
    }

    /// Returns true if receiving counter is good to use, and marks it as used {
    async fn receiving_counter_mark(&self, counter: u64) -> Result<(), WireGuardError> {
        let mut counter_validator = self.receiving_key_counter.lock().await;

        let ret = counter_validator.mark_did_receive(counter);
        if ret.is_ok() {
            counter_validator.receive_cnt += 1;
        }

        ret
    }

    /// src - an IP packet from the interface
    /// dst - pre-allocated space to hold the encapsulating UDP packet to send over the network
    /// returns the formatted packet, or None if the session has reached
    /// REJECT_AFTER_MESSAGES and must not be used to send any more data.
    pub(super) fn format_packet_data<'a>(
        &self,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> Option<&'a mut [u8]> {
        self.format_packet_data_with_type(super::DATA, src, dst)
    }

    pub(super) fn format_packet_data_with_type<'a>(
        &self,
        packet_type: super::MessageType,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> Option<&'a mut [u8]> {
        // Pad plaintext to a 16-byte boundary per WireGuard spec, unless
        // doing so would exceed the configured MTU. Computed before the
        // buffer check because the padded length (not the raw `src` length)
        // determines how many bytes are written below.
        let padded_len = if src.is_empty() {
            0
        } else {
            let candidate = (src.len() + 15) & !15;
            if candidate <= crate::MTU {
                candidate
            } else {
                src.len()
            }
        };

        // The output is the data header, the padded plaintext, and the AEAD
        // tag (DATA_OFFSET + padded_len + AEAD_SIZE). Padding can be up to 15
        // bytes larger than `src`, so a guard based on `src.len()` would
        // under-reserve and the tag write below would panic on a tightly
        // sized buffer.
        if dst.len() < DATA_OFFSET + padded_len + AEAD_SIZE {
            panic!("The destination buffer is too small");
        }

        // Reserve a unique counter value with a saturating CAS loop. A plain
        // `fetch_add` would keep incrementing past `REJECT_AFTER_MESSAGES` and
        // eventually wrap to 0, reusing the same nonce under the same session
        // key — a full session-key compromise. The loop refuses to advance
        // once the counter has reached the spec limit, so the atomic stays
        // pinned at `REJECT_AFTER_MESSAGES` until the session is replaced.
        let sending_key_counter = loop {
            let current = self.sending_key_counter.load(Ordering::Relaxed);
            if current >= REJECT_AFTER_MESSAGES {
                // Per the WireGuard spec, this session has exhausted its
                // nonce budget and a rekey is mandatory before further
                // traffic. Refuse to encrypt; the caller will trigger a new
                // handshake.
                return None;
            }
            match self.sending_key_counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break current,
                Err(_) => continue,
            }
        };

        let (message_type, rest) = dst.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (counter, data) = rest.split_at_mut(8);

        message_type.copy_from_slice(&packet_type.to_le_bytes());
        receiver_index.copy_from_slice(&self.sending_index.to_le_bytes());
        counter.copy_from_slice(&sending_key_counter.to_le_bytes());

        let n = {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&sending_key_counter.to_le_bytes());

            data[..src.len()].copy_from_slice(src);

            if padded_len > src.len() {
                data[src.len()..padded_len].fill(0);
            }

            let tag = self
                .sender
                .encrypt_in_place_detached((&nonce).into(), b"", &mut data[..padded_len])
                .unwrap();

            data[padded_len..padded_len + AEAD_SIZE].copy_from_slice(tag.as_ref());

            padded_len + AEAD_SIZE
        };

        Some(&mut dst[..DATA_OFFSET + n])
    }

    /// packet - a data packet we received from the network
    /// dst - pre-allocated space to hold the encapsulated IP packet, to send to the interface
    ///       dst will always take less space than src
    /// return the size of the encapsulated packet on success
    pub(super) async fn receive_packet_data<'a>(
        &self,
        packet: Data<'_>,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        let ct_len = packet.encrypted_encapsulated_packet.len();
        if dst.len() < ct_len {
            // This is a very incorrect use of the library, therefore panic and not error
            panic!("The destination buffer is too small");
        }
        if packet.receiver_idx != self.receiving_index {
            return Err(WireGuardError::WrongIndex);
        }
        // Per the WireGuard spec, sessions must refuse to process any
        // packets at counter values >= REJECT_AFTER_MESSAGES.
        if packet.counter >= REJECT_AFTER_MESSAGES {
            return Err(WireGuardError::InvalidCounter);
        }
        // Don't reuse counters, in case this is a replay attack we want to quickly check the counter without running expensive decryption
        self.receiving_counter_quick_check(packet.counter).await?;

        let ret = {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&packet.counter.to_le_bytes());

            let data = packet.encrypted_encapsulated_packet;
            let pt_len = data.len() - AEAD_SIZE;

            let (ciphertext, tag_bytes) = data.split_at(pt_len);

            dst[..pt_len].copy_from_slice(ciphertext);

            let tag = Tag::from_slice(tag_bytes);

            self.receiver
                .decrypt_in_place_detached((&nonce).into(), b"", &mut dst[..pt_len], tag)
                .map_err(|_| WireGuardError::InvalidAeadTag)?;

            &mut dst[..pt_len]
        };

        // After decryption is done, check counter again, and mark as received
        self.receiving_counter_mark(packet.counter).await?;
        Ok(ret)
    }

    /// Returns the estimated downstream packet loss for this session
    pub(super) async fn current_packet_cnt(&self) -> (u64, u64) {
        let counter_validator = self.receiving_key_counter.lock().await;
        (counter_validator.next, counter_validator.receive_cnt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_replay_counter() {
        let mut c: ReceivingKeyCounterValidator = Default::default();

        assert!(c.mark_did_receive(0).is_ok());
        assert!(c.mark_did_receive(0).is_err());
        assert!(c.mark_did_receive(1).is_ok());
        assert!(c.mark_did_receive(1).is_err());
        assert!(c.mark_did_receive(63).is_ok());
        assert!(c.mark_did_receive(63).is_err());
        assert!(c.mark_did_receive(15).is_ok());
        assert!(c.mark_did_receive(15).is_err());

        for i in 64..N_BITS + 128 {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3).is_ok());
        for i in 0..=N_BITS * 2 {
            assert!(matches!(
                c.will_accept(i),
                Err(WireGuardError::InvalidCounter)
            ));
            assert!(c.mark_did_receive(i).is_err());
        }
        for i in N_BITS * 2 + 1..N_BITS * 3 {
            assert!(c.will_accept(i).is_ok());
        }
        assert!(matches!(
            c.will_accept(N_BITS * 3),
            Err(WireGuardError::DuplicateCounter)
        ));

        for i in (N_BITS * 2 + 1..N_BITS * 3).rev() {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72 + 125).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 63).is_ok());

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_err());
    }

    #[tokio::test]
    async fn rejects_send_counter_at_or_past_limit() {
        // Build a Session with arbitrary keys and force the sending counter
        // to REJECT_AFTER_MESSAGES; format_packet_data must refuse to emit a
        // packet rather than reusing a nonce past the spec limit.
        let session = Session::new(0, 0, [0u8; 32], [1u8; 32]);
        session
            .sending_key_counter
            .store(REJECT_AFTER_MESSAGES, Ordering::Relaxed);

        let mut dst = vec![0u8; 256];
        assert!(session.format_packet_data(&[0u8; 32], &mut dst).is_none());
    }
}
