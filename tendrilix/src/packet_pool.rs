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
use alloc::vec::Vec;

#[cfg(not(feature = "std"))]
use embassy_time::Instant;
#[cfg(feature = "std")]
use tokio::time::Instant;

use crate::{MAX_PACKET_SIZE, noise::MessageType};

/// Minimum packet descriptor capacity for the shared packet pool.
///
/// The byte arena is the hard memory limit for queued packet data, but keeping
/// a small descriptor floor avoids tiny profiles becoming descriptor-bound
/// when they mostly queue very small packets.
pub(crate) const MIN_PACKET_POOL_PACKETS: usize = 32;

/// Target queued-packet data bytes represented by one packet descriptor.
///
/// This intentionally tracks small packets rather than MTU-sized packets so a
/// pool can hold a burst of SYNs or keepalives without wasting the byte arena.
pub(crate) const PACKET_POOL_BYTES_PER_DESCRIPTOR: usize = 32;

/// Upper bound for derived packet descriptors so large byte pools do not spend
/// unbounded RAM on metadata.
pub(crate) const MAX_DERIVED_PACKET_POOL_PACKETS: usize = 512;

/// Derive packet descriptor capacity from the packet byte arena size.
pub(crate) const fn packet_pool_packets_for_bytes(bytes: usize) -> usize {
    let packets = bytes / PACKET_POOL_BYTES_PER_DESCRIPTOR;
    let packets = if packets < MIN_PACKET_POOL_PACKETS {
        MIN_PACKET_POOL_PACKETS
    } else {
        packets
    };

    if packets > MAX_DERIVED_PACKET_POOL_PACKETS {
        MAX_DERIVED_PACKET_POOL_PACKETS
    } else {
        packets
    }
}

/// Opaque handle to a packet stored in the shared device packet pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketHandle(usize);

/// Borrowed view of a queued packet.
pub(crate) struct QueuedPacketRef<'a> {
    pub(crate) packet_type: MessageType,
    pub(crate) data: &'a [u8],
}

/// Device-wide packet pool sized from the selected memory profile.
pub(crate) type DevicePacketPool = PacketPool<
    { packet_pool_packets_for_bytes(crate::limits::MAX_PACKET_POOL_BYTES) },
    { crate::limits::MAX_PACKET_POOL_BYTES },
>;

#[cfg(not(feature = "alloc"))]
#[derive(Clone, Copy)]
struct PacketSlot {
    next: Option<PacketHandle>,
    offset: usize,
    len: usize,
    queued_at: Instant,
    packet_type: MessageType,
    used: bool,
}

#[cfg(not(feature = "alloc"))]
impl PacketSlot {
    const fn new() -> Self {
        Self {
            next: None,
            offset: 0,
            len: 0,
            queued_at: Instant::from_ticks(0),
            packet_type: 0,
            used: false,
        }
    }
}

#[cfg(feature = "alloc")]
struct PacketSlot {
    next: Option<PacketHandle>,
    queued_at: Instant,
    packet_type: MessageType,
    data: Vec<u8>,
}

/// Variable-sized packet pool shared by all tunnels on a device.
///
/// In `no_alloc` builds this uses a caller-selected number of packet
/// descriptors (`N`) plus a caller-selected byte arena (`BYTES`). With the
/// `alloc` feature enabled the same external API is kept, but packet payloads
/// live in heap-allocated `Vec`s and descriptors are stored in a growable slot
/// table. `BYTES` remains the total queued-data limit, so the selected memory
/// profile still controls backpressure.
///
/// Queue links are intrusive: the same `next` field is used while a descriptor
/// is in one peer's pending-packet queue.
pub(crate) struct PacketPool<const N: usize, const BYTES: usize> {
    #[cfg(not(feature = "alloc"))]
    slots: [PacketSlot; N],
    #[cfg(not(feature = "alloc"))]
    arena: [u8; BYTES],

    #[cfg(feature = "alloc")]
    slots: Vec<Option<PacketSlot>>,
    #[cfg(feature = "alloc")]
    free: Vec<usize>,
    #[cfg(feature = "alloc")]
    used_bytes: usize,
}

#[cfg(not(feature = "alloc"))]
impl<const N: usize, const BYTES: usize> PacketPool<N, BYTES> {
    pub(crate) fn new() -> Self {
        Self {
            slots: [PacketSlot::new(); N],
            arena: [0; BYTES],
        }
    }

    pub(crate) fn alloc(
        &mut self,
        packet_type: MessageType,
        packet: &[u8],
        queued_at: Instant,
    ) -> Option<PacketHandle> {
        if packet.len() > MAX_PACKET_SIZE || packet.len() > BYTES {
            return None;
        }

        let handle = self.free_slot()?;
        let offset = self.find_gap(packet.len())?;

        self.arena[offset..offset + packet.len()].copy_from_slice(packet);

        let slot = &mut self.slots[handle.0];
        slot.next = None;
        slot.offset = offset;
        slot.len = packet.len();
        slot.queued_at = queued_at;
        slot.packet_type = packet_type;
        slot.used = true;

        Some(handle)
    }

    pub(crate) fn queued_at(&self, handle: PacketHandle) -> Instant {
        self.slots[handle.0].queued_at
    }

    pub(crate) fn get(&self, handle: PacketHandle) -> QueuedPacketRef<'_> {
        let slot = &self.slots[handle.0];
        QueuedPacketRef {
            packet_type: slot.packet_type,
            data: &self.arena[slot.offset..slot.offset + slot.len],
        }
    }

    pub(crate) fn free(&mut self, handle: PacketHandle) {
        let slot = &mut self.slots[handle.0];
        slot.next = None;
        slot.offset = 0;
        slot.len = 0;
        slot.used = false;
    }

    pub(crate) fn free_chain(&mut self, mut head: Option<PacketHandle>) {
        while let Some(handle) = head {
            head = self.take_next(handle);
            self.free(handle);
        }
    }

    pub(crate) fn set_next(&mut self, handle: PacketHandle, next: Option<PacketHandle>) {
        self.slots[handle.0].next = next;
    }

    pub(crate) fn next(&self, handle: PacketHandle) -> Option<PacketHandle> {
        self.slots[handle.0].next
    }

    pub(crate) fn take_next(&mut self, handle: PacketHandle) -> Option<PacketHandle> {
        let next = self.slots[handle.0].next;
        self.slots[handle.0].next = None;
        next
    }

    fn free_slot(&self) -> Option<PacketHandle> {
        self.slots
            .iter()
            .position(|slot| !slot.used)
            .map(PacketHandle)
    }

    fn find_gap(&self, len: usize) -> Option<usize> {
        let mut start: usize = 0;

        loop {
            let end = start.checked_add(len)?;
            if end > BYTES {
                return None;
            }

            let mut next_start = None;
            for slot in self.slots.iter().filter(|slot| slot.used) {
                let slot_start = slot.offset;
                let slot_end = slot.offset + slot.len;

                if start < slot_end && end > slot_start {
                    next_start = Some(slot_end);
                    break;
                }
            }

            match next_start {
                Some(offset) => start = offset,
                None => return Some(start),
            }
        }
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize, const BYTES: usize> PacketPool<N, BYTES> {
    pub(crate) fn new() -> Self {
        Self {
            slots: Vec::with_capacity(N),
            free: Vec::new(),
            used_bytes: 0,
        }
    }

    pub(crate) fn alloc(
        &mut self,
        packet_type: MessageType,
        packet: &[u8],
        queued_at: Instant,
    ) -> Option<PacketHandle> {
        if packet.len() > MAX_PACKET_SIZE || self.used_bytes.checked_add(packet.len())? > BYTES {
            return None;
        }

        let handle = self.free_slot()?;
        let slot = PacketSlot {
            next: None,
            queued_at,
            packet_type,
            data: Vec::from(packet),
        };

        if handle.0 == self.slots.len() {
            self.slots.push(Some(slot));
        } else {
            self.slots[handle.0] = Some(slot);
        }
        self.used_bytes += packet.len();

        Some(handle)
    }

    pub(crate) fn queued_at(&self, handle: PacketHandle) -> Instant {
        self.slot(handle).queued_at
    }

    pub(crate) fn get(&self, handle: PacketHandle) -> QueuedPacketRef<'_> {
        let slot = self.slot(handle);
        QueuedPacketRef {
            packet_type: slot.packet_type,
            data: &slot.data,
        }
    }

    pub(crate) fn free(&mut self, handle: PacketHandle) {
        let slot = self
            .slots
            .get_mut(handle.0)
            .expect("packet handle is within the pool descriptor table")
            .take()
            .expect("packet handle references a live packet");

        self.used_bytes -= slot.data.len();
        self.free.push(handle.0);
    }

    pub(crate) fn free_chain(&mut self, mut head: Option<PacketHandle>) {
        while let Some(handle) = head {
            head = self.take_next(handle);
            self.free(handle);
        }
    }

    pub(crate) fn set_next(&mut self, handle: PacketHandle, next: Option<PacketHandle>) {
        self.slot_mut(handle).next = next;
    }

    pub(crate) fn next(&self, handle: PacketHandle) -> Option<PacketHandle> {
        self.slot(handle).next
    }

    pub(crate) fn take_next(&mut self, handle: PacketHandle) -> Option<PacketHandle> {
        let slot = self.slot_mut(handle);
        let next = slot.next;
        slot.next = None;
        next
    }

    fn free_slot(&mut self) -> Option<PacketHandle> {
        self.free
            .pop()
            .map(PacketHandle)
            .or_else(|| (self.slots.len() < N).then_some(PacketHandle(self.slots.len())))
    }

    fn slot(&self, handle: PacketHandle) -> &PacketSlot {
        self.slots
            .get(handle.0)
            .and_then(Option::as_ref)
            .expect("packet handle references a live packet")
    }

    fn slot_mut(&mut self, handle: PacketHandle) -> &mut PacketSlot {
        self.slots
            .get_mut(handle.0)
            .and_then(Option::as_mut)
            .expect("packet handle references a live packet")
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[test]
    fn alloc_mode_enforces_descriptor_limit() {
        let now = Instant::now();
        let mut pool = PacketPool::<2, 1024>::new();

        let first = pool.alloc(0, &[1], now).expect("first descriptor");
        let second = pool.alloc(0, &[2], now).expect("second descriptor");
        assert!(pool.alloc(0, &[3], now).is_none());

        pool.free(first);
        assert!(pool.alloc(0, &[4], now).is_some());
        pool.free(second);
    }

    #[test]
    #[should_panic(expected = "packet handle references a live packet")]
    fn alloc_mode_double_free_panics() {
        let now = Instant::now();
        let mut pool = PacketPool::<1, 1024>::new();
        let handle = pool.alloc(0, &[1], now).expect("descriptor");

        pool.free(handle);
        pool.free(handle);
    }

    #[test]
    #[should_panic(expected = "packet handle is within the pool descriptor table")]
    fn alloc_mode_stale_handle_panics() {
        let mut pool = PacketPool::<1, 1024>::new();

        pool.free(PacketHandle(1));
    }
}
