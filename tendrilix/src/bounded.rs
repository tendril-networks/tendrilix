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

//! Fallible helpers for collections that are growable with `alloc` and
//! fixed-capacity without it.
//!
//! The public crate API keeps using concrete collection types (`Vec`,
//! `HashMap`, `heapless::Vec`, `heapless::FnvIndexMap`, ...), but internal code
//! should prefer these traits when it is building a collection whose capacity can
//! be exhausted in embedded profiles. In `alloc` builds the operations cannot
//! fail; in `no_alloc` builds overflow is reported as [`CapacityError`].

/// Error returned when a bounded collection runs out of capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CapacityError {
    context: &'static str,
}

#[allow(unused)]
impl CapacityError {
    pub(crate) const fn new(context: &'static str) -> Self {
        Self { context }
    }

    pub(crate) const fn context(self) -> &'static str {
        self.context
    }
}

pub(crate) trait TryPush<T> {
    fn try_push(&mut self, value: T, context: &'static str) -> Result<(), CapacityError>;
}

pub(crate) trait TryInsert<K, V> {
    fn try_insert_entry(
        &mut self,
        key: K,
        value: V,
        context: &'static str,
    ) -> Result<(), CapacityError>;
}

pub(crate) trait TryInsertKey<K> {
    fn try_insert_key(&mut self, key: K, context: &'static str) -> Result<(), CapacityError>;
}

#[cfg(feature = "alloc")]
impl<T> TryPush<T> for alloc::vec::Vec<T> {
    fn try_push(&mut self, value: T, _context: &'static str) -> Result<(), CapacityError> {
        self.push(value);
        Ok(())
    }
}

#[cfg(not(feature = "alloc"))]
impl<T, const N: usize> TryPush<T> for heapless::Vec<T, N> {
    fn try_push(&mut self, value: T, context: &'static str) -> Result<(), CapacityError> {
        self.push(value).map_err(|_| CapacityError::new(context))
    }
}

#[cfg(feature = "alloc")]
impl<K: Eq + core::hash::Hash, V> TryInsert<K, V> for hashbrown::HashMap<K, V> {
    fn try_insert_entry(
        &mut self,
        key: K,
        value: V,
        _context: &'static str,
    ) -> Result<(), CapacityError> {
        self.insert(key, value);
        Ok(())
    }
}

#[cfg(not(feature = "alloc"))]
impl<K: Eq + core::hash::Hash, V, const N: usize> TryInsert<K, V>
    for heapless::index_map::FnvIndexMap<K, V, N>
{
    fn try_insert_entry(
        &mut self,
        key: K,
        value: V,
        context: &'static str,
    ) -> Result<(), CapacityError> {
        self.insert(key, value)
            .map(|_| ())
            .map_err(|_| CapacityError::new(context))
    }
}

#[cfg(feature = "alloc")]
impl<K: Eq + core::hash::Hash> TryInsertKey<K> for hashbrown::HashSet<K> {
    fn try_insert_key(&mut self, key: K, _context: &'static str) -> Result<(), CapacityError> {
        self.insert(key);
        Ok(())
    }
}

#[cfg(not(feature = "alloc"))]
impl<K: Eq + core::hash::Hash, const N: usize> TryInsertKey<K>
    for heapless::index_set::FnvIndexSet<K, N>
{
    fn try_insert_key(&mut self, key: K, context: &'static str) -> Result<(), CapacityError> {
        self.insert(key)
            .map(|_| ())
            .map_err(|_| CapacityError::new(context))
    }
}
