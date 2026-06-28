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

#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "allowed-ips-ipv4")]
use core::net::Ipv4Addr;
#[cfg(feature = "allowed-ips-ipv6")]
use core::net::Ipv6Addr;
use core::{net::IpAddr, num::NonZeroU16};

use crate::ipnet::IpNet;

#[cfg(not(any(feature = "allowed-ips-ipv4", feature = "allowed-ips-ipv6",)))]
compile_error!(
    "tendrilix requires at least one of the `allowed-ips-ipv4` or `allowed-ips-ipv6` features to be enabled"
);

#[cfg(feature = "alloc")]
type NodeVec<T, const N: usize> = alloc::vec::Vec<T>;

#[cfg(not(feature = "alloc"))]
type NodeVec<T, const N: usize> = heapless::Vec<T, N>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowedIPsError {
    InvalidCidr,
    Full,
}

/// Unsigned integer used to store a normalized network prefix for one address
/// family.
///
/// Implemented for `u32` (IPv4) and `u128` (IPv6) so that each address-family
/// trie stores prefixes at the natural width of that family. This keeps IPv4
/// nodes 4-byte aligned and compact instead of inheriting `u128`'s 16-byte
/// alignment, which previously roughly doubled the size of every IPv4 trie
/// node.
trait PrefixWord: Copy + Eq {
    /// Width of an address in this family, in bits (32 for IPv4, 128 for IPv6).
    const ADDR_BITS: u8;
    /// The all-zero prefix, used for the `/0` root node.
    const ZERO: Self;

    /// Returns the bit at `index`, counting from the most significant bit.
    ///
    /// `index == 0` addresses the first network bit. Callers must ensure
    /// `index < BITS`.
    fn bit_at(self, index: u8) -> u8;

    /// Masks `self` so only the first `prefix_len` network bits remain.
    ///
    /// This normalizes prefixes before insertion and comparison, ensuring host
    /// bits do not affect trie shape or lookup results.
    fn mask(self, prefix_len: u8) -> Self;
}

macro_rules! impl_prefix_word {
    ($ty:ty, $bits:expr) => {
        impl PrefixWord for $ty {
            const ADDR_BITS: u8 = $bits;
            const ZERO: Self = 0;

            #[inline]
            fn bit_at(self, index: u8) -> u8 {
                debug_assert!(index < Self::ADDR_BITS);

                ((self >> (Self::ADDR_BITS - 1 - index)) & 1) as u8
            }

            #[inline]
            fn mask(self, prefix_len: u8) -> Self {
                debug_assert!(prefix_len <= Self::ADDR_BITS);

                if prefix_len == 0 {
                    0
                } else if prefix_len == Self::ADDR_BITS {
                    self
                } else {
                    let host_bits = Self::ADDR_BITS - prefix_len;
                    let host_mask = (1 as $ty << host_bits) - 1;

                    self & !host_mask
                }
            }
        }
    };
}

impl_prefix_word!(u32, 32);
impl_prefix_word!(u128, 128);

/// A node in the path-compressed binary prefix trie.
///
/// `prefix` stores the network bits for this node, masked to `prefix_len`, at
/// the width of the trie's address family (`W`). Children are addressed by the
/// next bit after `prefix_len`, where `0` is the left branch and `1` is the
/// right branch. A node may be structural only (`data == None`) or may
/// represent an inserted prefix (`data == Some(_)`).
struct Node<W, D> {
    /// Network prefix bits, always normalized by [`PrefixWord::mask`].
    prefix: W,
    /// Number of significant bits in [`Self::prefix`].
    prefix_len: u8,
    /// Child indices in the arena, keyed by the next prefix bit.
    child: [Option<NodeIndex>; 2],
    /// Payload for an inserted prefix, if this node is an actual entry.
    data: Option<D>,
}

type NodeIndex = NonZeroU16;

fn encode_node_index(index: usize) -> Result<NodeIndex, AllowedIPsError> {
    let stored = u16::try_from(index + 1).map_err(|_| AllowedIPsError::Full)?;
    NonZeroU16::new(stored).ok_or(AllowedIPsError::Full)
}

fn decode_node_index(index: NodeIndex) -> usize {
    usize::from(index.get() - 1)
}

impl<W, D> Node<W, D> {
    fn new(prefix: W, prefix_len: u8) -> Self {
        Self {
            prefix,
            prefix_len,
            child: [None, None],
            data: None,
        }
    }
}

/// Path-compressed binary trie for one address family.
///
/// `W` is the prefix word type for the address family: `u32` for IPv4 and
/// `u128` for IPv6 (its [`PrefixWord::ADDR_BITS`] gives the key width). `N` is the
/// total arena capacity, including the root node, when the `alloc` feature is
/// disabled. With `alloc` enabled, nodes are stored in a dynamically growing
/// `alloc::vec::Vec` and `N` is ignored for storage. Child links are stable
/// arena indices in both modes.
///
/// The trie performs longest-prefix-match lookups. Insertions may create
/// intermediate structural nodes when a new prefix partially overlaps an
/// existing child. Removals are lazy and clear only payloads, so structural nodes
/// continue to occupy capacity until [`Trie::clear`] is called.
struct Trie<W, D, const N: usize> {
    /// Arena containing the root, structural split nodes, and payload nodes.
    nodes: NodeVec<Node<W, D>, N>,
}

impl<W: PrefixWord, D, const N: usize> Trie<W, D, N> {
    /// Creates an empty trie containing only the `/0` root node.
    fn new() -> Self {
        // Root node: prefix /0.
        #[cfg(feature = "alloc")]
        let nodes = vec![Node::new(W::ZERO, 0)];
        #[cfg(not(feature = "alloc"))]
        let nodes = {
            let mut nodes = heapless::Vec::new();
            nodes
                .push(Node::new(W::ZERO, 0))
                .ok()
                .expect("Trie root insertion must fit when N > 0");
            nodes
        };
        Self { nodes }
    }

    /// Removes all entries and structural nodes, then recreates the `/0` root.
    fn clear(&mut self) {
        #[cfg(not(feature = "alloc"))]
        assert!(
            N > 0,
            "Trie capacity N must include space for the root node"
        );

        self.nodes.clear();

        #[cfg(feature = "alloc")]
        self.nodes.push(Node::new(W::ZERO, 0));
        #[cfg(not(feature = "alloc"))]
        self.nodes
            .push(Node::new(W::ZERO, 0))
            .ok()
            .expect("Trie root insertion must fit when N > 0");
    }

    /// Inserts `data` for `prefix/prefix_len`.
    ///
    /// The prefix is normalized before insertion. If an entry already exists at
    /// the same prefix length on the same path, its payload is replaced and the
    /// old payload is returned. If the new prefix diverges within an existing
    /// child, the child is split by inserting an intermediate node for the shared
    /// prefix.
    ///
    /// Returns [`AllowedIpsError::Full`] if the fixed arena has insufficient
    /// capacity for the new leaf and any required intermediate node.
    fn insert(&mut self, prefix: W, prefix_len: u8, data: D) -> Result<Option<D>, AllowedIPsError> {
        let prefix = prefix.mask(prefix_len);
        let mut node_idx = 0usize;

        loop {
            if self.nodes[node_idx].prefix_len == prefix_len {
                self.nodes[node_idx].prefix = prefix;
                return Ok(self.nodes[node_idx].data.replace(data));
            }

            let branch = prefix.bit_at(self.nodes[node_idx].prefix_len) as usize;

            let Some(child_idx) = self.nodes[node_idx].child[branch].map(decode_node_index) else {
                let new_idx = encode_node_index(self.nodes.len())?;

                #[cfg(feature = "alloc")]
                self.nodes.push(Node {
                    prefix,
                    prefix_len,
                    child: [None, None],
                    data: Some(data),
                });
                #[cfg(not(feature = "alloc"))]
                self.nodes
                    .push(Node {
                        prefix,
                        prefix_len,
                        child: [None, None],
                        data: Some(data),
                    })
                    .map_err(|_| AllowedIPsError::Full)?;

                self.nodes[node_idx].child[branch] = Some(new_idx);
                return Ok(None);
            };

            let child_prefix = self.nodes[child_idx].prefix;
            let child_prefix_len = self.nodes[child_idx].prefix_len;

            let common = common_prefix_len(prefix, prefix_len, child_prefix, child_prefix_len);

            if common == child_prefix_len {
                node_idx = child_idx;
                continue;
            }

            // Split the existing child. This creates an intermediate node
            // containing the shared prefix, then hangs the old child and
            // possibly the new leaf below it.
            #[cfg(not(feature = "alloc"))]
            let needed = if common == prefix_len { 1 } else { 2 };

            #[cfg(not(feature = "alloc"))]
            if self.nodes.len() + needed > N {
                return Err(AllowedIPsError::Full);
            }

            let intermediate_idx = self.nodes.len();
            let encoded_intermediate_idx = encode_node_index(intermediate_idx)?;
            let intermediate_prefix = prefix.mask(common);

            let old_branch = child_prefix.bit_at(common) as usize;

            let mut intermediate = Node::new(intermediate_prefix, common);
            intermediate.child[old_branch] = Some(encode_node_index(child_idx)?);

            if common == prefix_len {
                intermediate.data = Some(data);

                #[cfg(feature = "alloc")]
                self.nodes.push(intermediate);
                #[cfg(not(feature = "alloc"))]
                self.nodes
                    .push(intermediate)
                    .map_err(|_| AllowedIPsError::Full)?;

                self.nodes[node_idx].child[branch] = Some(encoded_intermediate_idx);
                return Ok(None);
            }

            let new_branch = prefix.bit_at(common) as usize;
            let new_leaf_idx = intermediate_idx + 1;

            intermediate.child[new_branch] = Some(encode_node_index(new_leaf_idx)?);

            #[cfg(feature = "alloc")]
            self.nodes.push(intermediate);
            #[cfg(not(feature = "alloc"))]
            self.nodes
                .push(intermediate)
                .map_err(|_| AllowedIPsError::Full)?;

            #[cfg(feature = "alloc")]
            self.nodes.push(Node {
                prefix,
                prefix_len,
                child: [None, None],
                data: Some(data),
            });
            #[cfg(not(feature = "alloc"))]
            self.nodes
                .push(Node {
                    prefix,
                    prefix_len,
                    child: [None, None],
                    data: Some(data),
                })
                .map_err(|_| AllowedIPsError::Full)?;

            self.nodes[node_idx].child[branch] = Some(encoded_intermediate_idx);
            return Ok(None);
        }
    }

    /// Finds the payload for the most-specific prefix matching `key`.
    ///
    /// Traversal follows the bits of `key`, remembering the last node with a
    /// payload. Because the trie is path-compressed, each child candidate is
    /// checked by masking `key` to the child prefix length before descending.
    fn find(&self, key: W) -> Option<&D> {
        let mut node_idx = 0usize;
        let mut best = self.nodes[node_idx].data.as_ref();

        loop {
            if self.nodes[node_idx].prefix_len == W::ADDR_BITS {
                break;
            }

            let branch = key.bit_at(self.nodes[node_idx].prefix_len) as usize;

            let Some(child_idx) = self.nodes[node_idx].child[branch].map(decode_node_index) else {
                break;
            };

            let child = &self.nodes[child_idx];

            if key.mask(child.prefix_len) != child.prefix {
                break;
            }

            node_idx = child_idx;

            if let Some(data) = self.nodes[node_idx].data.as_ref() {
                best = Some(data);
            }
        }

        best
    }

    /// Clears payloads for all entries whose data satisfies `predicate`.
    ///
    /// This does not unlink or compact nodes. That keeps arena indices stable and
    /// avoids moving payloads, but removed entries do not free capacity.
    fn remove<F>(&mut self, predicate: &mut F)
    where
        F: FnMut(&D) -> bool,
    {
        for node in &mut self.nodes {
            let remove = match node.data.as_ref() {
                Some(data) => predicate(data),
                None => false,
            };

            if remove {
                node.data = None;
            }
        }

        // Deliberately no structural pruning here.
        //
        // The trie remains correct after lazy deletion, and keeping indices
        // stable avoids compaction complexity in the fixed-capacity arena.
        // This also means removed nodes continue to consume capacity until
        // clear() is called.
    }

    /// Returns true if `prefix/prefix_len` overlaps any payload-bearing prefix.
    ///
    /// Two prefixes overlap when at least one address belongs to both ranges.
    /// Equivalently, their common prefix is at least as long as the shorter
    /// prefix length.
    fn overlaps(&self, prefix: W, prefix_len: u8) -> bool {
        let prefix = prefix.mask(prefix_len);

        self.iter()
            .any(|(_, existing_prefix, existing_prefix_len)| {
                prefixes_overlap(prefix, prefix_len, existing_prefix, existing_prefix_len)
            })
    }

    /// Iterates over all nodes that currently contain payloads.
    ///
    /// Iteration order is arena insertion/split order rather than prefix-sorted
    /// order.
    fn iter(&self) -> TrieIter<'_, W, D, N> {
        TrieIter {
            inner: self.nodes.iter(),
        }
    }
}

/// Iterator over payload-bearing trie nodes.
struct TrieIter<'a, W, D, const N: usize> {
    inner: core::slice::Iter<'a, Node<W, D>>,
}

impl<'a, W: PrefixWord, D, const N: usize> Iterator for TrieIter<'a, W, D, N> {
    type Item = (&'a D, W, u8);

    fn next(&mut self) -> Option<Self::Item> {
        for node in self.inner.by_ref() {
            if let Some(data) = node.data.as_ref() {
                return Some((data, node.prefix, node.prefix_len));
            }
        }

        None
    }
}

/// AllowedIPs table.
///
/// With the `alloc` feature, this uses dynamically growing `alloc::vec::Vec`
/// storage. Without `alloc`, this is fixed-capacity and `N` is the node capacity
/// per address family trie, including each trie's root node.
///
/// Removal is lazy: [`AllowedIPs::remove`] clears matching payloads but does not
/// prune or compact structural trie nodes. Lookups and iteration remain correct,
/// but removed entries do not free node capacity. Call [`AllowedIPs::clear`] to
/// reclaim all node capacity.
#[cfg(feature = "alloc")]
pub struct AllowedIPs<D> {
    #[cfg(feature = "allowed-ips-ipv4")]
    v4: Trie<u32, D, 0>,
    #[cfg(feature = "allowed-ips-ipv6")]
    v6: Trie<u128, D, 0>,
}

#[cfg(not(feature = "alloc"))]
pub struct AllowedIPs<D, const N: usize> {
    #[cfg(feature = "allowed-ips-ipv4")]
    v4: Trie<u32, D, N>,
    #[cfg(feature = "allowed-ips-ipv6")]
    v6: Trie<u128, D, N>,
}

#[cfg(feature = "alloc")]
impl<D> Default for AllowedIPs<D> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "alloc"))]
impl<D, const N: usize> Default for AllowedIPs<D, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "alloc")]
impl<D> AllowedIPs<D> {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "allowed-ips-ipv4")]
            v4: Trie::new(),
            #[cfg(feature = "allowed-ips-ipv6")]
            v6: Trie::new(),
        }
    }

    pub fn clear(&mut self) {
        #[cfg(feature = "allowed-ips-ipv4")]
        self.v4.clear();
        #[cfg(feature = "allowed-ips-ipv6")]
        self.v6.clear();
    }

    pub fn insert(&mut self, network: IpNet, data: D) -> Result<Option<D>, AllowedIPsError> {
        let cidr = network.prefix_len();

        match network.network() {
            #[cfg(feature = "allowed-ips-ipv4")]
            IpAddr::V4(addr) => self.v4.insert(u32::from(addr), cidr, data),
            #[cfg(feature = "allowed-ips-ipv6")]
            IpAddr::V6(addr) => self.v6.insert(u128::from(addr), cidr, data),
            #[allow(unreachable_patterns)]
            _ => Err(AllowedIPsError::InvalidCidr),
        }
    }

    pub fn find(&self, key: IpAddr) -> Option<&D> {
        match key {
            #[cfg(feature = "allowed-ips-ipv4")]
            IpAddr::V4(addr) => self.v4.find(u32::from(addr)),
            #[cfg(feature = "allowed-ips-ipv6")]
            IpAddr::V6(addr) => self.v6.find(u128::from(addr)),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// Returns true if `network` overlaps any existing allowed IP prefix.
    ///
    /// Exact matches, less-specific prefixes that contain existing entries, and
    /// more-specific prefixes contained by existing entries are all considered
    /// overlapping. IPv4 and IPv6 prefixes never overlap each other.
    pub fn overlaps(&self, network: IpNet) -> Result<bool, AllowedIPsError> {
        let cidr = network.prefix_len();

        match network.network() {
            #[cfg(feature = "allowed-ips-ipv4")]
            IpAddr::V4(addr) => Ok(self.v4.overlaps(u32::from(addr), cidr)),
            #[cfg(feature = "allowed-ips-ipv6")]
            IpAddr::V6(addr) => Ok(self.v6.overlaps(u128::from(addr), cidr)),
            #[allow(unreachable_patterns)]
            _ => Err(AllowedIPsError::InvalidCidr),
        }
    }

    /// Removes all entries whose payload matches `predicate`.
    ///
    /// This uses lazy deletion: matching payloads are cleared, but trie nodes are
    /// not pruned or compacted. This preserves stable arena indices and keeps
    /// lookups correct, but it does not reclaim capacity. Call [`Self::clear`] to
    /// reclaim all capacity.
    pub fn remove<F>(&mut self, mut predicate: F)
    where
        F: FnMut(&D) -> bool,
    {
        #[cfg(feature = "allowed-ips-ipv4")]
        self.v4.remove(&mut predicate);
        #[cfg(feature = "allowed-ips-ipv6")]
        self.v6.remove(&mut predicate);
    }

    pub fn iter(&self) -> Iter<'_, D> {
        Iter {
            #[cfg(feature = "allowed-ips-ipv4")]
            v4: self.v4.iter(),
            #[cfg(feature = "allowed-ips-ipv6")]
            v6: self.v6.iter(),
        }
    }

    pub fn try_from_iter<'a, I>(iter: I) -> Result<Self, AllowedIPsError>
    where
        I: IntoIterator<Item = (&'a IpNet, D)>,
        D: 'a,
    {
        let mut allowed_ips = Self::new();

        for (ip, data) in iter {
            allowed_ips.insert(*ip, data)?;
        }

        Ok(allowed_ips)
    }
}

#[cfg(not(feature = "alloc"))]
impl<D, const N: usize> AllowedIPs<D, N> {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "allowed-ips-ipv4")]
            v4: Trie::new(),
            #[cfg(feature = "allowed-ips-ipv6")]
            v6: Trie::new(),
        }
    }

    pub fn clear(&mut self) {
        #[cfg(feature = "allowed-ips-ipv4")]
        self.v4.clear();
        #[cfg(feature = "allowed-ips-ipv6")]
        self.v6.clear();
    }

    pub fn insert(&mut self, network: IpNet, data: D) -> Result<Option<D>, AllowedIPsError> {
        let cidr = network.prefix_len();

        match network.network() {
            #[cfg(feature = "allowed-ips-ipv4")]
            IpAddr::V4(addr) => self.v4.insert(u32::from(addr), cidr, data),
            #[cfg(feature = "allowed-ips-ipv6")]
            IpAddr::V6(addr) => self.v6.insert(u128::from(addr), cidr, data),
            #[allow(unreachable_patterns)]
            _ => Err(AllowedIPsError::InvalidCidr),
        }
    }

    pub fn find(&self, key: IpAddr) -> Option<&D> {
        match key {
            #[cfg(feature = "allowed-ips-ipv4")]
            IpAddr::V4(addr) => self.v4.find(u32::from(addr)),
            #[cfg(feature = "allowed-ips-ipv6")]
            IpAddr::V6(addr) => self.v6.find(u128::from(addr)),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// Returns true if `network` overlaps any existing allowed IP prefix.
    ///
    /// Exact matches, less-specific prefixes that contain existing entries, and
    /// more-specific prefixes contained by existing entries are all considered
    /// overlapping. IPv4 and IPv6 prefixes never overlap each other.
    pub fn overlaps(&self, network: IpNet) -> Result<bool, AllowedIPsError> {
        let cidr = network.prefix_len();

        match network.network() {
            #[cfg(feature = "allowed-ips-ipv4")]
            IpAddr::V4(addr) => Ok(self.v4.overlaps(u32::from(addr), cidr)),
            #[cfg(feature = "allowed-ips-ipv6")]
            IpAddr::V6(addr) => Ok(self.v6.overlaps(u128::from(addr), cidr)),
            #[allow(unreachable_patterns)]
            _ => Err(AllowedIPsError::InvalidCidr),
        }
    }

    /// Removes all entries whose payload matches `predicate`.
    ///
    /// This uses lazy deletion: matching payloads are cleared, but trie nodes are
    /// not pruned or compacted. This preserves stable arena indices and keeps
    /// lookups correct, but it does not reclaim capacity. Call [`Self::clear`] to
    /// reclaim all capacity.
    pub fn remove<F>(&mut self, mut predicate: F)
    where
        F: FnMut(&D) -> bool,
    {
        #[cfg(feature = "allowed-ips-ipv4")]
        self.v4.remove(&mut predicate);
        #[cfg(feature = "allowed-ips-ipv6")]
        self.v6.remove(&mut predicate);
    }

    pub fn iter(&self) -> Iter<'_, D, N> {
        Iter {
            #[cfg(feature = "allowed-ips-ipv4")]
            v4: self.v4.iter(),
            #[cfg(feature = "allowed-ips-ipv6")]
            v6: self.v6.iter(),
        }
    }

    pub fn try_from_iter<'a, I>(iter: I) -> Result<Self, AllowedIPsError>
    where
        I: IntoIterator<Item = (&'a IpNet, D)>,
        D: 'a,
    {
        let mut allowed_ips = Self::new();

        for (ip, data) in iter {
            allowed_ips.insert(*ip, data)?;
        }

        Ok(allowed_ips)
    }
}

#[cfg(feature = "alloc")]
pub struct Iter<'a, D> {
    #[cfg(feature = "allowed-ips-ipv4")]
    v4: TrieIter<'a, u32, D, 0>,
    #[cfg(feature = "allowed-ips-ipv6")]
    v6: TrieIter<'a, u128, D, 0>,
}

#[cfg(not(feature = "alloc"))]
pub struct Iter<'a, D, const N: usize> {
    #[cfg(feature = "allowed-ips-ipv4")]
    v4: TrieIter<'a, u32, D, N>,
    #[cfg(feature = "allowed-ips-ipv6")]
    v6: TrieIter<'a, u128, D, N>,
}

#[cfg(feature = "alloc")]
impl<'a, D> Iterator for Iter<'a, D> {
    type Item = (&'a D, IpNet);

    fn next(&mut self) -> Option<Self::Item> {
        #[cfg(feature = "allowed-ips-ipv4")]
        if let Some((data, prefix, prefix_len)) = self.v4.next() {
            return Some((
                data,
                IpNet::new(IpAddr::V4(Ipv4Addr::from(prefix)), prefix_len).unwrap(),
            ));
        }

        #[cfg(feature = "allowed-ips-ipv6")]
        if let Some((data, prefix, prefix_len)) = self.v6.next() {
            return Some((
                data,
                IpNet::new(IpAddr::V6(Ipv6Addr::from(prefix)), prefix_len).unwrap(),
            ));
        }

        None
    }
}

#[cfg(not(feature = "alloc"))]
impl<'a, D, const N: usize> Iterator for Iter<'a, D, N> {
    type Item = (&'a D, IpNet);

    fn next(&mut self) -> Option<Self::Item> {
        #[cfg(feature = "allowed-ips-ipv4")]
        if let Some((data, prefix, prefix_len)) = self.v4.next() {
            return Some((
                data,
                IpNet::new(IpAddr::V4(Ipv4Addr::from(prefix)), prefix_len).unwrap(),
            ));
        }

        #[cfg(feature = "allowed-ips-ipv6")]
        if let Some((data, prefix, prefix_len)) = self.v6.next() {
            return Some((
                data,
                IpNet::new(IpAddr::V6(Ipv6Addr::from(prefix)), prefix_len).unwrap(),
            ));
        }

        None
    }
}

#[cfg(feature = "alloc")]
impl<'a, D> FromIterator<(&'a IpNet, D)> for AllowedIPs<D>
where
    D: 'a,
{
    fn from_iter<I: IntoIterator<Item = (&'a IpNet, D)>>(iter: I) -> Self {
        Self::try_from_iter(iter).expect(
            "AllowedIPs::from_iter failed; use AllowedIPs::try_from_iter to handle insertion errors",
        )
    }
}

#[cfg(not(feature = "alloc"))]
impl<'a, D, const N: usize> FromIterator<(&'a IpNet, D)> for AllowedIPs<D, N>
where
    D: 'a,
{
    fn from_iter<I: IntoIterator<Item = (&'a IpNet, D)>>(iter: I) -> Self {
        Self::try_from_iter(iter).expect(
            "AllowedIPs::from_iter failed; use AllowedIPs::try_from_iter to handle capacity errors",
        )
    }
}

/// Computes the shared prefix length of two normalized prefixes.
///
/// The result is capped at the shorter prefix length. It is used during insert
/// to decide whether to descend into a child or split it with an intermediate
/// node.
fn common_prefix_len<W: PrefixWord>(a: W, a_len: u8, b: W, b_len: u8) -> u8 {
    let max = core::cmp::min(a_len, b_len);

    for i in 0..max {
        if a.bit_at(i) != b.bit_at(i) {
            return i;
        }
    }

    max
}

/// Returns true if two normalized CIDR prefixes contain at least one common address.
fn prefixes_overlap<W: PrefixWord>(a: W, a_len: u8, b: W, b_len: u8) -> bool {
    common_prefix_len(a, a_len, b, b_len) == core::cmp::min(a_len, b_len)
}

#[cfg(test)]
mod tests {
    use core::net::IpAddr;
    #[cfg(feature = "allowed-ips-ipv4")]
    use core::net::Ipv4Addr;
    #[cfg(feature = "allowed-ips-ipv6")]
    use core::net::Ipv6Addr;

    use super::*;

    #[cfg(feature = "alloc")]
    type TestAllowedIps<D> = AllowedIPs<D>;

    #[cfg(not(feature = "alloc"))]
    type TestAllowedIps<D> = AllowedIPs<D, 64>;

    #[cfg(feature = "allowed-ips-ipv4")]
    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[cfg(feature = "allowed-ips-ipv6")]
    #[allow(clippy::too_many_arguments)]
    fn v6(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
    }

    #[cfg(feature = "allowed-ips-ipv4")]
    fn build_allowed_ips_v4() -> TestAllowedIps<char> {
        let mut map: TestAllowedIps<char> = Default::default();
        map.insert(IpNet::new(v4(127, 0, 0, 1), 32).unwrap(), '1')
            .unwrap();
        map.insert(IpNet::new(v4(45, 25, 15, 1), 30).unwrap(), '6')
            .unwrap();
        map.insert(IpNet::new(v4(127, 0, 15, 1), 16).unwrap(), '2')
            .unwrap();
        map.insert(IpNet::new(v4(127, 1, 15, 1), 24).unwrap(), '3')
            .unwrap();
        map.insert(IpNet::new(v4(255, 1, 15, 1), 24).unwrap(), '4')
            .unwrap();
        map.insert(IpNet::new(v4(60, 25, 15, 1), 32).unwrap(), '5')
            .unwrap();
        map
    }

    #[cfg(feature = "allowed-ips-ipv6")]
    fn build_allowed_ips_v6() -> TestAllowedIps<char> {
        let mut map: TestAllowedIps<char> = Default::default();
        map.insert(
            IpNet::new(v6(0x0553, 0, 0, 1, 0, 0, 0, 0), 128).unwrap(),
            '7',
        )
        .unwrap();
        map
    }

    #[cfg(feature = "allowed-ips-ipv4")]
    #[test]
    fn test_allowed_ips_insert_find_v4() {
        let map = build_allowed_ips_v4();

        assert_eq!(map.find(v4(127, 0, 0, 1)), Some(&'1'));
        assert_eq!(map.find(v4(127, 0, 255, 255)), Some(&'2'));
        assert_eq!(map.find(v4(127, 1, 255, 255)), None);
        assert_eq!(map.find(v4(127, 1, 15, 255)), Some(&'3'));
        assert_eq!(map.find(v4(255, 1, 15, 2)), Some(&'4'));
        assert_eq!(map.find(v4(60, 25, 15, 1)), Some(&'5'));
        assert_eq!(map.find(v4(20, 0, 0, 100)), None);
        assert_eq!(map.find(v4(45, 25, 15, 1)), Some(&'6'));
    }

    #[cfg(feature = "allowed-ips-ipv6")]
    #[test]
    fn test_allowed_ips_insert_find_v6() {
        let map = build_allowed_ips_v6();

        assert_eq!(map.find(v6(0x0553, 0, 0, 1, 0, 0, 0, 0)), Some(&'7'));
        assert_eq!(map.find(v6(0x0553, 0, 0, 1, 0, 0, 0, 1)), None);
    }

    #[cfg(feature = "allowed-ips-ipv4")]
    #[test]
    fn test_allowed_ips_remove_v4() {
        let mut map = build_allowed_ips_v4();
        map.remove(|c| *c == '5' || *c == '1');

        assert_eq!(map.find(v4(60, 25, 15, 1)), None);
        assert_eq!(map.find(v4(127, 0, 0, 1)), Some(&'2'));
    }

    #[cfg(feature = "allowed-ips-ipv6")]
    #[test]
    fn test_allowed_ips_remove_v6() {
        let mut map = build_allowed_ips_v6();
        map.remove(|c| *c == '7');

        assert_eq!(map.find(v6(0x0553, 0, 0, 1, 0, 0, 0, 0)), None);
    }

    #[cfg(feature = "allowed-ips-ipv4")]
    #[test]
    fn test_allowed_ips_iter_v4() {
        let map = build_allowed_ips_v4();

        #[cfg(feature = "alloc")]
        let items: alloc::vec::Vec<_> = map.iter().collect();
        #[cfg(not(feature = "alloc"))]
        let items: heapless::Vec<_, 64> = map.iter().collect();

        assert!(items.contains(&(&'6', IpNet::new(v4(45, 25, 15, 0), 30).unwrap())));
        assert!(items.contains(&(&'5', IpNet::new(v4(60, 25, 15, 1), 32).unwrap())));
        assert!(items.contains(&(&'2', IpNet::new(v4(127, 0, 0, 0), 16).unwrap())));
        assert!(items.contains(&(&'1', IpNet::new(v4(127, 0, 0, 1), 32).unwrap())));
        assert!(items.contains(&(&'3', IpNet::new(v4(127, 1, 15, 0), 24).unwrap())));
        assert!(items.contains(&(&'4', IpNet::new(v4(255, 1, 15, 0), 24).unwrap())));
        assert_eq!(items.len(), 6);
    }

    #[cfg(feature = "allowed-ips-ipv6")]
    #[test]
    fn test_allowed_ips_iter_v6() {
        let map = build_allowed_ips_v6();

        #[cfg(feature = "alloc")]
        let items: alloc::vec::Vec<_> = map.iter().collect();
        #[cfg(not(feature = "alloc"))]
        let items: heapless::Vec<_, 64> = map.iter().collect();

        assert!(items.contains(&(
            &'7',
            IpNet::new(v6(0x0553, 0, 0, 1, 0, 0, 0, 0), 128).unwrap()
        )));
        assert_eq!(items.len(), 1);
    }

    #[cfg(feature = "allowed-ips-ipv4")]
    #[test]
    fn test_allowed_ips_v4_kernel_compatibility() {
        let mut map: TestAllowedIps<char> = Default::default();

        map.insert(IpNet::new(v4(192, 168, 4, 0), 24).unwrap(), 'a')
            .unwrap();
        map.insert(IpNet::new(v4(192, 168, 4, 4), 32).unwrap(), 'b')
            .unwrap();
        map.insert(IpNet::new(v4(192, 168, 0, 0), 16).unwrap(), 'c')
            .unwrap();
        map.insert(IpNet::new(v4(192, 95, 5, 64), 27).unwrap(), 'd')
            .unwrap();
        map.insert(IpNet::new(v4(192, 95, 5, 65), 27).unwrap(), 'c')
            .unwrap();
        map.insert(IpNet::new(v4(0, 0, 0, 0), 0).unwrap(), 'e')
            .unwrap();
        map.insert(IpNet::new(v4(64, 15, 112, 0), 20).unwrap(), 'g')
            .unwrap();
        map.insert(IpNet::new(v4(64, 15, 123, 211), 25).unwrap(), 'h')
            .unwrap();
        map.insert(IpNet::new(v4(10, 0, 0, 0), 25).unwrap(), 'a')
            .unwrap();
        map.insert(IpNet::new(v4(10, 0, 0, 128), 25).unwrap(), 'b')
            .unwrap();
        map.insert(IpNet::new(v4(10, 1, 0, 0), 30).unwrap(), 'a')
            .unwrap();
        map.insert(IpNet::new(v4(10, 1, 0, 4), 30).unwrap(), 'b')
            .unwrap();
        map.insert(IpNet::new(v4(10, 1, 0, 8), 29).unwrap(), 'c')
            .unwrap();
        map.insert(IpNet::new(v4(10, 1, 0, 16), 29).unwrap(), 'd')
            .unwrap();

        assert_eq!(Some(&'a'), map.find(v4(192, 168, 4, 20)));
        assert_eq!(Some(&'a'), map.find(v4(192, 168, 4, 0)));
        assert_eq!(Some(&'b'), map.find(v4(192, 168, 4, 4)));
        assert_eq!(Some(&'c'), map.find(v4(192, 168, 200, 182)));
        assert_eq!(Some(&'c'), map.find(v4(192, 95, 5, 68)));
        assert_eq!(Some(&'e'), map.find(v4(192, 95, 5, 96)));
        assert_eq!(Some(&'g'), map.find(v4(64, 15, 116, 26)));
        assert_eq!(Some(&'g'), map.find(v4(64, 15, 127, 3)));

        map.insert(IpNet::new(v4(1, 0, 0, 0), 32).unwrap(), 'a')
            .unwrap();
        map.insert(IpNet::new(v4(64, 0, 0, 0), 32).unwrap(), 'a')
            .unwrap();
        map.insert(IpNet::new(v4(128, 0, 0, 0), 32).unwrap(), 'a')
            .unwrap();
        map.insert(IpNet::new(v4(192, 0, 0, 0), 32).unwrap(), 'a')
            .unwrap();
        map.insert(IpNet::new(v4(255, 0, 0, 0), 32).unwrap(), 'a')
            .unwrap();

        assert_eq!(Some(&'a'), map.find(v4(1, 0, 0, 0)));
        assert_eq!(Some(&'a'), map.find(v4(64, 0, 0, 0)));
        assert_eq!(Some(&'a'), map.find(v4(128, 0, 0, 0)));
        assert_eq!(Some(&'a'), map.find(v4(192, 0, 0, 0)));
        assert_eq!(Some(&'a'), map.find(v4(255, 0, 0, 0)));

        map.remove(|c| *c == 'a');

        assert_ne!(Some(&'a'), map.find(v4(1, 0, 0, 0)));
        assert_ne!(Some(&'a'), map.find(v4(64, 0, 0, 0)));
        assert_ne!(Some(&'a'), map.find(v4(128, 0, 0, 0)));
        assert_ne!(Some(&'a'), map.find(v4(192, 0, 0, 0)));
        assert_ne!(Some(&'a'), map.find(v4(255, 0, 0, 0)));

        map.clear();

        map.insert(IpNet::new(v4(192, 168, 0, 0), 16).unwrap(), 'a')
            .unwrap();
        map.insert(IpNet::new(v4(192, 168, 0, 0), 24).unwrap(), 'a')
            .unwrap();

        map.remove(|c| *c == 'a');

        assert_ne!(Some(&'a'), map.find(v4(192, 168, 0, 1)));
    }

    #[cfg(feature = "allowed-ips-ipv6")]
    #[test]
    fn test_allowed_ips_v6_kernel_compatibility() {
        let mut map: TestAllowedIps<char> = Default::default();

        map.insert(
            IpNet::new(
                v6(0x2607, 0x5300, 0x6000, 0x6b00, 0, 0, 0xc05f, 0x0543),
                128,
            )
            .unwrap(),
            'd',
        )
        .unwrap();
        map.insert(
            IpNet::new(v6(0x2607, 0x5300, 0x6000, 0x6b00, 0, 0, 0, 0), 64).unwrap(),
            'c',
        )
        .unwrap();
        map.insert(IpNet::new(v6(0, 0, 0, 0, 0, 0, 0, 0), 0).unwrap(), 'e')
            .unwrap();
        map.insert(IpNet::new(v6(0, 0, 0, 0, 0, 0, 0, 0), 0).unwrap(), 'f')
            .unwrap();
        map.insert(
            IpNet::new(v6(0x2404, 0x6800, 0, 0, 0, 0, 0, 0), 32).unwrap(),
            'g',
        )
        .unwrap();
        map.insert(
            IpNet::new(
                v6(
                    0x2404, 0x6800, 0x4004, 0x0800, 0xdead, 0xbeef, 0xdead, 0xbeef,
                ),
                64,
            )
            .unwrap(),
            'h',
        )
        .unwrap();
        map.insert(
            IpNet::new(
                v6(
                    0x2404, 0x6800, 0x4004, 0x0800, 0xdead, 0xbeef, 0xdead, 0xbeef,
                ),
                128,
            )
            .unwrap(),
            'a',
        )
        .unwrap();
        map.insert(
            IpNet::new(
                v6(
                    0x2444, 0x6800, 0x40e4, 0x0800, 0xdeae, 0xbeef, 0x0def, 0xbeef,
                ),
                128,
            )
            .unwrap(),
            'c',
        )
        .unwrap();
        map.insert(
            IpNet::new(v6(0x2444, 0x6800, 0xf0e4, 0x0800, 0xeeae, 0xbeef, 0, 0), 98).unwrap(),
            'b',
        )
        .unwrap();

        assert_eq!(
            Some(&'d'),
            map.find(v6(0x2607, 0x5300, 0x6000, 0x6b00, 0, 0, 0xc05f, 0x0543))
        );
        assert_eq!(
            Some(&'c'),
            map.find(v6(0x2607, 0x5300, 0x6000, 0x6b00, 0, 0, 0xc02e, 0x01ee))
        );
        assert_eq!(
            Some(&'f'),
            map.find(v6(0x2607, 0x5300, 0x6000, 0x6b01, 0, 0, 0, 0))
        );
        assert_eq!(
            Some(&'g'),
            map.find(v6(0x2404, 0x6800, 0x4004, 0x0806, 0, 0, 0, 0x1006))
        );
        assert_eq!(
            Some(&'g'),
            map.find(v6(0x2404, 0x6800, 0x4004, 0x0806, 0, 0x1234, 0, 0x5678))
        );
        assert_eq!(
            Some(&'f'),
            map.find(v6(0x2404, 0x67ff, 0x4004, 0x0806, 0, 0x1234, 0, 0x5678))
        );
        assert_eq!(
            Some(&'f'),
            map.find(v6(0x2404, 0x6801, 0x4004, 0x0806, 0, 0x1234, 0, 0x5678))
        );
        assert_eq!(
            Some(&'h'),
            map.find(v6(0x2404, 0x6800, 0x4004, 0x0800, 0, 0x1234, 0, 0x5678))
        );
        assert_eq!(
            Some(&'h'),
            map.find(v6(0x2404, 0x6800, 0x4004, 0x0800, 0, 0, 0, 0))
        );
        assert_eq!(
            Some(&'h'),
            map.find(v6(
                0x2404, 0x6800, 0x4004, 0x0800, 0x1010, 0x1010, 0x1010, 0x1010
            ))
        );
        assert_eq!(
            Some(&'a'),
            map.find(v6(
                0x2404, 0x6800, 0x4004, 0x0800, 0xdead, 0xbeef, 0xdead, 0xbeef
            ))
        );
    }

    #[cfg(feature = "allowed-ips-ipv4")]
    #[test]
    fn test_allowed_ips_iter_zero_leaf_bits() {
        let mut map: TestAllowedIps<char> = Default::default();
        map.insert(IpNet::new(v4(10, 111, 0, 1), 32).unwrap(), '1')
            .unwrap();
        map.insert(IpNet::new(v4(10, 111, 0, 2), 32).unwrap(), '2')
            .unwrap();
        map.insert(IpNet::new(v4(10, 111, 0, 3), 32).unwrap(), '3')
            .unwrap();

        #[cfg(feature = "alloc")]
        let items: alloc::vec::Vec<_> = map.iter().collect();
        #[cfg(not(feature = "alloc"))]
        let items: heapless::Vec<_, 64> = map.iter().collect();

        assert!(items.contains(&(&'1', IpNet::new(v4(10, 111, 0, 1), 32).unwrap())));
        assert!(items.contains(&(&'2', IpNet::new(v4(10, 111, 0, 2), 32).unwrap())));
        assert!(items.contains(&(&'3', IpNet::new(v4(10, 111, 0, 3), 32).unwrap())));
        assert_eq!(items.len(), 3);
    }

    #[cfg(all(not(feature = "alloc"), feature = "allowed-ips-ipv4"))]
    #[test]
    fn test_allowed_ips_try_from_iter_reports_full_v4() {
        let ips = [
            (IpNet::new(v4(10, 0, 0, 0), 8).unwrap(), 'a'),
            (IpNet::new(v4(192, 168, 0, 0), 16).unwrap(), 'b'),
        ];

        let result = AllowedIPs::<char, 1>::try_from_iter(ips.iter().map(|(ip, data)| (ip, *data)));

        assert_eq!(result.err(), Some(AllowedIPsError::Full));
    }

    #[cfg(all(not(feature = "alloc"), feature = "allowed-ips-ipv6"))]
    #[test]
    fn test_allowed_ips_try_from_iter_reports_full_v6() {
        let ips = [
            (
                IpNet::new(v6(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0), 48).unwrap(),
                'a',
            ),
            (
                IpNet::new(v6(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0), 48).unwrap(),
                'b',
            ),
        ];

        let result = AllowedIPs::<char, 1>::try_from_iter(ips.iter().map(|(ip, data)| (ip, *data)));

        assert_eq!(result.err(), Some(AllowedIPsError::Full));
    }

    #[cfg(feature = "allowed-ips-ipv4")]
    #[test]
    fn test_allowed_ips_remove_accepts_fn_mut() {
        let mut map = build_allowed_ips_v4();
        let mut removed = 0usize;

        map.remove(|c| {
            let should_remove = *c == '1' || *c == '2';
            if should_remove {
                removed += 1;
            }
            should_remove
        });

        assert_eq!(removed, 2);
        assert_eq!(map.find(v4(127, 0, 0, 1)), None);
        assert_eq!(map.find(v4(127, 0, 255, 255)), None);
    }

    #[cfg(feature = "allowed-ips-ipv4")]
    #[test]
    fn test_allowed_ips_overlaps_v4() {
        let mut map: TestAllowedIps<char> = Default::default();
        map.insert(IpNet::new(v4(10, 0, 0, 0), 24).unwrap(), 'a')
            .unwrap();
        map.insert(IpNet::new(v4(172, 16, 4, 8), 30).unwrap(), 'b')
            .unwrap();

        assert_eq!(
            map.overlaps(IpNet::new(v4(10, 0, 0, 0), 24).unwrap()),
            Ok(true)
        );
        assert_eq!(
            map.overlaps(IpNet::new(v4(10, 0, 0, 42), 32).unwrap()),
            Ok(true)
        );
        assert_eq!(
            map.overlaps(IpNet::new(v4(10, 0, 0, 0), 16).unwrap()),
            Ok(true)
        );
        assert_eq!(
            map.overlaps(IpNet::new(v4(172, 16, 4, 10), 32).unwrap()),
            Ok(true)
        );
        assert_eq!(
            map.overlaps(IpNet::new(v4(10, 0, 1, 0), 24).unwrap()),
            Ok(false)
        );
        assert_eq!(
            map.overlaps(IpNet::new(v4(172, 16, 4, 12), 30).unwrap()),
            Ok(false)
        );
    }

    #[cfg(feature = "allowed-ips-ipv6")]
    #[test]
    fn test_allowed_ips_overlaps_v6() {
        let mut map: TestAllowedIps<char> = Default::default();
        map.insert(
            IpNet::new(v6(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0), 48).unwrap(),
            'a',
        )
        .unwrap();

        assert_eq!(
            map.overlaps(IpNet::new(v6(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1), 128).unwrap()),
            Ok(true)
        );
        assert_eq!(
            map.overlaps(IpNet::new(v6(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32).unwrap()),
            Ok(true)
        );
        assert_eq!(
            map.overlaps(IpNet::new(v6(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0), 48).unwrap()),
            Ok(false)
        );
    }

    #[cfg(all(feature = "allowed-ips-ipv4", feature = "allowed-ips-ipv6"))]
    #[test]
    fn test_allowed_ips_overlaps_ignores_removed_entries_and_other_family() {
        let mut map: TestAllowedIps<char> = Default::default();
        map.insert(IpNet::new(v4(192, 168, 1, 0), 24).unwrap(), 'a')
            .unwrap();
        map.insert(
            IpNet::new(v6(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0), 48).unwrap(),
            'b',
        )
        .unwrap();

        map.remove(|c| *c == 'a');

        assert_eq!(
            map.overlaps(IpNet::new(v4(192, 168, 1, 42), 32).unwrap()),
            Ok(false)
        );
        assert_eq!(
            map.overlaps(IpNet::new(v4(32, 1, 13, 184), 32).unwrap()),
            Ok(false)
        );
        assert_eq!(
            map.overlaps(IpNet::new(v6(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1), 128).unwrap()),
            Ok(true)
        );
    }
}
