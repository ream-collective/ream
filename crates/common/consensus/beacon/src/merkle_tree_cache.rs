//! Merkle trees of large state lists. Each root rehashes only the leaves that differ from the
//! last hashed copy.

use std::{
    fmt,
    sync::{Arc, Mutex},
};

use alloy_primitives::B256;
use ethereum_hashing::{ZERO_HASHES, ZERO_HASHES_MAX_INDEX, hash32_concat};
use tree_hash::{TreeHash, mix_in_length};

use crate::{
    cache_lock, historical_summary::HistoricalSummary, parallel::parallel_map,
    pending_consolidation::PendingConsolidation, pending_deposit::PendingDeposit,
    pending_partial_withdrawal::PendingPartialWithdrawal, sync_committee::SyncCommittee,
};

/// Levels of a Merkle tree, leaves first. A missing right child is the zero subtree, as in SSZ.
pub(crate) struct MerkleTree {
    levels: Vec<Vec<B256>>,
}

impl MerkleTree {
    pub(crate) fn new(leaves: Vec<B256>) -> Self {
        let mut tree = Self {
            levels: vec![leaves],
        };
        tree.rebuild_upper_levels();
        tree
    }

    pub(crate) fn leaf_count(&self) -> usize {
        self.levels[0].len()
    }

    pub(crate) fn leaf(&self, index: usize) -> B256 {
        self.levels[0][index]
    }

    /// Writes `leaf` at `index`, or appends it when `index` is the leaf count.
    pub(crate) fn set_leaf(&mut self, index: usize, leaf: B256) {
        match self.levels[0].get_mut(index) {
            Some(current) => *current = leaf,
            None => self.levels[0].push(leaf),
        }
    }

    /// Drops the leaves from `len` on. Returns the index of the new last leaf, whose path to the
    /// root must be rehashed, or `None` when there is nothing to rehash.
    pub(crate) fn truncate(&mut self, len: usize) -> Option<usize> {
        if len >= self.levels[0].len() {
            return None;
        }
        self.levels[0].truncate(len);
        if len == 0 {
            self.rebuild_upper_levels();
        }
        len.checked_sub(1)
    }

    /// Rehashes the paths above the leaves at `dirty`, given in ascending order.
    pub(crate) fn rehash(&mut self, mut dirty: Vec<usize>) {
        if dirty.is_empty() {
            return;
        }
        if levels_needed(self.levels[0].len()) != self.levels.len() {
            self.rebuild_upper_levels();
            return;
        }
        for depth in 1..self.levels.len() {
            for index in dirty.iter_mut() {
                *index >>= 1;
            }
            dirty.dedup();
            let width = self.levels[depth - 1].len().div_ceil(2);
            self.levels[depth].resize(width, B256::ZERO);
            let below = &self.levels[depth - 1];
            let nodes = parallel_map(&dirty, PARALLEL_HASH_THRESHOLD, |&index| {
                parent(below, index, depth - 1)
            });
            for (&index, node) in dirty.iter().zip(nodes) {
                self.levels[depth][index] = node;
            }
        }
    }

    /// Root of the tree padded with zero leaves to `2^limit_depth` leaves.
    pub(crate) fn root(&self, limit_depth: usize) -> B256 {
        let used_depth = self.levels.len() - 1;
        let mut node = if self.levels[0].is_empty() {
            zero_hash(0)
        } else {
            self.levels[used_depth][0]
        };
        for depth in used_depth..limit_depth {
            node = B256::from(hash32_concat(node.as_slice(), zero_hash(depth).as_slice()));
        }
        node
    }

    fn rebuild_upper_levels(&mut self) {
        self.levels.truncate(1);
        for depth in 1..levels_needed(self.levels[0].len()) {
            let below = &self.levels[depth - 1];
            let indices: Vec<usize> = (0..below.len().div_ceil(2)).collect();
            let level = parallel_map(&indices, PARALLEL_HASH_THRESHOLD, |&index| {
                parent(below, index, depth - 1)
            });
            self.levels.push(level);
        }
    }
}

/// Levels needed for `leaf_count` leaves.
fn levels_needed(leaves: usize) -> usize {
    leaves.max(1).next_power_of_two().trailing_zeros() as usize + 1
}

fn parent(below: &[B256], index: usize, below_depth: usize) -> B256 {
    let left = below[2 * index];
    let right = below
        .get(2 * index + 1)
        .copied()
        .unwrap_or_else(|| zero_hash(below_depth));
    B256::from(hash32_concat(left.as_slice(), right.as_slice()))
}

/// Root of a subtree of `2^depth` zero chunks.
pub(crate) fn zero_hash(depth: usize) -> B256 {
    if depth <= ZERO_HASHES_MAX_INDEX {
        return B256::from(ZERO_HASHES[depth]);
    }
    let mut node = B256::from(ZERO_HASHES[ZERO_HASHES_MAX_INDEX]);
    for _ in ZERO_HASHES_MAX_INDEX..depth {
        node = B256::from(hash32_concat(node.as_slice(), node.as_slice()));
    }
    node
}

/// Below this many nodes, hashing stays on the calling thread.
pub(crate) const PARALLEL_HASH_THRESHOLD: usize = 16_384;

/// Root of an SSZ list or vector of basic values, shared by a state and its clones.
#[derive(Clone, Default)]
pub struct PackedListRootCache(Arc<Mutex<Option<MerkleTree>>>);

impl PackedListRootCache {
    /// Root of a `List[uint64, 2^(limit_depth + 2)]`.
    pub fn u64_list_root(&self, values: &[u64], limit_depth: usize) -> B256 {
        let chunk_count = values.len().div_ceil(4);
        mix_in_length(
            &self.chunks_root(chunk_count, |index| u64_chunk(values, index), limit_depth),
            values.len(),
        )
    }

    /// Root of a `Vector[uint64, N]`, `N` being `values.len()`.
    pub fn u64_vector_root(&self, values: &[u64]) -> B256 {
        let chunk_count = values.len().div_ceil(4);
        self.chunks_root(
            chunk_count,
            |index| u64_chunk(values, index),
            vector_depth(chunk_count),
        )
    }

    /// Root of a `Vector[Bytes32, N]`, `N` being `values.len()`.
    pub fn b256_vector_root(&self, values: &[B256]) -> B256 {
        self.chunks_root(
            values.len(),
            |index| values[index],
            vector_depth(values.len()),
        )
    }

    /// Root of a `List[uint8, 2^(limit_depth + 5)]`.
    pub fn u8_list_root(&self, values: &[u8], limit_depth: usize) -> B256 {
        let chunk_count = values.len().div_ceil(32);
        let chunk = |index: usize| {
            let mut bytes = [0u8; 32];
            let source = &values[index * 32..values.len().min(index * 32 + 32)];
            bytes[..source.len()].copy_from_slice(source);
            B256::from(bytes)
        };
        mix_in_length(
            &self.chunks_root(chunk_count, chunk, limit_depth),
            values.len(),
        )
    }

    fn chunks_root(
        &self,
        chunk_count: usize,
        chunk: impl Fn(usize) -> B256 + Sync,
        limit_depth: usize,
    ) -> B256 {
        let mut tree = cache_lock::lock(&self.0);
        match tree.as_mut() {
            Some(tree) => {
                let last = tree.truncate(chunk_count);
                // About 600,000 chunks for mainnet balances, so compare in parallel.
                let known = tree.leaf_count().min(chunk_count);
                let ranges: Vec<usize> = (0..known).step_by(PARALLEL_HASH_THRESHOLD).collect();
                let changed: Vec<(usize, B256)> = parallel_map(&ranges, 2, |&start| {
                    (start..(start + PARALLEL_HASH_THRESHOLD).min(known))
                        .filter_map(|index| {
                            let leaf = chunk(index);
                            (leaf != tree.leaf(index)).then_some((index, leaf))
                        })
                        .collect::<Vec<_>>()
                })
                .into_iter()
                .flatten()
                .collect();
                let mut dirty = Vec::with_capacity(changed.len() + chunk_count - known + 1);
                for (index, leaf) in changed {
                    tree.set_leaf(index, leaf);
                    dirty.push(index);
                }
                for index in known..chunk_count {
                    tree.set_leaf(index, chunk(index));
                    dirty.push(index);
                }
                dirty.extend(last);
                dirty.sort_unstable();
                dirty.dedup();
                tree.rehash(dirty);
            }
            None => *tree = Some(MerkleTree::new((0..chunk_count).map(chunk).collect())),
        }
        tree.as_ref()
            .expect("the tree was built above")
            .root(limit_depth)
    }
}

/// Leaf chunk `index` of packed `u64` values: four values, little-endian, zero-padded.
fn u64_chunk(values: &[u64], index: usize) -> B256 {
    let mut bytes = [0u8; 32];
    for (slot, value) in values[index * 4..values.len().min(index * 4 + 4)]
        .iter()
        .enumerate()
    {
        bytes[slot * 8..slot * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    B256::from(bytes)
}

/// Depth of the tree over a vector's `chunk_count` chunks, padded to a power of two.
fn vector_depth(chunk_count: usize) -> usize {
    chunk_count.max(1).next_power_of_two().trailing_zeros() as usize
}

/// Root of an SSZ list of containers, shared by a state and its clones. Only items that differ
/// from the cached copy are rehashed.
pub struct ContainerListRootCache<T>(Arc<Mutex<Option<ContainerListTree<T>>>>);

/// The items hashed last time, and the tree over their roots.
type ContainerListTree<T> = (Vec<T>, MerkleTree);

impl<T> Default for ContainerListRootCache<T> {
    fn default() -> Self {
        Self(Arc::default())
    }
}

impl<T> Clone for ContainerListRootCache<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Clone + PartialEq + TreeHash> ContainerListRootCache<T> {
    /// Root of a `List[T, 2^limit_depth]`.
    pub fn root(&self, items: &[T], limit_depth: usize) -> B256 {
        let mut cached = cache_lock::lock(&self.0);
        match cached.as_mut() {
            Some((copies, tree)) => {
                copies.truncate(items.len());
                let mut dirty: Vec<usize> = tree.truncate(items.len()).into_iter().collect();
                for (index, item) in items.iter().enumerate() {
                    match copies.get_mut(index) {
                        Some(copy) if copy == item => continue,
                        Some(copy) => *copy = item.clone(),
                        None => copies.push(item.clone()),
                    }
                    tree.set_leaf(index, item.tree_hash_root());
                    dirty.push(index);
                }
                dirty.sort_unstable();
                dirty.dedup();
                tree.rehash(dirty);
            }
            None => {
                *cached = Some((
                    items.to_vec(),
                    MerkleTree::new(items.iter().map(TreeHash::tree_hash_root).collect()),
                ))
            }
        }
        let (_, tree) = cached.as_ref().expect("the tree was built above");
        mix_in_length(&tree.root(limit_depth), items.len())
    }
}

/// Sync committee roots by allocation. A state replaces its committees rather than editing them,
/// so an allocation's root never changes.
#[derive(Clone, Default)]
pub struct SyncCommitteeRootCache(Arc<Mutex<Vec<CommitteeRoot>>>);

/// A sync committee and its root.
type CommitteeRoot = (Arc<SyncCommittee>, B256);

/// Committees kept: current and next, plus those of a state a period apart.
const MAX_CACHED_SYNC_COMMITTEES: usize = 4;

impl SyncCommitteeRootCache {
    pub fn root(&self, committee: &Arc<SyncCommittee>) -> B256 {
        let mut committees = cache_lock::lock(&self.0);
        if let Some((_, root)) = committees
            .iter()
            .find(|(cached, _)| Arc::ptr_eq(cached, committee))
        {
            return *root;
        }
        let root = committee.tree_hash_root();
        if committees.len() >= MAX_CACHED_SYNC_COMMITTEES {
            committees.remove(0);
        }
        committees.push((committee.clone(), root));
        root
    }
}

/// Root caches for the large state fields other than the validator registry.
#[derive(Clone, Default)]
pub struct StateFieldRootCaches {
    pub block_roots: PackedListRootCache,
    pub state_roots: PackedListRootCache,
    pub historical_roots: ContainerListRootCache<B256>,
    pub balances: PackedListRootCache,
    pub randao_mixes: PackedListRootCache,
    pub slashings: PackedListRootCache,
    pub previous_epoch_participation: PackedListRootCache,
    pub current_epoch_participation: PackedListRootCache,
    pub inactivity_scores: PackedListRootCache,
    pub sync_committees: SyncCommitteeRootCache,
    pub historical_summaries: ContainerListRootCache<HistoricalSummary>,
    pub pending_deposits: ContainerListRootCache<PendingDeposit>,
    pub pending_partial_withdrawals: ContainerListRootCache<PendingPartialWithdrawal>,
    pub pending_consolidations: ContainerListRootCache<PendingConsolidation>,
}

impl fmt::Debug for StateFieldRootCaches {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("StateFieldRootCaches").finish()
    }
}

#[cfg(test)]
mod tests {
    use ssz_types::{
        FixedVector, VariableList,
        typenum::{U16, U8192, U1099511627776},
    };

    use super::*;

    #[test]
    fn u64_list_root_matches_ssz_through_changes_and_growth() {
        let cache = PackedListRootCache::default();
        let mut values: Vec<u64> = Vec::new();
        let expected = |values: &Vec<u64>| {
            VariableList::<u64, U1099511627776>::new(values.clone())
                .unwrap()
                .tree_hash_root()
        };
        for length in [0, 1, 3, 4, 5, 9, 17, 40] {
            values.resize(length, 7);
            assert_eq!(cache.u64_list_root(&values, 38), expected(&values));
        }
        values[0] = 1;
        values[13] = 99;
        values[39] = u64::MAX;
        assert_eq!(cache.u64_list_root(&values, 38), expected(&values));
        // Shrinking and growing back, as states before and after an epoch's deposits alternate.
        let longer = values.clone();
        values.truncate(6);
        for _ in 0..2 {
            assert_eq!(cache.u64_list_root(&values, 38), expected(&values));
            assert_eq!(cache.u64_list_root(&longer, 38), expected(&longer));
        }
        assert_eq!(cache.u64_list_root(&[], 38), expected(&Vec::new()));
    }

    #[test]
    fn u8_list_root_matches_ssz_through_changes_and_growth() {
        let cache = PackedListRootCache::default();
        let mut values: Vec<u8> = Vec::new();
        let expected = |values: &Vec<u8>| {
            VariableList::<u8, U1099511627776>::new(values.clone())
                .unwrap()
                .tree_hash_root()
        };
        for length in [0, 1, 31, 32, 33, 100, 300] {
            values.resize(length, 3);
            assert_eq!(cache.u8_list_root(&values, 35), expected(&values));
        }
        values[0] = 7;
        values[250] = 1;
        assert_eq!(cache.u8_list_root(&values, 35), expected(&values));
    }

    #[test]
    fn vector_roots_match_ssz_through_changes() {
        let cache = PackedListRootCache::default();
        let mut roots = FixedVector::<B256, U8192>::from_elem(B256::ZERO);
        assert_eq!(cache.b256_vector_root(&roots), roots.tree_hash_root());
        roots[0] = B256::repeat_byte(1);
        roots[8191] = B256::repeat_byte(2);
        assert_eq!(cache.b256_vector_root(&roots), roots.tree_hash_root());

        let cache = PackedListRootCache::default();
        let mut values = FixedVector::<u64, U8192>::from_elem(0);
        assert_eq!(cache.u64_vector_root(&values), values.tree_hash_root());
        values[5] = 7;
        values[8190] = u64::MAX;
        assert_eq!(cache.u64_vector_root(&values), values.tree_hash_root());
    }

    #[test]
    fn container_list_root_matches_ssz_through_changes_and_growth() {
        let cache = ContainerListRootCache::<B256>::default();
        let mut items: Vec<B256> = Vec::new();
        let expected = |items: &Vec<B256>| {
            VariableList::<B256, U16>::new(items.clone())
                .unwrap()
                .tree_hash_root()
        };
        for seed in 0..9u8 {
            items.push(B256::repeat_byte(seed));
            assert_eq!(cache.root(&items, 4), expected(&items));
        }
        items[2] = B256::repeat_byte(0xaa);
        assert_eq!(cache.root(&items, 4), expected(&items));
        // Removing from the front shifts every item, as pending deposits do.
        let longer = items.clone();
        items.remove(0);
        for _ in 0..2 {
            assert_eq!(cache.root(&items, 4), expected(&items));
            assert_eq!(cache.root(&longer, 4), expected(&longer));
        }
    }
}
