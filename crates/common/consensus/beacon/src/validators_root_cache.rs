use std::{
    fmt,
    sync::{Arc, Mutex},
};

use alloy_primitives::B256;
use ream_consensus_misc::validator::Validator;
use tree_hash::{TreeHash, mix_in_length};

use crate::{
    chunked_list::{CHUNK_SIZE, ChunkedList},
    electra::zkvm_types::ValidatorRegistryLimit,
    merkle_tree_cache::{MerkleTree, parallel_map},
};

/// A state's validator registry, shared chunk by chunk between the state and its copies.
type Registry = ChunkedList<Validator, ValidatorRegistryLimit>;

/// Merkle tree of the validator registry, kept between state root computations and shared by a
/// state and its clones.
///
/// Hashing the registry from scratch takes 8 hashes per validator, about 3.2 s for mainnet's
/// 2.4 million validators, while a block changes only a few of them. The cache keeps the registry
/// it hashed last time, sharing its chunks. A chunk that is still the same allocation is
/// unchanged, because changing a chunk that the cache shares copies it first. The validators of
/// other chunks are compared with the ones hashed last time, and only the changed ones and the
/// path above them are rehashed. Comparing values, rather than tracking writes, keeps the root
/// correct for whichever state the cache is used with.
#[derive(Clone, Default)]
pub struct ValidatorsRootCache(Arc<Mutex<Option<ValidatorsTree>>>);

impl ValidatorsRootCache {
    /// `hash_tree_root` of `validators` as an SSZ list with room for `2^limit_depth` entries.
    pub fn root(&self, validators: &Registry, limit_depth: usize) -> B256 {
        let mut tree = self
            .0
            .lock()
            .expect("validators root cache lock is not poisoned");
        match tree.as_mut() {
            Some(tree) => tree.update(validators),
            None => *tree = Some(ValidatorsTree::build(validators)),
        }
        tree.as_ref()
            .expect("the tree was built above")
            .root(limit_depth)
    }
}

/// The cache is derived data, so it never makes two states differ.
impl PartialEq for ValidatorsRootCache {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl fmt::Debug for ValidatorsRootCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let validators = self
            .0
            .lock()
            .ok()
            .and_then(|tree| tree.as_ref().map(|tree| tree.hashed.len()))
            .unwrap_or(0);
        formatter
            .debug_struct("ValidatorsRootCache")
            .field("validators", &validators)
            .finish()
    }
}

/// Indices below `len`, in ascending order, where `validators` differs from `hashed`. Chunks the
/// two registries share are skipped, and the others are compared on as many threads as there are:
/// after epoch processing every chunk differs, about 2.4 million validators on mainnet.
fn changed_indices(hashed: &Registry, validators: &Registry, len: usize) -> Vec<usize> {
    let differing_chunks: Vec<usize> = (0..len.div_ceil(CHUNK_SIZE))
        .filter(|&chunk| !Arc::ptr_eq(&hashed.chunks()[chunk], &validators.chunks()[chunk]))
        .collect();
    let compare =
        |chunks: &[usize]| {
            let mut changed = Vec::new();
            for &chunk in chunks {
                let start = chunk * CHUNK_SIZE;
                let end = (start + CHUNK_SIZE).min(len);
                let hashed_chunk = &hashed.chunks()[chunk];
                let chunk_validators = &validators.chunks()[chunk];
                changed.extend((start..end).filter(|&index| {
                    hashed_chunk[index - start] != chunk_validators[index - start]
                }));
            }
            changed
        };
    // zkVM guests have no threads to spread the work over.
    let threads = std::thread::available_parallelism().map_or(1, |threads| threads.get());
    if cfg!(target_os = "zkvm") || differing_chunks.len() < threads * 4 {
        return compare(&differing_chunks);
    }
    let per_thread = differing_chunks.len().div_ceil(threads);
    std::thread::scope(|scope| {
        let workers: Vec<_> = differing_chunks
            .chunks(per_thread)
            .map(|chunks| scope.spawn(move || compare(chunks)))
            .collect();
        workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("comparison worker does not panic"))
            .collect()
    })
}

/// The registry hashed last time, and the tree over its validators' roots.
struct ValidatorsTree {
    hashed: Registry,
    tree: MerkleTree,
}

impl ValidatorsTree {
    fn build(validators: &Registry) -> Self {
        Self {
            hashed: validators.clone(),
            tree: MerkleTree::new(
                // Each chunk is 1,024 validators of about 8 hashes each.
                parallel_map(validators.chunks(), 16, |chunk| {
                    chunk
                        .iter()
                        .map(|validator| validator.tree_hash_root())
                        .collect::<Vec<_>>()
                })
                .into_iter()
                .flatten()
                .collect(),
            ),
        }
    }

    fn update(&mut self, validators: &Registry) {
        // A state from before an epoch's deposits has a shorter registry than the one hashed last.
        let common = self.hashed.len().min(validators.len());
        let last = self.tree.truncate(validators.len());
        let mut dirty = changed_indices(&self.hashed, validators, common);
        dirty.extend(last);
        dirty.sort_unstable();
        dirty.dedup();
        dirty.extend(common..validators.len());
        for &index in &dirty {
            self.tree
                .set_leaf(index, validators[index].tree_hash_root());
        }
        self.tree.rehash(dirty);
        self.hashed = validators.clone();
    }

    fn root(&self, limit_depth: usize) -> B256 {
        mix_in_length(&self.tree.root(limit_depth), self.hashed.len())
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::FixedBytes;
    use ream_bls::PublicKey;

    use super::*;

    fn validator(seed: u8) -> Validator {
        Validator {
            public_key: PublicKey {
                inner: FixedBytes::repeat_byte(seed),
            },
            withdrawal_credentials: B256::repeat_byte(seed),
            effective_balance: 32_000_000_000 + seed as u64,
            slashed: false,
            activation_eligibility_epoch: seed as u64,
            activation_epoch: seed as u64 + 1,
            exit_epoch: u64::MAX,
            withdrawable_epoch: u64::MAX,
        }
    }

    const LIMIT_DEPTH: usize = 40;

    fn expected_root(validators: &Registry) -> B256 {
        validators.tree_hash_root()
    }

    #[test]
    fn matches_ssz_list_root_through_changes_and_growth() {
        let cache = ValidatorsRootCache::default();
        let mut validators = Registry::default();
        assert_eq!(
            cache.root(&validators, LIMIT_DEPTH),
            expected_root(&validators)
        );

        for seed in 0..5 {
            validators.push(validator(seed)).unwrap();
            assert_eq!(
                cache.root(&validators, LIMIT_DEPTH),
                expected_root(&validators)
            );
        }
        // Crossing a power of two adds a level.
        for seed in 5..9 {
            validators.push(validator(seed)).unwrap();
        }
        assert_eq!(
            cache.root(&validators, LIMIT_DEPTH),
            expected_root(&validators)
        );

        // Each mutable field, including a key change at an existing index. The cache shares the
        // registry's chunks, so changing one copies it first and the root follows the copy.
        validators[3].effective_balance -= 1_000_000_000;
        validators[0].slashed = true;
        validators[8].withdrawal_credentials = B256::repeat_byte(0x02);
        validators[5].exit_epoch = 100;
        validators[2].public_key = validator(77).public_key;
        assert_eq!(
            cache.root(&validators, LIMIT_DEPTH),
            expected_root(&validators)
        );

        // A state from before validators were added has a shorter registry. Alternating between
        // the two, as fork choice does around an epoch boundary, gives each its own root.
        let shorter = Registry::new(validators.to_vec()[..3].to_vec()).unwrap();
        for _ in 0..2 {
            assert_eq!(cache.root(&shorter, LIMIT_DEPTH), expected_root(&shorter));
            assert_eq!(
                cache.root(&validators, LIMIT_DEPTH),
                expected_root(&validators)
            );
        }
        let empty = Registry::default();
        assert_eq!(cache.root(&empty, LIMIT_DEPTH), expected_root(&empty));
        assert_eq!(
            cache.root(&validators, LIMIT_DEPTH),
            expected_root(&validators)
        );
    }
}
