use std::{
    fmt,
    sync::{Arc, Mutex},
};

use alloy_primitives::B256;
use ream_consensus_misc::validator::Validator;
use tree_hash::{TreeHash, mix_in_length};

use crate::{
    cache_lock,
    chunked_list::{CHUNK_SIZE, ChunkedList},
    electra::zkvm_types::ValidatorRegistryLimit,
    merkle_tree_cache::{MerkleTree, parallel_map},
};

/// Validator registry, shared chunk by chunk between a state and its copies.
type Registry = ChunkedList<Validator, ValidatorRegistryLimit>;

/// Merkle tree of the validator registry, shared by a state and its clones. Only validators that
/// differ from the last hashed registry are rehashed; chunks that are still the same allocation
/// are skipped without comparing.
#[derive(Clone, Default)]
pub struct ValidatorsRootCache(Arc<Mutex<Option<ValidatorsTree>>>);

impl ValidatorsRootCache {
    /// `hash_tree_root` of `validators` as an SSZ list with room for `2^limit_depth` entries.
    pub fn root(&self, validators: &Registry, limit_depth: usize) -> B256 {
        let mut tree = cache_lock::lock(&self.0);
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

/// Ascending indices below `len` where `validators` differs from `hashed`. Shared chunks are
/// skipped and the rest are compared in parallel.
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
    // zkVM guests have no threads.
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

        // Changing any field, including the key, must change the root.
        validators[3].effective_balance -= 1_000_000_000;
        validators[0].slashed = true;
        validators[8].withdrawal_credentials = B256::repeat_byte(0x02);
        validators[5].exit_epoch = 100;
        validators[2].public_key = validator(77).public_key;
        assert_eq!(
            cache.root(&validators, LIMIT_DEPTH),
            expected_root(&validators)
        );

        // Alternate between a shorter and a longer registry, as around an epoch boundary.
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
