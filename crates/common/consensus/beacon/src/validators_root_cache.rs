use std::{
    fmt,
    sync::{Arc, Mutex},
};

use alloy_primitives::B256;
use ream_consensus_misc::validator::Validator;
use tree_hash::{TreeHash, mix_in_length};

use crate::{cache_lock, merkle_tree_cache::MerkleTree};

/// Merkle tree of the validator registry, shared by a state and its clones. Only validators that
/// differ from the copy hashed last time are rehashed.
#[derive(Clone, Default)]
pub struct ValidatorsRootCache(Arc<Mutex<Option<ValidatorsTree>>>);

impl ValidatorsRootCache {
    /// `hash_tree_root` of `validators` as an SSZ list with room for `2^limit_depth` entries.
    pub fn root(&self, validators: &[Validator], limit_depth: usize) -> B256 {
        let mut tree = cache_lock::lock(&self.0);
        match tree.as_mut() {
            Some(tree) if tree.snapshots.len() <= validators.len() => tree.update(validators),
            _ => *tree = Some(ValidatorsTree::build(validators)),
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
            .and_then(|tree| tree.as_ref().map(|tree| tree.snapshots.len()))
            .unwrap_or(0);
        formatter
            .debug_struct("ValidatorsRootCache")
            .field("validators", &validators)
            .finish()
    }
}

/// Ascending indices where `validators` differs from `snapshots`, compared in parallel.
fn changed_indices(snapshots: &[Validator], validators: &[Validator]) -> Vec<usize> {
    // zkVM guests have no threads.
    if cfg!(target_os = "zkvm") {
        return (0..validators.len())
            .filter(|&index| validators[index] != snapshots[index])
            .collect();
    }
    let threads = std::thread::available_parallelism().map_or(1, |threads| threads.get());
    let chunk_size = validators.len().div_ceil(threads).max(1);
    std::thread::scope(|scope| {
        let workers: Vec<_> = validators
            .chunks(chunk_size)
            .zip(snapshots.chunks(chunk_size))
            .enumerate()
            .map(|(chunk, (validators, snapshots))| {
                scope.spawn(move || {
                    validators
                        .iter()
                        .zip(snapshots)
                        .enumerate()
                        .filter(|(_, (validator, snapshot))| validator != snapshot)
                        .map(|(offset, _)| chunk * chunk_size + offset)
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("comparison worker does not panic"))
            .collect()
    })
}

/// The validators hashed last time, and the tree over their roots.
struct ValidatorsTree {
    snapshots: Vec<Validator>,
    tree: MerkleTree,
}

impl ValidatorsTree {
    fn build(validators: &[Validator]) -> Self {
        Self {
            snapshots: validators.to_vec(),
            tree: MerkleTree::new(
                validators
                    .iter()
                    .map(|validator| validator.tree_hash_root())
                    .collect(),
            ),
        }
    }

    fn update(&mut self, validators: &[Validator]) {
        let known = self.snapshots.len();
        let mut dirty = changed_indices(&self.snapshots, &validators[..known]);
        dirty.extend(known..validators.len());
        for &index in &dirty {
            let validator = &validators[index];
            match self.snapshots.get_mut(index) {
                Some(cached) => cached.clone_from(validator),
                None => self.snapshots.push(validator.clone()),
            }
            self.tree.set_leaf(index, validator.tree_hash_root());
        }
        self.tree.rehash(dirty);
    }

    fn root(&self, limit_depth: usize) -> B256 {
        mix_in_length(&self.tree.root(limit_depth), self.snapshots.len())
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::FixedBytes;
    use ream_bls::PublicKey;
    use ssz_types::{VariableList, typenum::U1099511627776};

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

    fn expected_root(validators: &[Validator]) -> B256 {
        VariableList::<Validator, U1099511627776>::new(validators.to_vec())
            .unwrap()
            .tree_hash_root()
    }

    #[test]
    fn matches_ssz_list_root_through_changes_and_growth() {
        let cache = ValidatorsRootCache::default();
        let mut validators: Vec<Validator> = Vec::new();
        assert_eq!(cache.root(&validators, 40), expected_root(&validators));

        for seed in 0..5 {
            validators.push(validator(seed));
            assert_eq!(cache.root(&validators, 40), expected_root(&validators));
        }
        // Crossing a power of two adds a level.
        for seed in 5..9 {
            validators.push(validator(seed));
        }
        assert_eq!(cache.root(&validators, 40), expected_root(&validators));

        // Each mutable field, including a key change at an existing index.
        validators[3].effective_balance -= 1_000_000_000;
        validators[0].slashed = true;
        validators[8].withdrawal_credentials = B256::repeat_byte(0x02);
        validators[5].exit_epoch = 100;
        validators[2].public_key = validator(77).public_key;
        assert_eq!(cache.root(&validators, 40), expected_root(&validators));

        // A shorter registry, as an unrelated state sharing the cache would have, rebuilds.
        validators.truncate(3);
        assert_eq!(cache.root(&validators, 40), expected_root(&validators));
    }
}
