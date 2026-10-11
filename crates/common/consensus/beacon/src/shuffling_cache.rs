use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex, RwLock},
};

use alloy_primitives::B256;

/// Most epochs kept. Block processing needs the previous, current and next epoch.
const MAX_CACHED_EPOCHS: usize = 8;

/// `(epoch, seed)` of one epoch's attester shuffling.
type ShufflingKey = (u64, B256);

/// Shuffled active validator indices per `(epoch, seed)`, shared by a state and its clones.
///
/// An entry stays valid for every descendant of the state that computed it: along one chain the
/// seed of an epoch is fixed at the end of `epoch - 2`, and its active set is fixed earlier still,
/// because activations and exits are scheduled at least `MAX_SEED_LOOKAHEAD + 1` epochs ahead.
/// States decoded or built independently start with an empty cache, so states that happen to
/// share a seed but not a validator set never share entries.
#[derive(Clone, Default)]
pub struct ShufflingCache(Arc<ShufflingCacheInner>);

#[derive(Default)]
struct ShufflingCacheInner {
    entries: RwLock<HashMap<ShufflingKey, Arc<Vec<u64>>>>,
    /// Shufflings being computed ahead on another thread; see `start_computing`.
    computing: Mutex<HashSet<ShufflingKey>>,
}

impl ShufflingCache {
    pub fn get_or_insert_with(
        &self,
        epoch: u64,
        seed: B256,
        compute: impl FnOnce() -> Vec<u64>,
    ) -> Arc<Vec<u64>> {
        if let Some(shuffling) = self
            .0
            .entries
            .read()
            .expect("shuffling cache lock is not poisoned")
            .get(&(epoch, seed))
        {
            return shuffling.clone();
        }

        let shuffling = Arc::new(compute());
        let mut entries = self
            .0
            .entries
            .write()
            .expect("shuffling cache lock is not poisoned");
        if entries.len() >= MAX_CACHED_EPOCHS
            && let Some(oldest) = entries.keys().min_by_key(|(epoch, _)| *epoch).copied()
        {
            entries.remove(&oldest);
        }
        entries.insert((epoch, seed), shuffling.clone());
        shuffling
    }

    /// Whether a shuffling for `(epoch, seed)` should be computed ahead: it is neither cached nor
    /// being computed. Returns true at most once per key until `finish_computing`.
    pub fn start_computing(&self, epoch: u64, seed: B256) -> bool {
        let cached = self
            .0
            .entries
            .read()
            .expect("shuffling cache lock is not poisoned")
            .contains_key(&(epoch, seed));
        !cached
            && self
                .0
                .computing
                .lock()
                .expect("shuffling cache lock is not poisoned")
                .insert((epoch, seed))
    }

    pub fn finish_computing(&self, epoch: u64, seed: B256) {
        self.0
            .computing
            .lock()
            .expect("shuffling cache lock is not poisoned")
            .remove(&(epoch, seed));
    }
}

/// The cache is derived data, so it never makes two states differ.
impl PartialEq for ShufflingCache {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl fmt::Debug for ShufflingCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self
            .0
            .entries
            .read()
            .map(|entries| entries.len())
            .unwrap_or(0);
        formatter
            .debug_struct("ShufflingCache")
            .field("entries", &entries)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_entries_and_old_epochs_are_evicted() {
        let cache = ShufflingCache::default();
        let clone = cache.clone();
        let seed = B256::repeat_byte(1);

        assert_eq!(
            *cache.get_or_insert_with(5, seed, || vec![3, 1, 2]),
            [3, 1, 2]
        );
        // A clone sees the entry and does not recompute it.
        assert_eq!(
            *clone.get_or_insert_with(5, seed, || unreachable!()),
            [3, 1, 2]
        );
        // A different seed for the same epoch is a different shuffling.
        assert_eq!(*cache.get_or_insert_with(5, B256::ZERO, || vec![9]), [9]);

        for epoch in 10..10 + MAX_CACHED_EPOCHS as u64 {
            cache.get_or_insert_with(epoch, seed, Vec::new);
        }
        let mut recomputed = false;
        cache.get_or_insert_with(5, seed, || {
            recomputed = true;
            vec![]
        });
        assert!(
            recomputed,
            "the oldest epoch is evicted once the cache is full"
        );
    }
}
