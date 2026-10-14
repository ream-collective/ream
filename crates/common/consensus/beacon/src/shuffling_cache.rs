use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex, RwLock},
};

use alloy_primitives::B256;

use crate::cache_lock;

/// Most epochs kept. Block processing needs the previous, current and next epoch.
const MAX_CACHED_EPOCHS: usize = 8;

/// `(epoch, seed)` of one epoch's attester shuffling.
type ShufflingKey = (u64, B256);

/// Shuffled active validator indices per `(epoch, seed)`, shared by a state and its clones.
/// Entries stay valid for descendants, since an epoch's seed and active set are fixed epochs ahead.
/// Independently built states start empty, so they never share entries.
#[derive(Clone, Default)]
pub struct ShufflingCache(Arc<ShufflingCacheInner>);

#[derive(Default)]
struct ShufflingCacheInner {
    entries: RwLock<HashMap<ShufflingKey, Arc<Vec<u64>>>>,
    /// Shufflings being computed ahead on another thread.
    computing: Mutex<HashSet<ShufflingKey>>,
}

impl ShufflingCache {
    pub fn get_or_insert_with(
        &self,
        epoch: u64,
        seed: B256,
        compute: impl FnOnce() -> Vec<u64>,
    ) -> Arc<Vec<u64>> {
        if let Some(shuffling) = cache_lock::read(&self.0.entries).get(&(epoch, seed)) {
            return shuffling.clone();
        }

        let shuffling = Arc::new(compute());
        let mut entries = cache_lock::write(&self.0.entries);
        if entries.len() >= MAX_CACHED_EPOCHS
            && let Some(oldest) = entries.keys().min_by_key(|(epoch, _)| *epoch).copied()
        {
            entries.remove(&oldest);
        }
        entries.insert((epoch, seed), shuffling.clone());
        shuffling
    }

    /// Claims `(epoch, seed)` for computing ahead; false if it is cached or already claimed.
    pub fn start_computing(&self, epoch: u64, seed: B256) -> bool {
        let cached = cache_lock::read(&self.0.entries).contains_key(&(epoch, seed));
        !cached && cache_lock::lock(&self.0.computing).insert((epoch, seed))
    }

    pub fn finish_computing(&self, epoch: u64, seed: B256) {
        cache_lock::lock(&self.0.computing).remove(&(epoch, seed));
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
