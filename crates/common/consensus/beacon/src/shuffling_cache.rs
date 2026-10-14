use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, OnceLock, RwLock},
};

use alloy_primitives::B256;

use crate::cache_lock;

/// Most epochs kept. Block processing needs the previous, current and next epoch.
const MAX_CACHED_EPOCHS: usize = 8;

/// An epoch and the root of the block that decides its attester shuffling.
type ShufflingKey = (u64, B256);

/// One epoch's shuffling, filled by the first caller while later callers wait for it.
type ShufflingSlot = Arc<OnceLock<Arc<Vec<u64>>>>;

/// Shuffled active validator indices per epoch and deciding block, shared by a state and its
/// clones. States whose chains share the deciding block have the same shuffling, so sibling forks
/// never read each other's entries. Independently built states start empty.
#[derive(Clone, Default)]
pub struct ShufflingCache(Arc<RwLock<HashMap<ShufflingKey, ShufflingSlot>>>);

impl ShufflingCache {
    /// The shuffling of `epoch` decided by the block `decision_root`. Only one caller runs
    /// `compute`, outside the cache's lock; the others wait for its result. `compute` must not ask
    /// this cache for the same key.
    pub fn get_or_insert_with(
        &self,
        epoch: u64,
        decision_root: B256,
        compute: impl FnOnce() -> Vec<u64>,
    ) -> Arc<Vec<u64>> {
        self.slot((epoch, decision_root))
            .get_or_init(|| Arc::new(compute()))
            .clone()
    }

    /// Whether the shuffling of `epoch` decided by `decision_root` is cached or being computed.
    pub fn contains(&self, epoch: u64, decision_root: B256) -> bool {
        cache_lock::read(&self.0).contains_key(&(epoch, decision_root))
    }

    fn slot(&self, key: ShufflingKey) -> ShufflingSlot {
        if let Some(slot) = cache_lock::read(&self.0).get(&key) {
            return slot.clone();
        }
        let mut entries = cache_lock::write(&self.0);
        if !entries.contains_key(&key)
            && entries.len() >= MAX_CACHED_EPOCHS
            && let Some(oldest) = entries.keys().min_by_key(|(epoch, _)| *epoch).copied()
        {
            entries.remove(&oldest);
        }
        entries.entry(key).or_default().clone()
    }
}

impl fmt::Debug for ShufflingCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self.0.read().map(|entries| entries.len()).unwrap_or(0);
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
        // A different deciding block for the same epoch is a different shuffling.
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

    #[test]
    fn concurrent_callers_compute_a_shuffling_once() {
        let cache = ShufflingCache::default();
        let computed = std::sync::atomic::AtomicUsize::new(0);
        let seed = B256::repeat_byte(2);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    let shuffling = cache.get_or_insert_with(3, seed, || {
                        computed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(20));
                        vec![4, 2]
                    });
                    assert_eq!(*shuffling, [4, 2]);
                });
            }
        });
        assert_eq!(computed.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(cache.contains(3, seed));
    }
}
