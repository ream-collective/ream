use std::{fmt, sync::Mutex};

use crate::cache_lock;

/// Total active balance of one epoch. It only changes when epoch processing updates effective
/// balances, which clears it. A clone copies the value, not the cell, so states never affect each
/// other.
#[derive(Default)]
pub struct TotalActiveBalanceCache(Mutex<Option<(u64, u64)>>);

impl TotalActiveBalanceCache {
    pub fn get_or_insert_with(&self, epoch: u64, compute: impl FnOnce() -> u64) -> u64 {
        let mut cached = cache_lock::lock(&self.0);
        match *cached {
            Some((cached_epoch, balance)) if cached_epoch == epoch => balance,
            _ => {
                let balance = compute();
                *cached = Some((epoch, balance));
                balance
            }
        }
    }

    pub fn clear(&self) {
        *cache_lock::lock(&self.0) = None;
    }

    fn value(&self) -> Option<(u64, u64)> {
        *cache_lock::lock(&self.0)
    }
}

impl Clone for TotalActiveBalanceCache {
    fn clone(&self) -> Self {
        Self(Mutex::new(self.value()))
    }
}

impl fmt::Debug for TotalActiveBalanceCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TotalActiveBalanceCache")
            .field(&self.value())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_once_per_epoch_and_clones_stay_independent() {
        let cache = TotalActiveBalanceCache::default();
        assert_eq!(cache.get_or_insert_with(3, || 100), 100);
        assert_eq!(cache.get_or_insert_with(3, || unreachable!()), 100);
        // A new epoch computes again.
        assert_eq!(cache.get_or_insert_with(4, || 200), 200);

        let clone = cache.clone();
        cache.clear();
        // Clearing one state's cache leaves the clone's value alone.
        assert_eq!(clone.get_or_insert_with(4, || unreachable!()), 200);
        assert_eq!(cache.get_or_insert_with(4, || 250), 250);
    }
}
