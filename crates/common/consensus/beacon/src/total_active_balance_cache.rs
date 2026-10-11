use std::{fmt, sync::Mutex};

/// The total active balance of one epoch, remembered by one state.
///
/// Computing it scans the whole validator registry, and block processing asks for it for every
/// attestation and the sync aggregate. Within an epoch it only changes when epoch processing
/// updates effective balances, which clears it: activations, exits and new deposits all take
/// effect in later epochs. A clone copies the value but not the cell, so a later change to one
/// state never reaches the other.
#[derive(Default)]
pub struct TotalActiveBalanceCache(Mutex<Option<(u64, u64)>>);

impl TotalActiveBalanceCache {
    pub fn get_or_insert_with(&self, epoch: u64, compute: impl FnOnce() -> u64) -> u64 {
        let mut cached = self
            .0
            .lock()
            .expect("total active balance cache lock is not poisoned");
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
        *self
            .0
            .lock()
            .expect("total active balance cache lock is not poisoned") = None;
    }

    fn value(&self) -> Option<(u64, u64)> {
        *self
            .0
            .lock()
            .expect("total active balance cache lock is not poisoned")
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
