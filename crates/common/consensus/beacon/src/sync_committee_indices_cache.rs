use std::{
    fmt,
    sync::{Arc, Mutex},
};

use ream_bls::PublicKey;

use crate::cache_lock;

/// Committees kept: current and next.
const MAX_CACHED_COMMITTEES: usize = 2;

/// Registry indices of recent sync committees, keyed by aggregate public key and shared by a state
/// and its clones. Callers check each index against the registry before using it.
#[derive(Clone, Default)]
pub struct SyncCommitteeIndicesCache(Arc<Mutex<Vec<CommitteeIndices>>>);

/// A committee's aggregate public key and the registry indices of its members.
type CommitteeIndices = (PublicKey, Arc<Vec<usize>>);

impl SyncCommitteeIndicesCache {
    pub fn get(&self, aggregate_public_key: &PublicKey) -> Option<Arc<Vec<usize>>> {
        cache_lock::lock(&self.0)
            .iter()
            .find(|(key, _)| key == aggregate_public_key)
            .map(|(_, indices)| indices.clone())
    }

    pub fn insert(&self, aggregate_public_key: PublicKey, indices: Arc<Vec<usize>>) {
        let mut entries = cache_lock::lock(&self.0);
        entries.retain(|(key, _)| *key != aggregate_public_key);
        if entries.len() >= MAX_CACHED_COMMITTEES {
            entries.remove(0);
        }
        entries.push((aggregate_public_key, indices));
    }
}

/// The cache is derived data, so it never makes two states differ.
impl PartialEq for SyncCommitteeIndicesCache {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl fmt::Debug for SyncCommitteeIndicesCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let committees = self.0.lock().map(|entries| entries.len()).unwrap_or(0);
        formatter
            .debug_struct("SyncCommitteeIndicesCache")
            .field("committees", &committees)
            .finish()
    }
}
