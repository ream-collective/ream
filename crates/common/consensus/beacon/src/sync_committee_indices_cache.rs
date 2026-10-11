use std::{
    fmt,
    sync::{Arc, Mutex},
};

use ream_bls::PublicKey;

/// Most committees kept: the current and the next one.
const MAX_CACHED_COMMITTEES: usize = 2;

/// Validator indices of recent sync committees, keyed by the committee's aggregate public key and
/// shared by a state and its clones.
///
/// Finding the indices maps the whole registry's public keys, about 2.4 million on mainnet, and
/// block processing needs them for every sync aggregate while a committee lasts a whole period.
/// The caller checks each cached index against the registry before using it, so an entry is never
/// wrong for the state it is used with.
#[derive(Clone, Default)]
pub struct SyncCommitteeIndicesCache(Arc<Mutex<Vec<CommitteeIndices>>>);

/// A committee's aggregate public key and the registry indices of its members.
type CommitteeIndices = (PublicKey, Arc<Vec<usize>>);

impl SyncCommitteeIndicesCache {
    pub fn get(&self, aggregate_public_key: &PublicKey) -> Option<Arc<Vec<usize>>> {
        self.0
            .lock()
            .expect("sync committee indices cache lock is not poisoned")
            .iter()
            .find(|(key, _)| key == aggregate_public_key)
            .map(|(_, indices)| indices.clone())
    }

    pub fn insert(&self, aggregate_public_key: PublicKey, indices: Arc<Vec<usize>>) {
        let mut entries = self
            .0
            .lock()
            .expect("sync committee indices cache lock is not poisoned");
        entries.retain(|(key, _)| *key != aggregate_public_key);
        if entries.len() >= MAX_CACHED_COMMITTEES {
            entries.remove(0);
        }
        entries.push((aggregate_public_key, indices));
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
