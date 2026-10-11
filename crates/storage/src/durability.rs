use std::{cell::Cell, sync::Arc};

use redb::{Database, Durability};
use tracing::warn;

thread_local! {
    /// How many `DeferredSync` guards are alive on this thread.
    static DEFERRING: Cell<usize> = const { Cell::new(0) };
}

/// The durability for a commit made now on this thread: `Durability::None` while a
/// `DeferredSync` guard lives, `Durability::Immediate` otherwise.
pub(crate) fn commit_durability() -> Durability {
    if DEFERRING.get() > 0 {
        Durability::None
    } else {
        Durability::Immediate
    }
}

/// While alive, commits made on this thread through the storage tables skip the disk sync; dropping
/// it makes them all durable with one synced commit.
///
/// Importing a block makes several small commits, each synced, and a sync costs several
/// milliseconds on macOS. redb applies commits in order, so a crash before the final sync loses
/// the deferred commits together and leaves the database as it was before them. Use it only around
/// code that does not await: the guard is per thread.
pub struct DeferredSync {
    db: Arc<Database>,
}

impl DeferredSync {
    pub(crate) fn new(db: Arc<Database>) -> Self {
        DEFERRING.set(DEFERRING.get() + 1);
        Self { db }
    }
}

impl Drop for DeferredSync {
    fn drop(&mut self) {
        let remaining = DEFERRING.get() - 1;
        DEFERRING.set(remaining);
        if remaining > 0 {
            return;
        }
        let synced = self.db.begin_write().map(|mut write_txn| {
            write_txn
                .set_durability(Durability::Immediate)
                .expect("no table is open in this transaction");
            write_txn.commit()
        });
        match synced {
            Ok(Ok(())) => {}
            Ok(Err(err)) => warn!("Failed to sync deferred commits: {err:?}"),
            Err(err) => warn!("Failed to sync deferred commits: {err:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use tempdir::TempDir;

    use super::*;
    use crate::{
        db::ReamDB,
        tables::{field::REDBField, table::REDBTable},
    };

    #[test]
    fn deferred_commits_sync_when_the_last_guard_drops() {
        let dir = TempDir::new("ream_deferred_sync").unwrap();
        {
            let db = ReamDB::new(dir.path().to_path_buf())
                .unwrap()
                .init_beacon_db()
                .unwrap();
            let outer = db.defer_sync();
            let inner = db.defer_sync();
            assert!(matches!(commit_durability(), Durability::None));
            db.time_provider().insert(42).unwrap();
            db.block_timeliness_provider()
                .insert(Default::default(), true)
                .unwrap();
            drop(inner);
            // Still deferred: the outer guard is alive.
            assert!(matches!(commit_durability(), Durability::None));
            drop(outer);
            assert!(matches!(commit_durability(), Durability::Immediate));
        }

        // The commits made while deferred were synced and survive reopening the database.
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        assert_eq!(db.time_provider().get().unwrap(), 42);
        assert_eq!(
            db.block_timeliness_provider()
                .get(Default::default())
                .unwrap(),
            Some(true)
        );
    }
}
