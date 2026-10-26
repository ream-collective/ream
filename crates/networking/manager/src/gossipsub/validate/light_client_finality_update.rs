use std::{
    future::Future,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Ok;
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_misc::constants::beacon::SYNC_COMMITTEE_SIZE;
use ream_light_client::finality_update::LightClientFinalityUpdate;
use ream_network_spec::networks::beacon_network_spec;
use ream_storage::cache::BeaconCacheDB;

use crate::gossipsub::validate::{
    light_client_local::local_finality_update_blocking, result::ValidationResult,
};

const BASIS_POINTS: u64 = 10_000;

/// Whether the sync message due time of `signature_slot`, `get_sync_message_due_ms()` after the
/// slot starts, has passed at `now_ms` with a `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance. Light
/// client updates are only forwarded after it, once the block at `signature_slot` had time to
/// propagate.
pub(crate) fn sync_message_due_has_passed(
    genesis_time: u64,
    signature_slot: u64,
    now_ms: u64,
) -> bool {
    let spec = beacon_network_spec();
    let due_ms = genesis_time
        .saturating_mul(1000)
        .saturating_add(signature_slot.saturating_mul(spec.slot_duration_ms))
        .saturating_add(spec.sync_message_due_bps * spec.slot_duration_ms / BASIS_POINTS);
    now_ms.saturating_add(spec.maximum_gossip_clock_disparity) >= due_ms
}

pub(crate) fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Error getting current time")
        .as_millis() as u64
}

pub async fn validate_light_client_finality_update(
    update: &LightClientFinalityUpdate,
    beacon_chain: &BeaconChain,
    cached_db: &BeaconCacheDB,
) -> anyhow::Result<ValidationResult> {
    let genesis_time = beacon_chain.head()?.state.genesis_time;
    let local = local_finality_update_blocking(beacon_chain.db().clone(), update.signature_slot);
    validate_finality_update(update, genesis_time, unix_time_ms(), cached_db, local).await
}

/// Why an update for `new_slot` is not newer than the last forwarded one, if it is not.
fn older_than_forwarded(
    forwarded: Option<(u64, bool)>,
    new_slot: u64,
    has_supermajority: bool,
) -> Option<&'static str> {
    let (prev_slot, prev_slot_supermajority) = forwarded?;
    if new_slot < prev_slot {
        return Some("Finality update slot is less than the last forwarded update slot");
    }
    if new_slot == prev_slot {
        if prev_slot_supermajority {
            return Some("Finality update already gossiped");
        }
        if !has_supermajority {
            return Some("Worse than previous update");
        }
    }
    None
}

/// `local` is the update this node computes for the update's signature slot. It is only awaited
/// for an update that would otherwise be forwarded, because computing it can load a state.
async fn validate_finality_update(
    update: &LightClientFinalityUpdate,
    genesis_time: u64,
    now_ms: u64,
    cached_db: &BeaconCacheDB,
    local: impl Future<Output = anyhow::Result<Option<LightClientFinalityUpdate>>>,
) -> anyhow::Result<ValidationResult> {
    // [IGNORE] The finalized header is greater than that of all previously forwarded finality
    // updates or it matches the highest previously forwarded slot and also has a supermajority
    // participation while previously forwarded slot did not indicate supermajority
    let new_slot = update.finalized_header.beacon.slot;
    let participation_count = update
        .sync_aggregate
        .sync_committee_bits
        .iter()
        .filter(|b| *b)
        .count() as u64;

    let has_supermajority = participation_count * 3 > SYNC_COMMITTEE_SIZE * 2;

    // [IGNORE] The finality_update is received after the block at signature_slot was given enough
    // time to propagate through the network
    if !sync_message_due_has_passed(genesis_time, update.signature_slot, now_ms) {
        return Ok(ValidationResult::Ignore("Too early".to_string()));
    };

    let forwarded = *cached_db.seen_forwarded_finality_update_slot.read().await;
    if let Some(reason) = older_than_forwarded(forwarded, new_slot, has_supermajority) {
        return Ok(ValidationResult::Ignore(reason.into()));
    }

    // [IGNORE] The received finality_update matches the locally computed one exactly
    match local.await? {
        Some(local) if local == *update => {}
        Some(_) => {
            return Ok(ValidationResult::Ignore(
                "Finality update does not match the locally computed one".into(),
            ));
        }
        None => {
            return Ok(ValidationResult::Ignore(
                "No local block at the finality update's signature slot".into(),
            ));
        }
    }

    // Updates are validated concurrently, so the forwarded slot is checked again and recorded
    // under one write lock. Otherwise two updates could both pass, and the older could be
    // recorded last.
    let mut forwarded_slot = cached_db.seen_forwarded_finality_update_slot.write().await;
    if let Some(reason) = older_than_forwarded(*forwarded_slot, new_slot, has_supermajority) {
        return Ok(ValidationResult::Ignore(reason.into()));
    }

    *forwarded_slot = Some((new_slot, has_supermajority));
    // Still under the slot lock, so the stored update is the one the slot belongs to.
    *cached_db
        .forwarded_light_client_finality_update
        .write()
        .await = Some(update.clone());

    Ok(ValidationResult::Accept)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ream_light_client::header::LightClientHeader;
    use ream_network_spec::networks::initialize_test_network_spec;

    use super::*;

    fn finality_update(finalized_slot: u64) -> LightClientFinalityUpdate {
        let mut finalized_header = LightClientHeader::default();
        finalized_header.beacon.slot = finalized_slot;
        LightClientFinalityUpdate {
            attested_header: LightClientHeader::default(),
            finalized_header,
            finality_branch: Default::default(),
            sync_aggregate: Default::default(),
            signature_slot: 0,
        }
    }

    /// Validates `updates` at once and returns how many were accepted.
    async fn accepted_concurrently(
        cached_db: &Arc<BeaconCacheDB>,
        updates: Vec<LightClientFinalityUpdate>,
    ) -> usize {
        let tasks = updates
            .into_iter()
            .map(|update| {
                let cached_db = cached_db.clone();
                tokio::spawn(async move {
                    let local = update.clone();
                    validate_finality_update(&update, 0, unix_time_ms(), &cached_db, async {
                        Ok(Some(local))
                    })
                    .await
                    .expect("validation runs")
                })
            })
            .collect::<Vec<_>>();
        let mut accepted = 0;
        for task in tasks {
            if let ValidationResult::Accept = task.await.expect("validation task completes") {
                accepted += 1;
            }
        }
        accepted
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_copies_are_accepted_once() {
        initialize_test_network_spec();
        let cached_db = Arc::new(BeaconCacheDB::new());
        let accepted = accepted_concurrently(&cached_db, vec![finality_update(64); 8]).await;
        assert_eq!(accepted, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_older_update_is_never_recorded_over_a_newer_one() {
        initialize_test_network_spec();
        for _ in 0..32 {
            let cached_db = Arc::new(BeaconCacheDB::new());
            accepted_concurrently(&cached_db, (1..=8).map(finality_update).collect()).await;
            let recorded_slot = *cached_db.seen_forwarded_finality_update_slot.read().await;
            let stored_slot = cached_db
                .forwarded_light_client_finality_update
                .read()
                .await
                .as_ref()
                .map(|update| update.finalized_header.beacon.slot);
            assert_eq!(recorded_slot.map(|(slot, _)| slot), Some(8));
            assert_eq!(stored_slot, Some(8));
        }
    }

    #[tokio::test]
    async fn an_update_that_differs_from_the_local_one_is_ignored() {
        initialize_test_network_spec();
        let cached_db = BeaconCacheDB::new();
        let mut local = finality_update(64);
        local.signature_slot = 1;
        let result =
            validate_finality_update(&finality_update(64), 0, unix_time_ms(), &cached_db, async {
                Ok(Some(local))
            })
            .await
            .expect("validation runs");

        assert!(matches!(result, ValidationResult::Ignore(_)));
        assert_eq!(
            *cached_db.seen_forwarded_finality_update_slot.read().await,
            None
        );
    }

    #[test]
    fn updates_wait_for_the_sync_message_due_time() {
        initialize_test_network_spec();
        // Slot 5 starts 60 s after genesis; its sync messages are due 3999 ms in, and gossip
        // allows 500 ms of clock disparity.
        let genesis_time = 1_000;
        let earliest_ms = 1_000_000 + 60_000 + 3_999 - 500;
        assert!(!sync_message_due_has_passed(
            genesis_time,
            5,
            earliest_ms - 1
        ));
        assert!(sync_message_due_has_passed(genesis_time, 5, earliest_ms));
    }
}
