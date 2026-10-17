use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Ok;
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_misc::constants::beacon::SYNC_COMMITTEE_SIZE;
use ream_light_client::finality_update::LightClientFinalityUpdate;
use ream_network_spec::networks::beacon_network_spec;
use ream_storage::cache::BeaconCacheDB;

use crate::gossipsub::validate::result::ValidationResult;

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
    validate_finality_update(update, genesis_time, unix_time_ms(), cached_db).await
}

async fn validate_finality_update(
    update: &LightClientFinalityUpdate,
    genesis_time: u64,
    now_ms: u64,
    cached_db: &BeaconCacheDB,
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
    if let Some((prev_slot, prev_slot_supermajority)) =
        *cached_db.seen_forwarded_finality_update_slot.read().await
    {
        if new_slot < prev_slot {
            return Ok(ValidationResult::Ignore(
                "Finality update slot is less than the last forwarded update slot".into(),
            ));
        }

        if new_slot == prev_slot {
            if prev_slot_supermajority {
                return Ok(ValidationResult::Ignore(
                    "Finality update already gossiped".into(),
                ));
            } else if !has_supermajority {
                return Ok(ValidationResult::Ignore(
                    "Worse than previous update".into(),
                ));
            }
        }
    }

    // [IGNORE] The finality_update is received after the block at signature_slot was given enough
    // time to propagate through the network
    if !sync_message_due_has_passed(genesis_time, update.signature_slot, now_ms) {
        return Ok(ValidationResult::Ignore("Too early".to_string()));
    };

    *cached_db.seen_forwarded_finality_update_slot.write().await =
        Some((new_slot, has_supermajority));

    *cached_db
        .forwarded_light_client_finality_update
        .write()
        .await = Some(update.clone());

    Ok(ValidationResult::Accept)
}

#[cfg(test)]
mod tests {
    use ream_network_spec::networks::initialize_test_network_spec;

    use super::sync_message_due_has_passed;

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
