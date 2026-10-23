use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use ream_bls::traits::Verifiable;
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_misc::{
    constants::beacon::DOMAIN_SYNC_COMMITTEE,
    misc::{compute_epoch_at_slot, compute_signing_root},
};
use ream_network_spec::networks::beacon_network_spec;
use ream_storage::cache::{BeaconCacheDB, SyncCommitteeKey, insert_if_unseen};
use ream_validator_beacon::sync_committee::{
    SyncCommitteeMessage, compute_subnets_for_sync_committee_at_slot,
};

use super::result::ValidationResult;

/// Whether `slot` is the wall-clock slot at `now_ms`, allowing MAXIMUM_GOSSIP_CLOCK_DISPARITY on
/// both ends. Uses the wall clock: the store's slot can lag while it is busy importing a block.
pub fn is_current_slot(genesis_time: u64, slot: u64, now_ms: u64) -> bool {
    let spec = beacon_network_spec();
    let start_ms = genesis_time
        .saturating_mul(1000)
        .saturating_add(slot.saturating_mul(spec.slot_duration_ms));
    let end_ms = start_ms.saturating_add(spec.slot_duration_ms);
    now_ms.saturating_add(spec.maximum_gossip_clock_disparity) >= start_ms
        && now_ms < end_ms.saturating_add(spec.maximum_gossip_clock_disparity)
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub async fn validate_sync_committee(
    message: &SyncCommitteeMessage,
    beacon_chain: &BeaconChain,
    subnet_id: u64,
    cached_db: &BeaconCacheDB,
) -> anyhow::Result<ValidationResult> {
    // A cheap read of the published head; everything below runs off-lock on the owned snapshot.
    let head = beacon_chain.head()?;
    let state = head.state.as_ref();

    // [IGNORE] The message's slot is for the current slot (with a MAXIMUM_GOSSIP_CLOCK_DISPARITY
    // allowance)
    if !is_current_slot(state.genesis_time, message.slot, now_ms()) {
        return Ok(ValidationResult::Ignore(
            "Message is not from current slot".into(),
        ));
    }

    // [REJECT] The subnet_id is valid for the given validator. The committee is the one of the
    // message's slot, which the head can still be behind at a period boundary.
    let Ok(subnets) =
        compute_subnets_for_sync_committee_at_slot(state, message.slot, message.validator_index)
    else {
        return Ok(ValidationResult::Ignore(
            "The head state has no committee for the message slot".into(),
        ));
    };
    if !subnets.contains(&subnet_id) {
        return Ok(ValidationResult::Reject(
            "Validator not in correct sync subcommittee".into(),
        ));
    }

    // [IGNORE] There has been no other valid sync committee message for the declared slot for the
    // validator referenced by sync_committee_message.validator_index (this requires maintaining a
    // cache of size SYNC_COMMITTEE_SIZE // SYNC_COMMITTEE_SUBNET_COUNT for each subnet that can be
    // flushed after each slot). Note this validation is per topic so that for a given slot,
    // multiple messages could be forwarded with the same validator_index as long as the subnet_ids
    // are distinct.
    let key = SyncCommitteeKey {
        subnet_id,
        slot: message.slot,
        validator_index: message.validator_index,
    };
    if cached_db.seen_sync_messages.read().await.contains(&key) {
        return Ok(ValidationResult::Ignore(
            "Duplicate sync committee message".into(),
        ));
    }

    // [REJECT] The signature is valid for the message beacon_block_root for the validator
    // referenced by validator_index.
    let signing_root = compute_signing_root(
        message.beacon_block_root,
        state.get_domain(
            DOMAIN_SYNC_COMMITTEE,
            Some(compute_epoch_at_slot(message.slot)),
        ),
    );
    if !message.signature.verify(
        &state
            .validators
            .get(message.validator_index as usize)
            .ok_or_else(|| anyhow!("Validator not found"))?
            .public_key,
        signing_root.as_slice(),
    )? {
        return Ok(ValidationResult::Reject(
            "The signature is not valid for the message beacon_block_root for the validator".into(),
        ));
    }

    if !insert_if_unseen(&cached_db.seen_sync_messages, key).await {
        return Ok(ValidationResult::Ignore(
            "Duplicate sync committee message".to_string(),
        ));
    }

    Ok(ValidationResult::Accept)
}

#[cfg(test)]
mod tests {
    use ream_network_spec::networks::initialize_test_network_spec;

    use super::*;

    #[test]
    fn current_slot_allows_clock_disparity_on_both_ends() {
        initialize_test_network_spec();
        let spec = beacon_network_spec();
        let genesis_time = 1_000;
        let slot = 5;
        let start_ms = genesis_time * 1000 + slot * spec.slot_duration_ms;
        let end_ms = start_ms + spec.slot_duration_ms;
        let disparity = spec.maximum_gossip_clock_disparity;

        assert!(!is_current_slot(
            genesis_time,
            slot,
            start_ms - disparity - 1
        ));
        assert!(is_current_slot(genesis_time, slot, start_ms - disparity));
        assert!(is_current_slot(genesis_time, slot, end_ms + disparity - 1));
        assert!(!is_current_slot(genesis_time, slot, end_ms + disparity));
    }
}
