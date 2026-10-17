use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_light_client::optimistic_update::LightClientOptimisticUpdate;
use ream_storage::cache::BeaconCacheDB;

use crate::gossipsub::validate::{
    light_client_finality_update::{sync_message_due_has_passed, unix_time_ms},
    result::ValidationResult,
};

pub async fn validate_light_client_optimistic_update(
    light_client_optimistic_update: &LightClientOptimisticUpdate,
    beacon_chain: &BeaconChain,
    cached_db: &BeaconCacheDB,
) -> anyhow::Result<ValidationResult> {
    let genesis_time = beacon_chain.head()?.state.genesis_time;
    validate_optimistic_update(
        light_client_optimistic_update,
        genesis_time,
        unix_time_ms(),
        cached_db,
    )
    .await
}

async fn validate_optimistic_update(
    light_client_optimistic_update: &LightClientOptimisticUpdate,
    genesis_time: u64,
    now_ms: u64,
    cached_db: &BeaconCacheDB,
) -> anyhow::Result<ValidationResult> {
    // [IGNORE] The optimistic_update is received after the block at signature_slot was given enough
    // time to propagate through the network
    if !sync_message_due_has_passed(
        genesis_time,
        light_client_optimistic_update.signature_slot,
        now_ms,
    ) {
        return Ok(ValidationResult::Ignore("Too early".to_string()));
    };

    let attested_header_slot = light_client_optimistic_update.attested_header.beacon.slot;
    let last_forwarded_slot = *cached_db.forwarded_optimistic_update_slot.read().await;

    // [IGNORE] The attested_header.beacon.slot is greater than that of all previously forwarded
    // optimistic_update(s)
    if last_forwarded_slot.is_some_and(|slot| slot >= attested_header_slot) {
        return Ok(ValidationResult::Ignore(
            "Optimistic update slot is older than previously forwarded update".to_string(),
        ));
    };

    let match_finality_update = if let Some(forwarded_lc_finality_update) = cached_db
        .forwarded_light_client_finality_update
        .read()
        .await
        .clone()
    {
        forwarded_lc_finality_update.attested_header
            == light_client_optimistic_update.attested_header
            && forwarded_lc_finality_update.sync_aggregate
                == light_client_optimistic_update.sync_aggregate
            && forwarded_lc_finality_update.signature_slot
                == light_client_optimistic_update.signature_slot
    } else {
        false
    };

    if !match_finality_update {
        return Ok(ValidationResult::Ignore(
            "Does not match finality update".to_string(),
        ));
    };

    Ok(ValidationResult::Accept)
}
