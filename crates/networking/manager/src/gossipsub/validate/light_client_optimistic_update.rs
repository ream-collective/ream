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
    // Updates are validated concurrently, so the forwarded slot is checked and recorded under one
    // write lock. Otherwise two copies could both pass, and an older update could be recorded last.
    let mut forwarded_slot = cached_db.forwarded_optimistic_update_slot.write().await;

    // [IGNORE] The attested_header.beacon.slot is greater than that of all previously forwarded
    // optimistic_update(s)
    if forwarded_slot.is_some_and(|slot| slot >= attested_header_slot) {
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

    *forwarded_slot = Some(attested_header_slot);
    Ok(ValidationResult::Accept)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ream_light_client::{
        finality_update::LightClientFinalityUpdate, header::LightClientHeader,
    };
    use ream_network_spec::networks::initialize_test_network_spec;

    use super::*;
    use crate::gossipsub::validate::light_client_finality_update::unix_time_ms;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_copies_are_accepted_once() {
        initialize_test_network_spec();
        let mut attested_header = LightClientHeader::default();
        attested_header.beacon.slot = 64;
        let cached_db = Arc::new(BeaconCacheDB::new());
        *cached_db
            .forwarded_light_client_finality_update
            .write()
            .await = Some(LightClientFinalityUpdate {
            attested_header: attested_header.clone(),
            finalized_header: LightClientHeader::default(),
            finality_branch: Default::default(),
            sync_aggregate: Default::default(),
            signature_slot: 0,
        });
        let update = Arc::new(LightClientOptimisticUpdate {
            attested_header,
            sync_aggregate: Default::default(),
            signature_slot: 0,
        });

        let tasks = (0..8)
            .map(|_| {
                let (cached_db, update) = (cached_db.clone(), update.clone());
                tokio::spawn(async move {
                    validate_optimistic_update(&update, 0, unix_time_ms(), &cached_db)
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
        assert_eq!(accepted, 1);
        assert_eq!(
            *cached_db.forwarded_optimistic_update_slot.read().await,
            Some(64)
        );
    }
}
