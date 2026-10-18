use std::collections::HashSet;

use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::{
    attester_slashing::AttesterSlashing, electra::beacon_state::BeaconState,
};
use ream_storage::cache::BeaconCacheDB;

use super::result::ValidationResult;

pub async fn validate_attester_slashing(
    attester_slashing: &AttesterSlashing,
    beacon_chain: &BeaconChain,
    cached_db: &BeaconCacheDB,
) -> anyhow::Result<ValidationResult> {
    // `process_attester_slashing` mutates the state, so work on an owned copy of the cached head
    // state; the store lock is not involved.
    let state = BeaconState::clone(&beacon_chain.head()?.state);
    validate_against_state(state, cached_db, attester_slashing).await
}

async fn validate_against_state(
    mut state: BeaconState,
    cached_db: &BeaconCacheDB,
    attester_slashing: &AttesterSlashing,
) -> anyhow::Result<ValidationResult> {
    let slashed_indices = attester_slashing
        .attestation_1
        .attesting_indices
        .iter()
        .cloned()
        .collect::<HashSet<_>>()
        .intersection(
            &attester_slashing
                .attestation_2
                .attesting_indices
                .iter()
                .cloned()
                .collect::<HashSet<_>>(),
        )
        .cloned()
        .collect::<HashSet<_>>();

    // [IGNORE] At least one index in the intersection of the attesting indices of each attestation
    // has not yet been seen in any prior attester_slashing
    if slashed_indices
        .difference(
            &cached_db
                .prior_seen_attester_slashing_indices
                .read()
                .await
                .iter()
                .map(|(key, _)| *key)
                .collect::<HashSet<_>>(),
        )
        .collect::<HashSet<_>>()
        .is_empty()
    {
        return Ok(ValidationResult::Ignore(
            "All indices have already been seen".to_string(),
        ));
    }

    // [REJECT] All of the conditions within process_attester_slashing pass validation.
    if let Err(err) = state.process_attester_slashing(attester_slashing) {
        return Ok(ValidationResult::Reject(format!(
            "process_attester_slashing fails validation: {err}"
        )));
    }

    // Copies validated concurrently all pass the check above, so it is repeated under the write
    // lock that records the indices, and only the first copy is accepted.
    let mut prior_seen = cached_db.prior_seen_attester_slashing_indices.write().await;
    if slashed_indices
        .iter()
        .all(|index| prior_seen.contains(index))
    {
        return Ok(ValidationResult::Ignore(
            "All indices have already been seen".to_string(),
        ));
    }
    for index in slashed_indices {
        prior_seen.put(index, ());
    }

    Ok(ValidationResult::Accept)
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use alloy_primitives::B256;
    use ream_bls::{PrivateKey, traits::Signable};
    use ream_consensus_misc::{
        attestation_data::AttestationData, checkpoint::Checkpoint,
        constants::beacon::DOMAIN_BEACON_ATTESTER, indexed_attestation::IndexedAttestation,
        misc::compute_signing_root,
    };
    use ssz::Decode;
    use ssz_types::VariableList;

    use super::*;

    /// A slashable validator of the Sepolia fixture state with a test key, and a double vote
    /// signed by it.
    fn double_vote() -> (BeaconState, AttesterSlashing) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../../testing/gossip-validation/tests/assets/sepolia/states/grandparent_state_9552074.ssz_snappy",
        );
        let bytes = snap::raw::Decoder::new()
            .decompress_vec(&std::fs::read(path).expect("fixture state is readable"))
            .expect("fixture state decompresses");
        let mut state = BeaconState::from_ssz_bytes(&bytes).expect("fixture state decodes");

        let epoch = state.get_current_epoch();
        let index = state
            .validators
            .iter()
            .position(|validator| validator.is_slashable_validator(epoch))
            .expect("fixture has a slashable validator");
        let key = PrivateKey {
            inner: B256::repeat_byte(1),
        };
        state.validators[index].public_key = key.public_key().expect("test key is a valid scalar");

        let attestation = |beacon_block_root| {
            let data = AttestationData {
                slot: state.slot,
                index: 0,
                beacon_block_root,
                source: Checkpoint::default(),
                target: Checkpoint {
                    epoch,
                    root: B256::ZERO,
                },
            };
            let domain = state.get_domain(DOMAIN_BEACON_ATTESTER, Some(epoch));
            IndexedAttestation {
                attesting_indices: VariableList::new(vec![index as u64]).expect("one index fits"),
                signature: key
                    .sign(compute_signing_root(&data, domain).as_slice())
                    .expect("test key signs"),
                data,
            }
        };
        let slashing = AttesterSlashing {
            attestation_1: attestation(B256::repeat_byte(1)),
            attestation_2: attestation(B256::repeat_byte(2)),
        };
        (state, slashing)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_copies_are_accepted_once() {
        let (state, slashing) = double_vote();
        let (state, slashing) = (Arc::new(state), Arc::new(slashing));
        let cached_db = Arc::new(BeaconCacheDB::new());

        let tasks = (0..8)
            .map(|_| {
                let (state, slashing, cached_db) =
                    (state.clone(), slashing.clone(), cached_db.clone());
                tokio::spawn(async move {
                    validate_against_state(BeaconState::clone(&state), &cached_db, &slashing)
                        .await
                        .expect("validation runs")
                })
            })
            .collect::<Vec<_>>();
        let mut accepted = 0;
        for task in tasks {
            match task.await.expect("validation task completes") {
                ValidationResult::Accept => accepted += 1,
                ValidationResult::Ignore(_) => {}
                result => panic!("unexpected result {result:?}"),
            }
        }
        assert_eq!(accepted, 1);
    }
}
