use anyhow::anyhow;
use ream_bls::{PublicKey, traits::Verifiable};
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::electra::beacon_state::BeaconState;
use ream_consensus_misc::{
    constants::beacon::{DOMAIN_SYNC_COMMITTEE, SYNC_COMMITTEE_SIZE},
    misc::{compute_epoch_at_slot, compute_signing_root, compute_sync_committee_period},
};
use ream_events_beacon::contribution_and_proof::SignedContributionAndProof;
use ream_storage::{
    cache::{
        BeaconCacheDB, CacheSyncCommitteeContribution, SyncCommitteeKey, is_non_strict_superset,
        record_aggregation_bits,
    },
    tables::field::REDBField,
};
use ream_validator_beacon::{
    constants::{
        DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
        SYNC_COMMITTEE_SUBNET_COUNT,
    },
    sync_committee::{SyncAggregatorSelectionData, is_sync_committee_aggregator},
};
use ssz_types::{BitVector, typenum::U128};

use super::{
    result::ValidationResult,
    sync_committee::{is_current_slot, now_ms},
};

pub async fn validate_sync_committee_contribution_and_proof(
    beacon_chain: &BeaconChain,
    cached_db: &BeaconCacheDB,
    signed_contribution_and_proof: &SignedContributionAndProof,
) -> anyhow::Result<ValidationResult> {
    // [IGNORE] The contribution's slot is for the current slot (with a
    // MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance)
    let slot = signed_contribution_and_proof.message.contribution.slot;
    let genesis_time = beacon_chain.db().genesis_time_provider().get()?;
    if !is_current_slot(genesis_time, slot, now_ms()) {
        return Ok(ValidationResult::Ignore(
            "Contribution is not from the current slot".to_string(),
        ));
    }

    let head = beacon_chain.head()?;
    validate_against_state(
        head.state.as_ref(),
        cached_db,
        signed_contribution_and_proof,
    )
    .await
}

async fn validate_against_state(
    state: &BeaconState,
    cached_db: &BeaconCacheDB,
    signed_contribution_and_proof: &SignedContributionAndProof,
) -> anyhow::Result<ValidationResult> {
    let contribution_and_proof = &signed_contribution_and_proof.message;
    let contribution = &contribution_and_proof.contribution;

    // [REJECT] if contribution.subcommittee_index is out of SYNC_COMMITTEE_SUBNET_COUNT range.
    if contribution.subcommittee_index >= SYNC_COMMITTEE_SUBNET_COUNT {
        return Ok(ValidationResult::Reject(
            "The subcommittee index is out of range".to_string(),
        ));
    }

    // [REJECT] if contribution doesn't have any participants
    if contribution.aggregation_bits.num_set_bits() == 0 {
        return Ok(ValidationResult::Reject(
            "The contribution has too many participants".to_string(),
        ));
    }

    // [REJECT] if is_sync_committee_aggregator(contribution_and_proof.selection_proof) is false
    if !is_sync_committee_aggregator(&contribution_and_proof.selection_proof) {
        return Ok(ValidationResult::Reject(
            "The selection proof is not a valid aggregator".to_string(),
        ));
    }

    // [REJECT] if the validator with index contribution_and_proof.aggregator_index is not in the
    // sync committee for the epoch of contribution.slot
    let validator_pubkey = &state
        .validators
        .get(usize::try_from(contribution_and_proof.aggregator_index)?)
        .ok_or_else(|| anyhow!("invalid aggregator_index"))?
        .public_key;

    let subcommittee_pubkeys =
        get_sync_subcommittee_pubkeys(state, contribution.subcommittee_index);
    let is_valid_committee_member = subcommittee_pubkeys.contains(validator_pubkey);

    if !is_valid_committee_member {
        return Ok(ValidationResult::Reject(
            "The aggregator is in the subcommittee".to_string(),
        ));
    }

    // [IGNORE] if a valid sync committee contribution with equal slot, beacon_block_root and
    // subcommittee_index whose aggregation_bits is a non-strict superset has already been seen.
    // [IGNORE] if a valid sync committee contribution has already been seen from the aggregator
    // for the slot contribution.slot and subcommittee index contribution.subcommittee_index.
    // Checked here so duplicates skip the signature checks, and again when marking this
    // contribution as seen.
    let contribution_key = CacheSyncCommitteeContribution {
        slot: contribution.slot,
        beacon_block_root: contribution.beacon_block_root,
        subcommittee_index: contribution.subcommittee_index,
    };
    let aggregator_key = SyncCommitteeKey {
        subnet_id: contribution.subcommittee_index,
        slot: contribution.slot,
        validator_index: contribution_and_proof.aggregator_index,
    };
    {
        let seen_contributions = cached_db.seen_sync_committee_contributions.read().await;
        let seen_aggregators = cached_db.seen_sync_contribution_aggregators.read().await;
        if let Some(reason) = already_seen(
            seen_contributions.peek(&contribution_key),
            &contribution.aggregation_bits,
            seen_aggregators.contains(&aggregator_key),
        ) {
            return Ok(ValidationResult::Ignore(reason.to_string()));
        }
    }

    // [REJECT] if contribution_and_proof.selection_proof is not a valid signature of the
    // SyncAggregatorSelectionData derived from the contribution of the validator

    let selection_data = SyncAggregatorSelectionData {
        slot: contribution.slot,
        subcommittee_index: contribution.subcommittee_index,
    };
    let contribution_epoch = compute_epoch_at_slot(contribution.slot);

    let is_selection_proof_valid = contribution_and_proof.selection_proof.verify(
        validator_pubkey,
        compute_signing_root(
            selection_data,
            state.get_domain(
                DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
                Some(contribution_epoch),
            ),
        )
        .as_slice(),
    )?;

    if !is_selection_proof_valid {
        return Ok(ValidationResult::Reject(
            "The selection proof is not a valid signature".to_string(),
        ));
    }

    // [REJECT] if aggregate signature is not valid for the message beacon_block_root and aggregate
    // pubkey derived from the participation info in aggregation_bits for the subcommittee
    let participant_pubkeys = subcommittee_pubkeys
        .iter()
        .zip(contribution.aggregation_bits.iter())
        .filter_map(|(public_key, participated)| participated.then_some(public_key))
        .collect::<Vec<&PublicKey>>();

    let is_sync_committee_valid = contribution.signature.fast_aggregate_verify(
        participant_pubkeys,
        compute_signing_root(
            contribution.beacon_block_root,
            state.get_domain(DOMAIN_SYNC_COMMITTEE, Some(contribution_epoch)),
        )
        .as_slice(),
    )?;

    if !is_sync_committee_valid {
        return Ok(ValidationResult::Reject(
            "The aggregate signature is not valid".to_string(),
        ));
    }

    // [REJECT] if aggregator signature of signed_contribution_and_proof.signature is not valid.
    let is_contribution_and_proof_valid = signed_contribution_and_proof.signature.verify(
        validator_pubkey,
        compute_signing_root(
            contribution_and_proof,
            state.get_domain(DOMAIN_CONTRIBUTION_AND_PROOF, Some(contribution_epoch)),
        )
        .as_slice(),
    )?;

    if !is_contribution_and_proof_valid {
        return Ok(ValidationResult::Reject(
            "The aggregator signature is not valid".to_string(),
        ));
    }

    // Mark this contribution as seen. Only valid contributions are recorded, so an invalid copy
    // cannot hide a valid one. Copies validated concurrently all reach this point; the second
    // check under both write locks accepts exactly one of them. No other code takes both locks.
    let mut seen_contributions = cached_db.seen_sync_committee_contributions.write().await;
    let mut seen_aggregators = cached_db.seen_sync_contribution_aggregators.write().await;
    if let Some(reason) = already_seen(
        seen_contributions.peek(&contribution_key),
        &contribution.aggregation_bits,
        seen_aggregators.contains(&aggregator_key),
    ) {
        return Ok(ValidationResult::Ignore(reason.to_string()));
    }
    seen_aggregators.put(aggregator_key, ());
    match seen_contributions.get_mut(&contribution_key) {
        Some(seen_bits) => record_aggregation_bits(seen_bits, &contribution.aggregation_bits),
        None => {
            seen_contributions.put(
                contribution_key,
                vec![contribution.aggregation_bits.clone()],
            );
        }
    }

    Ok(ValidationResult::Accept)
}

/// Why a contribution is a duplicate of valid ones already seen, if it is.
fn already_seen(
    seen_bits: Option<&Vec<BitVector<U128>>>,
    aggregation_bits: &BitVector<U128>,
    aggregator_seen: bool,
) -> Option<&'static str> {
    if seen_bits.is_some_and(|seen_bits| is_non_strict_superset(seen_bits, aggregation_bits)) {
        return Some(
            "A valid sync committee contribution with equal slot, beacon_block_root and subcommittee_index covering these aggregation bits has already been seen",
        );
    }
    if aggregator_seen {
        return Some(
            "A valid sync committee contribution for this aggregator, slot and subcommittee index has already been seen",
        );
    }
    None
}

pub fn get_sync_subcommittee_pubkeys(
    state: &BeaconState,
    subcommittee_index: u64,
) -> Vec<PublicKey> {
    let current_epoch = state.get_current_epoch();

    let next_slot_epoch = compute_epoch_at_slot(state.slot + 1);
    let sync_committee = if compute_sync_committee_period(current_epoch)
        == compute_sync_committee_period(next_slot_epoch)
    {
        state.current_sync_committee.as_ref()
    } else {
        state.next_sync_committee.as_ref()
    };

    let sync_subcommittee_size = SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT;
    let start = (subcommittee_index * sync_subcommittee_size) as usize;

    let end = start + sync_subcommittee_size as usize;
    sync_committee.public_keys[start..end].to_vec()
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use alloy_primitives::{B256, aliases::B32};
    use ream_bls::{
        BLSSignature, PrivateKey,
        traits::{Aggregatable, Signable},
    };
    use ream_consensus_beacon::sync_committee::SyncCommittee;
    use ream_events_beacon::contribution_and_proof::{
        ContributionAndProof, SyncCommitteeContribution,
    };
    use ssz::Decode;
    use tree_hash::TreeHash;

    use super::*;

    /// Test keys; key `i` is validator `i` and position `i` of sync subcommittee 0.
    const KEY_COUNT: u64 = 64;
    const BLOCK_ROOT: B256 = B256::repeat_byte(7);

    struct Fixture {
        state: BeaconState,
        keys: Vec<PrivateKey>,
    }

    impl Fixture {
        fn new() -> Self {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
                "../../../testing/gossip-validation/tests/assets/sepolia/states/grandparent_state_9552074.ssz_snappy",
            );
            let bytes = snap::raw::Decoder::new()
                .decompress_vec(&std::fs::read(path).expect("fixture state is readable"))
                .expect("fixture state decompresses");
            let mut state = BeaconState::from_ssz_bytes(&bytes).expect("fixture state decodes");

            let keys = (1..=KEY_COUNT)
                .map(|secret| {
                    let mut inner = B256::ZERO;
                    inner[0] = secret as u8;
                    PrivateKey { inner }
                })
                .collect::<Vec<_>>();
            let mut sync_committee = state.current_sync_committee.as_ref().clone();
            for (index, key) in keys.iter().enumerate() {
                let public_key = key.public_key().expect("test key is a valid scalar");
                state
                    .validators
                    .get_mut(index)
                    .expect("fixture has enough validators")
                    .public_key = public_key.clone();
                sync_committee.public_keys[index] = public_key;
            }
            // Either committee may be the one in force for the slot after the state's.
            let sync_committee: Arc<SyncCommittee> = Arc::new(sync_committee);
            state.current_sync_committee = sync_committee.clone();
            state.next_sync_committee = sync_committee;
            Self { state, keys }
        }

        fn sign(&self, validator_index: u64, domain_type: B32, root: B256) -> BLSSignature {
            let domain = self
                .state
                .get_domain(domain_type, Some(compute_epoch_at_slot(self.state.slot)));
            self.keys[validator_index as usize]
                .sign(compute_signing_root(root, domain).as_slice())
                .expect("test key signs")
        }

        /// Test validators whose selection proof makes them aggregators for subcommittee 0.
        fn aggregators(&self) -> Vec<u64> {
            (0..KEY_COUNT)
                .filter(|&index| is_sync_committee_aggregator(&self.selection_proof(index)))
                .collect()
        }

        fn selection_proof(&self, aggregator_index: u64) -> BLSSignature {
            let selection_data = SyncAggregatorSelectionData {
                slot: self.state.slot,
                subcommittee_index: 0,
            };
            self.sign(
                aggregator_index,
                DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
                selection_data.tree_hash_root(),
            )
        }

        fn contribution(
            &self,
            aggregator_index: u64,
            participants: &[u64],
        ) -> SignedContributionAndProof {
            let mut aggregation_bits = BitVector::<U128>::new();
            for &participant in participants {
                aggregation_bits
                    .set(participant as usize, true)
                    .expect("participant is in the subcommittee");
            }
            let signatures = participants
                .iter()
                .map(|&participant| self.sign(participant, DOMAIN_SYNC_COMMITTEE, BLOCK_ROOT))
                .collect::<Vec<_>>();
            let message = ContributionAndProof {
                aggregator_index,
                contribution: SyncCommitteeContribution {
                    slot: self.state.slot,
                    beacon_block_root: BLOCK_ROOT,
                    subcommittee_index: 0,
                    aggregation_bits,
                    signature: BLSSignature::aggregate(&signatures.iter().collect::<Vec<_>>())
                        .expect("signatures aggregate"),
                },
                selection_proof: self.selection_proof(aggregator_index),
            };
            let signature = self.sign(
                aggregator_index,
                DOMAIN_CONTRIBUTION_AND_PROOF,
                message.tree_hash_root(),
            );
            SignedContributionAndProof { message, signature }
        }

        async fn validate(
            &self,
            cached_db: &BeaconCacheDB,
            contribution: &SignedContributionAndProof,
        ) -> ValidationResult {
            validate_against_state(&self.state, cached_db, contribution)
                .await
                .expect("validation runs")
        }
    }

    #[tokio::test]
    async fn invalid_contribution_does_not_hide_a_valid_copy() {
        let fixture = Fixture::new();
        let cached_db = BeaconCacheDB::new();
        let aggregator = fixture.aggregators()[0];
        let valid = fixture.contribution(aggregator, &[aggregator, 1, 2]);
        let mut invalid = valid.clone();
        invalid.signature = fixture.sign(aggregator, DOMAIN_CONTRIBUTION_AND_PROOF, B256::ZERO);

        assert!(matches!(
            fixture.validate(&cached_db, &invalid).await,
            ValidationResult::Reject(_)
        ));
        assert!(matches!(
            fixture.validate(&cached_db, &valid).await,
            ValidationResult::Accept
        ));
        assert!(matches!(
            fixture.validate(&cached_db, &valid).await,
            ValidationResult::Ignore(_)
        ));
    }

    #[tokio::test]
    async fn only_contributions_covered_by_a_seen_one_are_ignored() {
        let fixture = Fixture::new();
        let cached_db = BeaconCacheDB::new();
        let aggregators = fixture.aggregators();
        assert!(aggregators.len() >= 4, "test keys give too few aggregators");

        let subset = fixture.contribution(aggregators[0], &[10, 11]);
        let superset = fixture.contribution(aggregators[1], &[10, 11, 12]);
        let covered = fixture.contribution(aggregators[2], &[11, 12]);
        let disjoint = fixture.contribution(aggregators[3], &[13]);

        assert!(matches!(
            fixture.validate(&cached_db, &subset).await,
            ValidationResult::Accept
        ));
        assert!(matches!(
            fixture.validate(&cached_db, &superset).await,
            ValidationResult::Accept
        ));
        assert!(matches!(
            fixture.validate(&cached_db, &covered).await,
            ValidationResult::Ignore(_)
        ));
        assert!(matches!(
            fixture.validate(&cached_db, &disjoint).await,
            ValidationResult::Accept
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_copies_are_accepted_once() {
        let fixture = Arc::new(Fixture::new());
        let cached_db = Arc::new(BeaconCacheDB::new());
        let aggregator = fixture.aggregators()[0];
        let contribution = Arc::new(fixture.contribution(aggregator, &[20, 21]));

        let tasks = (0..8)
            .map(|_| {
                let (fixture, cached_db, contribution) =
                    (fixture.clone(), cached_db.clone(), contribution.clone());
                tokio::spawn(async move { fixture.validate(&cached_db, &contribution).await })
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

    #[test]
    fn marking_a_superset_drops_the_bits_it_covers() {
        let bits = |indices: &[usize]| {
            let mut bits = BitVector::<U128>::new();
            for &index in indices {
                bits.set(index, true).expect("index fits");
            }
            bits
        };
        let mut seen = vec![bits(&[1]), bits(&[2, 3])];
        record_aggregation_bits(&mut seen, &bits(&[1, 2]));
        assert_eq!(seen, vec![bits(&[2, 3]), bits(&[1, 2])]);
        assert!(is_non_strict_superset(&seen, &bits(&[1])));
        assert!(is_non_strict_superset(&seen, &bits(&[1, 2])));
        assert!(!is_non_strict_superset(&seen, &bits(&[1, 3])));
    }
}
