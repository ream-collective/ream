use ream_bls::{BLSSignature, PrivateKey, traits::Signable};
use ream_consensus_beacon::{attestation::Attestation, electra::beacon_state::BeaconState};
use ream_consensus_misc::{
    constants::beacon::{DOMAIN_AGGREGATE_AND_PROOF, genesis_validators_root},
    misc::{compute_domain, compute_epoch_at_slot, compute_signing_root},
};
use ream_network_spec::networks::beacon_network_spec;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::attestation::get_slot_signature;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct AggregateAndProof {
    #[serde(with = "serde_utils::quoted_u64")]
    pub aggregator_index: u64,
    pub aggregate: Attestation,
    pub selection_proof: BLSSignature,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct SignedAggregateAndProof {
    pub message: AggregateAndProof,
    pub signature: BLSSignature,
}

pub fn get_aggregate_and_proof(
    state: &BeaconState,
    aggregator_index: u64,
    aggregate: Attestation,
    private_key: PrivateKey,
) -> anyhow::Result<AggregateAndProof> {
    Ok(AggregateAndProof {
        selection_proof: get_slot_signature(state, aggregate.data.slot, private_key)?,
        aggregator_index,
        aggregate,
    })
}

pub fn get_aggregate_and_proof_signature(
    state: &BeaconState,
    aggregate_and_proof: AggregateAndProof,
    private_key: PrivateKey,
) -> anyhow::Result<BLSSignature> {
    let domain = state.get_domain(
        DOMAIN_AGGREGATE_AND_PROOF,
        Some(compute_epoch_at_slot(
            aggregate_and_proof.aggregate.data.slot,
        )),
    );
    let signing_root = compute_signing_root(aggregate_and_proof, domain);
    Ok(private_key.sign(signing_root.as_ref())?)
}

pub fn sign_aggregate_and_proof(
    aggregate_and_proof: &AggregateAndProof,
    private_key: &PrivateKey,
) -> anyhow::Result<BLSSignature> {
    let epoch = compute_epoch_at_slot(aggregate_and_proof.aggregate.data.slot);
    let domain = compute_domain(
        DOMAIN_AGGREGATE_AND_PROOF,
        Some(beacon_network_spec().current_fork_version(epoch)),
        Some(genesis_validators_root()),
    );
    let signing_root = compute_signing_root(aggregate_and_proof, domain);
    Ok(private_key.sign(signing_root.as_ref())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregator_index_uses_the_beacon_api_quoted_form() {
        let root = format!("0x{}", "00".repeat(32));
        let signature = format!("0xc0{}", "00".repeat(95));
        // Shape of the body a validator client posts to `/eth/v2/validator/aggregate_and_proofs`.
        let request = serde_json::json!([{
            "message": {
                "aggregator_index": "56",
                "aggregate": {
                    "aggregation_bits": "0x03",
                    "data": {
                        "slot": "2",
                        "index": "0",
                        "beacon_block_root": root,
                        "source": {"epoch": "0", "root": root},
                        "target": {"epoch": "0", "root": root}
                    },
                    "signature": signature,
                    "committee_bits": "0x0100000000000000"
                },
                "selection_proof": signature
            },
            "signature": signature
        }]);

        // A bare-number decoder rejected every aggregate with HTTP 400.
        let aggregates: Vec<SignedAggregateAndProof> =
            serde_json::from_value(request.clone()).unwrap();
        assert_eq!(aggregates[0].message.aggregator_index, 56);
        assert_eq!(serde_json::to_value(&aggregates).unwrap(), request);
    }
}
