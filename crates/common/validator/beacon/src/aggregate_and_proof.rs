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
    use serde_json::json;

    use super::*;

    /// Lighthouse's validator client sends the aggregator index as a quoted string.
    #[test]
    fn signed_aggregate_and_proof_reads_quoted_aggregator_index() {
        let signature = format!("0xc0{}", "00".repeat(95));
        let root = format!("0x{}", "11".repeat(32));
        let checkpoint = json!({"epoch": "130701", "root": root});
        let request = json!({
            "message": {
                "aggregator_index": "1449083",
                "aggregate": {
                    "aggregation_bits": "0x03",
                    "data": {
                        "slot": "4182505",
                        "index": "0",
                        "beacon_block_root": root,
                        "source": checkpoint,
                        "target": checkpoint
                    },
                    "signature": signature,
                    "committee_bits": "0x0100000000000000"
                },
                "selection_proof": signature
            },
            "signature": signature
        });

        let decoded: SignedAggregateAndProof = serde_json::from_value(request.clone()).unwrap();
        assert_eq!(decoded.message.aggregator_index, 1449083);
        assert_eq!(serde_json::to_value(&decoded).unwrap(), request);
    }
}
