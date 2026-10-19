use alloy_primitives::{Bytes, U256};
use ream_consensus_misc::polynomial_commitments::{
    kzg_commitment::KZGCommitment, kzg_proof::KZGProof,
};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{
    VariableList,
    typenum::{U1024, U32768},
};
use tree_hash_derive::TreeHash;

use super::execution_payload::ExecutionPayloadV3;
use crate::{electra::execution_payload::ExecutionPayload, get_blobs::Blob};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(rename_all = "camelCase")]
pub struct BlobsBundleV1 {
    pub blobs: VariableList<Blob, U1024>,
    pub commitments: VariableList<KZGCommitment, U1024>,
    pub proofs: VariableList<KZGProof, U1024>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PayloadV4 {
    pub execution_payload: ExecutionPayloadV3,
    #[serde(with = "serde_utils::u256_hex_be")]
    pub block_value: U256,
    pub blobs_bundle: BlobsBundleV1,
    pub should_override_builder: bool,
    pub execution_requests: Vec<Bytes>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(rename_all = "camelCase")]
pub struct BlobsBundleV2 {
    pub commitments: VariableList<KZGCommitment, U1024>,
    pub proofs: VariableList<KZGProof, U32768>,
    pub blobs: VariableList<Blob, U1024>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PayloadV5 {
    pub execution_payload: ExecutionPayloadV3,
    #[serde(with = "serde_utils::u256_hex_be")]
    pub block_value: U256,
    pub blobs_bundle: BlobsBundleV2,
    pub should_override_builder: bool,
    pub execution_requests: Vec<Bytes>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum BlobsBundle {
    V1(BlobsBundleV1),
    V2(BlobsBundleV2),
}

impl BlobsBundle {
    pub fn get_commitments(&self) -> Vec<KZGCommitment> {
        match self {
            BlobsBundle::V1(bundle) => bundle.commitments.iter().cloned().collect(),
            BlobsBundle::V2(bundle) => bundle.commitments.iter().cloned().collect(),
        }
    }

    pub fn get_proofs(&self) -> Vec<KZGProof> {
        match self {
            BlobsBundle::V1(bundle) => bundle.proofs.iter().cloned().collect(),
            BlobsBundle::V2(bundle) => bundle.proofs.iter().cloned().collect(),
        }
    }

    pub fn get_blobs(&self) -> Vec<Blob> {
        match self {
            BlobsBundle::V1(bundle) => bundle.blobs.iter().cloned().collect(),
            BlobsBundle::V2(bundle) => bundle.blobs.iter().cloned().collect(),
        }
    }

    pub fn is_fulu(&self) -> bool {
        matches!(self, BlobsBundle::V2(_))
    }
}

#[derive(Deserialize, Debug)]
pub enum Payload {
    V4(PayloadV4),
    V5(PayloadV5),
}

impl Payload {
    pub fn execution_payload(&self) -> &ExecutionPayloadV3 {
        match self {
            Payload::V4(payload) => &payload.execution_payload,
            Payload::V5(payload) => &payload.execution_payload,
        }
    }

    pub fn execution_requests(&self) -> &Vec<Bytes> {
        match self {
            Payload::V4(payload) => &payload.execution_requests,
            Payload::V5(payload) => &payload.execution_requests,
        }
    }

    pub fn should_override_builder(&self) -> bool {
        match self {
            Payload::V4(payload) => payload.should_override_builder,
            Payload::V5(payload) => payload.should_override_builder,
        }
    }

    pub fn block_value(&self) -> &U256 {
        match self {
            Payload::V4(payload) => &payload.block_value,
            Payload::V5(payload) => &payload.block_value,
        }
    }

    pub fn blobs_bundle(&self) -> BlobsBundle {
        match self {
            Payload::V4(payload) => BlobsBundle::V1(payload.blobs_bundle.clone()),
            Payload::V5(payload) => BlobsBundle::V2(payload.blobs_bundle.clone()),
        }
    }

    pub fn to_execution_payload(&self) -> ExecutionPayload {
        let ep = self.execution_payload();
        ExecutionPayload {
            parent_hash: ep.parent_hash,
            fee_recipient: ep.fee_recipient,
            state_root: ep.state_root,
            receipts_root: ep.receipts_root,
            logs_bloom: ep.logs_bloom.clone(),
            prev_randao: ep.prev_randao,
            block_number: ep.block_number,
            gas_limit: ep.gas_limit,
            gas_used: ep.gas_used,
            timestamp: ep.timestamp,
            extra_data: ep.extra_data.clone(),
            base_fee_per_gas: ep.base_fee_per_gas,
            block_hash: ep.block_hash,
            transactions: ep.transactions.clone(),
            withdrawals: VariableList::new(
                ep.withdrawals.iter().cloned().map(Into::into).collect(),
            )
            .expect("converting a U16-bounded withdrawal list preserves its length"),
            blob_gas_used: ep.blob_gas_used,
            excess_blob_gas: ep.excess_blob_gas,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn geth_payload_response(blobs_bundle: Value) -> Value {
        json!({
            "executionPayload": {
                "parentHash": format!("0x{}", "11".repeat(32)),
                "feeRecipient": "0x428f4289844b51e1614143e15d665f109e16582d",
                "stateRoot": format!("0x{}", "22".repeat(32)),
                "receiptsRoot": format!("0x{}", "33".repeat(32)),
                "logsBloom": format!("0x{}", "00".repeat(256)),
                "prevRandao": format!("0x{}", "44".repeat(32)),
                "blockNumber": "0x1a2b3c",
                "gasLimit": "0x2aea540",
                "gasUsed": "0x0",
                "timestamp": "0x68f47c48",
                "extraData": "0x",
                "baseFeePerGas": "0x3f118629",
                "blockHash": format!("0x{}", "55".repeat(32)),
                "transactions": [],
                "withdrawals": [{
                    "index": "0x3a5e409",
                    "validatorIndex": "0x14faaf",
                    "address": "0x9029c772dde847622df1553ed9d9bdb7812e4f93",
                    "amount": "0x2be28b"
                }],
                "blobGasUsed": "0x0",
                "excessBlobGas": "0x0"
            },
            "blockValue": "0x0",
            "blobsBundle": blobs_bundle,
            "shouldOverrideBuilder": false,
            "executionRequests": []
        })
    }

    #[test]
    fn block_value_is_a_quantity() {
        let empty_bundle = json!({"blobs": [], "commitments": [], "proofs": []});

        let payload: PayloadV5 =
            serde_json::from_value(geth_payload_response(empty_bundle.clone())).unwrap();
        assert_eq!(payload.block_value, U256::ZERO);
        assert_eq!(
            payload.execution_payload.withdrawals[0].validator_index,
            0x14faaf
        );

        let mut response = geth_payload_response(empty_bundle);
        response["blockValue"] = json!("0x2386f26fc10000");
        let payload: PayloadV4 = serde_json::from_value(response).unwrap();
        assert_eq!(payload.block_value, U256::from(10_000_000_000_000_000u64));
    }
}
