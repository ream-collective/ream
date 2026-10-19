use alloy_primitives::{Address, B64, B256};
use serde::{Deserialize, Serialize};
use ssz_types::{VariableList, typenum::U16};

use super::{execution_payload::WithdrawalV1, payload_status::PayloadStatusV1};

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkchoiceStateV1 {
    pub head_block_hash: B256,
    pub safe_block_hash: B256,
    pub finalized_block_hash: B256,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadAttributesV3 {
    #[serde(with = "serde_utils::u64_hex_be")]
    pub timestamp: u64,
    pub prev_randao: B256,
    pub suggested_fee_recipient: Address,
    pub withdrawals: VariableList<WithdrawalV1, U16>,
    pub parent_beacon_block_root: B256,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkchoiceUpdateResult {
    pub payload_status: PayloadStatusV1,
    pub payload_id: Option<B64>,
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{address, b256};
    use serde_json::json;

    use super::*;

    #[test]
    fn payload_attributes_withdrawals_use_engine_api_hex_quantities() {
        let attributes = PayloadAttributesV3 {
            timestamp: 1_742_213_412,
            prev_randao: B256::ZERO,
            suggested_fee_recipient: Address::ZERO,
            withdrawals: VariableList::new(vec![WithdrawalV1 {
                index: 15,
                validator_index: 16,
                address: address!("0000000000000000000000000000000000000001"),
                amount: 17,
            }])
            .expect("one withdrawal fits"),
            parent_beacon_block_root: b256!(
                "0000000000000000000000000000000000000000000000000000000000000001"
            ),
        };

        let encoded = serde_json::to_value(attributes).expect("attributes should serialize");
        let withdrawal = &encoded["withdrawals"][0];
        assert_eq!(withdrawal["index"], json!("0xf"));
        assert_eq!(withdrawal["validatorIndex"], json!("0x10"));
        assert_eq!(withdrawal["amount"], json!("0x11"));
    }
}
