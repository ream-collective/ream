use ream_bls::PublicKey;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

#[derive(Debug, Deserialize, Serialize, Encode, Decode)]
pub struct ProposerDuty {
    #[serde(rename = "pubkey")]
    pub public_key: PublicKey,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode)]
pub struct AttesterDuty {
    #[serde(rename = "pubkey")]
    pub public_key: PublicKey,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub committee_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub committee_length: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub committees_at_slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_committee_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
}

#[derive(Debug, Deserialize, Serialize, Encode, Decode)]
pub struct SyncCommitteeDuty {
    #[serde(rename = "pubkey")]
    pub public_key: PublicKey,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "serde_utils::quoted_u64_vec")]
    pub validator_sync_committee_indices: Vec<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attester_duty_json_matches_the_beacon_api() {
        // A Lighthouse response; its validator client requires `committee_length`.
        let json = serde_json::json!({
            "pubkey": "0xa85e33ca0737c84dc947006226462a6eba8a96c41962248031980326ee1d119b5e64bb868c9c279ca9424799dda52698",
            "validator_index": "0",
            "committee_index": "35",
            "committee_length": "555",
            "committees_at_slot": "64",
            "validator_committee_index": "139",
            "slot": "4192826"
        });
        let duty: AttesterDuty = serde_json::from_value(json.clone()).expect("deserializes");
        assert_eq!(duty.committee_length, 555);
        assert_eq!(serde_json::to_value(&duty).expect("serializes"), json);
    }

    #[test]
    fn sync_committee_indices_are_quoted() {
        let duty = SyncCommitteeDuty {
            public_key: PublicKey::default(),
            validator_index: 865059,
            validator_sync_committee_indices: vec![473, 9],
        };
        let json = serde_json::to_value(&duty).expect("serializes");
        assert_eq!(
            json["validator_sync_committee_indices"],
            serde_json::json!(["473", "9"])
        );
        let parsed: SyncCommitteeDuty = serde_json::from_value(json).expect("deserializes");
        assert_eq!(parsed.validator_sync_committee_indices, vec![473, 9]);
    }
}
