use ream_bls::BLSSignature;
use ream_consensus_misc::attestation_data::AttestationData;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct SingleAttestation {
    #[serde(with = "serde_utils::quoted_u64")]
    pub committee_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub attester_index: u64,
    pub data: AttestationData,
    pub signature: BLSSignature,
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use ssz::{Decode, Encode};

    use super::SingleAttestation;

    fn request() -> Value {
        json!([{
            "committee_index": "0",
            "attester_index": "32",
            "data": {
                "slot": "69",
                "index": "0",
                "beacon_block_root": format!("0x{}", "00".repeat(32)),
                "source": {"epoch": "1", "root": format!("0x{}", "00".repeat(32))},
                "target": {"epoch": "2", "root": format!("0x{}", "00".repeat(32))}
            },
            "signature": format!("0xc0{}", "00".repeat(95))
        }])
    }

    #[test]
    fn single_attestation_validator_json_round_trip() {
        let request = request();
        let attestations: Vec<SingleAttestation> = serde_json::from_value(request.clone()).unwrap();
        let attestation = &attestations[0];
        assert_eq!(attestation.committee_index, 0);
        assert_eq!(attestation.attester_index, 32);
        assert_eq!(serde_json::to_value(&attestations).unwrap(), request);

        let encoded = attestation.as_ssz_bytes();
        assert_eq!(&encoded[..8], &0_u64.to_le_bytes());
        assert_eq!(&encoded[8..16], &32_u64.to_le_bytes());
        assert_eq!(
            SingleAttestation::from_ssz_bytes(&encoded).unwrap(),
            *attestation
        );
    }

    #[test]
    fn single_attestation_rejects_invalid_quoted_indices() {
        for field in ["committee_index", "attester_index"] {
            for invalid in ["-1", "18446744073709551616", "not-a-number"] {
                let mut request = request();
                request[0][field] = json!(invalid);
                assert!(serde_json::from_value::<Vec<SingleAttestation>>(request).is_err());
            }
        }
    }
}
