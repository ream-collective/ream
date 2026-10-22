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
    use serde_json::json;

    use super::*;

    /// The beacon API sends integers as quoted strings, as Lighthouse's validator client does.
    #[test]
    fn indices_are_quoted_in_json() {
        let attestation = json!({
            "committee_index": "3",
            "attester_index": "1449083",
            "data": {
                "slot": "4182505",
                "index": "0",
                "beacon_block_root": format!("0x{}", "11".repeat(32)),
                "source": {"epoch": "130701", "root": format!("0x{}", "22".repeat(32))},
                "target": {"epoch": "130702", "root": format!("0x{}", "33".repeat(32))}
            },
            "signature": format!("0x{}", "aa".repeat(96))
        });

        let decoded: SingleAttestation = serde_json::from_value(attestation.clone()).unwrap();
        assert_eq!(decoded.committee_index, 3);
        assert_eq!(decoded.attester_index, 1449083);
        assert_eq!(serde_json::to_value(&decoded).unwrap(), attestation);
    }
}
