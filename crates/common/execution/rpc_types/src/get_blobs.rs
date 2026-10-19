use ream_consensus_misc::{
    constants::beacon::BYTES_PER_BLOB, polynomial_commitments::kzg_proof::KZGProof,
};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{
    FixedVector,
    serde_utils::hex_fixed_vec,
    typenum::{U128, U131072},
};
use tree_hash_derive::TreeHash;

#[derive(
    Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Decode, Encode, TreeHash, Default,
)]
#[serde(transparent)]
pub struct Blob {
    #[serde(with = "hex_fixed_vec")]
    pub inner: FixedVector<u8, U131072>,
}

impl Blob {
    pub fn to_fixed_bytes(&self) -> [u8; BYTES_PER_BLOB] {
        let mut fixed_array = [0u8; BYTES_PER_BLOB];
        fixed_array.copy_from_slice(&self.inner);
        fixed_array
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Decode, Encode, Default)]
#[serde(rename_all = "camelCase")]
pub struct BlobAndProofV1 {
    pub blob: Blob,
    pub proof: KZGProof,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Decode, Encode, TreeHash)]
#[serde(rename_all = "camelCase")]
pub struct BlobAndProofV2 {
    pub blob: Blob,
    pub proofs: FixedVector<KZGProof, U128>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_and_proof_v2_carries_one_proof_per_cell() {
        let proof = format!("\"0x{}\"", "c0".to_string() + &"00".repeat(47));
        let json = format!(
            "{{\"blob\":\"0x{}\",\"proofs\":[{}]}}",
            "00".repeat(131072),
            vec![proof.as_str(); 128].join(",")
        );
        let blob_and_proof = serde_json::from_str::<BlobAndProofV2>(&json)
            .expect("an engine_getBlobsV2 entry should decode");
        assert_eq!(blob_and_proof.proofs.len(), 128);
    }
}
