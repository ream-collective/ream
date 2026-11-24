//! Integration checks for the pinned EIP-7688 dependencies before fork types migrate.

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssz::{Decode, Encode, ProgressiveBitList};
use ssz_derive::{Decode, Encode};
use ssz_types::{BitList, ProgressiveVariableList, VariableList, typenum::U4096};
use tree_hash::{ProgressiveMerkleHasher, TreeHash};
use tree_hash_derive::TreeHash;

fn hash_pair(left: B256, right: B256) -> B256 {
    B256::from_slice(&Sha256::digest(
        [left.as_slice(), right.as_slice()].concat(),
    ))
}

fn uint_chunk(value: u64) -> B256 {
    let mut chunk = B256::ZERO;
    chunk[..8].copy_from_slice(&value.to_le_bytes());
    chunk
}

// Materialize each padded binary subtree independently of the streaming sigp hasher.
// EIP-7916: hash(merkleize(chunks[:n], n), merkleize_progressive(chunks[n:], n * 4)).
fn reference_progressive(chunks: &[B256], capacity: usize) -> B256 {
    if chunks.is_empty() {
        return B256::ZERO;
    }
    let take = capacity.min(chunks.len());
    let mut layer = vec![B256::ZERO; capacity];
    layer[..take].copy_from_slice(&chunks[..take]);
    while layer.len() > 1 {
        layer = layer
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| hash_pair(pair[0], pair[1]))
            .collect();
    }
    hash_pair(
        layer[0],
        reference_progressive(&chunks[take..], capacity * 4),
    )
}

fn reference_bytes(bytes: &[u8]) -> B256 {
    let chunks: Vec<_> = bytes
        .chunks(32)
        .map(|bytes| {
            let mut chunk = B256::ZERO;
            chunk[..bytes.len()].copy_from_slice(bytes);
            chunk
        })
        .collect();
    reference_progressive(&chunks, 1)
}

#[test]
fn streaming_merkleization_crosses_subtree_boundaries() {
    for count in [0, 1, 2, 4, 5, 6, 20, 21, 22, 84, 85, 86, 340, 341, 342] {
        let chunks: Vec<_> = (1..=count).map(uint_chunk).collect();
        let bytes: Vec<_> = chunks
            .iter()
            .flat_map(|chunk| chunk.iter().copied())
            .collect();
        let mut hasher = ProgressiveMerkleHasher::new();
        for part in bytes.chunks(7) {
            hasher.write(part).unwrap();
        }
        assert_eq!(
            hasher.finish().unwrap(),
            reference_progressive(&chunks, 1),
            "{count} chunks"
        );
    }
}

#[test]
fn byte_lists_preserve_encoding_and_pack_before_hashing() {
    for len in [0, 1, 31, 32, 33, 159, 160, 161, 671, 672, 673] {
        let values: Vec<_> = (0..len).map(|i| (i % 251) as u8).collect();
        let progressive = ProgressiveVariableList::<u8>::new(values.clone()).unwrap();
        let legacy = VariableList::<u8, U4096>::new(values.clone()).unwrap();
        assert_eq!(progressive.as_ssz_bytes(), legacy.as_ssz_bytes());
        assert_eq!(
            ProgressiveVariableList::<u8>::from_ssz_bytes(&legacy.as_ssz_bytes()).unwrap(),
            progressive
        );
        assert_eq!(
            progressive.tree_hash_root(),
            hash_pair(reference_bytes(&values), uint_chunk(len as u64))
        );
    }
}

#[test]
fn u64_lists_pack_four_values_per_chunk() {
    for len in [0, 1, 3, 4, 5, 19, 20, 21, 83, 84, 85] {
        let values: Vec<_> = (0..len).map(|i| 0x0102_0304_0506_0708 + i as u64).collect();
        let bytes: Vec<_> = values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        let progressive = ProgressiveVariableList::<u64>::new(values.clone()).unwrap();
        let legacy = VariableList::<u64, U4096>::new(values).unwrap();
        assert_eq!(progressive.as_ssz_bytes(), legacy.as_ssz_bytes());
        assert_eq!(
            ProgressiveVariableList::<u64>::from_ssz_bytes(&bytes).unwrap(),
            progressive
        );
        assert_eq!(
            progressive.tree_hash_root(),
            hash_pair(reference_bytes(&bytes), uint_chunk(len as u64))
        );
    }
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
struct Sample {
    index: u64,
    root: B256,
}

#[test]
fn composite_lists_hash_one_root_per_element() {
    let values: Vec<_> = (0..22)
        .map(|index| Sample {
            index,
            root: B256::repeat_byte(index as u8),
        })
        .collect();
    let roots: Vec<_> = values
        .iter()
        .map(|value| hash_pair(uint_chunk(value.index), value.root))
        .collect();
    let progressive = ProgressiveVariableList::<Sample>::new(values.clone()).unwrap();
    let legacy = VariableList::<Sample, U4096>::new(values).unwrap();
    assert_eq!(progressive.as_ssz_bytes(), legacy.as_ssz_bytes());
    assert_eq!(
        ProgressiveVariableList::<Sample>::from_ssz_bytes(&legacy.as_ssz_bytes()).unwrap(),
        progressive
    );
    assert_eq!(
        progressive.tree_hash_root(),
        hash_pair(reference_progressive(&roots, 1), uint_chunk(22))
    );
}

#[test]
fn nested_lists_preserve_variable_length_offsets() {
    let values = [vec![], vec![42], vec![7; 33], vec![9; 161]];
    let progressive = ProgressiveVariableList::<ProgressiveVariableList<u8>>::new(
        values
            .iter()
            .map(|v| ProgressiveVariableList::new(v.clone()).unwrap())
            .collect(),
    )
    .unwrap();
    let legacy = VariableList::<VariableList<u8, U4096>, U4096>::new(
        values
            .iter()
            .map(|v| VariableList::new(v.clone()).unwrap())
            .collect(),
    )
    .unwrap();
    let roots: Vec<_> = values
        .iter()
        .map(|v| hash_pair(reference_bytes(v), uint_chunk(v.len() as u64)))
        .collect();
    assert_eq!(progressive.as_ssz_bytes(), legacy.as_ssz_bytes());
    assert_eq!(
        ProgressiveVariableList::<ProgressiveVariableList<u8>>::from_ssz_bytes(
            &legacy.as_ssz_bytes()
        )
        .unwrap(),
        progressive
    );
    assert_eq!(
        progressive.tree_hash_root(),
        hash_pair(reference_progressive(&roots, 1), uint_chunk(4))
    );
}

#[test]
fn bitlists_preserve_delimiter_but_hash_only_data_bits() {
    for len in [0, 1, 7, 8, 255, 256, 257, 1279, 1280, 1281] {
        let mut progressive = ProgressiveBitList::with_capacity(len);
        let mut legacy = BitList::<U4096>::with_capacity(len).unwrap();
        let mut packed = vec![0u8; len.div_ceil(8)];
        for i in 0..len {
            if i % 3 == 0 {
                progressive.set(i, true).unwrap();
                legacy.set(i, true).unwrap();
                packed[i / 8] |= 1 << (i % 8);
            }
        }
        assert_eq!(progressive.as_ssz_bytes(), legacy.as_ssz_bytes());
        assert_eq!(
            ProgressiveBitList::from_ssz_bytes(&legacy.as_ssz_bytes()).unwrap(),
            progressive
        );
        assert_eq!(
            progressive.tree_hash_root(),
            hash_pair(reference_bytes(&packed), uint_chunk(len as u64))
        );
    }
}

#[derive(Debug, PartialEq, Encode, Decode, Serialize, Deserialize, TreeHash)]
#[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 0, 1))]
struct ProgressiveSample {
    index: u64,
    values: ProgressiveVariableList<u8>,
}

#[derive(Encode)]
struct LegacySample {
    index: u64,
    values: VariableList<u8, U4096>,
}

#[test]
fn progressive_derive_preserves_bytes_and_inactive_field_positions() {
    let progressive = ProgressiveSample {
        index: 42,
        values: ProgressiveVariableList::new(vec![1, 2, 3]).unwrap(),
    };
    let legacy = LegacySample {
        index: 42,
        values: VariableList::new(vec![1, 2, 3]).unwrap(),
    };
    let values_root = hash_pair(reference_bytes(&[1, 2, 3]), uint_chunk(3));
    let fields_root = reference_progressive(&[uint_chunk(42), B256::ZERO, values_root], 1);
    assert_eq!(
        progressive.tree_hash_root(),
        hash_pair(fields_root, uint_chunk(0b101))
    );
    assert_eq!(progressive.as_ssz_bytes(), legacy.as_ssz_bytes());
    assert_eq!(
        ProgressiveSample::from_ssz_bytes(&legacy.as_ssz_bytes()).unwrap(),
        progressive
    );
    let json = serde_json::to_string(&progressive).unwrap();
    assert_eq!(
        serde_json::from_str::<ProgressiveSample>(&json).unwrap(),
        progressive
    );
}
