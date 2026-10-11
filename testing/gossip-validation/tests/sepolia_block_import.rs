//! Runs the state transition of a real Sepolia block, the core of block import for range sync and
//! gossip, checks how much of the expensive per-epoch work it repeats, and checks that storage
//! rebuilds the post-state it does not store whole.
//!
//! This is its own test binary because it sets the Sepolia network spec and genesis validators
//! root, which can be set only once per process.

use std::{path::PathBuf, sync::Once};

use ream_consensus_beacon::electra::{beacon_block::SignedBeaconBlock, beacon_state::BeaconState};
use ream_consensus_misc::constants::beacon::set_genesis_validator_root;
use ream_execution_engine::ExecutionEngine;
use ream_metrics::BEACON_SHUFFLING_CACHE_MISSES_TOTAL;
use ream_network_spec::networks::{SEPOLIA, set_beacon_network_spec};
use ream_storage::{db::ReamDB, tables::table::REDBTable};
use snap::raw::Decoder;
use ssz::Decode;
use tempdir::TempDir;
use tree_hash::TreeHash;

const PARENT_STATE: &str = "states/parent_state_9552075.ssz_snappy";
const CHILD_BLOCK: &str = "blocks/child_9552076.ssz_snappy";

static SETUP: Once = Once::new();

fn setup(state: &BeaconState) {
    SETUP.call_once(|| {
        set_beacon_network_spec(SEPOLIA.clone());
        set_genesis_validator_root(state.genesis_validators_root);
    });
}

fn read_asset<T: Decode>(path: &str) -> T {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/assets/sepolia")
        .join(path);
    let compressed = std::fs::read(&path).expect("asset should be readable");
    let bytes = Decoder::new()
        .decompress_vec(&compressed)
        .expect("asset should decompress");
    T::from_ssz_bytes(&bytes).expect("asset should decode")
}

#[tokio::test]
async fn sepolia_block_transition_shuffles_each_epoch_once() {
    let mut state: BeaconState = read_asset(PARENT_STATE);
    let block: SignedBeaconBlock = read_asset(CHILD_BLOCK);
    setup(&state);
    let attestations = block.message.body.attestations.len();
    assert!(
        attestations > 0,
        "the block must carry attestations for this test to mean anything"
    );

    // The cached state root must be the SSZ root, before the cache has seen the state and after.
    assert_eq!(state.state_root(), state.tree_hash_root());
    let misses_before = BEACON_SHUFFLING_CACHE_MISSES_TOTAL.get();
    // Verifies the proposer and every attestation signature, and the post-state root.
    state
        .state_transition(&block, true, &None::<ExecutionEngine>)
        .await
        .unwrap();
    let shufflings = BEACON_SHUFFLING_CACHE_MISSES_TOTAL.get() - misses_before;

    assert_eq!(state.tree_hash_root(), block.message.state_root);
    assert_eq!(state.state_root(), block.message.state_root);
    // A block's attestations reference only the current and previous epoch, so its transition
    // shuffles at most two epochs. Without the cache every committee of every attestation
    // rebuilt the active set and reshuffled it.
    assert!(
        (1..=2).contains(&shufflings),
        "{attestations} attestations computed {shufflings} epoch shufflings"
    );
}

#[tokio::test]
async fn state_stored_as_a_summary_is_rebuilt_and_survives_pruning() {
    let parent_state: BeaconState = read_asset(PARENT_STATE);
    let block: SignedBeaconBlock = read_asset(CHILD_BLOCK);
    setup(&parent_state);
    let parent_root = block.message.parent_root;
    let block_root = block.message.tree_hash_root();
    let mut post_state = parent_state.clone();
    post_state
        .state_transition(&block, true, &None::<ExecutionEngine>)
        .await
        .unwrap();

    // No in-memory cache, so every read below goes to disk.
    let dir = TempDir::new("ream_state_summaries").unwrap();
    let db = ReamDB::new(dir.path().to_path_buf())
        .unwrap()
        .init_beacon_db()
        .unwrap();
    db.block_provider()
        .insert(block_root, block.clone())
        .unwrap();
    // The parent has no stored parent of its own, so it is stored whole.
    db.state_provider()
        .insert(parent_root, parent_state)
        .unwrap();
    // The child is in the same epoch as its parent, so only its summary is stored.
    db.state_provider().insert(block_root, post_state).unwrap();
    let stored_whole = |root| db.state_provider().is_stored_whole(root).unwrap();
    assert!(stored_whole(parent_root));
    assert!(!stored_whole(block_root));
    assert!(db.state_provider().contains_key(block_root).unwrap());

    let rebuilt = db.state_provider().get(block_root).unwrap().unwrap();
    assert_eq!(rebuilt.tree_hash_root(), block.message.state_root);

    // Finalizing the child stores it whole and deletes the parent's state.
    assert_eq!(db.state_provider().prune_finalized(block_root).unwrap(), 1);
    assert!(stored_whole(block_root));
    assert!(db.state_provider().get(parent_root).unwrap().is_none());
    let finalized = db.state_provider().get(block_root).unwrap().unwrap();
    assert_eq!(finalized.tree_hash_root(), block.message.state_root);
}
