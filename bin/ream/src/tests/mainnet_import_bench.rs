//! Offline mainnet block-import benchmark.
//!
//! Importing a mainnet block is far slower than on a devnet because every per-block cost scales
//! with the ~1M-validator state. These tests replay real mainnet blocks without a network so the
//! cost can be measured repeatably.
//!
//! 1. Run a beacon node on mainnet until it has imported a few blocks, then stop it.
//! 2. `REAM_BENCH_SOURCE_DATA_DIR=<its --data-dir> REAM_BENCH_FIXTURE_DIR=<out> cargo test
//!    --release -p ream --bin ream extract_mainnet_import_fixture -- --ignored --nocapture`. The
//!    fixture starts at the node's finalized block; set `REAM_BENCH_MAX_BLOCKS` to keep only that
//!    many blocks after it.
//! 3. `REAM_BENCH_FIXTURE_DIR=<out> cargo test --release -p ream --bin ream
//!    mainnet_block_import_bench -- --ignored --nocapture`. Set `REAM_BENCH_MAX_AVG_MS` to fail
//!    when the average import time per block exceeds a budget. Set `REAM_BENCH_KEEP_DATA` to retain
//!    the benchmark database after the run.

use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use ream_chain_beacon::beacon_chain::{BeaconChain, BlockProcessingOutcome};
use ream_consensus_beacon::{
    data_column_sidecar::{ColumnIdentifier, DataColumnSidecar, NUMBER_OF_COLUMNS},
    electra::{beacon_block::SignedBeaconBlock, beacon_state::BeaconState},
};
use ream_consensus_misc::{
    constants::beacon::set_genesis_validator_root, misc::compute_epoch_at_slot,
};
use ream_fork_choice_beacon::store::get_forkchoice_store;
use ream_metrics::beacon::{
    BEACON_BLOCK_STATE_ROOT_SECONDS, BEACON_BLOCK_STATE_TRANSITION_SECONDS,
};
use ream_network_spec::networks::{MAINNET, set_beacon_network_spec};
use ream_operation_pool::OperationPool;
use ream_storage::{
    cache::BeaconCacheDB,
    db::{ReamDB, beacon::BeaconDB},
    tables::{
        field::REDBField,
        table::{CustomTable, REDBTable},
    },
};
use ream_sync_committee_pool::SyncCommitteePool;
use ssz::{Decode, Encode};
use tree_hash::TreeHash;

const ANCHOR_STATE: &str = "anchor_state.ssz";
const ANCHOR_BLOCK: &str = "anchor_block.ssz";

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(env::var(name).unwrap_or_else(|_| panic!("{name} must be set")))
}

fn open_db(data_dir: &Path) -> BeaconDB {
    ReamDB::new(data_dir.to_path_buf())
        .expect("database should open")
        .init_beacon_db()
        .expect("beacon database should initialize")
}

fn block_dir(fixture_dir: &Path, position: usize, slot: u64) -> PathBuf {
    fixture_dir.join(format!("{position:03}_{slot}"))
}

#[test]
#[ignore = "needs REAM_BENCH_SOURCE_DATA_DIR from a node that imported mainnet blocks"]
fn extract_mainnet_import_fixture() {
    let source = open_db(&env_path("REAM_BENCH_SOURCE_DATA_DIR"));
    let fixture_dir = env_path("REAM_BENCH_FIXTURE_DIR");
    fs::create_dir_all(&fixture_dir).expect("fixture dir should be creatable");

    // The node deletes states before the finalized block, so the finalized block is the oldest
    // anchor whose state is still available.
    let anchor_root = source.finalized_checkpoint_provider().get().unwrap().root;
    let head_root = source
        .slot_index_provider()
        .get_highest_root()
        .unwrap()
        .expect("database has imported blocks");

    // Walk parents from the newest block so side-fork blocks in the slot index are skipped.
    let mut blocks = Vec::new();
    let mut root = head_root;
    while root != anchor_root {
        let block = source
            .block_provider()
            .get(root)
            .unwrap()
            .expect("every ancestor of the head is stored");
        root = block.message.parent_root;
        blocks.push(block);
    }
    blocks.reverse();
    if let Ok(max_blocks) = env::var("REAM_BENCH_MAX_BLOCKS") {
        blocks.truncate(
            max_blocks
                .parse()
                .expect("REAM_BENCH_MAX_BLOCKS is a number"),
        );
    }

    let anchor_state = source
        .state_provider()
        .get(anchor_root)
        .unwrap()
        .expect("anchor state is stored");
    let anchor_block = source
        .block_provider()
        .get(anchor_root)
        .unwrap()
        .expect("anchor block is stored");
    fs::write(fixture_dir.join(ANCHOR_STATE), anchor_state.as_ssz_bytes()).unwrap();
    fs::write(fixture_dir.join(ANCHOR_BLOCK), anchor_block.as_ssz_bytes()).unwrap();

    let columns = source.column_sidecars_provider();
    for (position, block) in blocks.iter().enumerate() {
        let block_root = block.message.tree_hash_root();
        let dir = block_dir(&fixture_dir, position, block.message.slot);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("block.ssz"), block.as_ssz_bytes()).unwrap();
        for index in 0..NUMBER_OF_COLUMNS {
            if let Some(column) = columns
                .get(ColumnIdentifier::new(block_root, index))
                .unwrap()
            {
                fs::write(
                    dir.join(format!("column_{index}.ssz")),
                    column.as_ssz_bytes(),
                )
                .unwrap();
            }
        }
    }
    println!(
        "wrote anchor slot {} and {} blocks to {}",
        anchor_state.slot,
        blocks.len(),
        fixture_dir.display()
    );
}

fn read<T: Decode>(path: &Path) -> T {
    T::from_ssz_bytes(&fs::read(path).unwrap_or_else(|err| panic!("{}: {err}", path.display())))
        .unwrap_or_else(|err| panic!("{}: {err:?}", path.display()))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs REAM_BENCH_FIXTURE_DIR written by extract_mainnet_import_fixture"]
async fn mainnet_block_import_bench() {
    let fixture_dir = env_path("REAM_BENCH_FIXTURE_DIR");
    set_beacon_network_spec(MAINNET.clone());

    let anchor_state: BeaconState = read(&fixture_dir.join(ANCHOR_STATE));
    let anchor_block: SignedBeaconBlock = read(&fixture_dir.join(ANCHOR_BLOCK));
    set_genesis_validator_root(anchor_state.genesis_validators_root);
    let anchor_slot = anchor_state.slot;

    // A running node has these keys ready (it prepares them at startup), so do the same here
    // and time only block import.
    let epoch = anchor_state.get_current_epoch();
    let active_keys: Vec<_> = anchor_state
        .validators
        .iter()
        .filter(|validator| validator.is_active_validator(epoch))
        .map(|validator| validator.public_key.clone())
        .collect();
    let started = Instant::now();
    let prepared = ream_bls::prewarm_public_keys(&active_keys);
    println!(
        "prepared {prepared} active validator keys in {:.1} s",
        started.elapsed().as_secs_f64()
    );

    let mut block_dirs: Vec<PathBuf> = fs::read_dir(&fixture_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect();
    block_dirs.sort();
    assert!(!block_dirs.is_empty(), "fixture has no blocks");

    let data_dir = env::temp_dir().join(format!(
        "ream_mainnet_import_bench_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&data_dir).unwrap();
    // The node keeps recent states in memory; without this cache every parent state would be
    // decoded from disk.
    let db = open_db(&data_dir).with_cache(Arc::new(BeaconCacheDB::default()));

    // Bootstrap exactly like checkpoint sync. Set the clock directly so every block is in the past:
    // `on_tick` would step through every slot since the anchor.
    drop(get_forkchoice_store(anchor_state, anchor_block, db.clone()).unwrap());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    db.time_provider().insert(now).unwrap();
    let beacon_chain = BeaconChain::new(
        db,
        Arc::new(OperationPool::default()),
        Arc::new(SyncCommitteePool::default()),
        None,
        None,
    );

    let mut import_ms = Vec::new();
    let mut epoch_start_ms = Vec::new();
    let mut previous_slot = anchor_slot;
    println!(
        "slot        attestations  columns  state_root_ms  state_transition_ms  import_ms  \
         epoch_start"
    );
    for dir in &block_dirs {
        let block: SignedBeaconBlock = read(&dir.join("block.ssz"));
        let required_columns = beacon_chain
            .store
            .lock()
            .await
            .data_availability_checker
            .required_columns()
            .clone();
        let columns: Vec<DataColumnSidecar> = required_columns
            .iter()
            .filter_map(|index| {
                let path = dir.join(format!("column_{index}.ssz"));
                path.exists().then(|| read(&path))
            })
            .collect();
        let column_count = columns.len();
        let slot = block.message.slot;
        let attestations = block.message.body.attestations.len();

        // Same order as range sync: columns into the availability checker, then the block.
        let transition_before = BEACON_BLOCK_STATE_TRANSITION_SECONDS.get_sample_sum();
        let state_root_before = BEACON_BLOCK_STATE_ROOT_SECONDS.get_sample_sum();
        let started = Instant::now();
        for column in columns {
            beacon_chain
                .import_data_column_sidecar_if(column, |_| Ok(()))
                .await
                .unwrap();
        }
        let outcome = beacon_chain.process_block(block).await.unwrap();
        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        let transition_ms =
            (BEACON_BLOCK_STATE_TRANSITION_SECONDS.get_sample_sum() - transition_before) * 1000.0;
        let state_root_ms =
            (BEACON_BLOCK_STATE_ROOT_SECONDS.get_sample_sum() - state_root_before) * 1000.0;
        assert!(
            matches!(outcome, BlockProcessingOutcome::Imported { .. }),
            "block at slot {slot} was not imported: {outcome:?}"
        );
        // The first block of an epoch also runs epoch processing and stores its state whole.
        let epoch_start = compute_epoch_at_slot(slot) > compute_epoch_at_slot(previous_slot);
        previous_slot = slot;
        println!(
            "{slot:<12}{attestations:<14}{column_count:<9}{state_root_ms:<15.0}{transition_ms:<21.0}\
             {elapsed_ms:<11.0}{}",
            if epoch_start { "yes" } else { "" }
        );
        if epoch_start {
            epoch_start_ms.push(elapsed_ms);
        }
        import_ms.push(elapsed_ms);
    }

    let average = |values: &[f64]| values.iter().sum::<f64>() / values.len().max(1) as f64;
    let average_ms = average(&import_ms);
    println!(
        "imported {} blocks, average {average_ms:.0} ms per block",
        import_ms.len()
    );
    // The first block builds the state's caches, which a running node has already built.
    println!(
        "after the first block: average {:.0} ms; epoch starts: {} blocks, average {:.0} ms",
        average(&import_ms[1..]),
        epoch_start_ms.len(),
        average(&epoch_start_ms)
    );
    if env::var_os("REAM_BENCH_KEEP_DATA").is_some() {
        println!("retained benchmark data at {}", data_dir.display());
    } else {
        let _ = fs::remove_dir_all(&data_dir);
    }

    if let Ok(budget) = env::var("REAM_BENCH_MAX_AVG_MS") {
        let budget: f64 = budget.parse().expect("REAM_BENCH_MAX_AVG_MS is a number");
        assert!(
            average_ms <= budget,
            "average import time {average_ms:.0} ms exceeds the {budget:.0} ms budget"
        );
    }
}

