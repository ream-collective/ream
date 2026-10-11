use std::{path::PathBuf, sync::Arc};

use ream_consensus_beacon::electra::beacon_state::BeaconState;
use ssz::Decode;

/// A small Sepolia beacon state from the gossip validation test assets.
pub(crate) fn sepolia_state() -> Arc<BeaconState> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../testing/gossip-validation/tests/assets/sepolia/states/grandparent_state_9552074.ssz_snappy",
    );
    let bytes = snap::raw::Decoder::new()
        .decompress_vec(&std::fs::read(path).unwrap())
        .unwrap();
    Arc::new(BeaconState::from_ssz_bytes(&bytes).unwrap())
}
