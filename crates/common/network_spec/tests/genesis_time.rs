use std::time::{SystemTime, UNIX_EPOCH};

use ream_network_spec::networks::{HOODI, set_beacon_network_spec, set_genesis_time};

#[test]
fn wall_clock_uses_the_chain_genesis_time() {
    set_beacon_network_spec(HOODI.clone());
    let spec = &HOODI;
    assert_eq!(spec.genesis_time(), spec.min_genesis_time);

    // Hoodi: MIN_GENESIS_TIME 1742212800 + GENESIS_DELAY 600.
    set_genesis_time(1_742_213_400);
    assert_eq!(spec.genesis_time(), 1_742_213_400);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expected_slot = (now - 1_742_213_400) / spec.seconds_per_slot();
    let slot = spec.slot_n_days_ago(0);
    assert!(
        slot.abs_diff(expected_slot) <= 1,
        "slot {slot}, expected {expected_slot}"
    );
}
