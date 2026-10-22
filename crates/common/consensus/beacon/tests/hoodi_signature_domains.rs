use std::str::FromStr;

use alloy_primitives::{B256, b256};
use ream_bls::{BLSSignature, PublicKey, traits::Verifiable};
use ream_consensus_beacon::{
    electra::beacon_state::{is_valid_deposit_signature, voluntary_exit_domain},
    voluntary_exit::VoluntaryExit,
};
use ream_consensus_misc::misc::compute_signing_root;
use ream_network_spec::networks::{HOODI, set_beacon_network_spec};

const HOODI_GENESIS_VALIDATORS_ROOT: B256 =
    b256!("212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f");

fn signature(hex: &str) -> BLSSignature {
    serde_json::from_str(&format!("\"{hex}\"")).expect("valid signature hex")
}

/// Real Hoodi messages: these only verify with Hoodi's fork versions, not mainnet's.
#[test]
fn hoodi_signatures_verify_with_hoodi_fork_versions() {
    set_beacon_network_spec(HOODI.clone());

    // Deposit made with ethstaker-deposit-cli 1.3.1 for Hoodi.
    let deposit_key = PublicKey::from_str(
        "0xb24f3d01b0e5bc726b8aad948c0165e10ab07338eea0fdc0a1df29275710dc374dd660b2f6dbed4b735571df7e1fab85",
    )
    .unwrap();
    let deposit_signature = signature(
        "0xaf7f25e5418e2c0d4fb7cf0eed0d6f3a93ff4b96f60a478845ccecd2953ffad4f7721302581723786d2a61213d43246a0bdea1a43f74fbd898dbf7c1fe6ae2e49d86238b06928365d2c2dff72bdb24934b368a3b3d3ba9b0d21d26cd8f67360f",
    );
    assert!(
        is_valid_deposit_signature(
            &deposit_key,
            b256!("010000000000000000000000428f4289844b51e1614143e15d665f109e16582d"),
            32_000_000_000,
            &deposit_signature,
        )
        .unwrap()
    );

    // Exit included in Hoodi block 0x7c71dc87…a671 (slot 4179448).
    let exit_key = PublicKey::from_str(
        "0xadbe2a4fa0ca2bae8605972cc5b23e7db86374c9e69a0ed8b178b390eac8a5b14af29febe71c0108dee4e439821e8f3b",
    )
    .unwrap();
    let exit_signature = signature(
        "0x818075d2043b4ad5d047bfa12d0bff548754edf8940c5ca5ae3ee17489707fee5f578dc83555d057f0dcc26dcfa325281017313b3f12c0307fc00844a89cdcbb118326c57b64d4069d96639ac3ba172bcc7b26172542dbb4919c69f787a42f2a",
    );
    let exit = VoluntaryExit {
        epoch: 130_607,
        validator_index: 1_665_183,
    };
    let signing_root =
        compute_signing_root(exit, voluntary_exit_domain(HOODI_GENESIS_VALIDATORS_ROOT));
    assert!(
        exit_signature
            .verify(&exit_key, signing_root.as_ref())
            .unwrap()
    );
}
