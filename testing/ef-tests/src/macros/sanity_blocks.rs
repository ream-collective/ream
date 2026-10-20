#[macro_export]
macro_rules! test_sanity_blocks {
    ($operation_name:ident, $path:expr) => {
        paste::paste! {
            #[cfg(test)]
            #[allow(non_snake_case)]
            mod $operation_name {
                use std::{fs, path::Path};

                use ream_execution_engine::mock_engine::MockExecutionEngine;
                use ream_network_spec::networks::initialize_test_network_spec;
                use serde_yaml;

                use super::*;

                #[derive(Debug, serde::Deserialize)]
                struct MetaData {
                    blocks_count: usize,
                    bls_setting: Option<usize>,
                }

                #[tokio::test]
                async fn $operation_name() {
                    initialize_test_network_spec();
                    let base_path = std::env::current_dir()
                        .unwrap()
                        .join(format!("mainnet/tests/mainnet/fulu/{}/pyspec_tests", $path));

                    let mock_engine = Some(MockExecutionEngine::new());

                    for entry in std::fs::read_dir(&base_path).unwrap() {
                        let entry = entry.unwrap();
                        let case_dir = entry.path();
                        if !case_dir.is_dir() {
                            continue;
                        }

                        let case_name = case_dir.file_name().unwrap().to_str().unwrap();
                        println!("Testing case: {}", case_name);

                        let meta: MetaData = {
                            let meta_path = case_dir.join("meta.yaml");
                            let content =
                                fs::read_to_string(meta_path).expect("Failed to read meta.yaml");
                            serde_yaml::from_str(&content).expect("Failed to parse meta.yaml")
                        };

                        let mut state: BeaconState =
                            utils::read_ssz_snappy(&case_dir.join("pre.ssz_snappy"))
                                .expect("cannot find test asset (pre.ssz_snappy)");

                        let mut result: Result<(), String> = Ok(());

                        for i in 0..meta.blocks_count {
                            let block_ssz = case_dir.join(format!("blocks_{i}.ssz_snappy"));
                            let block_yaml = case_dir.join(format!("blocks_{i}.yaml"));

                            let signed_block: SignedBeaconBlock = if block_ssz.exists() {
                                utils::read_ssz_snappy(&block_ssz)
                                    .expect(&format!("cannot find test asset (blocks_{i}.ssz_snappy)"))
                            } else if block_yaml.exists() {
                                let yaml = fs::read_to_string(&block_yaml)
                                    .expect(&format!("cannot read blocks_{i}.yaml"));
                                serde_yaml::from_str(&yaml)
                                    .expect(&format!("Failed to parse blocks_{i}.yaml"))
                            } else {
                                panic!("Missing test asset for block {i}");
                            };

                            // ``on_block`` starts a block in a later epoch from its parent state
                            // advanced to that epoch's first slot when that state was built ahead
                            // of time. That path must reach the same post-state.
                            let block_epoch = ream_consensus_misc::misc::compute_epoch_at_slot(
                                signed_block.message.slot,
                            );
                            let mut advanced = (state.get_current_epoch() < block_epoch)
                                .then(|| {
                                    let mut advanced = state.clone();
                                    advanced
                                        .process_slots(
                                            ream_consensus_misc::misc::compute_start_slot_at_epoch(
                                                block_epoch,
                                            ),
                                        )
                                        .ok()
                                        .map(|()| advanced)
                                })
                                .flatten();

                            result = state
                                .state_transition(&signed_block, true, &mock_engine)
                                .await
                                .map_err(|err| err.to_string());

                            if let Some(advanced) = &mut advanced {
                                let advanced_result = advanced
                                    .state_transition_from_epoch_start(
                                        &signed_block,
                                        true,
                                        &mock_engine,
                                    )
                                    .await;
                                assert_eq!(
                                    advanced_result.is_ok(),
                                    result.is_ok(),
                                    "advanced pre-state disagrees on block {i} in case {case_name}"
                                );
                                if result.is_ok() {
                                    assert!(
                                        *advanced == state,
                                        "advanced pre-state gives another post-state for block {i} in case {case_name}"
                                    );
                                }
                            }
                        }

                        let expected_post = utils::read_ssz_snappy::<BeaconState>(&case_dir.join("post.ssz_snappy"));

                        match (result, expected_post) {
                            (Ok(_), Ok(expected)) => {
                                assert_eq!(
                                    state, expected,
                                    "Post state mismatch in case {}",
                                    case_name
                                );
                            }
                            (Ok(_), Err(_)) => {
                                panic!("Test case {} should have failed but succeeded", case_name);
                            }
                            (Err(err), Ok(_)) => {
                                panic!(
                                    "Test case {} should have succeeded but failed, err={:?}",
                                    case_name, err
                                );
                            }
                            (Err(_), Err(_)) => {
                                // Expected: invalid operations result in an error and no post state.
                                println!(
                                    "Test case {} failed as expected, no post state available.",
                                    case_name
                                );
                            }
                        }
                    }
                }
            }
        }
    };
}
