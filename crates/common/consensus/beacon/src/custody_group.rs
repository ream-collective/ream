use alloy_primitives::U256;
use anyhow::{Ok, Result, anyhow, ensure};
use discv5::enr::NodeId;
use ream_consensus_misc::constants::beacon::NUM_CUSTODY_GROUPS;
use ream_network_spec::networks::beacon::{BeaconNetworkSpec, beacon_network_spec};
use sha2::{Digest, Sha256};

use crate::{
    data_column_sidecar::{DATA_COLUMN_SIDECAR_SUBNET_COUNT, NUMBER_OF_COLUMNS},
    electra::beacon_state::BeaconState,
};

pub fn get_validators_custody_requirement(
    state: &BeaconState,
    validator_indices: &[u64],
) -> Result<u64> {
    let mut total_node_balance = 0u128;
    for validator_index in validator_indices {
        let validator = state
            .validators
            .get(*validator_index as usize)
            .ok_or_else(|| anyhow!("Validator index out of bounds: {validator_index}"))?;
        total_node_balance += validator.effective_balance as u128;
    }

    let spec = beacon_network_spec();
    Ok(compute_validators_custody_requirement(
        total_node_balance,
        spec.balance_per_additional_custody_group,
        spec.validator_custody_requirement,
        spec.number_of_custody_groups,
    ))
}

fn compute_validators_custody_requirement(
    total_node_balance: u128,
    balance_per_additional_custody_group: u64,
    validator_custody_requirement: u64,
    number_of_custody_groups: u64,
) -> u64 {
    let count = total_node_balance / balance_per_additional_custody_group as u128;
    let count = count.min(number_of_custody_groups as u128) as u64;
    count
        .max(validator_custody_requirement)
        .min(number_of_custody_groups)
}

pub fn get_custody_group_indices(node_id: NodeId, custody_group_count: u64) -> Result<Vec<u64>> {
    ensure!(
        custody_group_count <= NUM_CUSTODY_GROUPS,
        "Custody group count more than number of custody groups"
    );

    if custody_group_count == NUM_CUSTODY_GROUPS {
        return Ok((0..NUM_CUSTODY_GROUPS).collect());
    }

    let mut custody_indices = Vec::new();
    // The spec's `NodeID` is a uint256 whose big-endian encoding is the discv5 node id, while
    // `uint_to_bytes(current_id)` serializes it little-endian before hashing.
    let mut current_id = U256::from_be_bytes(node_id.raw());

    while custody_indices.len() < custody_group_count as usize {
        let hash = Sha256::digest(current_id.to_le_bytes::<32>());

        let mut array = [0u8; 8];
        array.copy_from_slice(&hash[0..8]);
        let index = u64::from_le_bytes(array) % NUM_CUSTODY_GROUPS;

        if !custody_indices.contains(&index) {
            custody_indices.push(index);
        }

        // Wraps from UINT256_MAX to 0, as the spec's overflow prevention does.
        current_id = current_id.wrapping_add(U256::from(1));
    }
    custody_indices.sort();
    Ok(custody_indices)
}

pub fn compute_columns_for_custody_group(custody_group_index: u64) -> Result<Vec<u64>> {
    ensure!(
        custody_group_index < NUM_CUSTODY_GROUPS,
        "Custody group index is greater than total custody groups"
    );

    let mut column_indices = Vec::new();
    for column in 0..NUMBER_OF_COLUMNS {
        if column % NUM_CUSTODY_GROUPS == custody_group_index {
            column_indices.push(column);
        }
    }

    Ok(column_indices)
}

pub fn compute_subnet_for_data_column_sidecar(column_index: u64) -> u64 {
    column_index % DATA_COLUMN_SIDECAR_SUBNET_COUNT
}

/// Fulu custody settings taken from the network configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustodyConfig {
    number_of_custody_groups: u64,
    custody_requirement: u64,
    samples_per_slot: u64,
}

impl CustodyConfig {
    /// Used for every node, whatever its custody group count. Returns an error if the network
    /// config sets the network-wide totals `NUMBER_OF_CUSTODY_GROUPS` or
    /// `DATA_COLUMN_SIDECAR_SUBNET_COUNT` to anything other than 128. The custody helpers and
    /// gossip subnet mapping are hardcoded to 128, so other values would silently produce wrong
    /// assignments.
    pub fn from_network_spec(spec: &BeaconNetworkSpec) -> Result<Self> {
        ensure!(
            spec.number_of_custody_groups == NUM_CUSTODY_GROUPS,
            "Unsupported NUMBER_OF_CUSTODY_GROUPS {}, expected {NUM_CUSTODY_GROUPS}",
            spec.number_of_custody_groups
        );
        ensure!(
            spec.data_column_sidecar_subnet_count == DATA_COLUMN_SIDECAR_SUBNET_COUNT,
            "Unsupported DATA_COLUMN_SIDECAR_SUBNET_COUNT {}, expected {DATA_COLUMN_SIDECAR_SUBNET_COUNT}",
            spec.data_column_sidecar_subnet_count
        );
        ensure!(
            spec.custody_requirement <= spec.number_of_custody_groups,
            "CUSTODY_REQUIREMENT {} exceeds NUMBER_OF_CUSTODY_GROUPS {}",
            spec.custody_requirement,
            spec.number_of_custody_groups
        );
        ensure!(
            spec.samples_per_slot <= spec.number_of_custody_groups,
            "SAMPLES_PER_SLOT {} exceeds NUMBER_OF_CUSTODY_GROUPS {}",
            spec.samples_per_slot,
            spec.number_of_custody_groups
        );

        Ok(Self {
            number_of_custody_groups: spec.number_of_custody_groups,
            custody_requirement: spec.custody_requirement,
            samples_per_slot: spec.samples_per_slot,
        })
    }

    pub fn sampling_size(&self, custody_group_count: u64) -> u64 {
        self.samples_per_slot.max(custody_group_count)
    }
}

/// The custody groups and columns a node stores and serves, the larger set it samples each slot,
/// and the data column subnets it must subscribe to for sampling. All lists are sorted and
/// deduplicated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyAssignment {
    pub custody_group_count: u64,
    pub sampling_size: u64,
    pub custody_groups: Vec<u64>,
    pub custody_columns: Vec<u64>,
    pub sampling_groups: Vec<u64>,
    pub sampling_columns: Vec<u64>,
    pub data_column_subnet_ids: Vec<u64>,
}

impl CustodyAssignment {
    /// `custody_group_count` must be between `CUSTODY_REQUIREMENT` and
    /// `NUMBER_OF_CUSTODY_GROUPS`, because an honest node custodies at least
    /// `CUSTODY_REQUIREMENT` groups.
    pub fn new(node_id: NodeId, custody_group_count: u64, config: &CustodyConfig) -> Result<Self> {
        ensure!(
            custody_group_count >= config.custody_requirement,
            "Custody group count {custody_group_count} is below CUSTODY_REQUIREMENT {}",
            config.custody_requirement
        );
        ensure!(
            custody_group_count <= config.number_of_custody_groups,
            "Custody group count {custody_group_count} exceeds NUMBER_OF_CUSTODY_GROUPS {}",
            config.number_of_custody_groups
        );

        let sampling_size = config.sampling_size(custody_group_count);
        let custody_groups = get_custody_group_indices(node_id, custody_group_count)?;
        let sampling_groups = get_custody_group_indices(node_id, sampling_size)?;
        let custody_columns = compute_columns_for_custody_groups(&custody_groups)?;
        let sampling_columns = compute_columns_for_custody_groups(&sampling_groups)?;

        let mut data_column_subnet_ids = sampling_columns
            .iter()
            .map(|column| compute_subnet_for_data_column_sidecar(*column))
            .collect::<Vec<_>>();
        data_column_subnet_ids.sort_unstable();
        data_column_subnet_ids.dedup();

        Ok(Self {
            custody_group_count,
            sampling_size,
            custody_groups,
            custody_columns,
            sampling_groups,
            sampling_columns,
            data_column_subnet_ids,
        })
    }
}

fn compute_columns_for_custody_groups(custody_groups: &[u64]) -> Result<Vec<u64>> {
    let mut columns = Vec::new();
    for custody_group in custody_groups {
        columns.extend(compute_columns_for_custody_group(*custody_group)?);
    }
    columns.sort_unstable();
    Ok(columns)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;
    use discv5::enr::NodeId;
    use ream_network_spec::networks::beacon::{BeaconNetworkSpec, DEV, HOODI, MAINNET, SEPOLIA};

    use super::{
        CustodyAssignment, CustodyConfig, compute_columns_for_custody_group,
        compute_subnet_for_data_column_sidecar, compute_validators_custody_requirement,
        get_custody_group_indices,
    };

    const BALANCE_PER_ADDITIONAL_CUSTODY_GROUP: u64 = 32_000_000_000;
    const VALIDATOR_CUSTODY_REQUIREMENT: u64 = 8;
    const NUMBER_OF_CUSTODY_GROUPS: u64 = 128;

    fn compute(total_node_balance: u128) -> u64 {
        compute_validators_custody_requirement(
            total_node_balance,
            BALANCE_PER_ADDITIONAL_CUSTODY_GROUP,
            VALIDATOR_CUSTODY_REQUIREMENT,
            NUMBER_OF_CUSTODY_GROUPS,
        )
    }

    #[test]
    fn custody_requirement_matches_consensus_spec_boundaries() {
        let balance_per_group = BALANCE_PER_ADDITIONAL_CUSTODY_GROUP as u128;
        let cases = [
            (0, VALIDATOR_CUSTODY_REQUIREMENT),
            (8 * balance_per_group - 1, VALIDATOR_CUSTODY_REQUIREMENT),
            (8 * balance_per_group, VALIDATOR_CUSTODY_REQUIREMENT),
            (9 * balance_per_group, 9),
            (10 * balance_per_group, 10),
            (
                NUMBER_OF_CUSTODY_GROUPS as u128 * balance_per_group,
                NUMBER_OF_CUSTODY_GROUPS,
            ),
            (
                (NUMBER_OF_CUSTODY_GROUPS as u128 + 1) * balance_per_group,
                NUMBER_OF_CUSTODY_GROUPS,
            ),
        ];

        for (total_node_balance, expected) in cases {
            assert_eq!(compute(total_node_balance), expected);
        }
    }

    // Big-endian encoding of the uint256 used in the vectors below.
    const ORDINARY_NODE_ID: &str =
        "8b9a3c1f0e7d6a5b4c3d2e1f00112233445566778899aabbccddeeff01234567";

    fn node_id(value: U256) -> NodeId {
        NodeId::new(&value.to_be_bytes::<32>())
    }

    fn ordinary_node_id() -> NodeId {
        node_id(U256::from_str_radix(ORDINARY_NODE_ID, 16).expect("valid hex"))
    }

    fn mainnet_config() -> CustodyConfig {
        CustodyConfig::from_network_spec(&MAINNET).expect("mainnet custody config is valid")
    }

    fn all_indices() -> Vec<u64> {
        (0..128).collect()
    }

    // Expected values come from a direct transcription of `get_custody_groups` in
    // consensus-specs fulu/das-core.md (hashlib.sha256, little-endian uint_to_bytes,
    // UINT256_MAX wrapping to 0), independent of this implementation.
    #[test]
    fn custody_groups_match_spec_vectors() {
        let cases: [(NodeId, u64, &[u64]); 24] = [
            (node_id(U256::ZERO), 1, &[102]),
            (node_id(U256::ZERO), 4, &[1, 17, 87, 102]),
            (node_id(U256::ZERO), 8, &[1, 17, 19, 42, 75, 87, 102, 117]),
            (
                node_id(U256::ZERO),
                16,
                &[
                    1, 6, 17, 19, 23, 26, 27, 42, 44, 52, 75, 87, 93, 102, 117, 124,
                ],
            ),
            (node_id(U256::from(1)), 1, &[1]),
            (node_id(U256::from(1)), 4, &[1, 17, 75, 87]),
            (node_id(U256::from(1)), 8, &[1, 6, 17, 19, 42, 75, 87, 117]),
            (
                node_id(U256::from(1)),
                16,
                &[
                    1, 6, 17, 19, 23, 26, 27, 42, 44, 52, 75, 86, 87, 93, 117, 124,
                ],
            ),
            (node_id(U256::from(1_048_576)), 1, &[65]),
            (node_id(U256::from(1_048_576)), 4, &[37, 55, 65, 118]),
            (
                node_id(U256::from(1_048_576)),
                8,
                &[4, 30, 37, 55, 65, 86, 95, 118],
            ),
            (
                node_id(U256::from(1_048_576)),
                16,
                &[
                    4, 25, 29, 30, 35, 37, 41, 47, 55, 65, 74, 86, 91, 95, 103, 118,
                ],
            ),
            (node_id(U256::MAX - U256::from(1)), 1, &[1]),
            (node_id(U256::MAX - U256::from(1)), 4, &[1, 47, 87, 102]),
            (
                node_id(U256::MAX - U256::from(1)),
                8,
                &[1, 17, 19, 42, 47, 75, 87, 102],
            ),
            (
                node_id(U256::MAX - U256::from(1)),
                16,
                &[
                    1, 6, 17, 19, 23, 26, 27, 42, 44, 47, 52, 75, 87, 93, 102, 117,
                ],
            ),
            (node_id(U256::MAX), 1, &[47]),
            (node_id(U256::MAX), 4, &[1, 47, 87, 102]),
            (node_id(U256::MAX), 8, &[1, 17, 19, 42, 47, 75, 87, 102]),
            (
                node_id(U256::MAX),
                16,
                &[
                    1, 6, 17, 19, 23, 26, 27, 42, 44, 47, 52, 75, 87, 93, 102, 117,
                ],
            ),
            (ordinary_node_id(), 1, &[9]),
            (ordinary_node_id(), 4, &[9, 37, 48, 62]),
            (ordinary_node_id(), 8, &[9, 37, 48, 62, 82, 83, 98, 110]),
            (
                ordinary_node_id(),
                16,
                &[
                    1, 7, 9, 26, 37, 43, 48, 62, 67, 82, 83, 84, 89, 98, 109, 110,
                ],
            ),
        ];

        for (node_id, custody_group_count, expected) in cases {
            assert_eq!(
                get_custody_group_indices(node_id, custody_group_count).expect("valid count"),
                expected,
                "node_id={node_id}, custody_group_count={custody_group_count}"
            );
        }
    }

    #[test]
    fn custody_groups_count_boundaries() {
        for value in [U256::ZERO, U256::MAX - U256::from(1), U256::MAX] {
            let node_id = node_id(value);
            assert!(
                get_custody_group_indices(node_id, 0)
                    .expect("zero is a legal helper count")
                    .is_empty()
            );
            assert_eq!(
                get_custody_group_indices(node_id, 128).expect("max count"),
                all_indices()
            );
            assert!(get_custody_group_indices(node_id, 129).is_err());
            assert!(get_custody_group_indices(node_id, u64::MAX).is_err());
        }
    }

    #[test]
    fn custody_groups_are_deterministic_unique_and_nested() {
        for node_id in [
            node_id(U256::ZERO),
            node_id(U256::MAX),
            node_id(U256::MAX - U256::from(1)),
            ordinary_node_id(),
        ] {
            let mut previous = Vec::new();
            for custody_group_count in 0..=128 {
                let groups =
                    get_custody_group_indices(node_id, custody_group_count).expect("valid count");
                assert_eq!(
                    groups,
                    get_custody_group_indices(node_id, custody_group_count).expect("valid count")
                );
                assert_eq!(groups.len() as u64, custody_group_count);
                assert!(groups.windows(2).all(|pair| pair[0] < pair[1]));
                assert!(groups.iter().all(|group| *group < 128));
                assert!(previous.iter().all(|group| groups.contains(group)));
                previous = groups;
            }
        }
    }

    #[test]
    fn columns_for_custody_group_match_spec() {
        assert_eq!(
            compute_columns_for_custody_group(0).expect("min group"),
            [0]
        );
        assert_eq!(
            compute_columns_for_custody_group(127).expect("max group"),
            [127]
        );
        assert!(compute_columns_for_custody_group(128).is_err());

        let mut all_columns = Vec::new();
        for group in 0..128 {
            // NUMBER_OF_CUSTODY_GROUPS * i + group for i in range(NUMBER_OF_COLUMNS // 128)
            assert_eq!(
                compute_columns_for_custody_group(group).expect("valid group"),
                [group]
            );
            all_columns.extend(compute_columns_for_custody_group(group).expect("valid group"));
        }
        assert_eq!(all_columns, all_indices());
    }

    #[test]
    fn subnet_for_data_column_matches_spec() {
        assert_eq!(compute_subnet_for_data_column_sidecar(0), 0);
        assert_eq!(compute_subnet_for_data_column_sidecar(127), 127);
        assert_eq!(compute_subnet_for_data_column_sidecar(128), 0);
        assert_eq!(compute_subnet_for_data_column_sidecar(255), 127);
    }

    #[test]
    fn custody_config_is_valid_for_supported_networks() {
        let config = mainnet_config();
        for spec in [&*SEPOLIA, &*HOODI, &*DEV] {
            assert_eq!(
                CustodyConfig::from_network_spec(spec).expect("valid config"),
                config
            );
        }
        assert_eq!(config.sampling_size(4), 8);
        assert_eq!(config.sampling_size(8), 8);
        assert_eq!(config.sampling_size(9), 9);
        assert_eq!(config.sampling_size(128), 128);
    }

    #[test]
    fn custody_config_rejects_unsupported_values() {
        let mutations: [fn(&mut BeaconNetworkSpec); 4] = [
            |spec| spec.number_of_custody_groups = 64,
            |spec| spec.data_column_sidecar_subnet_count = 64,
            |spec| spec.custody_requirement = 129,
            |spec| spec.samples_per_slot = 129,
        ];
        for mutate in mutations {
            let mut spec = (**MAINNET).clone();
            mutate(&mut spec);
            assert!(CustodyConfig::from_network_spec(&spec).is_err());
        }
    }

    #[test]
    fn assignment_matches_spec_vectors_for_current_configuration() {
        let config = mainnet_config();
        let node_id = ordinary_node_id();

        let cgc_4 = CustodyAssignment::new(node_id, 4, &config).expect("cgc 4");
        let sampled = vec![9, 37, 48, 62, 82, 83, 98, 110];
        assert_eq!(cgc_4.custody_group_count, 4);
        assert_eq!(cgc_4.sampling_size, 8);
        assert_eq!(cgc_4.custody_groups, [9, 37, 48, 62]);
        assert_eq!(cgc_4.custody_columns, [9, 37, 48, 62]);
        assert_eq!(cgc_4.sampling_groups, sampled);
        assert_eq!(cgc_4.sampling_columns, sampled);
        assert_eq!(cgc_4.data_column_subnet_ids, sampled);

        let cgc_8 = CustodyAssignment::new(node_id, 8, &config).expect("cgc 8");
        assert_eq!(cgc_8.sampling_size, 8);
        assert_eq!(cgc_8.custody_groups, sampled);
        assert_eq!(cgc_8.custody_columns, sampled);
        assert_eq!(cgc_8.sampling_groups, sampled);
        assert_eq!(cgc_8.sampling_columns, sampled);
        assert_eq!(cgc_8.data_column_subnet_ids, sampled);

        // Full custody: every group, column and subnet.
        let cgc_128 = CustodyAssignment::new(node_id, 128, &config).expect("cgc 128");
        assert_eq!(cgc_128.sampling_size, 128);
        assert_eq!(cgc_128.custody_groups, all_indices());
        assert_eq!(cgc_128.custody_columns, all_indices());
        assert_eq!(cgc_128.sampling_groups, all_indices());
        assert_eq!(cgc_128.sampling_columns, all_indices());
        assert_eq!(cgc_128.data_column_subnet_ids, all_indices());
    }

    #[test]
    fn assignment_enforces_node_custody_policy() {
        let config = mainnet_config();
        let node_id = ordinary_node_id();

        assert!(CustodyAssignment::new(node_id, 0, &config).is_err());
        assert!(CustodyAssignment::new(node_id, 3, &config).is_err());
        assert!(CustodyAssignment::new(node_id, 4, &config).is_ok());
        assert!(CustodyAssignment::new(node_id, 128, &config).is_ok());
        assert!(CustodyAssignment::new(node_id, 129, &config).is_err());
    }

    #[test]
    fn assignment_custody_is_subset_of_sampling() {
        let config = mainnet_config();
        for node_id in [
            node_id(U256::ZERO),
            node_id(U256::MAX - U256::from(1)),
            node_id(U256::MAX),
            ordinary_node_id(),
        ] {
            for custody_group_count in 4..=128 {
                let assignment = CustodyAssignment::new(node_id, custody_group_count, &config)
                    .expect("valid count");
                assert_eq!(
                    assignment,
                    CustodyAssignment::new(node_id, custody_group_count, &config)
                        .expect("valid count")
                );
                assert_eq!(assignment.sampling_size, custody_group_count.max(8));
                assert_eq!(
                    assignment.sampling_groups.len() as u64,
                    assignment.sampling_size
                );
                assert!(
                    assignment
                        .custody_groups
                        .iter()
                        .all(|group| assignment.sampling_groups.contains(group))
                );
                assert!(
                    assignment
                        .custody_columns
                        .iter()
                        .all(|column| assignment.sampling_columns.contains(column))
                );

                let mut expected_subnets = assignment
                    .sampling_columns
                    .iter()
                    .map(|column| column % 128)
                    .collect::<Vec<_>>();
                expected_subnets.sort_unstable();
                expected_subnets.dedup();
                assert_eq!(assignment.data_column_subnet_ids, expected_subnets);
                assert!(
                    assignment
                        .data_column_subnet_ids
                        .windows(2)
                        .all(|pair| pair[0] < pair[1])
                );
            }
        }
    }
}
