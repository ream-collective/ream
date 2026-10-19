use std::path::Path;

use ream_consensus_beacon::custody_group::{CustodyAssignment, CustodyConfig};
use ream_network_spec::networks::beacon_network_spec;
use ream_p2p::network::beacon::identity::local_node_id;

/// The custody of the local node: every custody group for a supernode, otherwise
/// `CUSTODY_REQUIREMENT` groups (fulu das-core.md, "Custody setting"). The groups follow from the
/// node id of the network key in `data_dir`, so the chain and the network derive the same ones.
pub fn local_custody_assignment(
    data_dir: &Path,
    supernode: bool,
) -> anyhow::Result<CustodyAssignment> {
    let config = CustodyConfig::from_network_spec(&beacon_network_spec())?;
    let custody_group_count = if supernode {
        config.number_of_custody_groups()
    } else {
        config.custody_requirement()
    };
    CustodyAssignment::new(local_node_id(data_dir)?, custody_group_count, &config)
}

#[cfg(test)]
mod tests {
    use ream_network_spec::networks::initialize_test_network_spec;

    use super::*;

    #[test]
    fn a_node_custodies_the_requirement_unless_it_is_a_supernode() {
        initialize_test_network_spec();
        let spec = beacon_network_spec();
        let data_dir = tempfile::tempdir().unwrap();

        let custody = local_custody_assignment(data_dir.path(), false).unwrap();
        assert_eq!(custody.custody_group_count, spec.custody_requirement);
        assert_eq!(
            custody.sampling_columns.len() as u64,
            spec.samples_per_slot.max(spec.custody_requirement)
        );
        assert_eq!(
            custody.data_column_subnet_ids.len(),
            custody.sampling_columns.len()
        );
        // The network key is reused, so the assignment is stable across restarts.
        assert_eq!(
            local_custody_assignment(data_dir.path(), false).unwrap(),
            custody
        );

        let supernode = local_custody_assignment(data_dir.path(), true).unwrap();
        assert_eq!(supernode.custody_group_count, spec.number_of_custody_groups);
        assert_eq!(supernode.sampling_columns, (0..128).collect::<Vec<_>>());
    }
}
