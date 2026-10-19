use std::path::Path;

use ream_consensus_beacon::custody_group::{CustodyAssignment, CustodyConfig};
use ream_network_spec::networks::beacon_network_spec;
use ream_p2p::network::beacon::{identity::local_node_id, utils::read_meta_data_from_disk};
use tracing::warn;

/// The custody of the local node: every custody group for a supernode, otherwise
/// `CUSTODY_REQUIREMENT` groups (fulu das-core.md, "Custody setting"). The groups follow from the
/// node id of the network key in `data_dir`, so the chain and the network derive the same ones.
///
/// The node keeps the custody group count it advertised before, which the MetaData in `data_dir`
/// records. Peers expect it to serve those columns, so the count is never lowered (fulu
/// validator.md, "Validator custody").
pub fn local_custody_assignment(
    data_dir: &Path,
    supernode: bool,
) -> anyhow::Result<CustodyAssignment> {
    let config = CustodyConfig::from_network_spec(&beacon_network_spec())?;
    let configured = if supernode {
        config.number_of_custody_groups()
    } else {
        config.custody_requirement()
    };
    let advertised = match read_meta_data_from_disk(data_dir.to_path_buf()) {
        Ok(meta_data) => meta_data
            .custody_group_count
            .min(config.number_of_custody_groups()),
        Err(err) => {
            warn!("Failed to read the advertised custody group count: {err:?}");
            0
        }
    };
    if advertised > configured {
        warn!(
            advertised,
            configured,
            "The node keeps the custody group count it advertised before; a lower count needs a \
             new data dir"
        );
    }
    CustodyAssignment::new(
        local_node_id(data_dir)?,
        configured.max(advertised),
        &config,
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use ream_network_spec::networks::initialize_test_network_spec;
    use ream_p2p::network::beacon::utils::META_DATA_FILE_NAME;
    use ream_req_resp::beacon::messages::meta_data::GetMetaDataV3;
    use ssz::Encode;

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

    #[test]
    fn a_node_keeps_the_custody_group_count_it_advertised() {
        initialize_test_network_spec();
        let spec = beacon_network_spec();
        let data_dir = tempfile::tempdir().unwrap();
        let advertise = |custody_group_count| {
            fs::write(
                data_dir.path().join(META_DATA_FILE_NAME),
                GetMetaDataV3 {
                    custody_group_count,
                    ..Default::default()
                }
                .as_ssz_bytes(),
            )
            .unwrap();
        };

        // A data dir that ran as a supernode stays one without `--supernode`.
        advertise(spec.number_of_custody_groups);
        assert_eq!(
            local_custody_assignment(data_dir.path(), false)
                .unwrap()
                .custody_group_count,
            spec.number_of_custody_groups
        );

        // A custody node that turns into a supernode custodies every group.
        advertise(spec.custody_requirement);
        assert_eq!(
            local_custody_assignment(data_dir.path(), true)
                .unwrap()
                .custody_group_count,
            spec.number_of_custody_groups
        );
    }
}
