use std::path::Path;

use discv5::enr::NodeId;
use ream_consensus_beacon::{
    custody_group::{CustodyAssignment, CustodyConfig, get_validators_custody_requirement},
    electra::beacon_state::BeaconState,
};
use ream_consensus_misc::misc::compute_epoch_at_slot;
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

/// Slots given to join the new subnets before blocks wait for a larger sampled set. Lighthouse
/// waits 30 s (`CUSTODY_CHANGE_DA_EFFECTIVE_DELAY_SECONDS`) and then switches at the next epoch.
const CUSTODY_CHANGE_DELAY_SLOTS: u64 = 3;

/// What the node must change after `ValidatorCustody::on_slot`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CustodyChange {
    /// A larger custody to advertise and subscribe to now.
    pub raised: Option<CustodyAssignment>,
    /// The sampled columns blocks wait for from now on.
    pub sampling_columns: Option<Vec<u64>>,
}

/// Validator custody (fulu validator.md, "Validator custody"): a node with validators attached
/// custodies `get_validators_custody_requirement` groups, at least `VALIDATOR_CUSTODY_REQUIREMENT`,
/// and the count never decreases. The attached validators are those that prepared to propose
/// through this node, which a validator client does every epoch.
pub struct ValidatorCustody {
    node_id: NodeId,
    config: CustodyConfig,
    custody_group_count: u64,
    /// A raised sampled set and the epoch from which blocks wait for it.
    pending_sampling: Option<(u64, Vec<u64>)>,
}

impl ValidatorCustody {
    pub fn new(node_id: NodeId, custody: &CustodyAssignment) -> anyhow::Result<Self> {
        Ok(Self {
            node_id,
            config: CustodyConfig::from_network_spec(&beacon_network_spec())?,
            custody_group_count: custody.custody_group_count,
            pending_sampling: None,
        })
    }

    /// Raises the custody to `validator_custody_requirement` when it is larger. A raise is
    /// advertised at once, and blocks wait for its sampled columns from the epoch after
    /// `CUSTODY_CHANGE_DELAY_SLOTS`, so that gossip has delivered them by then.
    pub fn on_slot(
        &mut self,
        slot: u64,
        validator_custody_requirement: Option<u64>,
    ) -> anyhow::Result<CustodyChange> {
        let mut change = CustodyChange::default();
        if self
            .pending_sampling
            .as_ref()
            .is_some_and(|(epoch, _)| compute_epoch_at_slot(slot) >= *epoch)
        {
            change.sampling_columns = self.pending_sampling.take().map(|(_, columns)| columns);
        }

        let Some(required) = validator_custody_requirement else {
            return Ok(change);
        };
        if required <= self.custody_group_count {
            return Ok(change);
        }

        let custody = CustodyAssignment::new(self.node_id, required, &self.config)?;
        self.custody_group_count = required;
        self.pending_sampling = Some((
            compute_epoch_at_slot(slot + CUSTODY_CHANGE_DELAY_SLOTS) + 1,
            custody.sampling_columns.clone(),
        ));
        change.raised = Some(custody);
        Ok(change)
    }

    pub fn has_pending_sampling(&self) -> bool {
        self.pending_sampling.is_some()
    }
}

/// `get_validators_custody_requirement` for the attached validators, from their effective
/// balances in `state`. Returns `None` without validators. An index the state does not know yet
/// is skipped until the state includes it.
pub fn attached_validators_custody_requirement(
    state: &BeaconState,
    validator_indices: &[u64],
) -> anyhow::Result<Option<u64>> {
    let validator_indices = validator_indices
        .iter()
        .copied()
        .filter(|index| (*index as usize) < state.validators.len())
        .collect::<Vec<_>>();
    if validator_indices.is_empty() {
        return Ok(None);
    }
    get_validators_custody_requirement(state, &validator_indices).map(Some)
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
    fn attached_validators_raise_the_custody_from_the_next_epoch() {
        initialize_test_network_spec();
        let spec = beacon_network_spec();
        let data_dir = tempfile::tempdir().unwrap();
        let node_id = local_node_id(data_dir.path()).unwrap();
        let custody = local_custody_assignment(data_dir.path(), false).unwrap();
        let mut validator_custody = ValidatorCustody::new(node_id, &custody).unwrap();

        // No validators: nothing changes.
        assert_eq!(
            validator_custody.on_slot(64, None).unwrap(),
            CustodyChange::default()
        );

        // The first validators raise the advertised count at once.
        let change = validator_custody
            .on_slot(64, Some(spec.validator_custody_requirement))
            .unwrap();
        let raised = change.raised.expect("the custody grows");
        assert_eq!(
            raised.custody_group_count,
            spec.validator_custody_requirement
        );
        assert_eq!(change.sampling_columns, None);
        // The same requirement does not raise it again.
        assert_eq!(
            validator_custody
                .on_slot(65, Some(spec.validator_custody_requirement))
                .unwrap(),
            CustodyChange::default()
        );

        // Blocks wait for the larger sampled set from the epoch after the delay: slot 64 + 3 is
        // in epoch 2, so the set applies from epoch 3.
        assert_eq!(
            validator_custody
                .on_slot(95, None)
                .unwrap()
                .sampling_columns,
            None
        );
        assert_eq!(
            validator_custody
                .on_slot(96, None)
                .unwrap()
                .sampling_columns,
            Some(raised.sampling_columns.clone())
        );
        assert!(!validator_custody.has_pending_sampling());

        // A lower requirement never lowers the count, and a larger one raises it again.
        assert_eq!(
            validator_custody
                .on_slot(97, Some(spec.custody_requirement))
                .unwrap(),
            CustodyChange::default()
        );
        let all = validator_custody
            .on_slot(97, Some(spec.number_of_custody_groups))
            .unwrap()
            .raised
            .expect("the custody grows to every group");
        assert_eq!(all.sampling_columns, (0..128).collect::<Vec<_>>());
        // Sampled columns only grow, so blocks keep waiting for every column they waited for.
        assert!(
            raised
                .sampling_columns
                .iter()
                .all(|column| all.sampling_columns.contains(column))
        );
    }

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
