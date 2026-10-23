use alloy_primitives::B256;
use ream_consensus_beacon::electra::beacon_block::SignedBeaconBlock;
use serde::{Deserialize, Serialize};

/// Head event.
///
/// The node has finished processing, resulting in a new head.
/// `previous_duty_dependent_root` is `get_block_root_at_slot(state,
/// compute_start_slot_at_epoch(epoch - 1) - 1)` and `current_duty_dependent_root` is
/// `get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch) - 1)`. Both dependent roots
/// use the genesis block root in the case of underflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadEvent {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    pub block: B256,
    pub state: B256,
    pub epoch_transition: bool,
    pub previous_duty_dependent_root: B256,
    pub current_duty_dependent_root: B256,
    pub execution_optimistic: bool,
}

/// Block event.
///
/// The node has received a block (from P2P or API) that is successfully imported
/// on the fork-choice `on_block` handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEvent {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    pub block: B256,
    pub execution_optimistic: bool,
}

impl BlockEvent {
    /// Ream imports a block only after the execution engine returns VALID, so it is never
    /// optimistic.
    pub fn from_block(signed_block: &SignedBeaconBlock, block_root: B256) -> Self {
        Self {
            slot: signed_block.message.slot,
            block: block_root,
            execution_optimistic: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imported_block_event_is_not_optimistic() {
        let block = SignedBeaconBlock {
            message: Default::default(),
            signature: Default::default(),
        };

        let event = BlockEvent::from_block(&block, B256::repeat_byte(1));

        assert!(!event.execution_optimistic);
    }
}

/// Finalized checkpoint event.
///
/// Emitted when the finalized checkpoint has been updated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizedCheckpointEvent {
    pub block: B256,
    pub state: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub epoch: u64,
    pub execution_optimistic: bool,
}

/// Chain reorg event.
///
/// Emitted when the chain has been reorganized, resulting in a different canonical head.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainReorgEvent {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub depth: u64,
    pub old_head_block: B256,
    pub new_head_block: B256,
    pub old_head_state: B256,
    pub new_head_state: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub epoch: u64,
    pub execution_optimistic: bool,
}

/// Block gossip event.
///
/// The node has received a block (from P2P or API) that passes validation rules
/// of the beacon_block topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockGossipEvent {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    pub block: B256,
}
