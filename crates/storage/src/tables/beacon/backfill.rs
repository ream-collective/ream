//! Durable bootstrap provenance and historical coverage. No live fork-choice state belongs here.
use alloy_primitives::B256;
use redb::TableDefinition;
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};

pub(crate) const BOOTSTRAP: TableDefinition<&str, &[u8]> = TableDefinition::new("beacon_bootstrap");
pub(crate) const META: &str = "backfill_meta";
pub(crate) const GVR: &str = "genesis_validators_root";
pub(crate) const MARKER: &str = "mode";
pub(crate) const IN_PROGRESS: &str = "in_progress";

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BackfillMeta {
    pub revision: u64,
    pub origin: Origin,
    pub blocks: BlockCoverage,
    pub sidecars: SidecarCoverage,
}

impl BackfillMeta {
    /// First slot from which every required sidecar at or below the origin is held. Above the
    /// origin, forward import only accepts blocks whose sidecars are already durable.
    pub fn sidecars_available_from(&self) -> u64 {
        self.sidecars
            .frontier
            .unwrap_or_else(|| self.origin.slot.saturating_add(1))
    }

    /// The Status `earliest_available_slot`: the oldest block held, unless required sidecars
    /// are still missing inside the retention window starting at `sidecar_retention_start_slot`,
    /// in which case it is the slot from which blocks and sidecars are both complete.
    ///
    /// Unconfirmed anchor sidecars always count as missing: anchor recovery confirms them
    /// itself once the anchor leaves the window.
    pub fn earliest_available_slot(&self, sidecar_retention_start_slot: u64) -> u64 {
        let blocks_from = self.blocks.frontier.oldest_block_slot;
        match self.sidecars.frontier {
            Some(sidecars_from) if sidecars_from <= sidecar_retention_start_slot => blocks_from,
            _ => blocks_from.max(self.sidecars_available_from()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Origin {
    pub slot: u64,
    pub root: B256,
    pub state_root: B256,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BlockCoverage {
    pub frontier: Frontier,
    pub state: BlockBackfillState,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Frontier {
    pub oldest_block_slot: u64,
    pub oldest_block_root: B256,
    pub oldest_block_parent: B256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockBackfillState {
    InProgress,
    BlocksComplete,
    UnsupportedForkBoundary { boundary_slot: u64 },
}

// Stable fixed-width disk representation, with reserved zero payload for states without a slot.
impl Encode for BlockBackfillState {
    fn is_ssz_fixed_len() -> bool {
        true
    }
    fn ssz_fixed_len() -> usize {
        9
    }
    fn ssz_bytes_len(&self) -> usize {
        9
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let (tag, slot) = match self {
            Self::InProgress => (0u8, 0u64),
            Self::BlocksComplete => (1, 0),
            Self::UnsupportedForkBoundary { boundary_slot } => (2, *boundary_slot),
        };
        tag.ssz_append(buf);
        slot.ssz_append(buf);
    }
}
impl Decode for BlockBackfillState {
    fn is_ssz_fixed_len() -> bool {
        true
    }
    fn ssz_fixed_len() -> usize {
        9
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != 9 {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: 9,
            });
        }
        let slot = u64::from_ssz_bytes(&bytes[1..])?;
        match (bytes[0], slot) {
            (0, 0) => Ok(Self::InProgress),
            (1, 0) => Ok(Self::BlocksComplete),
            (2, boundary_slot) => Ok(Self::UnsupportedForkBoundary { boundary_slot }),
            _ => Err(DecodeError::BytesInvalid("Invalid backfill state".into())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct SidecarCoverage {
    pub frontier: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackfillMode {
    Checkpoint(BackfillMeta),
    GenesisSynced,
    Legacy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_ssz_round_trip_and_reject_invalid_state_tags() {
        let mut meta = BackfillMeta {
            revision: 7,
            origin: Origin {
                slot: 64,
                root: B256::repeat_byte(1),
                state_root: B256::repeat_byte(2),
            },
            blocks: BlockCoverage {
                frontier: Frontier {
                    oldest_block_slot: 32,
                    oldest_block_root: B256::repeat_byte(3),
                    oldest_block_parent: B256::repeat_byte(4),
                },
                state: BlockBackfillState::InProgress,
            },
            sidecars: SidecarCoverage { frontier: Some(48) },
        };
        for state in [
            BlockBackfillState::InProgress,
            BlockBackfillState::BlocksComplete,
            BlockBackfillState::UnsupportedForkBoundary { boundary_slot: 32 },
        ] {
            meta.blocks.state = state;
            for frontier in [None, Some(48)] {
                meta.sidecars.frontier = frontier;
                assert_eq!(
                    BackfillMeta::from_ssz_bytes(&meta.as_ssz_bytes()).unwrap(),
                    meta
                );
            }
        }
        assert!(BlockBackfillState::from_ssz_bytes(&[9; 9]).is_err());
        assert!(BlockBackfillState::from_ssz_bytes(&[0, 1, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn earliest_available_slot_never_covers_missing_sidecars_in_retention() {
        let mut meta = BackfillMeta {
            revision: 0,
            origin: Origin {
                slot: 640,
                root: B256::repeat_byte(1),
                state_root: B256::repeat_byte(2),
            },
            blocks: BlockCoverage {
                frontier: Frontier {
                    oldest_block_slot: 640,
                    oldest_block_root: B256::repeat_byte(1),
                    oldest_block_parent: B256::repeat_byte(4),
                },
                state: BlockBackfillState::InProgress,
            },
            sidecars: SidecarCoverage { frontier: None },
        };

        // Anchor sidecars pending: nothing at or below the origin is complete yet.
        assert_eq!(meta.earliest_available_slot(320), 641);
        meta.sidecars.frontier = Some(640);
        assert_eq!(meta.earliest_available_slot(320), 640);

        // Blocks backfilled below sidecar coverage inside the retention window do not lower it.
        meta.blocks.frontier.oldest_block_slot = 400;
        assert_eq!(meta.earliest_available_slot(320), 640);
        // Once sidecar coverage reaches the start of the window, the oldest block counts.
        meta.sidecars.frontier = Some(320);
        assert_eq!(meta.earliest_available_slot(320), 400);
        meta.blocks.frontier.oldest_block_slot = 100;
        assert_eq!(meta.earliest_available_slot(320), 100);

        // The origin is older than the window, or Fulu is not active: only blocks matter.
        meta.sidecars.frontier = Some(640);
        assert_eq!(meta.earliest_available_slot(641), 100);
        assert_eq!(meta.earliest_available_slot(u64::MAX), 100);
        // Until anchor recovery confirms the anchor, it is never advertised.
        meta.sidecars.frontier = None;
        assert_eq!(meta.earliest_available_slot(641), 641);
        assert_eq!(meta.earliest_available_slot(u64::MAX), 641);
    }
}
