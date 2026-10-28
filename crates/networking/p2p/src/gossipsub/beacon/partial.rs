//! The gossipsub side of Fulu partial columns: what this node advertises and sends per peer.

use std::{
    collections::{HashSet, VecDeque},
    fmt::Debug,
    sync::Arc,
};

use alloy_primitives::B256;
use libp2p::{
    PeerId,
    gossipsub::partial_messages::{Metadata, Partial, PartialAction, PartialError},
};
use parking_lot::Mutex;
use ream_consensus_beacon::partial_data_column_sidecar::{
    CellsBitList, PartialColumn, PartialDataColumnHeader, PartialDataColumnPartsMetadata,
    PartialDataColumnSidecar, partial_column_group_id,
};
use ssz::{Decode, Encode};

/// Blocks whose header recipients are remembered.
const HEADER_TRACKED_BLOCKS: usize = 4;

/// A column to advertise and serve over partial messages.
#[derive(Debug, Clone)]
pub struct PartialColumnMessage {
    pub header: Arc<PartialDataColumnHeader>,
    pub column: Arc<PartialColumn>,
    /// Ask peers for the cells the column lacks.
    pub request_missing: bool,
}

pub type HeaderSentSet = Arc<Mutex<HashSet<PeerId>>>;

/// The peers each recent block's header went to, so a peer gets it once per block.
#[derive(Default)]
pub struct HeaderSentTracker {
    blocks: VecDeque<(B256, HeaderSentSet)>,
}

impl HeaderSentTracker {
    pub fn for_block(&mut self, block_root: B256) -> HeaderSentSet {
        if let Some((_, peers)) = self.blocks.iter().find(|(root, _)| *root == block_root) {
            return peers.clone();
        }
        if self.blocks.len() == HEADER_TRACKED_BLOCKS {
            self.blocks.pop_front();
        }
        let peers = HeaderSentSet::default();
        self.blocks.push_back((block_root, peers.clone()));
        peers
    }
}

/// A peer's parts metadata. It only grows: gossipsub skips a publish whose metadata adds no bit.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MaybeKnownMetadata {
    Unknown,
    Known {
        metadata: Box<PartialDataColumnPartsMetadata>,
        encoded: Vec<u8>,
    },
}

impl MaybeKnownMetadata {
    fn known(metadata: PartialDataColumnPartsMetadata) -> Self {
        Self::Known {
            encoded: metadata.as_ssz_bytes(),
            metadata: Box::new(metadata),
        }
    }

    fn merge(&mut self, received: PartialDataColumnPartsMetadata) -> Result<bool, PartialError> {
        let Self::Known { metadata, encoded } = self else {
            *self = Self::known(received);
            return Ok(true);
        };
        let len = metadata.available.len();
        if [
            metadata.requests.len(),
            received.available.len(),
            received.requests.len(),
        ]
        .iter()
        .any(|other| *other != len)
        {
            return Err(PartialError::InvalidFormat);
        }
        let available = metadata.available.union(&received.available);
        let requests = metadata.requests.union(&received.requests);
        if available == metadata.available && requests == metadata.requests {
            return Ok(false);
        }
        metadata.available = available;
        metadata.requests = requests;
        *encoded = metadata.as_ssz_bytes();
        Ok(true)
    }
}

impl Metadata for MaybeKnownMetadata {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Unknown => &[],
            Self::Known { encoded, .. } => encoded,
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<bool, PartialError> {
        let received = PartialDataColumnPartsMetadata::from_ssz_bytes(data)
            .or(Err(PartialError::InvalidFormat))?;
        self.merge(received)
    }

    fn update_from_data(&mut self, data: &[u8]) -> Result<(), PartialError> {
        if data.is_empty() {
            return Ok(());
        }
        let sidecar =
            PartialDataColumnSidecar::from_ssz_bytes(data).or(Err(PartialError::InvalidFormat))?;
        // A header-only message may carry a bitmap of any length, which says nothing.
        if sidecar.cells_present_bitmap.is_zero() {
            return Ok(());
        }
        self.merge(PartialDataColumnPartsMetadata {
            available: sidecar.cells_present_bitmap.clone(),
            requests: sidecar.cells_present_bitmap,
        })
        .map(|_| ())
    }
}

/// One column as published to gossipsub, which asks it what to send each peer.
pub struct OutgoingPartialColumn {
    block_root: B256,
    column: Arc<PartialColumn>,
    metadata: MaybeKnownMetadata,
    header_message: Vec<u8>,
    header_sent: HeaderSentSet,
}

impl OutgoingPartialColumn {
    pub fn new(message: PartialColumnMessage, header_sent: HeaderSentSet) -> Self {
        let available = message.column.bitmap();
        // Request bits always cover the available cells, so they are never unset later.
        let requests = if message.request_missing {
            let mut all = available.clone_zeroed();
            all.not_inplace();
            all
        } else {
            available.clone()
        };
        let header_message = PartialColumn::empty(message.column.index, message.column.cells.len())
            .to_sidecar(None, Some(&message.header))
            .as_ssz_bytes();
        Self {
            block_root: message.header.block_root(),
            column: message.column,
            metadata: MaybeKnownMetadata::known(PartialDataColumnPartsMetadata {
                available,
                requests,
            }),
            header_message,
            header_sent,
        }
    }
}

impl Partial for OutgoingPartialColumn {
    fn group_id(&self) -> Vec<u8> {
        partial_column_group_id(self.block_root)
    }

    fn metadata(&self) -> Box<dyn Metadata> {
        Box::new(self.metadata.clone())
    }

    fn partial_action_from_metadata(
        &self,
        peer_id: PeerId,
        metadata: Option<&[u8]>,
    ) -> Result<PartialAction, PartialError> {
        match metadata {
            // The peer may not know the block yet: send it the header once.
            None => Ok(PartialAction {
                need: false,
                send: self.header_sent.lock().insert(peer_id).then(|| {
                    (
                        self.header_message.clone(),
                        Box::new(MaybeKnownMetadata::Unknown) as Box<dyn Metadata>,
                    )
                }),
            }),
            Some([]) => Ok(PartialAction {
                need: false,
                send: None,
            }),
            Some(metadata) => {
                // A peer that sent metadata already has the header.
                self.header_sent.lock().insert(peer_id);
                action_for_peer(&self.column, metadata)
            }
        }
    }
}

/// Sends the cells the peer requests and lacks, and marks whether it has cells this node lacks.
fn action_for_peer(column: &PartialColumn, metadata: &[u8]) -> Result<PartialAction, PartialError> {
    let peer = PartialDataColumnPartsMetadata::from_ssz_bytes(metadata)
        .or(Err(PartialError::InvalidFormat))?;
    let held = column.bitmap();
    if peer.available.len() != held.len() || peer.requests.len() != held.len() {
        return Err(PartialError::InvalidFormat);
    }
    let need = !peer.available.is_subset(&held);
    let wanted: CellsBitList = peer.requests.difference(&peer.available);
    let sidecar = column.to_sidecar(Some(&wanted), None);
    if sidecar.partial_column.is_empty() {
        return Ok(PartialAction { need, send: None });
    }
    let sent = &sidecar.cells_present_bitmap;
    let peer_after = PartialDataColumnPartsMetadata {
        available: peer.available.union(sent),
        requests: peer.requests.union(sent),
    };
    Ok(PartialAction {
        need,
        send: Some((
            sidecar.as_ssz_bytes(),
            Box::new(MaybeKnownMetadata::known(peer_after)) as Box<dyn Metadata>,
        )),
    })
}

#[cfg(test)]
mod tests {
    use ream_consensus_beacon::data_column_sidecar::Cell;
    use ream_consensus_misc::polynomial_commitments::kzg_proof::KZGProof;

    use super::*;

    fn bits(len: usize, set: &[usize]) -> CellsBitList {
        let mut bitmap = CellsBitList::with_capacity(len).unwrap();
        for index in set {
            bitmap.set(*index, true).unwrap();
        }
        bitmap
    }

    fn outgoing(held: &[usize], blob_count: usize) -> OutgoingPartialColumn {
        let mut column = PartialColumn::empty(5, blob_count);
        column.insert_cells(
            held.iter()
                .map(|index| (*index, Cell::default(), KZGProof::default()))
                .collect(),
        );
        let header = PartialDataColumnHeader {
            kzg_commitments: Default::default(),
            signed_block_header: Default::default(),
            kzg_commitments_inclusion_proof: Default::default(),
        };
        OutgoingPartialColumn::new(
            PartialColumnMessage {
                header: Arc::new(header),
                column: Arc::new(column),
                request_missing: true,
            },
            HeaderSentSet::default(),
        )
    }

    #[test]
    fn metadata_only_grows_and_rejects_other_lengths() {
        let mut metadata = MaybeKnownMetadata::Unknown;
        let first = PartialDataColumnPartsMetadata {
            available: bits(3, &[0]),
            requests: bits(3, &[0, 1]),
        };
        assert_eq!(metadata.update(&first.as_ssz_bytes()), Ok(true));
        assert_eq!(metadata.update(&first.as_ssz_bytes()), Ok(false));

        let second = PartialDataColumnPartsMetadata {
            available: bits(3, &[2]),
            requests: bits(3, &[]),
        };
        assert_eq!(metadata.update(&second.as_ssz_bytes()), Ok(true));
        assert_eq!(
            metadata,
            MaybeKnownMetadata::known(PartialDataColumnPartsMetadata {
                available: bits(3, &[0, 2]),
                requests: bits(3, &[0, 1]),
            })
        );

        let shorter = PartialDataColumnPartsMetadata {
            available: bits(2, &[]),
            requests: bits(2, &[]),
        };
        assert!(metadata.update(&shorter.as_ssz_bytes()).is_err());
    }

    #[test]
    fn a_peer_gets_the_header_once_then_only_the_cells_it_requests_and_lacks() {
        let column = outgoing(&[0, 1, 2], 4);
        let peer = PeerId::random();

        assert!(
            column
                .partial_action_from_metadata(peer, None)
                .unwrap()
                .send
                .is_some()
        );
        assert!(
            column
                .partial_action_from_metadata(peer, None)
                .unwrap()
                .send
                .is_none()
        );

        let peer_metadata = PartialDataColumnPartsMetadata {
            available: bits(4, &[0, 3]),
            requests: bits(4, &[0, 1, 3]),
        };
        let action = column
            .partial_action_from_metadata(peer, Some(&peer_metadata.as_ssz_bytes()))
            .unwrap();
        assert!(action.need, "the peer holds cell 3, which this node lacks");
        let (body, _) = action.send.unwrap();
        let sent = PartialDataColumnSidecar::from_ssz_bytes(&body).unwrap();
        assert_eq!(sent.cells_present_bitmap, bits(4, &[1]));
    }
}
