//! Cross-seeding of reconstructed data columns, as required by das-core "Reconstruction and
//! cross-seeding": a column the node obtained through reconstruction must be sent to the mesh of
//! its subnet, as if it had arrived over the network.

use ream_consensus_beacon::data_column_sidecar::DataColumnSidecar;
use ream_consensus_misc::constants::beacon::genesis_validators_root;
use ream_metrics::BEACON_DATA_AVAILABILITY_CROSS_SEEDED_COLUMNS_TOTAL;
use ream_network_spec::networks::beacon_network_spec;
use ream_p2p::{
    gossipsub::beacon::topics::{GossipTopic, GossipTopicKind},
    network::beacon::channel::GossipMessage,
};
use ream_storage::cache::BeaconCacheDB;
use ssz::Encode;

use crate::p2p_sender::P2PSender;

/// Publishes each rebuilt column on its subnet topic and returns how many were published.
///
/// Two kinds of column are skipped. A column already marked seen passed gossip validation while
/// reconstruction ran, and gossipsub forwards that copy. A column at or before the finalized slot
/// is ignored by every peer's gossip validation.
///
/// Published columns are not marked seen. A copy of the same column can be waiting in gossipsub
/// for validation; marking it seen would make that copy IGNOREd, while gossipsub rejects the local
/// publish as a duplicate of it, so neither copy would be forwarded. Echoes of a published column
/// need no marker: they carry the same message id, which gossipsub already drops as a duplicate.
pub async fn publish_reconstructed_columns(
    columns: Vec<DataColumnSidecar>,
    finalized_slot: u64,
    cached_db: &BeaconCacheDB,
    p2p_sender: &P2PSender,
) -> usize {
    let columns = {
        let seen = cached_db.seen_data_column_sidecars.read().await;
        columns
            .into_iter()
            .filter(|sidecar| {
                let header = &sidecar.signed_block_header.message;
                header.slot > finalized_slot
                    && !seen.contains(&(header.slot, header.proposer_index, sidecar.index))
            })
            .collect::<Vec<_>>()
    };

    // Received gossip is only decoded on this digest, so it is the one the node subscribes to.
    let fork_digest = beacon_network_spec().fork_digest(
        beacon_network_spec().current_epoch(),
        genesis_validators_root(),
    );
    for sidecar in &columns {
        p2p_sender.send_gossip(GossipMessage {
            topic: GossipTopic {
                fork: fork_digest,
                kind: GossipTopicKind::DataColumnSidecar(sidecar.compute_subnet()),
            },
            data: sidecar.as_ssz_bytes(),
        });
    }
    BEACON_DATA_AVAILABILITY_CROSS_SEEDED_COLUMNS_TOTAL.inc_by(columns.len() as u64);
    columns.len()
}

#[cfg(test)]
mod tests {
    use ream_consensus_beacon::{
        data_column_sidecar::{NUMBER_OF_COLUMNS, get_data_column_sidecars},
        electra::beacon_block::SignedBeaconBlock,
    };
    use ream_network_spec::networks::initialize_test_network_spec;
    use ream_p2p::{
        gossipsub::beacon::message::GossipsubMessage, network::beacon::channel::P2PMessage,
    };
    use ssz::Decode;
    use tokio::sync::mpsc;

    use super::*;
    use crate::gossipsub::handle::init_gossipsub_config_with_topics;

    fn columns_at_slot(slot: u64) -> Vec<DataColumnSidecar> {
        let mut block = SignedBeaconBlock {
            message: Default::default(),
            signature: Default::default(),
        };
        block.message.slot = slot;
        get_data_column_sidecars(
            block.signed_header(),
            block.message.body.blob_kzg_commitments.clone(),
            Default::default(),
            Vec::new(),
        )
        .expect("columns of an empty block should build")
    }

    fn seen_tuple(sidecar: &DataColumnSidecar) -> (u64, u64, u64) {
        let header = &sidecar.signed_block_header.message;
        (header.slot, header.proposer_index, sidecar.index)
    }

    /// Column indices published so far, checking each went to its own subnet topic.
    fn published_indices(receiver: &mut mpsc::UnboundedReceiver<P2PMessage>) -> Vec<u64> {
        let mut indices = Vec::new();
        while let Ok(message) = receiver.try_recv() {
            let P2PMessage::Gossip(message) = message else {
                panic!("only gossip should be sent");
            };
            let sidecar = DataColumnSidecar::from_ssz_bytes(&message.data)
                .expect("published data should be a column");
            assert_eq!(
                message.topic.kind,
                GossipTopicKind::DataColumnSidecar(sidecar.compute_subnet())
            );
            indices.push(sidecar.index);
        }
        indices
    }

    #[tokio::test]
    async fn rebuilt_columns_are_published_on_their_subnets() {
        initialize_test_network_spec();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let columns = columns_at_slot(1);
        let rebuilt = columns[(NUMBER_OF_COLUMNS / 2) as usize..].to_vec();

        let published = publish_reconstructed_columns(
            rebuilt,
            0,
            &BeaconCacheDB::default(),
            &P2PSender(sender),
        )
        .await;

        assert_eq!(published, (NUMBER_OF_COLUMNS / 2) as usize);
        assert_eq!(
            published_indices(&mut receiver),
            (NUMBER_OF_COLUMNS / 2..NUMBER_OF_COLUMNS).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn columns_that_passed_gossip_validation_are_not_published() {
        initialize_test_network_spec();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let cached_db = BeaconCacheDB::default();
        let columns = columns_at_slot(1);
        cached_db
            .seen_data_column_sidecars
            .write()
            .await
            .put(seen_tuple(&columns[0]), ());

        let published =
            publish_reconstructed_columns(columns[..2].to_vec(), 0, &cached_db, &P2PSender(sender))
                .await;

        assert_eq!(published, 1);
        assert_eq!(published_indices(&mut receiver), vec![1]);
    }

    #[tokio::test]
    async fn publishing_does_not_mark_columns_seen() {
        initialize_test_network_spec();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let cached_db = BeaconCacheDB::default();
        let columns = columns_at_slot(1);

        publish_reconstructed_columns(columns[..1].to_vec(), 0, &cached_db, &P2PSender(sender))
            .await;

        assert_eq!(published_indices(&mut receiver), vec![0]);
        // A gossip copy of this column waiting for validation must still be validated, not
        // IGNOREd as seen, or neither copy is forwarded.
        assert!(
            !cached_db
                .seen_data_column_sidecars
                .read()
                .await
                .contains(&seen_tuple(&columns[0]))
        );
    }

    #[tokio::test]
    async fn published_columns_use_a_topic_the_node_subscribes_to() {
        initialize_test_network_spec();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let columns = columns_at_slot(1);

        publish_reconstructed_columns(
            columns[..1].to_vec(),
            0,
            &BeaconCacheDB::default(),
            &P2PSender(sender),
        )
        .await;

        let Ok(P2PMessage::Gossip(message)) = receiver.try_recv() else {
            panic!("the column should be published");
        };
        // Peers on this node's fork digest dedupe by topic and data, so a copy published on any
        // other topic would get a different message id and reach a different mesh.
        assert!(
            init_gossipsub_config_with_topics(None)
                .topics
                .contains(&message.topic)
        );
        let decoded = GossipsubMessage::decode(&message.topic.into(), &message.data)
            .expect("the published column should decode on its topic");
        assert!(matches!(
            decoded,
            GossipsubMessage::DataColumnSidecar(sidecar) if *sidecar == columns[0]
        ));
    }

    #[tokio::test]
    async fn columns_at_or_before_the_finalized_slot_are_not_published() {
        initialize_test_network_spec();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let columns = columns_at_slot(32);

        let published = publish_reconstructed_columns(
            columns,
            32,
            &BeaconCacheDB::default(),
            &P2PSender(sender),
        )
        .await;

        assert_eq!(published, 0);
        assert!(published_indices(&mut receiver).is_empty());
    }
}
