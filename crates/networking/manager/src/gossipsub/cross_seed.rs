//! Cross-seeding of reconstructed data columns, as required by das-core "Reconstruction and
//! cross-seeding": a column the node obtained through reconstruction must be sent to the mesh of
//! its subnet, as if it had arrived over the network.

use std::{ops::Range, time::Duration};

use alloy_primitives::B256;
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::data_column_sidecar::DataColumnSidecar;
use ream_consensus_misc::{
    constants::beacon::genesis_validators_root, misc::compute_start_slot_at_epoch,
};
use ream_metrics::BEACON_DATA_AVAILABILITY_CROSS_SEEDED_COLUMNS_TOTAL;
use ream_network_spec::networks::beacon_network_spec;
use ream_p2p::{
    gossipsub::beacon::topics::{GossipTopic, GossipTopicKind},
    network::beacon::channel::GossipMessage,
};
use ream_storage::{cache::BeaconCacheDB, tables::field::REDBField};
use ssz::Encode;
use tracing::debug;

use crate::p2p_sender::P2PSender;

/// How long to wait, picked uniformly per block, before rebuilding a block's columns. das-core
/// says "Nodes MAY delay this reconstruction allowing time for other columns to arrive over the
/// network. If delaying reconstruction, nodes may use a random delay in order to desynchronize
/// reconstruction among nodes". A block is imported once half its columns arrive, so the
/// reconstruction is announced while gossip is still delivering the rest. When gossip fills every
/// gap during the wait, the reconstruction finds all columns stored and does nothing.
pub const RECONSTRUCTION_DELAY_MS: Range<u64> = 500..1500;

/// Waits a random `RECONSTRUCTION_DELAY_MS`, then rebuilds a block's missing columns and
/// publishes the ones this node stored. Returns how many columns were published.
pub async fn reconstruct_and_cross_seed(
    beacon_chain: &BeaconChain,
    cached_db: &BeaconCacheDB,
    p2p_sender: &P2PSender,
    block_root: B256,
) -> anyhow::Result<usize> {
    tokio::time::sleep(Duration::from_millis(rand::random_range(
        RECONSTRUCTION_DELAY_MS,
    )))
    .await;
    let stored = beacon_chain.reconstruct_data_columns(block_root).await?;
    if stored.is_empty() {
        return Ok(0);
    }
    let finalized_checkpoint = beacon_chain.db().finalized_checkpoint_provider().get()?;
    let published = publish_reconstructed_columns(
        stored,
        compute_start_slot_at_epoch(finalized_checkpoint.epoch),
        cached_db,
        p2p_sender,
    )
    .await;
    debug!(%block_root, published, "Cross-seeded reconstructed data columns");
    Ok(published)
}

/// Publishes each column on its subnet topic and marks it seen in the cache gossip validation
/// reads, so a peer echoing it back is ignored as a duplicate.
///
/// Two kinds of column are skipped. A column already marked seen passed gossip validation while
/// reconstruction ran, and gossipsub forwards that copy. A column at or before the finalized slot
/// is ignored by every peer's gossip validation.
async fn publish_reconstructed_columns(
    columns: Vec<DataColumnSidecar>,
    finalized_slot: u64,
    cached_db: &BeaconCacheDB,
    p2p_sender: &P2PSender,
) -> usize {
    let columns = {
        let mut seen = cached_db.seen_data_column_sidecars.write().await;
        columns
            .into_iter()
            .filter(|sidecar| {
                let header = &sidecar.signed_block_header.message;
                if header.slot <= finalized_slot {
                    return false;
                }
                let tuple = (header.slot, header.proposer_index, sidecar.index);
                if seen.contains(&tuple) {
                    return false;
                }
                seen.put(tuple, ());
                true
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
    use std::sync::Arc;

    use ream_consensus_beacon::{
        data_column_sidecar::{ColumnIdentifier, NUMBER_OF_COLUMNS, get_data_column_sidecars},
        electra::beacon_block::SignedBeaconBlock,
    };
    use ream_consensus_misc::checkpoint::Checkpoint;
    use ream_metrics::{
        BEACON_DATA_AVAILABILITY_RECONSTRUCTIONS_RUN_TOTAL,
        BEACON_DATA_AVAILABILITY_RECONSTRUCTIONS_SKIPPED_COMPLETE_TOTAL,
    };
    use ream_network_spec::networks::initialize_test_network_spec;
    use ream_operation_pool::OperationPool;
    use ream_p2p::network::beacon::channel::P2PMessage;
    use ream_storage::{
        db::ReamDB,
        tables::table::{CustomTable, REDBTable},
    };
    use ream_sync_committee_pool::SyncCommitteePool;
    use ssz::Decode;
    use tempfile::TempDir;
    use tokio::sync::mpsc;
    use tree_hash::TreeHash;

    use super::*;
    use crate::gossipsub::validate::{
        data_column_sidecar::validate_data_column_sidecar_full, result::DependencyValidationResult,
    };

    struct Harness {
        _data_dir: TempDir,
        beacon_chain: BeaconChain,
        cached_db: BeaconCacheDB,
        p2p_sender: P2PSender,
        p2p_receiver: mpsc::UnboundedReceiver<P2PMessage>,
        block_root: B256,
        columns: Vec<DataColumnSidecar>,
    }

    impl Harness {
        /// A stored block at `slot` whose columns are built but not stored.
        fn new(slot: u64, finalized_epoch: u64) -> Self {
            initialize_test_network_spec();
            let data_dir = tempfile::tempdir().expect("tempdir should be created");
            let beacon_db = ReamDB::new(data_dir.path().to_path_buf())
                .expect("ReamDB should init")
                .init_beacon_db()
                .expect("beacon DB tables should init");
            beacon_db
                .finalized_checkpoint_provider()
                .insert(Checkpoint {
                    epoch: finalized_epoch,
                    root: B256::ZERO,
                })
                .expect("finalized checkpoint should be stored");
            let beacon_chain = BeaconChain::new(
                beacon_db,
                Arc::new(OperationPool::default()),
                Arc::new(SyncCommitteePool::default()),
                None,
                None,
            );
            let mut block = SignedBeaconBlock {
                message: Default::default(),
                signature: Default::default(),
            };
            block.message.slot = slot;
            let block_root = block.message.tree_hash_root();
            let columns = get_data_column_sidecars(
                block.signed_header(),
                block.message.body.blob_kzg_commitments.clone(),
                Default::default(),
                Vec::new(),
            )
            .expect("columns of an empty block should build");
            beacon_chain
                .db()
                .block_provider()
                .insert(block_root, block)
                .expect("block should be stored");
            let (sender, p2p_receiver) = mpsc::unbounded_channel();
            Self {
                _data_dir: data_dir,
                beacon_chain,
                cached_db: BeaconCacheDB::default(),
                p2p_sender: P2PSender(sender),
                p2p_receiver,
                block_root,
                columns,
            }
        }

        fn store_columns(&self, indices: impl Fn(u64) -> bool) {
            self.beacon_chain
                .db()
                .column_sidecars_provider()
                .insert_batch(
                    self.columns
                        .iter()
                        .filter(|sidecar| indices(sidecar.index))
                        .cloned()
                        .collect(),
                )
                .expect("columns should be stored");
        }

        async fn cross_seed(&self) -> usize {
            reconstruct_and_cross_seed(
                &self.beacon_chain,
                &self.cached_db,
                &self.p2p_sender,
                self.block_root,
            )
            .await
            .expect("reconstruction should succeed")
        }

        /// Column indices published so far, checking each went to its own subnet topic.
        fn published_indices(&mut self) -> Vec<u64> {
            let mut indices = Vec::new();
            while let Ok(message) = self.p2p_receiver.try_recv() {
                let P2PMessage::Gossip(message) = message else {
                    panic!("only gossip should be sent");
                };
                let sidecar = DataColumnSidecar::from_ssz_bytes(&message.data)
                    .expect("published data should be a column");
                assert_eq!(
                    message.topic.kind,
                    GossipTopicKind::DataColumnSidecar(sidecar.compute_subnet())
                );
                assert_eq!(sidecar, self.columns[sidecar.index as usize]);
                indices.push(sidecar.index);
            }
            indices
        }

        fn seen_tuple(&self, index: u64) -> (u64, u64, u64) {
            let header = &self.columns[index as usize].signed_block_header.message;
            (header.slot, header.proposer_index, index)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn rebuilt_columns_are_published_once() {
        let mut harness = Harness::new(1, 0);
        harness.store_columns(|index| index < NUMBER_OF_COLUMNS / 2);
        // Other tests share these counters and only add to them, so the checks are lower bounds.
        let runs = BEACON_DATA_AVAILABILITY_RECONSTRUCTIONS_RUN_TOTAL.get();
        let skipped = BEACON_DATA_AVAILABILITY_RECONSTRUCTIONS_SKIPPED_COMPLETE_TOTAL.get();
        let cross_seeded = BEACON_DATA_AVAILABILITY_CROSS_SEEDED_COLUMNS_TOTAL.get();

        assert_eq!(harness.cross_seed().await, (NUMBER_OF_COLUMNS / 2) as usize);
        assert_eq!(
            harness.published_indices(),
            (NUMBER_OF_COLUMNS / 2..NUMBER_OF_COLUMNS).collect::<Vec<_>>()
        );
        assert!(BEACON_DATA_AVAILABILITY_RECONSTRUCTIONS_RUN_TOTAL.get() > runs);
        assert!(
            BEACON_DATA_AVAILABILITY_CROSS_SEEDED_COLUMNS_TOTAL.get()
                >= cross_seeded + NUMBER_OF_COLUMNS / 2
        );

        // Everything is stored now, so a repeated reconstruction has nothing to publish.
        assert_eq!(harness.cross_seed().await, 0);
        assert!(harness.published_indices().is_empty());
        assert!(BEACON_DATA_AVAILABILITY_RECONSTRUCTIONS_SKIPPED_COMPLETE_TOTAL.get() > skipped);
    }

    #[tokio::test(start_paused = true)]
    async fn reconstruction_waits_the_random_delay_first() {
        let mut harness = Harness::new(1, 0);
        harness.store_columns(|index| index < NUMBER_OF_COLUMNS / 2);

        let started = tokio::time::Instant::now();
        harness.cross_seed().await;

        let waited = started.elapsed();
        assert!(
            Duration::from_millis(RECONSTRUCTION_DELAY_MS.start) <= waited
                && waited <= Duration::from_millis(RECONSTRUCTION_DELAY_MS.end),
            "waited {waited:?}"
        );
        assert_eq!(
            harness.published_indices().len(),
            (NUMBER_OF_COLUMNS / 2) as usize
        );
    }

    #[tokio::test(start_paused = true)]
    async fn gossip_filling_the_gaps_during_the_delay_skips_reconstruction() {
        let mut harness = Harness::new(1, 0);
        harness.store_columns(|index| index < NUMBER_OF_COLUMNS / 2);

        let (published, ()) = tokio::join!(harness.cross_seed(), async {
            // Earlier than any delay, so the rest arrives while reconstruction waits.
            tokio::time::sleep(Duration::from_millis(RECONSTRUCTION_DELAY_MS.start / 5)).await;
            harness.store_columns(|index| index >= NUMBER_OF_COLUMNS / 2);
        });

        assert_eq!(published, 0);
        assert!(harness.published_indices().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn columns_that_already_arrived_are_not_published() {
        let mut harness = Harness::new(1, 0);
        // Column 64 was stored before reconstruction; column 65 passed gossip validation but is
        // not stored yet, so reconstruction stores it while the gossip copy is forwarded.
        harness.store_columns(|index| index <= NUMBER_OF_COLUMNS / 2);
        harness
            .cached_db
            .seen_data_column_sidecars
            .write()
            .await
            .put(harness.seen_tuple(NUMBER_OF_COLUMNS / 2 + 1), ());

        harness.cross_seed().await;

        assert_eq!(
            harness.published_indices(),
            (NUMBER_OF_COLUMNS / 2 + 2..NUMBER_OF_COLUMNS).collect::<Vec<_>>()
        );
        assert!(
            harness
                .beacon_chain
                .db()
                .column_sidecars_provider()
                .get(ColumnIdentifier::new(
                    harness.block_root,
                    NUMBER_OF_COLUMNS / 2 + 1
                ))
                .expect("column read should succeed")
                .is_some()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn echo_of_a_published_column_is_ignored_as_seen() {
        let mut harness = Harness::new(1, 0);
        harness.store_columns(|index| index < NUMBER_OF_COLUMNS / 2);
        harness.cross_seed().await;
        harness.published_indices();

        let echo = &harness.columns[(NUMBER_OF_COLUMNS - 1) as usize];
        let result = validate_data_column_sidecar_full(
            echo,
            &harness.beacon_chain,
            0,
            echo.compute_subnet(),
            &harness.cached_db,
        )
        .await
        .expect("validation should not fail");

        assert!(
            matches!(&result, DependencyValidationResult::Ignore(reason) if reason.contains("seen")),
            "expected the echo to be ignored as seen"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn columns_at_or_before_the_finalized_slot_are_not_published() {
        // Finalized epoch 1 starts at slot 32, after the block at slot 1.
        let mut harness = Harness::new(1, 1);
        harness.store_columns(|index| index < NUMBER_OF_COLUMNS / 2);

        assert_eq!(harness.cross_seed().await, 0);

        assert!(harness.published_indices().is_empty());
        assert!(
            harness
                .beacon_chain
                .db()
                .column_sidecars_provider()
                .get(ColumnIdentifier::new(
                    harness.block_root,
                    NUMBER_OF_COLUMNS - 1
                ))
                .expect("column read should succeed")
                .is_some(),
            "the rebuilt column is still stored"
        );
    }
}
