use std::sync::Arc;

use libp2p::{
    PeerId,
    gossipsub::{Message, MessageAcceptance, MessageId, TopicHash},
};
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::data_column_sidecar::NUMBER_OF_COLUMNS;
use ream_metrics::BEACON_GOSSIP_PENDING_ITEMS_DROPPED_TOTAL;
use ream_p2p::gossipsub::beacon::topics::{GossipTopic, GossipTopicKind};
use ream_storage::cache::BeaconCacheDB;
use tokio::sync::{Mutex, Semaphore, mpsc};
use tracing::debug;

use super::handle::handle_gossipsub_message;
use crate::{block_lookup::PendingGossipItem, p2p_sender::P2PSender};

/// Messages waiting for a worker. A full queue sheds new messages as IGNORE, which does not
/// penalize their senders; mainnet sends thousands of attestations per slot.
const GOSSIP_QUEUE_CAPACITY: usize = 16_384;

/// Columns the workers validated whose block waits on its parent's availability, queued for the
/// manager loop, which owns the lookups. A block yields at most one item per column, so the
/// queue holds two blocks' worth: the next block's columns can arrive while the loop drains the
/// last one's. A column with 21 blobs is about 45 KB, so a full queue holds about 12 MB. Items
/// that do not fit are dropped: once the block is pending availability, its missing columns are
/// fetched by root.
pub const PENDING_ITEM_QUEUE_CAPACITY: usize = 2 * NUMBER_OF_COLUMNS as usize;

/// How many gossip messages all [`GossipWorkers`] pools may handle at once. Validation runs BLS
/// and KZG checks synchronously, so each handler at work can hold a runtime thread; the budget is
/// one per runtime worker thread but two, which stay free for the network loops.
#[derive(Clone)]
pub struct GossipWorkerBudget {
    workers: usize,
    permits: Arc<Semaphore>,
}

impl GossipWorkerBudget {
    pub fn for_current_runtime() -> Self {
        Self::new(
            tokio::runtime::Handle::current()
                .metrics()
                .num_workers()
                .saturating_sub(2)
                .max(1),
        )
    }

    fn new(workers: usize) -> Self {
        Self {
            workers,
            permits: Arc::new(Semaphore::new(workers)),
        }
    }
}

/// Whether `topic` carries data column sidecars. They go to their own [`GossipWorkers`]: on
/// mainnet a supernode gets 128 per block, and importing each one waits for the store lock, so
/// handling them on the manager loop kept it busy for most of every slot.
pub fn is_data_column(topic: &TopicHash) -> bool {
    matches!(
        GossipTopic::from_topic_hash(topic).map(|topic| topic.kind),
        Ok(GossipTopicKind::DataColumnSidecar(_))
    )
}

/// Whether a message on `topic` is handled by a [`GossipWorkers`] task. Blocks and their sidecars
/// stay on the manager loop, which tracks their lookups and availability; every other topic is
/// validated against shared state only, so its messages can be handled concurrently.
pub fn is_handled_concurrently(topic: &TopicHash) -> bool {
    match GossipTopic::from_topic_hash(topic) {
        Ok(topic) => !matches!(
            topic.kind,
            GossipTopicKind::BeaconBlock
                | GossipTopicKind::BlobSidecar(_)
                | GossipTopicKind::DataColumnSidecar(_)
        ),
        Err(_) => false,
    }
}

struct GossipWork {
    message: Message,
    message_id: MessageId,
    propagation_source: PeerId,
}

/// Tasks that validate and import gossip messages off the manager loop. Handled one at a time,
/// attestation BLS checks alone fell minutes behind the network on mainnet.
pub struct GossipWorkers {
    sender: mpsc::Sender<GossipWork>,
    p2p_sender: P2PSender,
}

impl GossipWorkers {
    /// Starts as many tasks as `budget` allows handlers, so one pool can use the whole budget
    /// while the others are idle; a task takes a permit once it has a message. A column whose
    /// block waits on its parent's availability yields lookup work, which goes to
    /// `pending_items` because the manager loop owns the lookups.
    pub fn start(
        beacon_chain: Arc<BeaconChain>,
        cached_db: Arc<BeaconCacheDB>,
        p2p_sender: P2PSender,
        pending_items: mpsc::Sender<PendingGossipItem>,
        budget: &GossipWorkerBudget,
    ) -> Self {
        let (sender, receiver) = mpsc::channel::<GossipWork>(GOSSIP_QUEUE_CAPACITY);
        let receiver = Arc::new(Mutex::new(receiver));
        for _ in 0..budget.workers {
            let permits = budget.permits.clone();
            let receiver = receiver.clone();
            let beacon_chain = beacon_chain.clone();
            let cached_db = cached_db.clone();
            let p2p_sender = p2p_sender.clone();
            let pending_items = pending_items.clone();
            tokio::spawn(async move {
                loop {
                    let Some(work) = receiver.lock().await.recv().await else {
                        return;
                    };
                    let Ok(_permit) = permits.acquire().await else {
                        return;
                    };
                    let mut pending_item = None;
                    let mut unknown_parent_block = None;
                    let acceptance = handle_gossipsub_message(
                        work.message,
                        &beacon_chain,
                        &cached_db,
                        &mut pending_item,
                        &mut unknown_parent_block,
                    )
                    .await;
                    // Only blocks produce unknown-parent work, and they never come here.
                    debug_assert!(unknown_parent_block.is_none());
                    if let Some(item) = pending_item
                        && !try_forward(&pending_items, item)
                    {
                        debug!("Pending gossip item queue is full, dropping a column");
                        BEACON_GOSSIP_PENDING_ITEMS_DROPPED_TOTAL.inc();
                    }
                    p2p_sender.report_gossip_validation(
                        work.message_id,
                        work.propagation_source,
                        acceptance,
                    );
                }
            });
        }
        Self { sender, p2p_sender }
    }

    /// Queues `message` for a worker, or reports it as IGNORE when the queue is full.
    pub fn submit(&self, message: Message, message_id: MessageId, propagation_source: PeerId) {
        let work = GossipWork {
            message,
            message_id,
            propagation_source,
        };
        if let Err(err) = self.sender.try_send(work) {
            let work = match err {
                mpsc::error::TrySendError::Full(work) | mpsc::error::TrySendError::Closed(work) => {
                    work
                }
            };
            debug!("Gossip queue is full, ignoring message {}", work.message_id);
            self.p2p_sender.report_gossip_validation(
                work.message_id,
                work.propagation_source,
                MessageAcceptance::Ignore,
            );
        }
    }
}

/// Sends `item` unless the queue is full, and returns whether it was not dropped for that. A
/// closed queue means the manager loop is shutting down, so its items are not counted as dropped.
fn try_forward<T>(sender: &mpsc::Sender<T>, item: T) -> bool {
    !matches!(
        sender.try_send(item),
        Err(mpsc::error::TrySendError::Full(_))
    )
}

#[cfg(test)]
mod tests {
    use alloy_primitives::aliases::B32;
    use libp2p::gossipsub::IdentTopic;
    use ream_p2p::gossipsub::beacon::topics::{GossipTopic, GossipTopicKind};
    use tokio::sync::mpsc;

    use super::{GossipWorkerBudget, is_data_column, is_handled_concurrently, try_forward};

    fn topic_hash(kind: GossipTopicKind) -> libp2p::gossipsub::TopicHash {
        IdentTopic::new(
            GossipTopic {
                fork: B32::ZERO,
                kind,
            }
            .to_string(),
        )
        .hash()
    }

    #[test]
    fn blocks_and_sidecars_stay_on_the_manager_loop() {
        assert!(!is_handled_concurrently(&topic_hash(
            GossipTopicKind::BeaconBlock
        )));
        assert!(!is_handled_concurrently(&topic_hash(
            GossipTopicKind::BlobSidecar(0)
        )));
        assert!(!is_handled_concurrently(&topic_hash(
            GossipTopicKind::DataColumnSidecar(3)
        )));
        assert!(is_handled_concurrently(&topic_hash(
            GossipTopicKind::BeaconAttestation(5)
        )));
        assert!(is_handled_concurrently(&topic_hash(
            GossipTopicKind::AggregateAndProof
        )));
        assert!(is_handled_concurrently(&topic_hash(
            GossipTopicKind::SyncCommittee(1)
        )));
        assert!(!is_handled_concurrently(&IdentTopic::new("unknown").hash()));
    }

    #[test]
    fn only_data_columns_go_to_the_column_workers() {
        assert!(is_data_column(&topic_hash(
            GossipTopicKind::DataColumnSidecar(3)
        )));
        assert!(!is_data_column(&topic_hash(GossipTopicKind::BeaconBlock)));
        assert!(!is_data_column(&topic_hash(GossipTopicKind::BlobSidecar(
            0
        ))));
        assert!(!is_data_column(&topic_hash(
            GossipTopicKind::BeaconAttestation(5)
        )));
        assert!(!is_data_column(&IdentTopic::new("unknown").hash()));
    }

    #[test]
    fn a_full_pending_queue_drops_the_item() {
        let (sender, mut receiver) = mpsc::channel(1);
        assert!(try_forward(&sender, 1));
        assert!(!try_forward(&sender, 2));
        assert_eq!(receiver.try_recv(), Ok(1));
        assert!(receiver.try_recv().is_err());

        drop(receiver);
        assert!(
            try_forward(&sender, 3),
            "a closed queue is not counted as full"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn pools_share_a_budget_that_leaves_two_threads_free() {
        let budget = GossipWorkerBudget::for_current_runtime();
        assert_eq!(budget.workers, 4);
        let shared = budget.clone();
        let _held = budget
            .permits
            .acquire_many(4)
            .await
            .expect("budget is open");
        assert_eq!(shared.permits.available_permits(), 0);
    }
}
