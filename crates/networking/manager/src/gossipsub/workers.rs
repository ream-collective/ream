use std::sync::Arc;

use libp2p::{
    PeerId,
    gossipsub::{Message, MessageAcceptance, MessageId, TopicHash},
};
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_p2p::gossipsub::beacon::topics::{GossipTopic, GossipTopicKind};
use ream_storage::cache::BeaconCacheDB;
use tokio::sync::{Mutex, mpsc};
use tracing::debug;

use super::handle::handle_gossipsub_message;
use crate::p2p_sender::P2PSender;

/// Messages waiting for a worker. A full queue sheds new messages as IGNORE, which does not
/// penalize their senders; mainnet sends thousands of attestations per slot.
const GOSSIP_QUEUE_CAPACITY: usize = 16_384;

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
    /// Starts one task per runtime worker thread but two, which stay free for the network loops.
    pub fn start(
        beacon_chain: Arc<BeaconChain>,
        cached_db: Arc<BeaconCacheDB>,
        p2p_sender: P2PSender,
    ) -> Self {
        let workers = tokio::runtime::Handle::current()
            .metrics()
            .num_workers()
            .saturating_sub(2)
            .max(1);
        let (sender, receiver) = mpsc::channel::<GossipWork>(GOSSIP_QUEUE_CAPACITY);
        let receiver = Arc::new(Mutex::new(receiver));
        for _ in 0..workers {
            let receiver = receiver.clone();
            let beacon_chain = beacon_chain.clone();
            let cached_db = cached_db.clone();
            let p2p_sender = p2p_sender.clone();
            tokio::spawn(async move {
                loop {
                    let Some(work) = receiver.lock().await.recv().await else {
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
                    // Only blocks and sidecars produce lookup work, and they never come here.
                    debug_assert!(pending_item.is_none() && unknown_parent_block.is_none());
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

#[cfg(test)]
mod tests {
    use alloy_primitives::aliases::B32;
    use libp2p::gossipsub::IdentTopic;
    use ream_p2p::gossipsub::beacon::topics::{GossipTopic, GossipTopicKind};

    use super::is_handled_concurrently;

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
}
