use std::sync::Arc;

use libp2p::{
    PeerId,
    gossipsub::{Message, MessageAcceptance, MessageId, TopicHash},
};
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_p2p::gossipsub::beacon::topics::{GossipTopic, GossipTopicKind};
use ream_storage::cache::BeaconCacheDB;
use tokio::{
    sync::{Mutex, mpsc},
    task::{JoinError, JoinSet},
};
use tracing::{debug, error};

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
    tasks: JoinSet<()>,
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
        let worker_p2p_sender = p2p_sender.clone();
        let tasks = spawn_workers(workers, receiver, move |work: GossipWork| {
            let beacon_chain = beacon_chain.clone();
            let cached_db = cached_db.clone();
            let p2p_sender = worker_p2p_sender.clone();
            async move {
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
        Self {
            sender,
            p2p_sender,
            tasks,
        }
    }

    /// Waits until a worker task ends. Workers run until the queue closes, which only happens when
    /// `self` is dropped, so this returns the error of a worker that panicked.
    pub async fn stopped(&mut self) -> Option<JoinError> {
        self.tasks.join_next().await?.err()
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
                mpsc::error::TrySendError::Full(work) => {
                    debug!("Gossip queue is full, ignoring message {}", work.message_id);
                    work
                }
                mpsc::error::TrySendError::Closed(work) => {
                    error!(
                        "No gossip worker is running, ignoring message {}",
                        work.message_id
                    );
                    work
                }
            };
            self.p2p_sender.report_gossip_validation(
                work.message_id,
                work.propagation_source,
                MessageAcceptance::Ignore,
            );
        }
    }
}

/// Starts `count` tasks that take items from `receiver` one at a time and pass them to `handle`.
/// The tasks end once `receiver`'s senders are dropped and the queue is empty. A panic in `handle`
/// ends its task, and the returned set reports it.
fn spawn_workers<Work, Handle, HandleFuture>(
    count: usize,
    receiver: mpsc::Receiver<Work>,
    handle: Handle,
) -> JoinSet<()>
where
    Work: Send + 'static,
    Handle: Fn(Work) -> HandleFuture + Clone + Send + 'static,
    HandleFuture: Future<Output = ()> + Send,
{
    let receiver = Arc::new(Mutex::new(receiver));
    let mut tasks = JoinSet::new();
    for _ in 0..count {
        let receiver = receiver.clone();
        let handle = handle.clone();
        tasks.spawn(async move {
            loop {
                let Some(work) = receiver.lock().await.recv().await else {
                    return;
                };
                handle(work).await;
            }
        });
    }
    tasks
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use alloy_primitives::aliases::B32;
    use libp2p::gossipsub::IdentTopic;
    use ream_p2p::gossipsub::beacon::topics::{GossipTopic, GossipTopicKind};
    use tokio::sync::mpsc;

    use super::{is_handled_concurrently, spawn_workers};

    #[tokio::test]
    async fn a_panicking_worker_is_reported() {
        let (sender, receiver) = mpsc::channel::<bool>(4);
        let handled = Arc::new(AtomicUsize::new(0));
        let counter = handled.clone();
        let mut tasks = spawn_workers(2, receiver, move |panics: bool| {
            let counter = counter.clone();
            async move {
                assert!(!panics, "test worker panics");
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });

        sender.send(false).await.expect("workers are running");
        sender.send(true).await.expect("workers are running");
        let err = tasks
            .join_next()
            .await
            .expect("a worker ends")
            .expect_err("the worker panicked");
        assert!(err.is_panic());

        // The other worker keeps taking work until the queue closes.
        sender
            .send(false)
            .await
            .expect("one worker is still running");
        drop(sender);
        assert!(tasks.join_next().await.expect("a worker ends").is_ok());
        assert_eq!(handled.load(Ordering::SeqCst), 2);
    }

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
