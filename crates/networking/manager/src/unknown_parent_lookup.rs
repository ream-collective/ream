use std::{
    collections::{HashSet, VecDeque},
    fmt,
};

use alloy_primitives::B256;
use libp2p::PeerId;
use ream_chain_beacon::beacon_chain::{BeaconChain, BlockProcessingOutcome};
use ream_consensus_beacon::electra::beacon_block::SignedBeaconBlock;
use ream_p2p::network::beacon::{
    channel::{P2PCallbackError, P2PCallbackResponse, P2PMessage, P2PRequest},
    network_state::NetworkState,
};
use ream_req_resp::{beacon::messages::BeaconResponseMessage, error::ReqRespError};
use ream_storage::tables::table::REDBTable;
use ream_syncer::unknown_parent_lookups::{
    LookupActionId, ParentStatus, PayloadOrigin, UnknownBlockMeta, UnknownParentAction,
    UnknownParentLookupCoordinator,
};
use tokio::sync::mpsc;
use tracing::warn;
use tree_hash::TreeHash;

use crate::{
    gossipsub::validate::{
        beacon_block::validate_lookup_beacon_block, result::DependencyValidationResult,
    },
    p2p_sender::P2PSender,
};

#[derive(Debug)]
pub enum UnknownParentLookupUpdate {
    Downloaded {
        action_id: LookupActionId,
        requested_root: B256,
        block: Box<SignedBeaconBlock>,
    },
    DownloadFailed {
        action_id: LookupActionId,
        requested_root: B256,
        peer: PeerId,
        error: ParentLookupRequestError,
    },
    BlockImported {
        action_id: LookupActionId,
        block_root: B256,
    },
    BlockPendingAvailability {
        action_id: LookupActionId,
        block_root: B256,
    },
    BlockFailed {
        action_id: LookupActionId,
        block_root: B256,
        retry_by_download: bool,
        error: String,
    },
}

pub fn spawn_unknown_parent_action(
    action: UnknownParentAction<SignedBeaconBlock, PeerId>,
    beacon_chain: std::sync::Arc<BeaconChain>,
    cached_db: std::sync::Arc<ream_storage::cache::BeaconCacheDB>,
    p2p_sender: P2PSender,
    update_sender: mpsc::Sender<UnknownParentLookupUpdate>,
) {
    tokio::spawn(async move {
        let update =
            execute_unknown_parent_action(action, &beacon_chain, &cached_db, &p2p_sender).await;
        let _ = update_sender.send(update).await;
    });
}

async fn execute_unknown_parent_action(
    action: UnknownParentAction<SignedBeaconBlock, PeerId>,
    beacon_chain: &BeaconChain,
    cached_db: &ream_storage::cache::BeaconCacheDB,
    p2p_sender: &P2PSender,
) -> UnknownParentLookupUpdate {
    match action {
        UnknownParentAction::RequestBlock {
            action_id,
            block_root,
            peer,
        } => match request_single_block_by_root(p2p_sender, peer, block_root).await {
            Ok(block) => UnknownParentLookupUpdate::Downloaded {
                action_id,
                requested_root: block_root,
                block: Box::new(block),
            },
            Err(err) => UnknownParentLookupUpdate::DownloadFailed {
                action_id,
                requested_root: block_root,
                peer,
                error: err,
            },
        },
        UnknownParentAction::ProcessBlock {
            action_id,
            meta,
            origin,
            payload,
        } => {
            if let PayloadOrigin::Gossip = origin {
                match validate_lookup_beacon_block(beacon_chain, cached_db, &payload).await {
                    Ok(DependencyValidationResult::Accept) => {}
                    Ok(other) => {
                        return UnknownParentLookupUpdate::BlockFailed {
                            action_id,
                            block_root: meta.block_root,
                            retry_by_download: false,
                            error: format!("gossip validation returned {other:?}"),
                        };
                    }
                    Err(err) => {
                        return UnknownParentLookupUpdate::BlockFailed {
                            action_id,
                            block_root: meta.block_root,
                            retry_by_download: false,
                            error: err.to_string(),
                        };
                    }
                }
            }

            match beacon_chain.process_block(payload).await {
                Ok(BlockProcessingOutcome::Imported { block_root }) => {
                    UnknownParentLookupUpdate::BlockImported {
                        action_id,
                        block_root,
                    }
                }
                Ok(BlockProcessingOutcome::PendingAvailability { block_root }) => {
                    UnknownParentLookupUpdate::BlockPendingAvailability {
                        action_id,
                        block_root,
                    }
                }
                Err(err) => UnknownParentLookupUpdate::BlockFailed {
                    action_id,
                    block_root: meta.block_root,
                    retry_by_download: true,
                    error: err.to_string(),
                },
            }
        }
    }
}

pub async fn parent_status(
    beacon_chain: &BeaconChain,
    parent_root: B256,
) -> anyhow::Result<ParentStatus> {
    let store = beacon_chain.store.lock().await;
    let imported = store.db.block_provider().get(parent_root)?.is_some()
        && store.db.state_provider().contains_key(parent_root)?;
    if imported {
        return Ok(ParentStatus::Imported);
    }
    if store
        .data_availability_checker
        .pending_block(&parent_root)
        .is_some()
    {
        return Ok(ParentStatus::PendingAvailability);
    }
    Ok(ParentStatus::Unknown)
}

/// Peers that answered blocks-by-root with an unsupported-protocol error. Nodes that only relay
/// gossip do this, and they are often the first to forward a block; asking them again only spends
/// a lookup's attempts.
#[derive(Debug, Default)]
pub struct BlocksByRootRefusals {
    order: VecDeque<PeerId>,
    peers: HashSet<PeerId>,
}

const MAX_REFUSING_PEERS: usize = 1024;

impl BlocksByRootRefusals {
    pub fn insert(&mut self, peer: PeerId) {
        if !self.peers.insert(peer) {
            return;
        }
        self.order.push_back(peer);
        if self.order.len() > MAX_REFUSING_PEERS
            && let Some(oldest) = self.order.pop_front()
        {
            self.peers.remove(&oldest);
        }
    }

    pub fn contains(&self, peer: &PeerId) -> bool {
        self.peers.contains(peer)
    }
}

/// A connected peer, not in `exclude`, that sent its status and has not refused blocks by root.
/// The choice is spread over candidates by `block_root`, so concurrent lookups ask different peers.
pub fn fallback_lookup_peer(
    network_state: &NetworkState,
    refusals: &BlocksByRootRefusals,
    exclude: &[PeerId],
    block_root: B256,
) -> Option<PeerId> {
    pick_fallback_peer(
        network_state
            .connected_peers()
            .into_iter()
            .map(|peer| (peer.peer_id, peer.status.is_some())),
        refusals,
        exclude,
        block_root,
    )
}

/// `fallback_lookup_peer` over `(peer, sent status)` pairs of connected peers.
fn pick_fallback_peer(
    peers: impl Iterator<Item = (PeerId, bool)>,
    refusals: &BlocksByRootRefusals,
    exclude: &[PeerId],
    block_root: B256,
) -> Option<PeerId> {
    let mut candidates = peers
        .filter(|(peer, sent_status)| {
            *sent_status && !exclude.contains(peer) && !refusals.contains(peer)
        })
        .map(|(peer, _)| peer)
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return None;
    }
    candidates.sort();
    let index = u64::from_le_bytes(block_root[..8].try_into().expect("root has 32 bytes"));
    Some(candidates[(index % candidates.len() as u64) as usize])
}

pub async fn apply_unknown_parent_update(
    coordinator: &mut UnknownParentLookupCoordinator<SignedBeaconBlock, PeerId>,
    beacon_chain: &BeaconChain,
    network_state: &NetworkState,
    refusals: &mut BlocksByRootRefusals,
    update: UnknownParentLookupUpdate,
) {
    match update {
        UnknownParentLookupUpdate::Downloaded {
            action_id,
            requested_root,
            block,
        } => {
            let meta = UnknownBlockMeta {
                block_root: requested_root,
                parent_root: block.message.parent_root,
                slot: block.message.slot,
            };
            match parent_status(beacon_chain, meta.parent_root).await {
                Ok(status) => {
                    if let Err(err) =
                        coordinator.download_succeeded(action_id, meta, *block, status)
                    {
                        warn!(
                            ?requested_root,
                            ?err,
                            "Dropping invalid parent lookup chain"
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        ?requested_root,
                        ?err,
                        "Failed to classify downloaded parent"
                    );
                    coordinator.download_failed(action_id, requested_root);
                }
            }
        }
        UnknownParentLookupUpdate::DownloadFailed {
            action_id,
            requested_root,
            peer,
            error,
        } => {
            warn!(
                ?requested_root,
                %peer,
                ?error,
                "Blocks-by-root parent lookup failed"
            );
            if matches!(error, ParentLookupRequestError::UnsupportedProtocol) {
                refusals.insert(peer);
            }
            // Prefer a peer this lookup has not asked yet. Without one, the lookup retries the
            // peers it has rather than cycling between the last two that failed.
            let mut asked = coordinator.asked_peers(requested_root).to_vec();
            asked.push(peer);
            let replacement = fallback_lookup_peer(network_state, refusals, &asked, requested_root);
            coordinator.replace_peer(requested_root, &peer, replacement);
            coordinator.download_failed(action_id, requested_root);
        }
        UnknownParentLookupUpdate::BlockImported {
            action_id,
            block_root,
        } => {
            coordinator.process_imported(action_id, block_root);
        }
        UnknownParentLookupUpdate::BlockPendingAvailability {
            action_id,
            block_root,
        } => {
            coordinator.process_pending_availability(action_id, block_root);
        }
        UnknownParentLookupUpdate::BlockFailed {
            action_id,
            block_root,
            retry_by_download,
            error,
        } => {
            warn!(
                ?block_root,
                ?error,
                "Unknown-parent block processing failed"
            );
            coordinator.process_failed(action_id, block_root, retry_by_download);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentLookupRequestError {
    RequestChannelClosed,
    EmptyResponse,
    ExtraResponse,
    WrongRoot { expected: B256, received: B256 },
    UnexpectedResponseType,
    Disconnected,
    Timeout,
    UnsupportedProtocol,
    Callback(String),
    ResponseChannelClosed,
}

impl fmt::Display for ParentLookupRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestChannelClosed => write!(formatter, "P2P request channel closed"),
            Self::EmptyResponse => write!(formatter, "blocks-by-root response was empty"),
            Self::ExtraResponse => write!(formatter, "blocks-by-root returned more than one block"),
            Self::WrongRoot { expected, received } => write!(
                formatter,
                "blocks-by-root returned root {received}, expected {expected}"
            ),
            Self::UnexpectedResponseType => {
                write!(formatter, "received a non-blocks-by-root response")
            }
            Self::Disconnected => write!(formatter, "peer disconnected during blocks-by-root"),
            Self::Timeout => write!(formatter, "blocks-by-root request timed out"),
            Self::UnsupportedProtocol => {
                write!(formatter, "peer does not serve blocks-by-root")
            }
            Self::Callback(error) => write!(formatter, "blocks-by-root callback failed: {error}"),
            Self::ResponseChannelClosed => {
                write!(
                    formatter,
                    "blocks-by-root response channel closed before end-of-stream"
                )
            }
        }
    }
}

impl std::error::Error for ParentLookupRequestError {}

pub async fn request_single_block_by_root(
    p2p_sender: &P2PSender,
    peer_id: PeerId,
    expected_root: B256,
) -> Result<SignedBeaconBlock, ParentLookupRequestError> {
    let (callback, mut response_receiver) = mpsc::channel(2);
    if p2p_sender
        .0
        .send(P2PMessage::Request(P2PRequest::BlockRoots {
            peer_id,
            roots: vec![expected_root],
            callback,
        }))
        .is_err()
    {
        return Err(ParentLookupRequestError::RequestChannelClosed);
    }

    let mut received_block = None;
    while let Some(response) = response_receiver.recv().await {
        match response {
            Ok(P2PCallbackResponse::ResponseMessage(message)) => {
                let BeaconResponseMessage::BeaconBlocksByRoot(block) = message.as_ref() else {
                    return Err(ParentLookupRequestError::UnexpectedResponseType);
                };
                if received_block.is_some() {
                    return Err(ParentLookupRequestError::ExtraResponse);
                }

                let received_root = block.message.tree_hash_root();
                if received_root != expected_root {
                    return Err(ParentLookupRequestError::WrongRoot {
                        expected: expected_root,
                        received: received_root,
                    });
                }
                received_block = Some(block.clone());
            }
            Ok(P2PCallbackResponse::EndOfStream) => {
                return received_block.ok_or(ParentLookupRequestError::EmptyResponse);
            }
            Ok(P2PCallbackResponse::Disconnected) => {
                return Err(ParentLookupRequestError::Disconnected);
            }
            Ok(P2PCallbackResponse::Timeout) => {
                return Err(ParentLookupRequestError::Timeout);
            }
            Err(P2PCallbackError::ReqResp(ReqRespError::UnsupportedProtocol)) => {
                return Err(ParentLookupRequestError::UnsupportedProtocol);
            }
            Err(err) => return Err(ParentLookupRequestError::Callback(err.to_string())),
        }
    }

    Err(ParentLookupRequestError::ResponseChannelClosed)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use anyhow::anyhow;
    use ream_p2p::network::beacon::channel::P2PCallbackError;
    use ream_syncer::unknown_parent_lookups::UnknownParentLookupConfig;
    use tokio::sync::mpsc::{self, UnboundedReceiver, error::TryRecvError};

    use super::*;

    fn setup() -> (P2PSender, UnboundedReceiver<P2PMessage>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (P2PSender(sender), receiver)
    }

    async fn intercept_request(
        receiver: &mut UnboundedReceiver<P2PMessage>,
        expected_peer: PeerId,
        expected_root: B256,
    ) -> mpsc::Sender<Result<P2PCallbackResponse, P2PCallbackError>> {
        let message = receiver.recv().await.expect("request should be sent");
        let P2PMessage::Request(P2PRequest::BlockRoots {
            peer_id,
            roots,
            callback,
        }) = message
        else {
            panic!("expected a blocks-by-root request");
        };
        assert_eq!(peer_id, expected_peer);
        assert_eq!(roots, vec![expected_root]);
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        callback
    }

    fn block() -> SignedBeaconBlock {
        SignedBeaconBlock {
            message: Default::default(),
            signature: Default::default(),
        }
    }

    #[tokio::test]
    async fn returns_one_matching_block_after_end_of_stream() {
        let (sender, mut receiver) = setup();
        let peer_id = PeerId::random();
        let block = block();
        let block_root = block.message.tree_hash_root();
        let request_sender = sender.clone();
        let request = tokio::spawn(async move {
            request_single_block_by_root(&request_sender, peer_id, block_root).await
        });

        let callback = intercept_request(&mut receiver, peer_id, block_root).await;
        callback
            .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
                BeaconResponseMessage::BeaconBlocksByRoot(block.clone()),
            ))))
            .await
            .expect("block response should be delivered");
        callback
            .send(Ok(P2PCallbackResponse::EndOfStream))
            .await
            .expect("end-of-stream should be delivered");

        assert_eq!(request.await.expect("request task should join"), Ok(block));
    }

    #[tokio::test]
    async fn rejects_a_wrong_root() {
        let (sender, mut receiver) = setup();
        let peer_id = PeerId::random();
        let block = block();
        let received_root = block.message.tree_hash_root();
        let expected_root = B256::repeat_byte(0x42);
        assert_ne!(received_root, expected_root);
        let request_sender = sender.clone();
        let request = tokio::spawn(async move {
            request_single_block_by_root(&request_sender, peer_id, expected_root).await
        });

        let callback = intercept_request(&mut receiver, peer_id, expected_root).await;
        callback
            .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
                BeaconResponseMessage::BeaconBlocksByRoot(block),
            ))))
            .await
            .expect("wrong-root response should be delivered");

        assert_eq!(
            request.await.expect("request task should join"),
            Err(ParentLookupRequestError::WrongRoot {
                expected: expected_root,
                received: received_root,
            })
        );
    }

    #[tokio::test]
    async fn rejects_an_empty_response() {
        let (sender, mut receiver) = setup();
        let peer_id = PeerId::random();
        let expected_root = B256::repeat_byte(0x42);
        let request_sender = sender.clone();
        let request = tokio::spawn(async move {
            request_single_block_by_root(&request_sender, peer_id, expected_root).await
        });

        let callback = intercept_request(&mut receiver, peer_id, expected_root).await;
        callback
            .send(Ok(P2PCallbackResponse::EndOfStream))
            .await
            .expect("end-of-stream should be delivered");

        assert_eq!(
            request.await.expect("request task should join"),
            Err(ParentLookupRequestError::EmptyResponse)
        );
    }

    #[tokio::test]
    async fn rejects_an_extra_response() {
        let (sender, mut receiver) = setup();
        let peer_id = PeerId::random();
        let block = block();
        let expected_root = block.message.tree_hash_root();
        let request_sender = sender.clone();
        let request = tokio::spawn(async move {
            request_single_block_by_root(&request_sender, peer_id, expected_root).await
        });

        let callback = intercept_request(&mut receiver, peer_id, expected_root).await;
        for _ in 0..2 {
            callback
                .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
                    BeaconResponseMessage::BeaconBlocksByRoot(block.clone()),
                ))))
                .await
                .expect("block response should be delivered");
        }

        assert_eq!(
            request.await.expect("request task should join"),
            Err(ParentLookupRequestError::ExtraResponse)
        );
    }

    #[tokio::test]
    async fn returns_callback_errors() {
        let (sender, mut receiver) = setup();
        let peer_id = PeerId::random();
        let expected_root = B256::repeat_byte(0x42);
        let request_sender = sender.clone();
        let request = tokio::spawn(async move {
            request_single_block_by_root(&request_sender, peer_id, expected_root).await
        });

        let callback = intercept_request(&mut receiver, peer_id, expected_root).await;
        callback
            .send(Err(anyhow!("transport failed").into()))
            .await
            .expect("callback error should be delivered");

        assert_eq!(
            request.await.expect("request task should join"),
            Err(ParentLookupRequestError::Callback(
                "transport failed".to_string()
            ))
        );
    }

    #[test]
    fn fallback_skips_refusing_excluded_and_statusless_peers() {
        let [refusing, excluded, statusless, usable] = [(); 4].map(|_| PeerId::random());
        let mut refusals = BlocksByRootRefusals::default();
        refusals.insert(refusing);
        let peers = [
            (refusing, true),
            (excluded, true),
            (statusless, false),
            (usable, true),
        ];
        assert_eq!(
            pick_fallback_peer(peers.into_iter(), &refusals, &[excluded], B256::ZERO),
            Some(usable)
        );
        assert_eq!(
            pick_fallback_peer(
                peers.into_iter().take(3),
                &refusals,
                &[excluded],
                B256::ZERO
            ),
            None
        );
    }

    /// A lookup whose peers keep failing asks every connected peer once before retrying any.
    #[test]
    fn successive_fallbacks_ask_peers_not_yet_asked() {
        let mut peers = [(); 3].map(|_| PeerId::random());
        peers.sort();
        let parent_root = B256::ZERO;
        let mut coordinator =
            UnknownParentLookupCoordinator::<(), PeerId>::new(UnknownParentLookupConfig::default());
        coordinator.insert_gossip_block(
            UnknownBlockMeta {
                block_root: B256::repeat_byte(1),
                parent_root,
                slot: 1,
            },
            (),
            peers[0],
        );
        let refusals = BlocksByRootRefusals::default();

        let mut requested = Vec::new();
        for _ in 0..peers.len() {
            let Some(UnknownParentAction::RequestBlock {
                action_id,
                block_root,
                peer,
            }) = coordinator.next_action()
            else {
                panic!("expected a block request");
            };
            assert_eq!(block_root, parent_root);
            requested.push(peer);

            let mut asked = coordinator.asked_peers(parent_root).to_vec();
            asked.push(peer);
            let replacement = pick_fallback_peer(
                peers.iter().map(|peer| (*peer, true)),
                &refusals,
                &asked,
                parent_root,
            );
            coordinator.replace_peer(parent_root, &peer, replacement);
            assert!(coordinator.download_failed(action_id, parent_root));
        }
        assert_eq!(requested, peers);
    }

    #[test]
    fn refusals_forget_the_oldest_peer_beyond_capacity() {
        let mut refusals = BlocksByRootRefusals::default();
        let first = PeerId::random();
        refusals.insert(first);
        for _ in 0..MAX_REFUSING_PEERS {
            refusals.insert(PeerId::random());
        }
        assert!(!refusals.contains(&first));
        assert_eq!(refusals.peers.len(), MAX_REFUSING_PEERS);
    }
}
