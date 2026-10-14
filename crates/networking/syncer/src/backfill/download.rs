//! Session-owned block downloads. The byte limit applies while receiving, before verification.
use ream_consensus_beacon::electra::beacon_block::SignedBeaconBlock;
use ream_p2p::network::beacon::channel::{
    P2PCallbackError, P2PCallbackResponse, P2PMessage, P2PRequest,
};
use ream_req_resp::{beacon::messages::BeaconResponseMessage, error::ReqRespError};
use ssz::Encode;
use tokio::sync::mpsc;

use super::scheduler::{Request, RequestKind};

pub(super) enum Response {
    Blocks(Vec<SignedBeaconBlock>),
    Fault(String),
    UnsupportedFork,
    Unavailable,
    /// A local resource limit, never evidence against the peer.
    TooLarge,
}

pub(super) async fn receive(
    request: &Request,
    sender: mpsc::UnboundedSender<P2PMessage>,
    max_bytes: usize,
) -> Response {
    // Do not queue an epoch of decoded blocks behind the consumer. Codec buffers and this
    // single callback item are transient overhead, separate from retained SSZ payload bytes.
    let (callback, mut receiver) = mpsc::channel(1);
    let message = match request.kind {
        RequestKind::Range { start_slot, count } => P2PRequest::BlockRange {
            peer_id: request.peer_id,
            start: start_slot,
            count,
            callback,
        },
        RequestKind::Parent { root } => P2PRequest::BlockRoots {
            peer_id: request.peer_id,
            roots: vec![root],
            callback,
        },
    };
    if sender.send(P2PMessage::Request(message)).is_err() {
        return Response::Unavailable;
    }
    let mut blocks = Vec::new();
    let mut bytes = 0usize;
    while let Some(response) = receiver.recv().await {
        match response {
            Ok(P2PCallbackResponse::ResponseMessage(message)) => {
                let block = match (&request.kind, message.as_ref()) {
                    (
                        RequestKind::Range { .. },
                        BeaconResponseMessage::BeaconBlocksByRange(block),
                    )
                    | (
                        RequestKind::Parent { .. },
                        BeaconResponseMessage::BeaconBlocksByRoot(block),
                    ) => block,
                    _ => return Response::Fault("unexpected block response type".to_string()),
                };
                let count = match request.kind {
                    RequestKind::Range { count, .. } => count,
                    RequestKind::Parent { .. } => 1,
                };
                if blocks.len() as u64 >= count {
                    return Response::Fault("too many blocks in response".to_string());
                }
                let size = block.ssz_bytes_len();
                if size > max_bytes.saturating_sub(bytes) {
                    return Response::TooLarge;
                }
                bytes += size;
                blocks.push(block.clone());
            }
            Ok(P2PCallbackResponse::EndOfStream) => return Response::Blocks(blocks),
            Err(P2PCallbackError::ReqResp(ReqRespError::UnsupportedFork(_))) => {
                return Response::UnsupportedFork;
            }
            Err(P2PCallbackError::ReqResp(ReqRespError::InvalidData(detail))) => {
                return Response::Fault(detail);
            }
            _ => return Response::Unavailable,
        }
    }
    Response::Unavailable
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use libp2p::PeerId;
    use ream_storage::tables::beacon::backfill::Frontier;
    use tokio::{
        task::JoinSet,
        time::{Duration, timeout},
    };

    use super::*;
    use crate::backfill::scheduler::{BackfillConfig, Scheduler};

    fn request() -> Request {
        let mut scheduler = Scheduler::new(
            BackfillConfig::default(),
            Frontier {
                oldest_block_slot: 32,
                oldest_block_root: Default::default(),
                oldest_block_parent: Default::default(),
            },
            0,
        );
        scheduler
            .next_requests(std::time::Instant::now(), 0, &mut |_, _| {
                Some(PeerId::random())
            })
            .remove(0)
    }

    fn block() -> SignedBeaconBlock {
        SignedBeaconBlock {
            message: Default::default(),
            signature: Default::default(),
        }
    }

    async fn callback(
        receiver: &mut mpsc::UnboundedReceiver<P2PMessage>,
    ) -> mpsc::Sender<Result<P2PCallbackResponse, P2PCallbackError>> {
        match receiver.recv().await.unwrap() {
            P2PMessage::Request(P2PRequest::BlockRange { callback, .. }) => callback,
            _ => panic!("expected block range request"),
        }
    }

    #[tokio::test]
    async fn receive_limit_stops_before_end_of_stream() {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let block = block();
        let size = block.ssz_bytes_len();
        let task = tokio::spawn(async move { receive(&request(), sender, size).await });
        let callback = callback(&mut receiver).await;
        for _ in 0..2 {
            callback
                .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
                    BeaconResponseMessage::BeaconBlocksByRange(block.clone()),
                ))))
                .await
                .unwrap();
        }
        // No EndOfStream: exceeding the cap must stop receiving immediately.
        assert!(matches!(
            timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap(),
            Response::TooLarge
        ));
        assert!(callback.is_closed());
    }

    #[tokio::test]
    async fn exact_receive_limit_is_accepted() {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let block = block();
        let size = block.ssz_bytes_len();
        let task = tokio::spawn(async move { receive(&request(), sender, size).await });
        let callback = callback(&mut receiver).await;
        callback
            .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
                BeaconResponseMessage::BeaconBlocksByRange(block),
            ))))
            .await
            .unwrap();
        callback
            .send(Ok(P2PCallbackResponse::EndOfStream))
            .await
            .unwrap();
        assert!(matches!(task.await.unwrap(), Response::Blocks(blocks) if blocks.len() == 1));
    }

    #[tokio::test]
    async fn cancelling_session_closes_inflight_response_receivers() {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move { receive(&request(), sender, usize::MAX).await });
        let callback = callback(&mut receiver).await;
        tasks.shutdown().await;
        assert!(callback.is_closed());
        assert!(
            callback
                .send(Ok(P2PCallbackResponse::EndOfStream))
                .await
                .is_err()
        );
    }
}
