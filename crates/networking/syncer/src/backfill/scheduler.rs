//! Decides what to download and what to commit while backfilling blocks below the checkpoint
//! origin. It performs no IO: the driver sends the requests, verifies the responses and writes
//! the commits.
//!
//! The uncommitted slots below the block frontier are split into one batch per epoch. Batches
//! are downloaded in parallel and committed strictly from the frontier downwards, and only when
//! the highest block of a batch is the parent of the frontier. A hash link is the only proof of
//! ancestry: an empty or short response proves nothing, so when the batches below the frontier
//! do not connect, the parent is requested by root and committed on its own.
use std::{
    collections::{BTreeMap, HashSet},
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use libp2p::PeerId;
use ream_chain_beacon::historical_blocks::RootedBlock;
use ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH;
use ream_storage::tables::beacon::backfill::Frontier;
use ssz::Encode;
use tracing::warn;

/// Delay before asking another peer for the parent of the frontier after an empty answer.
const PARENT_RETRY_DELAY: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct BackfillConfig {
    /// Concurrent range requests. The request for the parent of the frontier is not counted.
    pub max_inflight: usize,
    /// Retained SSZ payload budget, including reservations for downloads and verification.
    /// Codec buffers, one queued callback per request and Rust object overhead are separate.
    pub max_pending_bytes: usize,
    /// Share reserved for a single parent response, so oversized ranges cannot block progress.
    pub frontier_reserve_bytes: usize,
    /// Hard limit for a range response, reserved until verification finishes.
    pub max_response_bytes: usize,
    /// Lowest epoch below the frontier that may be requested ahead of it.
    pub max_window_epochs: u64,
    /// Answers collected for a batch that does not connect before its parent is asked by root.
    pub batch_retry_answers: usize,
    /// Consecutive empty batches below the frontier before the gap stops being trusted.
    pub empty_scan_limit: usize,
}

impl Default for BackfillConfig {
    fn default() -> Self {
        Self {
            max_inflight: 2,
            max_pending_bytes: 64 * 1024 * 1024,
            frontier_reserve_bytes: 16 * 1024 * 1024,
            max_response_bytes: 16 * 1024 * 1024,
            max_window_epochs: 16,
            batch_retry_answers: 2,
            empty_scan_limit: 2,
        }
    }
}

/// Identifies a request. A response whose generation is not the current one belongs to a
/// paused session and is dropped before it is judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId {
    generation: u64,
    sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestKind {
    Range {
        start_slot: u64,
        count: u64,
    },
    /// The parent of the block frontier, by root.
    Parent {
        root: B256,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub id: RequestId,
    pub peer_id: PeerId,
    pub kind: RequestKind,
}

/// A response after the driver has checked it against its request and verified signatures.
#[derive(Debug)]
pub enum Outcome {
    /// Well formed and correctly signed. May be empty or shorter than requested.
    Blocks(Vec<RootedBlock>),
    /// The response is evidence against the peer.
    Fault(String),
    /// Timeout, transport failure or `ResourceUnavailable`: evidence of nothing.
    Unavailable,
    /// The range exceeded our receive budget; recover by root without penalizing the peer.
    TooLarge,
    /// The peer answered with a block of a fork older than we can decode.
    UnsupportedFork,
}

#[derive(Debug)]
pub enum Step {
    /// Blocks in ascending order whose highest block is the parent of the frontier. The driver
    /// must report the result with [`Scheduler::on_committed`] or [`Scheduler::reset`].
    Commit(Vec<RootedBlock>),
    /// The frontier is at or below the retention target, or at genesis.
    Complete,
    /// The parent of the frontier is proven to be below the oldest fork we can decode.
    UnsupportedForkBoundary { boundary_slot: u64 },
    /// Nothing to commit until more responses arrive.
    Wait,
}

#[derive(Debug)]
enum BatchState {
    Todo,
    InFlight {
        id: RequestId,
        peer_id: PeerId,
    },
    Have {
        peer_id: PeerId,
        blocks: Vec<RootedBlock>,
        bytes: usize,
    },
}

/// The uncommitted slots `[start_slot, end_slot)` of one epoch.
#[derive(Debug)]
struct Batch {
    start_slot: u64,
    end_slot: u64,
    state: BatchState,
    /// Peers not to ask again for this batch until every candidate has been tried.
    attempted: HashSet<PeerId>,
    /// Well-formed answers received so far.
    answers: usize,
    /// Answers that exceeded the receive limit.
    too_large_answers: usize,
    /// This epoch must be fetched one parent at a time after exceeding the receive limit.
    by_root_only: bool,
    /// `(slot, root)` of blocks from answers set aside because they did not connect, kept until
    /// the frontier passes them and shows whether they were ancestors of the origin.
    doubted: Vec<(PeerId, Vec<(u64, B256)>)>,
}

#[derive(Debug)]
enum ParentRequest {
    Idle,
    InFlight { id: RequestId },
}

pub struct Scheduler {
    config: BackfillConfig,
    frontier: Frontier,
    /// Oldest slot whose block type we can decode. No range request starts below it.
    floor_slot: u64,
    generation: u64,
    next_sequence: u64,
    batches: BTreeMap<u64, Batch>,
    parent_wanted: bool,
    parent_request: ParentRequest,
    parent_attempted: HashSet<PeerId>,
    parent_retry_at: Option<Instant>,
    /// The verified parent of the frontier, waiting to be committed.
    pending_parent: Option<RootedBlock>,
    /// `(slot, root)` of the blocks last handed to the driver for commit.
    handed_out: Vec<(u64, B256)>,
    boundary: Option<u64>,
    /// Warn once per frontier.
    fork_stall_logged: bool,
    bans: Vec<(PeerId, String)>,
    evicted_batches: u64,
}

impl Scheduler {
    pub fn new(config: BackfillConfig, frontier: Frontier, floor_slot: u64) -> Self {
        Self {
            config,
            frontier,
            floor_slot,
            generation: 0,
            next_sequence: 0,
            batches: BTreeMap::new(),
            parent_wanted: false,
            parent_request: ParentRequest::Idle,
            parent_attempted: HashSet::new(),
            parent_retry_at: None,
            pending_parent: None,
            handed_out: Vec::new(),
            boundary: None,
            fork_stall_logged: false,
            bans: Vec::new(),
            evicted_batches: 0,
        }
    }

    /// Check provenance before the driver spends CPU verifying a response. Revision changes
    /// do not invalidate a request, but a paused generation or a superseded parent does.
    pub fn is_current(&self, id: RequestId) -> bool {
        id.generation == self.generation
            && (matches!(self.parent_request, ParentRequest::InFlight { id: current } if current == id)
                || self.batches.values().any(|batch| {
                    matches!(batch.state, BatchState::InFlight { id: current, .. } if current == id)
                }))
    }

    pub fn frontier(&self) -> &Frontier {
        &self.frontier
    }

    pub fn pending_bytes(&self) -> usize {
        self.batches
            .values()
            .map(|batch| match &batch.state {
                BatchState::Have { bytes, .. } => *bytes,
                _ => 0,
            })
            .sum()
    }

    pub fn evicted_batches(&self) -> u64 {
        self.evicted_batches
    }

    /// Peers proven to have sent a bad response since the last call.
    pub fn take_bans(&mut self) -> Vec<(PeerId, String)> {
        std::mem::take(&mut self.bans)
    }

    /// Ends the current session: responses still in flight will be dropped unjudged. Verified
    /// batches stay valid and are kept.
    pub fn pause(&mut self) {
        self.generation += 1;
        for batch in self.batches.values_mut() {
            if let BatchState::InFlight { peer_id, .. } = &batch.state {
                batch.attempted.remove(peer_id);
                batch.state = BatchState::Todo;
            }
        }
        self.parent_request = ParentRequest::Idle;
        self.parent_attempted.clear();
        self.parent_retry_at = None;
    }

    /// Restarts from durable metadata after a commit did not apply as planned.
    pub fn reset(&mut self, frontier: Frontier) {
        let config = self.config.clone();
        let generation = self.generation + 1;
        *self = Self::new(config, frontier, self.floor_slot);
        self.generation = generation;
    }

    fn next_id(&mut self) -> RequestId {
        self.next_sequence += 1;
        RequestId {
            generation: self.generation,
            sequence: self.next_sequence,
        }
    }

    fn lowest_epoch(&self, target_slot: u64) -> u64 {
        self.floor_slot.max(target_slot) / SLOTS_PER_EPOCH
    }

    fn inflight_ranges(&self) -> usize {
        self.batches
            .values()
            .filter(|batch| matches!(batch.state, BatchState::InFlight { .. }))
            .count()
    }

    /// Requests to send now. `pick_peer(lowest_slot, excluded)` reserves an idle peer able to
    /// serve `lowest_slot` that is not in `excluded`.
    pub fn next_requests(
        &mut self,
        now: Instant,
        target_slot: u64,
        pick_peer: &mut dyn FnMut(u64, &HashSet<PeerId>) -> Option<PeerId>,
    ) -> Vec<Request> {
        self.next_requests_with_downloads(now, target_slot, self.inflight_ranges(), pick_peer)
    }

    /// `downloads` includes obsolete requests still being drained by the driver, and completed
    /// responses waiting for verification. They retain their reservation until consumed.
    pub fn next_requests_with_downloads(
        &mut self,
        now: Instant,
        target_slot: u64,
        downloads: usize,
        pick_peer: &mut dyn FnMut(u64, &HashSet<PeerId>) -> Option<PeerId>,
    ) -> Vec<Request> {
        let mut requests = Vec::new();
        let frontier_slot = self.frontier.oldest_block_slot;
        if frontier_slot == 0 || frontier_slot <= target_slot {
            return requests;
        }

        if self.parent_wanted
            && self.pending_parent.is_none()
            && matches!(self.parent_request, ParentRequest::Idle)
            && self.parent_retry_at.is_none_or(|retry_at| now >= retry_at)
            && self
                .pending_bytes()
                .saturating_add(
                    downloads.saturating_mul(
                        self.config
                            .max_response_bytes
                            .max(self.config.frontier_reserve_bytes),
                    ),
                )
                .saturating_add(self.config.frontier_reserve_bytes)
                <= self.config.max_pending_bytes
        {
            match pick_peer(frontier_slot - 1, &self.parent_attempted) {
                Some(peer_id) => {
                    let id = self.next_id();
                    self.parent_request = ParentRequest::InFlight { id };
                    self.parent_attempted.insert(peer_id);
                    requests.push(Request {
                        id,
                        peer_id,
                        kind: RequestKind::Parent {
                            root: self.frontier.oldest_block_parent,
                        },
                    });
                }
                // Everyone was asked: start over rather than stall.
                None => self.parent_attempted.clear(),
            }
        }

        let top_epoch = (frontier_slot - 1) / SLOTS_PER_EPOCH;
        let lowest_epoch = self.lowest_epoch(target_slot);
        let mut epoch = top_epoch;
        while epoch >= lowest_epoch && top_epoch - epoch < self.config.max_window_epochs {
            let start_slot = (epoch * SLOTS_PER_EPOCH).max(self.floor_slot);
            let end_slot = ((epoch + 1) * SLOTS_PER_EPOCH).min(frontier_slot);
            if start_slot >= end_slot {
                break;
            }
            let inflight = self.inflight_ranges().max(downloads + requests.len());
            if inflight >= self.config.max_inflight {
                break;
            }
            let unreserved = self
                .config
                .max_pending_bytes
                .saturating_sub(self.config.frontier_reserve_bytes);
            let over_budget =
                self.pending_bytes() + (inflight + 1) * self.config.max_response_bytes > unreserved;

            let batch = self.batches.entry(epoch).or_insert_with(|| Batch {
                start_slot,
                end_slot,
                state: BatchState::Todo,
                attempted: HashSet::new(),
                answers: 0,
                too_large_answers: 0,
                by_root_only: false,
                doubted: Vec::new(),
            });
            if matches!(batch.state, BatchState::Todo) {
                // Never consume the parent reserve with range data.
                if over_budget {
                    break;
                }
                match pick_peer(batch.start_slot, &batch.attempted) {
                    Some(peer_id) => {
                        self.next_sequence += 1;
                        let id = RequestId {
                            generation: self.generation,
                            sequence: self.next_sequence,
                        };
                        batch.state = BatchState::InFlight { id, peer_id };
                        batch.attempted.insert(peer_id);
                        requests.push(Request {
                            id,
                            peer_id,
                            kind: RequestKind::Range {
                                start_slot: batch.start_slot,
                                count: batch.end_slot - batch.start_slot,
                            },
                        });
                    }
                    None => batch.attempted.clear(),
                }
            }

            if epoch == 0 {
                break;
            }
            epoch -= 1;
        }
        requests
    }

    /// Feeds one checked response back. Stale responses are dropped without being judged.
    pub fn on_result(&mut self, id: RequestId, peer_id: PeerId, outcome: Outcome, now: Instant) {
        if id.generation != self.generation {
            return;
        }

        if matches!(self.parent_request, ParentRequest::InFlight { id: parent_id } if parent_id == id)
        {
            self.parent_request = ParentRequest::Idle;
            self.on_parent_result(peer_id, outcome, now);
            return;
        }

        let frontier_slot = self.frontier.oldest_block_slot;
        let Some(batch) = self.batches.values_mut().find(
            |batch| matches!(batch.state, BatchState::InFlight { id: batch_id, .. } if batch_id == id),
        ) else {
            return;
        };
        match outcome {
            Outcome::Blocks(mut blocks) => {
                // The frontier may have moved into this range while the request was in flight.
                blocks.retain(|(_, block)| block.message.slot < frontier_slot);
                let bytes = blocks
                    .iter()
                    .map(|(_, block)| block.ssz_bytes_len())
                    .sum::<usize>();
                batch.answers += 1;
                batch.state = BatchState::Have {
                    peer_id,
                    blocks,
                    bytes,
                };
                self.evict();
            }
            Outcome::Fault(reason) => {
                batch.state = BatchState::Todo;
                self.bans.push((peer_id, reason));
            }
            // Range requests never start below the oldest supported fork.
            Outcome::UnsupportedFork => {
                batch.state = BatchState::Todo;
                self.bans.push((
                    peer_id,
                    "range response belongs to an unsupported fork".to_string(),
                ));
            }
            // Unverified, so it may be junk: ask another peer before falling back to by-root.
            Outcome::TooLarge => {
                batch.too_large_answers += 1;
                if batch.too_large_answers < self.config.batch_retry_answers {
                    batch.state = BatchState::Todo;
                } else {
                    batch.by_root_only = true;
                    batch.answers = self.config.batch_retry_answers;
                    batch.state = BatchState::Have {
                        peer_id,
                        blocks: vec![],
                        bytes: 0,
                    };
                }
            }
            Outcome::Unavailable => batch.state = BatchState::Todo,
        }
    }

    fn on_parent_result(&mut self, peer_id: PeerId, outcome: Outcome, now: Instant) {
        match outcome {
            Outcome::Blocks(mut blocks) => match blocks.pop() {
                Some((_, block)) if block.message.slot >= self.frontier.oldest_block_slot => {
                    self.bans.push((
                        peer_id,
                        "parent of the frontier is not below it".to_string(),
                    ));
                }
                Some((_, block)) if block.message.slot < self.floor_slot => {
                    self.boundary = Some(self.floor_slot);
                }
                Some(parent) => self.pending_parent = Some(parent),
                // A responder may skip a root it does not have.
                None => self.parent_retry_at = Some(now + PARENT_RETRY_DELAY),
            },
            // A valid answer for a parent that predates the forks we can decode.
            Outcome::UnsupportedFork => {
                // The digest is supplied by the peer: it does not authenticate the requested
                // root. Only a trusted frontier at the boundary itself proves its parent is
                // older. Above it, keep trying other peers (including across skipped slots).
                if self.frontier.oldest_block_slot <= self.floor_slot {
                    self.boundary = Some(self.floor_slot);
                } else {
                    if !self.fork_stall_logged {
                        self.fork_stall_logged = true;
                        warn!(
                            frontier_slot = self.frontier.oldest_block_slot,
                            "Parent of the frontier may predate the oldest supported fork, retrying"
                        );
                    }
                    self.parent_retry_at = Some(now + PARENT_RETRY_DELAY);
                }
            }
            Outcome::Fault(reason) => self.bans.push((peer_id, reason)),
            Outcome::Unavailable | Outcome::TooLarge => {
                self.parent_retry_at = Some(now + PARENT_RETRY_DELAY)
            }
        }
    }

    /// Drops the batches furthest from the frontier until the budget holds. They can be
    /// downloaded again. Even a lone batch must leave the parent reserve available.
    fn evict(&mut self) {
        while self.pending_bytes()
            > self
                .config
                .max_pending_bytes
                .saturating_sub(self.config.frontier_reserve_bytes)
        {
            let mut loaded = self.batches.iter().filter_map(|(epoch, batch)| {
                matches!(&batch.state, BatchState::Have { blocks, .. } if !blocks.is_empty())
                    .then_some(*epoch)
            });
            let Some(furthest) = loaded.next() else {
                return;
            };
            if let Some(batch) = self.batches.get_mut(&furthest) {
                batch.state = BatchState::Todo;
                batch.attempted.clear();
                batch.answers = 0;
                self.evicted_batches += 1;
            }
        }
    }

    /// What to do next given everything received so far.
    pub fn advance(&mut self, target_slot: u64) -> Step {
        let frontier_slot = self.frontier.oldest_block_slot;
        if frontier_slot == 0 || frontier_slot <= target_slot {
            return Step::Complete;
        }
        if let Some(parent) = self.pending_parent.take() {
            self.handed_out = vec![(parent.1.message.slot, parent.0)];
            return Step::Commit(vec![parent]);
        }
        if let Some(boundary_slot) = self.boundary
            && self.inflight_ranges() == 0
        {
            return Step::UnsupportedForkBoundary { boundary_slot };
        }
        if frontier_slot <= self.floor_slot {
            // Nothing below the frontier can be requested by range.
            self.parent_wanted = true;
            return Step::Wait;
        }

        // Walk down from the frontier over batches that claim to be empty until one holds
        // blocks. Its highest block either is the parent of the frontier, proving the empty
        // batches above it, or the claims so far cannot all be true.
        let lowest_epoch = self.lowest_epoch(target_slot);
        let mut empty_epochs = Vec::new();
        let mut unconnected_epoch = None;
        let mut epoch = (frontier_slot - 1) / SLOTS_PER_EPOCH;
        loop {
            if epoch < lowest_epoch {
                break;
            }
            match self.batches.get_mut(&epoch) {
                Some(Batch {
                    state: BatchState::Have { blocks, bytes, .. },
                    end_slot,
                    ..
                }) => match (blocks.first(), blocks.last()) {
                    (Some((_, lowest)), Some((highest_root, _)))
                        if *highest_root == self.frontier.oldest_block_parent =>
                    {
                        // The rest of this batch's range was answered as empty.
                        *end_slot = lowest.message.slot;
                        *bytes = 0;
                        let blocks = std::mem::take(blocks);
                        self.handed_out = blocks
                            .iter()
                            .map(|(root, block)| (block.message.slot, *root))
                            .collect();
                        return Step::Commit(blocks);
                    }
                    (Some(_), _) => {
                        unconnected_epoch = Some(epoch);
                        break;
                    }
                    _ => empty_epochs.push(epoch),
                },
                _ => {
                    if empty_epochs.len() < self.config.empty_scan_limit {
                        return Step::Wait;
                    }
                    break;
                }
            }
            if epoch == 0 {
                break;
            }
            epoch -= 1;
        }

        // Ask someone else for the highest doubtful batch first; once the answers agree that
        // nothing connects, only the parent itself can settle it.
        let retry_epoch = empty_epochs
            .into_iter()
            .chain(unconnected_epoch)
            .find(|epoch| {
                self.batches
                    .get(epoch)
                    .is_some_and(|batch| batch.answers < self.config.batch_retry_answers)
            });
        match retry_epoch.and_then(|epoch| self.batches.get_mut(&epoch)) {
            Some(batch) => {
                if let BatchState::Have {
                    peer_id, blocks, ..
                } = &batch.state
                    && !blocks.is_empty()
                {
                    batch.doubted.push((
                        *peer_id,
                        blocks
                            .iter()
                            .map(|(root, block)| (block.message.slot, *root))
                            .collect(),
                    ));
                }
                batch.state = BatchState::Todo;
            }
            None => self.parent_wanted = true,
        }
        Step::Wait
    }

    /// Records the durable commit of the blocks last handed out, which moved the block
    /// frontier down to `frontier`.
    ///
    /// Every slot between the new and the old frontier is now known: it holds a committed
    /// block or nothing. A peer that served any other block there served blocks that are not
    /// ancestors of the origin.
    pub fn on_committed(&mut self, frontier: Frontier) {
        let slot = frontier.oldest_block_slot;
        let settled = slot..self.frontier.oldest_block_slot;
        let canonical = std::mem::take(&mut self.handed_out)
            .into_iter()
            .collect::<HashSet<_>>();
        let is_other_chain = |block_slot: u64, root: B256| {
            settled.contains(&block_slot) && !canonical.contains(&(block_slot, root))
        };

        let mut finished_epochs = Vec::new();
        for (epoch, batch) in &mut self.batches {
            batch.doubted.retain_mut(|(peer_id, entries)| {
                if entries
                    .iter()
                    .any(|(block_slot, root)| is_other_chain(*block_slot, *root))
                {
                    self.bans.push((
                        *peer_id,
                        "served blocks that are not ancestors of the checkpoint".to_string(),
                    ));
                    return false;
                }
                entries.retain(|(block_slot, _)| *block_slot < slot);
                !entries.is_empty()
            });

            if batch.end_slot > slot
                && let BatchState::Have {
                    peer_id,
                    blocks,
                    bytes,
                } = &mut batch.state
            {
                let serves_other_chain = blocks
                    .iter()
                    .any(|(root, block)| is_other_chain(block.message.slot, *root));
                let omits_committed = canonical.iter().any(|(block_slot, _)| {
                    (batch.start_slot..batch.end_slot).contains(block_slot)
                        && !blocks
                            .iter()
                            .any(|(_, block)| block.message.slot == *block_slot)
                });
                if serves_other_chain {
                    self.bans.push((
                        *peer_id,
                        "served blocks that are not ancestors of the checkpoint".to_string(),
                    ));
                    batch.state = BatchState::Todo;
                } else if omits_committed && !batch.by_root_only {
                    // A short response is allowed, so this is no fault; the rest of the answer
                    // cannot be relied on to be complete either.
                    batch.state = BatchState::Todo;
                } else {
                    blocks.retain(|(_, block)| block.message.slot < slot);
                    *bytes = blocks.iter().map(|(_, block)| block.ssz_bytes_len()).sum();
                }
            }
            batch.end_slot = batch.end_slot.min(slot);
            if batch.start_slot >= batch.end_slot {
                finished_epochs.push(*epoch);
            }
        }
        for epoch in finished_epochs {
            self.batches.remove(&epoch);
        }

        self.boundary = None;
        self.fork_stall_logged = false;
        self.frontier = frontier;
        self.parent_wanted = false;
        self.parent_request = ParentRequest::Idle;
        self.parent_attempted.clear();
        self.parent_retry_at = None;
        self.pending_parent = None;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};

    use ream_consensus_beacon::electra::beacon_block::SignedBeaconBlock;
    use tree_hash::TreeHash;

    use super::*;

    fn block(slot: u64, parent_root: B256, graffiti: u8) -> RootedBlock {
        let mut block = SignedBeaconBlock {
            message: Default::default(),
            signature: Default::default(),
        };
        block.message.slot = slot;
        block.message.parent_root = parent_root;
        block.message.body.graffiti = B256::repeat_byte(graffiti);
        (block.message.tree_hash_root(), block)
    }

    /// Hash chain over `slots` (ascending).
    fn chain(slots: impl IntoIterator<Item = u64>, graffiti: u8) -> Vec<RootedBlock> {
        let mut parent_root = B256::repeat_byte(0xee);
        slots
            .into_iter()
            .map(|slot| {
                let entry = block(slot, parent_root, graffiti);
                parent_root = entry.0;
                entry
            })
            .collect()
    }

    fn frontier_at(block: &RootedBlock) -> Frontier {
        Frontier {
            oldest_block_slot: block.1.message.slot,
            oldest_block_root: block.0,
            oldest_block_parent: block.1.message.parent_root,
        }
    }

    fn in_range(blocks: &[RootedBlock], start_slot: u64, count: u64) -> Vec<RootedBlock> {
        blocks
            .iter()
            .filter(|(_, block)| (start_slot..start_slot + count).contains(&block.message.slot))
            .cloned()
            .collect()
    }

    /// Answers like a peer holding `blocks`.
    fn serve(blocks: &[RootedBlock], request: &Request) -> Outcome {
        Outcome::Blocks(match &request.kind {
            RequestKind::Range { start_slot, count } => in_range(blocks, *start_slot, *count),
            RequestKind::Parent { root } => blocks
                .iter()
                .filter(|(block_root, _)| block_root == root)
                .cloned()
                .collect(),
        })
    }

    /// Runs a scheduler against scripted peers and plays the driver's part: it commits what
    /// the scheduler hands over, checking every commit connects to the frontier.
    struct Harness {
        scheduler: Scheduler,
        peers: Vec<PeerId>,
        busy: HashSet<PeerId>,
        queue: VecDeque<Request>,
        sent: Vec<Request>,
        committed: Vec<RootedBlock>,
        bans: Vec<PeerId>,
        now: Instant,
        target_slot: u64,
    }

    impl Harness {
        fn new(
            config: BackfillConfig,
            anchor: &RootedBlock,
            floor_slot: u64,
            peers: usize,
        ) -> Self {
            Self {
                scheduler: Scheduler::new(config, frontier_at(anchor), floor_slot),
                peers: (0..peers).map(|_| PeerId::random()).collect(),
                busy: HashSet::new(),
                queue: VecDeque::new(),
                sent: Vec::new(),
                committed: Vec::new(),
                bans: Vec::new(),
                now: Instant::now(),
                target_slot: 0,
            }
        }

        /// Commits everything ready, then sends every request the scheduler wants.
        fn pump(&mut self) -> Option<Step> {
            loop {
                match self.scheduler.advance(self.target_slot) {
                    Step::Commit(blocks) => {
                        let frontier = self.scheduler.frontier().clone();
                        assert_eq!(
                            blocks.last().expect("commit is not empty").0,
                            frontier.oldest_block_parent,
                            "commit must connect to the frontier"
                        );
                        for pair in blocks.windows(2) {
                            assert_eq!(pair[1].1.message.parent_root, pair[0].0);
                        }
                        self.scheduler.on_committed(frontier_at(&blocks[0]));
                        self.committed.splice(0..0, blocks);
                    }
                    Step::Wait => break,
                    step => return Some(step),
                }
            }
            self.bans.extend(
                self.scheduler
                    .take_bans()
                    .into_iter()
                    .map(|(peer_id, _)| peer_id),
            );

            let (peers, busy, bans) = (&self.peers, &mut self.busy, &self.bans);
            let requests =
                self.scheduler
                    .next_requests(self.now, self.target_slot, &mut |_, excluded| {
                        let peer_id = *peers.iter().find(|peer_id| {
                            !busy.contains(peer_id)
                                && !excluded.contains(peer_id)
                                && !bans.contains(peer_id)
                        })?;
                        busy.insert(peer_id);
                        Some(peer_id)
                    });
            self.sent.extend(requests.iter().cloned());
            self.queue.extend(requests);
            None
        }

        fn answer(&mut self, request: Request, outcome: Outcome) {
            self.busy.remove(&request.peer_id);
            self.scheduler
                .on_result(request.id, request.peer_id, outcome, self.now);
        }

        /// Runs until the scheduler stops, answering the oldest request first.
        fn run(&mut self, mut respond: impl FnMut(&Self, &Request) -> Outcome) -> Step {
            for _ in 0..10_000 {
                if let Some(step) = self.pump() {
                    return step;
                }
                match self.queue.pop_front() {
                    Some(request) => {
                        let outcome = respond(self, &request);
                        self.answer(request, outcome);
                    }
                    None => self.now += PARENT_RETRY_DELAY,
                }
            }
            panic!("backfill made no progress");
        }

        fn peer(&self, request: &Request) -> usize {
            self.peers
                .iter()
                .position(|peer_id| *peer_id == request.peer_id)
                .expect("known peer")
        }

        fn range_requests(&self) -> Vec<(u64, u64)> {
            self.sent
                .iter()
                .filter_map(|request| match request.kind {
                    RequestKind::Range { start_slot, count } => Some((start_slot, count)),
                    RequestKind::Parent { .. } => None,
                })
                .collect()
        }

        fn parent_requests(&self) -> usize {
            self.sent.len() - self.range_requests().len()
        }
    }

    fn config(max_inflight: usize) -> BackfillConfig {
        BackfillConfig {
            max_inflight,
            ..Default::default()
        }
    }

    #[test]
    fn batches_arriving_out_of_order_are_committed_without_downloading_again() {
        let blocks = chain(0..=100, 0);
        let mut harness = Harness::new(config(3), &blocks[100], 0, 4);

        // Three epochs are requested at once; the one furthest from the frontier answers first.
        assert!(harness.pump().is_none());
        assert_eq!(harness.range_requests(), vec![(96, 4), (64, 32), (32, 32)]);
        let far = harness.queue.pop_back().expect("three requests");
        let outcome = serve(&blocks, &far);
        harness.answer(far, outcome);
        assert!(harness.pump().is_none());
        assert!(harness.committed.is_empty());

        let step = harness.run(|_, request| serve(&blocks, request));

        assert!(matches!(step, Step::Complete));
        assert_eq!(harness.committed, blocks[..100]);
        // Every epoch was downloaded exactly once and the parent was never asked by root.
        assert_eq!(
            harness.range_requests(),
            vec![(96, 4), (64, 32), (32, 32), (0, 32)]
        );
        assert_eq!(harness.parent_requests(), 0);
        assert!(harness.bans.is_empty());
    }

    #[test]
    fn skipped_slots_at_the_top_of_a_batch_are_proven_by_the_next_block() {
        // Slots 60..=70 and the whole of 96..=99 are skipped.
        let blocks = chain((0..60).chain(71..96).chain([100]), 0);
        let mut harness = Harness::new(config(2), blocks.last().expect("anchor"), 0, 3);

        let step = harness.run(|_, request| serve(&blocks, request));

        assert!(matches!(step, Step::Complete));
        assert_eq!(harness.committed, blocks[..blocks.len() - 1]);
        assert_eq!(harness.parent_requests(), 0);
        assert!(harness.bans.is_empty());
    }

    #[test]
    fn gap_longer_than_the_empty_scan_limit_is_resolved_by_root() {
        // Six empty epochs below the anchor: more than can be scanned on trust.
        let blocks = chain((0..40).chain([240]), 0);
        let mut harness = Harness::new(config(2), blocks.last().expect("anchor"), 0, 3);

        let step = harness.run(|_, request| serve(&blocks, request));

        assert!(matches!(step, Step::Complete));
        assert_eq!(harness.committed, blocks[..40]);
        assert_eq!(harness.parent_requests(), 1);
        // Empty answers are never evidence against a peer.
        assert!(harness.bans.is_empty());
        // Scanning ahead of the unresolved gap stays inside the lookahead window.
        assert!(harness.range_requests().len() <= 2 * 8 + 2);
    }

    #[test]
    fn peer_answering_empty_for_data_it_lacks_does_not_stall_or_get_banned() {
        let blocks = chain(0..=100, 0);
        let mut harness = Harness::new(config(2), &blocks[100], 0, 3);

        // Peer 0 has no history and answers every range with an empty stream.
        let step = harness.run(|harness, request| match harness.peer(request) {
            0 => Outcome::Blocks(vec![]),
            _ => serve(&blocks, request),
        });

        assert!(matches!(step, Step::Complete));
        assert_eq!(harness.committed, blocks[..100]);
        assert!(harness.bans.is_empty());
    }

    #[test]
    fn truncated_response_is_completed_from_another_peer() {
        let blocks = chain(0..=100, 0);
        let mut harness = Harness::new(config(2), &blocks[100], 0, 3);

        // Peer 0 cuts every range response short by returning only its lower half.
        let step = harness.run(
            |harness, request| match (harness.peer(request), &request.kind) {
                (0, RequestKind::Range { start_slot, count }) => {
                    Outcome::Blocks(in_range(&blocks, *start_slot, count / 2))
                }
                _ => serve(&blocks, request),
            },
        );

        assert!(matches!(step, Step::Complete));
        assert_eq!(harness.committed, blocks[..100]);
        assert!(harness.bans.is_empty());
    }

    #[test]
    fn blocks_of_another_chain_are_never_committed_and_their_sender_is_banned() {
        let blocks = chain(0..=100, 0);
        // Correctly linked among themselves, but not ancestors of the anchor.
        let other = chain(0..=100, 1);
        let mut harness = Harness::new(config(2), &blocks[100], 0, 3);

        let step = harness.run(|harness, request| match harness.peer(request) {
            0 => serve(&other, request),
            _ => serve(&blocks, request),
        });

        assert!(matches!(step, Step::Complete));
        assert_eq!(harness.committed, blocks[..100]);
        assert_eq!(harness.bans, vec![harness.peers[0]]);
    }

    #[test]
    fn faulty_response_bans_the_peer_and_the_batch_is_downloaded_again() {
        let blocks = chain(0..=40, 0);
        let mut harness = Harness::new(config(1), &blocks[40], 0, 2);

        let step = harness.run(|harness, request| match harness.peer(request) {
            0 => Outcome::Fault("bad signature".to_string()),
            _ => serve(&blocks, request),
        });

        assert!(matches!(step, Step::Complete));
        assert_eq!(harness.committed, blocks[..40]);
        assert_eq!(harness.bans, vec![harness.peers[0]]);
    }

    #[test]
    fn pending_blocks_stay_within_budget_and_backfill_still_completes() {
        let blocks = chain(0..=320, 0);
        let batch_bytes = in_range(&blocks, 0, 32)
            .iter()
            .map(|(_, block)| block.ssz_bytes_len())
            .sum::<usize>();
        let limits = BackfillConfig {
            max_inflight: 4,
            max_pending_bytes: 3 * batch_bytes,
            frontier_reserve_bytes: batch_bytes,
            max_response_bytes: 0,
            ..Default::default()
        };
        let mut harness = Harness::new(limits, &blocks[320], 0, 6);

        // The batch directly below the frontier is withheld while everything else arrives.
        let mut withheld = None;
        for _ in 0..200 {
            assert!(harness.pump().is_none());
            assert!(harness.scheduler.pending_bytes() <= 3 * batch_bytes);
            let Some(request) = harness.queue.pop_front() else {
                break;
            };
            if withheld.is_none() {
                withheld = Some(request);
                continue;
            }
            let outcome = serve(&blocks, &request);
            harness.answer(request, outcome);
        }
        assert!(harness.committed.is_empty());
        assert!(harness.scheduler.pending_bytes() > 0);

        // Lookahead stopped at the budget without the reserve; the withheld batch still fits.
        let withheld = withheld.expect("top batch was requested");
        let outcome = serve(&blocks, &withheld);
        harness.answer(withheld, outcome);
        let step = harness.run(|_, request| serve(&blocks, request));

        assert!(matches!(step, Step::Complete));
        assert_eq!(harness.committed, blocks[..320]);
        assert!(harness.bans.is_empty());
    }

    #[test]
    fn batches_over_budget_are_evicted_furthest_first_and_downloaded_again() {
        let blocks = chain(0..=160, 0);
        let batch_bytes = in_range(&blocks, 0, 32)
            .iter()
            .map(|(_, block)| block.ssz_bytes_len())
            .sum::<usize>();
        let limits = BackfillConfig {
            max_inflight: 5,
            // Lookahead is admitted on an estimate of zero, so responses overshoot the budget.
            max_pending_bytes: 2 * batch_bytes,
            frontier_reserve_bytes: 0,
            max_response_bytes: 0,
            ..Default::default()
        };
        let mut harness = Harness::new(limits, &blocks[160], 0, 6);

        assert!(harness.pump().is_none());
        // Answer everything except the batch directly below the frontier.
        let top = harness.queue.pop_front().expect("top batch");
        while let Some(request) = harness.queue.pop_front() {
            let outcome = serve(&blocks, &request);
            harness.answer(request, outcome);
        }
        assert!(harness.scheduler.evicted_batches() > 0);
        assert!(harness.scheduler.pending_bytes() <= 2 * batch_bytes);

        let outcome = serve(&blocks, &top);
        harness.answer(top, outcome);
        let step = harness.run(|_, request| serve(&blocks, request));

        assert!(matches!(step, Step::Complete));
        assert_eq!(harness.committed, blocks[..160]);
        assert!(harness.bans.is_empty());
    }

    #[test]
    fn fork_boundary_is_declared_only_on_proof_and_never_requested_by_range() {
        // Blocks below slot 64 belong to a fork we cannot decode.
        let blocks = chain(40..=100, 0);
        let mut harness = Harness::new(config(3), &blocks[60], 64, 3);

        // While batches above the boundary are still in flight nothing is concluded.
        assert!(harness.pump().is_none());
        assert_eq!(harness.range_requests(), vec![(96, 4), (64, 32)]);

        let mut parent_answers = 0;
        let step = harness.run(|_, request| match &request.kind {
            RequestKind::Range { .. } => serve(&blocks, request),
            RequestKind::Parent { .. } => {
                parent_answers += 1;
                // Empty answers and timeouts are not proof that the parent is below the fork.
                match parent_answers {
                    1 => Outcome::Blocks(vec![]),
                    2 => Outcome::Unavailable,
                    _ => Outcome::UnsupportedFork,
                }
            }
        });

        assert!(matches!(
            step,
            Step::UnsupportedForkBoundary { boundary_slot: 64 }
        ));
        assert_eq!(parent_answers, 3);
        assert_eq!(harness.scheduler.frontier().oldest_block_slot, 64);
        assert_eq!(harness.committed, blocks[24..60]);
        assert_eq!(harness.range_requests(), vec![(96, 4), (64, 32)]);
        // A valid block of an older fork is not evidence against the peer that sent it.
        assert!(harness.bans.is_empty());
    }

    #[test]
    fn decodable_parent_below_the_boundary_also_proves_it() {
        let blocks = chain([60, 64, 65, 70], 0);
        let mut harness = Harness::new(config(2), &blocks[3], 64, 2);

        let step = harness.run(|_, request| serve(&blocks, request));

        assert!(matches!(
            step,
            Step::UnsupportedForkBoundary { boundary_slot: 64 }
        ));
        assert_eq!(harness.committed, blocks[1..3]);
    }

    #[test]
    fn target_inside_an_epoch_completes_at_the_first_block_at_or_below_it() {
        let blocks = chain(0..=100, 0);
        let mut harness = Harness::new(config(2), &blocks[100], 0, 3);
        harness.target_slot = 70;

        let step = harness.run(|_, request| serve(&blocks, request));

        assert!(matches!(step, Step::Complete));
        assert_eq!(harness.scheduler.frontier().oldest_block_slot, 64);
        assert!(
            harness
                .range_requests()
                .iter()
                .all(|(start_slot, _)| *start_slot >= 64)
        );
    }

    #[test]
    fn paused_session_drops_responses_unjudged_and_keeps_verified_batches() {
        let blocks = chain(0..=100, 0);
        let mut harness = Harness::new(config(3), &blocks[100], 0, 4);

        assert!(harness.pump().is_none());
        let mut requests = std::mem::take(&mut harness.queue);
        // The lowest batch is verified before the pause; the others are still in flight.
        let verified = requests.pop_back().expect("three requests");
        let outcome = serve(&blocks, &verified);
        harness.answer(verified, outcome);
        let pending_bytes = harness.scheduler.pending_bytes();
        assert!(pending_bytes > 0);

        harness.scheduler.pause();
        for request in requests {
            // Even a faulty answer from the old session must not be held against the peer.
            harness.answer(request, Outcome::Fault("late".to_string()));
        }
        assert!(harness.scheduler.take_bans().is_empty());
        assert_eq!(harness.scheduler.pending_bytes(), pending_bytes);

        let sent_before_resume = harness.sent.len();
        let step = harness.run(|_, request| serve(&blocks, request));

        assert!(matches!(step, Step::Complete));
        assert_eq!(harness.committed, blocks[..100]);
        // The verified batch was not requested again after the pause.
        let requested_again = harness.sent[sent_before_resume..]
            .iter()
            .filter(|request| {
                request.kind
                    == RequestKind::Range {
                        start_slot: 32,
                        count: 32,
                    }
            })
            .count();
        assert_eq!(requested_again, 0);
        assert!(harness.bans.is_empty());
    }

    #[test]
    fn restart_resumes_from_the_durable_frontier() {
        let blocks = chain(0..=100, 0);
        let mut first = Harness::new(config(2), &blocks[100], 0, 3);
        first.target_slot = 64;
        assert!(matches!(
            first.run(|_, request| serve(&blocks, request)),
            Step::Complete
        ));
        let durable = first.scheduler.frontier().clone();
        assert_eq!(durable.oldest_block_slot, 64);

        // A new process only knows the persisted frontier.
        let mut second = Harness::new(config(2), &blocks[64], 0, 3);
        assert_eq!(second.scheduler.frontier(), &durable);
        assert!(matches!(
            second.run(|_, request| serve(&blocks, request)),
            Step::Complete
        ));
        assert_eq!(second.committed, blocks[..64]);
        assert!(
            second
                .range_requests()
                .iter()
                .all(|(start_slot, count)| start_slot + count <= 64)
        );
    }

    #[test]
    fn unanswerable_parent_request_keeps_the_frontier_and_keeps_trying() {
        let blocks = chain([10, 300], 0);
        let mut harness = Harness::new(config(2), &blocks[1], 0, 2);
        harness.target_slot = 10;

        let mut answers: HashMap<usize, usize> = HashMap::new();
        let mut parent_answers = 0;
        let step = harness.run(|harness, request| match &request.kind {
            RequestKind::Range { .. } => Outcome::Blocks(vec![]),
            RequestKind::Parent { .. } => {
                *answers.entry(harness.peer(request)).or_default() += 1;
                parent_answers += 1;
                if parent_answers < 5 {
                    assert_eq!(harness.scheduler.frontier().oldest_block_slot, 300);
                    Outcome::Blocks(vec![])
                } else {
                    serve(&blocks, request)
                }
            }
        });

        // The frontier only moved once a peer produced the parent; both peers were asked.
        assert!(matches!(step, Step::Complete));
        assert_eq!(harness.committed, blocks[..1]);
        assert_eq!(answers.len(), 2);
        assert!(harness.bans.is_empty());
    }
    #[test]
    fn unsupported_digest_does_not_discard_a_supported_parent_in_flight() {
        let blocks = chain([60, 80, 100], 0);
        let mut limits = config(2);
        limits.empty_scan_limit = 1;
        limits.batch_retry_answers = 1;
        let mut harness = Harness::new(limits, &blocks[2], 64, 3);
        assert!(harness.pump().is_none());
        let top = harness.queue.pop_front().unwrap();
        let lower = harness.queue.pop_front().unwrap();
        harness.answer(top, Outcome::Blocks(vec![]));
        assert!(harness.pump().is_none());
        let parent = harness.queue.pop_front().unwrap();
        assert!(matches!(parent.kind, RequestKind::Parent { .. }));
        harness.answer(parent, Outcome::UnsupportedFork);
        assert!(harness.pump().is_none());
        assert_eq!(harness.scheduler.frontier().oldest_block_slot, 100);
        let outcome = serve(&blocks, &lower);
        harness.answer(lower, outcome);
        let step = harness.run(|_, request| serve(&blocks, request));
        assert!(matches!(
            step,
            Step::UnsupportedForkBoundary { boundary_slot: 64 }
        ));
        assert_eq!(harness.committed, blocks[1..2]);
        assert!(harness.bans.is_empty());
    }

    #[test]
    fn oversized_epochs_recover_by_root_without_banning() {
        let blocks = chain(0..=65, 0);
        let block_bytes = blocks[0].1.ssz_bytes_len();
        let limits = BackfillConfig {
            max_pending_bytes: 4 * block_bytes,
            frontier_reserve_bytes: block_bytes,
            max_response_bytes: block_bytes,
            ..config(2)
        };
        let mut harness = Harness::new(limits, &blocks[65], 0, 3);
        let step = harness.run(|_, request| {
            let response = serve(&blocks, request);
            if matches!(&response, Outcome::Blocks(blocks) if blocks.len() > 1) {
                Outcome::TooLarge
            } else {
                response
            }
        });
        assert!(matches!(step, Step::Complete));
        assert_eq!(harness.committed, blocks[..65]);
        assert!(harness.bans.is_empty());
        // Each oversized epoch is asked from two peers, the single-block epoch once.
        assert_eq!(harness.range_requests().len(), 5);
    }

    #[test]
    fn one_peer_answering_too_large_does_not_force_by_root() {
        let blocks = chain(0..=65, 0);
        let mut harness = Harness::new(config(2), &blocks[65], 0, 3);
        let step = harness.run(|harness, request| {
            if harness.peer(request) == 0 {
                Outcome::TooLarge
            } else {
                serve(&blocks, request)
            }
        });
        assert!(matches!(step, Step::Complete));
        assert_eq!(harness.committed, blocks[..65]);
        assert!(harness.bans.is_empty());
        assert_eq!(harness.parent_requests(), 0);
    }

    #[test]
    fn obsolete_downloads_keep_their_memory_reservations_until_consumed() {
        let blocks = chain(0..=100, 0);
        let mut scheduler = Scheduler::new(BackfillConfig::default(), frontier_at(&blocks[100]), 0);
        // These requests are no longer represented in the scheduler's batches, but their
        // completed responses are still waiting in the driver's JoinSet.
        let requests = scheduler.next_requests_with_downloads(Instant::now(), 0, 3, &mut |_, _| {
            panic!("no capacity for more downloads")
        });
        assert!(requests.is_empty());
    }

    #[test]
    fn lone_batch_cannot_exceed_the_retained_budget() {
        let blocks = chain(0..=32, 0);
        let mut limits = config(1);
        limits.max_pending_bytes = blocks[0].1.ssz_bytes_len() * 2;
        limits.frontier_reserve_bytes = blocks[0].1.ssz_bytes_len();
        limits.max_response_bytes = 0; // Exercise eviction independently of receive admission.
        let mut harness = Harness::new(limits, &blocks[32], 0, 1);
        harness.pump();
        let request = harness.queue.pop_front().unwrap();
        let outcome = serve(&blocks, &request);
        harness.answer(request, outcome);
        assert_eq!(harness.scheduler.pending_bytes(), 0);
        assert_eq!(harness.scheduler.evicted_batches(), 1);
    }
}
