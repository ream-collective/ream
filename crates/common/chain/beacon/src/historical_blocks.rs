//! Checks for blocks below the checkpoint origin. No state transition runs for them: a response
//! is checked against its own request, proposer signatures are verified against the validator
//! registry of a trusted state, and ancestry is proven later by hash linkage to the block frontier.
//! A valid signature alone does not make a block an ancestor of the origin.
use std::collections::HashSet;

use alloy_primitives::B256;
use ream_bls::{PublicKey, traits::Verifiable};
use ream_consensus_beacon::electra::{beacon_block::SignedBeaconBlock, beacon_state::BeaconState};
use ream_consensus_misc::{
    constants::beacon::DOMAIN_BEACON_PROPOSER,
    misc::{compute_domain, compute_epoch_at_slot, compute_signing_root},
};
use ream_network_spec::networks::beacon::BeaconNetworkSpec;
use tree_hash::TreeHash;

/// A block with its `hash_tree_root`.
pub type RootedBlock = (B256, SignedBeaconBlock);

/// Evidence against the peer that produced a response.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResponseFault {
    #[error("block at slot {slot} is outside the requested range")]
    OutOfRange { slot: u64 },
    #[error("blocks are not in strictly ascending slot order")]
    NotAscending,
    #[error("response holds {received} blocks for a request of {requested}")]
    TooManyBlocks { received: usize, requested: u64 },
    #[error("block at slot {slot} does not build on the previous block of the response")]
    InternalChainBroken { slot: u64 },
    #[error("block {root} was not requested")]
    UnrequestedRoot { root: B256 },
    #[error("block {root} was sent more than once")]
    DuplicateRoot { root: B256 },
    #[error("block at slot {slot} names unknown proposer {proposer_index}")]
    InvalidProposerIndex { slot: u64, proposer_index: u64 },
    #[error("a proposer signature in the response is invalid")]
    BadSignature,
}

/// Proposer public keys by validator index. Indexes are append-only and keys never change, so
/// the registry of any state at or after the origin covers every historical proposer.
pub struct ProposerKeys(Vec<PublicKey>);

impl ProposerKeys {
    pub fn new(public_keys: Vec<PublicKey>) -> Self {
        Self(public_keys)
    }

    pub fn from_state(state: &BeaconState) -> Self {
        Self(
            state
                .validators
                .iter()
                .map(|validator| validator.public_key.clone())
                .collect(),
        )
    }
}

/// Checks a `BeaconBlocksByRange` response against its request and returns the blocks with
/// their roots. The response may be shorter than `count`; it is never reordered.
pub fn check_range_response(
    start_slot: u64,
    count: u64,
    blocks: Vec<SignedBeaconBlock>,
) -> Result<Vec<RootedBlock>, ResponseFault> {
    if blocks.len() as u64 > count {
        return Err(ResponseFault::TooManyBlocks {
            received: blocks.len(),
            requested: count,
        });
    }

    let end_slot = start_slot.saturating_add(count);
    let mut rooted: Vec<RootedBlock> = Vec::with_capacity(blocks.len());
    for block in blocks {
        let slot = block.message.slot;
        if slot < start_slot || slot >= end_slot {
            return Err(ResponseFault::OutOfRange { slot });
        }
        if let Some((previous_root, previous)) = rooted.last() {
            if slot <= previous.message.slot {
                return Err(ResponseFault::NotAscending);
            }
            if block.message.parent_root != *previous_root {
                return Err(ResponseFault::InternalChainBroken { slot });
            }
        }
        rooted.push((block.message.tree_hash_root(), block));
    }
    Ok(rooted)
}

/// Checks a `BeaconBlocksByRoot` response against its request. A responder may skip roots it
/// does not have, and the requested roots need not be adjacent or ordered.
pub fn check_roots_response(
    requested: &[B256],
    blocks: Vec<SignedBeaconBlock>,
) -> Result<Vec<RootedBlock>, ResponseFault> {
    let mut seen = HashSet::new();
    let mut rooted = Vec::with_capacity(blocks.len());
    for block in blocks {
        let root = block.message.tree_hash_root();
        if !requested.contains(&root) {
            return Err(ResponseFault::UnrequestedRoot { root });
        }
        if !seen.insert(root) {
            return Err(ResponseFault::DuplicateRoot { root });
        }
        rooted.push((root, block));
    }
    Ok(rooted)
}

/// Verifies every proposer signature. The genesis block is unsigned and is proven by hash
/// linkage alone.
pub fn verify_proposer_signatures(
    network_spec: &BeaconNetworkSpec,
    genesis_validators_root: B256,
    proposer_keys: &ProposerKeys,
    blocks: &[RootedBlock],
) -> Result<(), ResponseFault> {
    for (root, block) in blocks {
        let slot = block.message.slot;
        if slot == 0 {
            continue;
        }
        let proposer_index = block.message.proposer_index;
        let public_key = usize::try_from(proposer_index)
            .ok()
            .and_then(|index| proposer_keys.0.get(index))
            .ok_or(ResponseFault::InvalidProposerIndex {
                slot,
                proposer_index,
            })?;
        let domain = compute_domain(
            DOMAIN_BEACON_PROPOSER,
            Some(network_spec.current_fork_version(compute_epoch_at_slot(slot))),
            Some(genesis_validators_root),
        );
        // Malformed key or signature bytes cannot verify either.
        if !block
            .signature
            .verify(public_key, compute_signing_root(*root, domain).as_slice())
            .unwrap_or(false)
        {
            return Err(ResponseFault::BadSignature);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ream_bls::{BLSSignature, PrivateKey, traits::Signable};
    use ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH;
    use ream_network_spec::networks::beacon::DEV;

    use super::*;

    const GENESIS_VALIDATORS_ROOT: B256 = B256::repeat_byte(0x42);

    fn private_key(index: u64) -> PrivateKey {
        PrivateKey {
            inner: B256::with_last_byte(index as u8 + 1),
        }
    }

    fn proposer_keys(count: u64) -> ProposerKeys {
        ProposerKeys::new(
            (0..count)
                .map(|index| private_key(index).public_key().expect("valid key"))
                .collect(),
        )
    }

    fn sign(network_spec: &BeaconNetworkSpec, block: &mut SignedBeaconBlock) {
        let domain = compute_domain(
            DOMAIN_BEACON_PROPOSER,
            Some(network_spec.current_fork_version(compute_epoch_at_slot(block.message.slot))),
            Some(GENESIS_VALIDATORS_ROOT),
        );
        block.signature = private_key(block.message.proposer_index)
            .sign(compute_signing_root(block.message.tree_hash_root(), domain).as_slice())
            .expect("signing succeeds");
    }

    /// Signed hash chain over `slots` (ascending). The proposer of slot `s` is `s % 4`.
    fn chain(network_spec: &BeaconNetworkSpec, slots: &[u64]) -> Vec<SignedBeaconBlock> {
        let mut parent_root = B256::ZERO;
        slots
            .iter()
            .map(|slot| {
                let mut block = SignedBeaconBlock {
                    message: Default::default(),
                    signature: Default::default(),
                };
                block.message.slot = *slot;
                block.message.proposer_index = slot % 4;
                block.message.parent_root = parent_root;
                if *slot != 0 {
                    sign(network_spec, &mut block);
                }
                parent_root = block.message.tree_hash_root();
                block
            })
            .collect()
    }

    fn verify(
        network_spec: &BeaconNetworkSpec,
        blocks: Vec<SignedBeaconBlock>,
    ) -> Result<(), ResponseFault> {
        let rooted = blocks
            .into_iter()
            .map(|block| (block.message.tree_hash_root(), block))
            .collect::<Vec<_>>();
        verify_proposer_signatures(
            network_spec,
            GENESIS_VALIDATORS_ROOT,
            &proposer_keys(4),
            &rooted,
        )
    }

    #[test]
    fn range_response_may_be_short_and_keeps_order() {
        let blocks = chain(&DEV, &[64, 65, 70]);

        let rooted = check_range_response(64, 32, blocks.clone()).expect("valid response");

        assert_eq!(
            rooted
                .iter()
                .map(|(root, block)| (*root, block.message.slot))
                .collect::<Vec<_>>(),
            blocks
                .iter()
                .map(|block| (block.message.tree_hash_root(), block.message.slot))
                .collect::<Vec<_>>()
        );
        assert_eq!(check_range_response(64, 32, vec![]), Ok(vec![]));
    }

    #[test]
    fn range_response_violations_are_faults() {
        let blocks = chain(&DEV, &[64, 65, 70]);

        assert_eq!(
            check_range_response(65, 32, blocks.clone()),
            Err(ResponseFault::OutOfRange { slot: 64 })
        );
        assert_eq!(
            check_range_response(64, 6, blocks.clone()),
            Err(ResponseFault::OutOfRange { slot: 70 })
        );
        assert_eq!(
            check_range_response(64, 2, blocks.clone()),
            Err(ResponseFault::TooManyBlocks {
                received: 3,
                requested: 2
            })
        );
        assert_eq!(
            check_range_response(
                64,
                32,
                vec![blocks[1].clone(), blocks[0].clone(), blocks[2].clone()]
            ),
            Err(ResponseFault::NotAscending)
        );
        assert_eq!(
            check_range_response(64, 32, vec![blocks[0].clone(), blocks[0].clone()]),
            Err(ResponseFault::NotAscending)
        );
        // Ascending and in range, but slot 70 does not build on slot 64.
        assert_eq!(
            check_range_response(64, 32, vec![blocks[0].clone(), blocks[2].clone()]),
            Err(ResponseFault::InternalChainBroken { slot: 70 })
        );
    }

    #[test]
    fn roots_response_allows_missing_unordered_and_non_adjacent_roots() {
        let blocks = chain(&DEV, &[64, 65, 70, 90]);
        let roots = blocks
            .iter()
            .map(|block| block.message.tree_hash_root())
            .collect::<Vec<_>>();

        let rooted = check_roots_response(&roots, vec![blocks[3].clone(), blocks[0].clone()])
            .expect("valid response");
        assert_eq!(
            rooted.iter().map(|(root, _)| *root).collect::<Vec<_>>(),
            vec![roots[3], roots[0]]
        );
        assert_eq!(check_roots_response(&roots, vec![]), Ok(vec![]));

        assert_eq!(
            check_roots_response(&roots[..2], vec![blocks[2].clone()]),
            Err(ResponseFault::UnrequestedRoot { root: roots[2] })
        );
        assert_eq!(
            check_roots_response(&roots, vec![blocks[1].clone(), blocks[1].clone()]),
            Err(ResponseFault::DuplicateRoot { root: roots[1] })
        );
    }

    #[test]
    fn every_signature_in_a_response_is_verified() {
        let blocks = chain(&DEV, &[64, 65, 70, 71]);
        assert_eq!(verify(&DEV, blocks.clone()), Ok(()));

        let mut one_bad = blocks.clone();
        one_bad[2].signature = one_bad[1].signature.clone();
        assert_eq!(verify(&DEV, one_bad), Err(ResponseFault::BadSignature));

        // A valid signature by a validator other than the named proposer.
        let mut wrong_proposer = blocks.clone();
        wrong_proposer[3].message.proposer_index = 0;
        assert_eq!(
            verify(&DEV, wrong_proposer),
            Err(ResponseFault::BadSignature)
        );

        let mut unknown_proposer = blocks;
        unknown_proposer[0].message.proposer_index = 4;
        assert_eq!(
            verify(&DEV, unknown_proposer),
            Err(ResponseFault::InvalidProposerIndex {
                slot: 64,
                proposer_index: 4
            })
        );
    }

    #[test]
    fn genesis_block_is_not_signature_checked() {
        let blocks = chain(&DEV, &[0, 1]);
        assert!(blocks[0].signature == BLSSignature::default());

        assert_eq!(verify(&DEV, blocks.clone()), Ok(()));
        assert_eq!(verify(&DEV, vec![blocks[0].clone()]), Ok(()));

        // Only slot 0 is exempt.
        let mut unsigned = blocks;
        unsigned[1].signature = BLSSignature::default();
        assert_eq!(verify(&DEV, unsigned), Err(ResponseFault::BadSignature));
    }

    #[test]
    fn signing_domain_follows_the_fork_of_each_block() {
        let mut network_spec = (**DEV).clone();
        network_spec.electra_fork_epoch = 0;
        network_spec.fulu_fork_epoch = 2;
        assert_ne!(
            network_spec.current_fork_version(1),
            network_spec.current_fork_version(2)
        );
        let boundary = 2 * SLOTS_PER_EPOCH;

        // One response spanning the last Electra slot and the first Fulu slot.
        let blocks = chain(&network_spec, &[boundary - 1, boundary]);
        assert_eq!(verify(&network_spec, blocks.clone()), Ok(()));

        // The same blocks do not verify if the fork activates at a different epoch.
        let mut later_fork = network_spec.clone();
        later_fork.fulu_fork_epoch = 3;
        assert_eq!(
            verify(&later_fork, blocks),
            Err(ResponseFault::BadSignature)
        );
    }
}
