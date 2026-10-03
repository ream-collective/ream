//! Which data columns a remote peer is expected to serve.
//!
//! A peer's custody groups are a public function of its node ID and the `custody_group_count` it
//! advertises (consensus-specs fulu/das-core.md, "Public, deterministic selection"). The count is
//! advertised in the ENR `cgc` field before connecting and in `MetaData` v3 once connected
//! (fulu/p2p-interface.md, "Custody group count" and "MetaData").

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::aliases::B32;
use discv5::{
    Enr,
    enr::{NodeId, k256::ecdsa::VerifyingKey},
};
use libp2p::PeerId;
use libp2p_identity::PublicKey;
use ream_consensus_beacon::custody_group::{PeerCustodyGroups, compute_custody_group_for_column};
use ream_discv5::{
    eth2::{ENR_ETH2_KEY, EnrForkId},
    subnet::{CUSTODY_GROUP_COUNT_ENR_KEY, CustodyGroupCount},
};
use ream_req_resp::beacon::messages::meta_data::GetMetaDataV3;

/// Multihash code of the identity hash, used by libp2p when the encoded public key is short
/// enough to be stored in the peer ID itself.
const IDENTITY_MULTIHASH_CODE: u64 = 0x00;

/// Recovers the discv5 node ID of a peer from its libp2p peer ID.
///
/// A secp256k1 peer ID is an identity multihash of the peer's public key, and the node ID is the
/// keccak256 hash of the same key. libp2p authenticates the peer ID during the Noise handshake,
/// so the result is bound to the connected peer. Returns `None` for any other key type or hash,
/// because no node ID can be derived from those.
pub fn node_id_from_peer_id(peer_id: &PeerId) -> Option<NodeId> {
    let multihash = peer_id.as_ref();
    if multihash.code() != IDENTITY_MULTIHASH_CODE {
        return None;
    }
    let public_key = PublicKey::try_decode_protobuf(multihash.digest())
        .ok()?
        .try_into_secp256k1()
        .ok()?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key.to_bytes()).ok()?;
    Some(NodeId::from(verifying_key))
}

/// Where a peer's custody group count was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodySource {
    MetaData,
    Enr,
}

/// What is known about the data columns a peer is expected to serve.
///
/// Only `Advertised` makes a peer eligible for column requests. Every other state means the peer
/// is not expected to serve any column; none of them is treated as full custody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerCustody {
    /// The peer ID does not embed a secp256k1 public key, so the peer's node ID is unknown.
    UnknownNodeId,
    /// No `MetaData` has been received for this connection and the ENR, if any, has no `cgc`.
    NotAdvertised,
    /// The advertised count could not be decoded or exceeds `NUMBER_OF_CUSTODY_GROUPS`.
    Invalid { source: CustodySource },
    Advertised {
        source: CustodySource,
        groups: PeerCustodyGroups,
    },
}

impl PeerCustody {
    /// `MetaData` takes precedence over the ENR because it is the peer's own answer on the current
    /// connection. An invalid `MetaData` count is not replaced by the ENR value.
    pub fn derive(
        node_id: Option<NodeId>,
        meta_data: Option<&GetMetaDataV3>,
        enr: Option<&Enr>,
    ) -> Self {
        let Some(node_id) = node_id else {
            return Self::UnknownNodeId;
        };
        let (source, custody_group_count) = match (meta_data, enr) {
            (Some(meta_data), _) => (CustodySource::MetaData, Some(meta_data.custody_group_count)),
            (None, Some(enr)) => {
                match enr.get_decodable::<CustodyGroupCount>(CUSTODY_GROUP_COUNT_ENR_KEY) {
                    Some(Ok(count)) => (CustodySource::Enr, Some(count.0)),
                    Some(Err(_)) => (CustodySource::Enr, None),
                    None => return Self::NotAdvertised,
                }
            }
            (None, None) => return Self::NotAdvertised,
        };
        match custody_group_count
            .and_then(|count| PeerCustodyGroups::from_advertised(node_id, count).ok())
        {
            Some(groups) => Self::Advertised { source, groups },
            None => Self::Invalid { source },
        }
    }

    pub fn groups(&self) -> Option<&PeerCustodyGroups> {
        match self {
            Self::Advertised { groups, .. } => Some(groups),
            _ => None,
        }
    }

    pub fn custodies_column(&self, column_index: u64) -> bool {
        self.groups()
            .is_some_and(|groups| groups.custodies_column(column_index))
    }
}

/// Which peers are expected to serve each requested column, and which columns no peer covers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ColumnCoverage {
    /// Every covered column mapped to the peers expected to serve it, sorted by column and peer.
    pub peers_by_column: BTreeMap<u64, Vec<PeerId>>,
    /// Requested columns no peer is expected to serve, sorted and deduplicated.
    pub uncovered_columns: Vec<u64>,
}

impl ColumnCoverage {
    pub fn compute<'a>(
        peers: impl IntoIterator<Item = (PeerId, &'a PeerCustody)>,
        columns: &[u64],
    ) -> Self {
        let requested = columns.iter().copied().collect::<BTreeSet<_>>();
        let mut peers_by_column = BTreeMap::<u64, Vec<PeerId>>::new();
        for (peer_id, custody) in peers {
            let Some(groups) = custody.groups() else {
                continue;
            };
            for column in &requested {
                if groups.custodies_column(*column) {
                    peers_by_column.entry(*column).or_default().push(peer_id);
                }
            }
        }
        for peers in peers_by_column.values_mut() {
            peers.sort_unstable();
        }
        let uncovered_columns = requested
            .into_iter()
            .filter(|column| !peers_by_column.contains_key(column))
            .collect();
        Self {
            peers_by_column,
            uncovered_columns,
        }
    }

    /// Peers expected to serve at least one requested column, sorted and deduplicated.
    pub fn eligible_peers(&self) -> Vec<PeerId> {
        self.peers_by_column
            .values()
            .flatten()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Custody groups of the uncovered columns, sorted and deduplicated. Column indices outside
    /// `NUMBER_OF_COLUMNS` belong to no group and are skipped.
    pub fn uncovered_custody_groups(&self) -> Vec<u64> {
        self.uncovered_columns
            .iter()
            .filter_map(|column| compute_custody_group_for_column(*column).ok())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// Matches discovered ENRs on the given fork that advertise a TCP port and a valid `cgc` covering
/// at least one of `custody_groups`. An ENR without `cgc` or with an invalid one never matches.
pub fn custody_group_enr_predicate(
    fork_digest: B32,
    custody_groups: Vec<u64>,
) -> impl Fn(&Enr) -> bool + Send + Sync + 'static {
    move |enr: &Enr| {
        let on_fork = enr
            .get_decodable::<EnrForkId>(ENR_ETH2_KEY)
            .and_then(Result::ok)
            .is_some_and(|fork_id| fork_id.fork_digest == fork_digest);
        if !on_fork || (enr.tcp4().is_none() && enr.tcp6().is_none()) {
            return false;
        }
        PeerCustody::derive(Some(enr.node_id()), None, Some(enr))
            .groups()
            .is_some_and(|groups| {
                custody_groups
                    .iter()
                    .any(|custody_group| groups.custodies_group(*custody_group))
            })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use discv5::enr::CombinedKey;
    use libp2p_identity::Keypair;
    use ream_consensus_misc::constants::beacon::NUM_CUSTODY_GROUPS;

    use super::*;
    use crate::network::misc::peer_id_from_enr;

    const FORK_DIGEST: B32 = B32::new([1, 2, 3, 4]);

    fn enr_with(key: &CombinedKey, cgc: Option<&[u8]>, fork_digest: B32, tcp: bool) -> Enr {
        let mut builder = Enr::builder();
        builder.ip4(Ipv4Addr::new(10, 0, 0, 1));
        if tcp {
            builder.tcp4(9000);
        }
        builder.add_value(
            ENR_ETH2_KEY,
            &EnrForkId {
                fork_digest,
                ..Default::default()
            },
        );
        if let Some(cgc) = cgc {
            // RLP string encoding, so tests can store values the `cgc` encoder never produces.
            let rlp = match cgc {
                [byte] if *byte < 0x80 => vec![*byte],
                _ => [&[0x80 + cgc.len() as u8], cgc].concat(),
            };
            builder.add_value_rlp(CUSTODY_GROUP_COUNT_ENR_KEY, rlp.into());
        }
        builder.build(key).expect("valid enr")
    }

    fn advertised_enr(key: &CombinedKey, custody_group_count: u64) -> Enr {
        let mut builder = Enr::builder();
        builder.ip4(Ipv4Addr::new(10, 0, 0, 1));
        builder.tcp4(9000);
        builder.add_value(
            ENR_ETH2_KEY,
            &EnrForkId {
                fork_digest: FORK_DIGEST,
                ..Default::default()
            },
        );
        builder.add_value(
            CUSTODY_GROUP_COUNT_ENR_KEY,
            &CustodyGroupCount(custody_group_count),
        );
        builder.build(key).expect("valid enr")
    }

    fn meta_data(seq_number: u64, custody_group_count: u64) -> GetMetaDataV3 {
        GetMetaDataV3 {
            seq_number,
            custody_group_count,
            ..Default::default()
        }
    }

    fn node_id() -> NodeId {
        NodeId::new(&[7; 32])
    }

    #[test]
    fn node_id_from_peer_id_matches_the_enr_of_the_same_key() {
        for _ in 0..8 {
            let key = CombinedKey::generate_secp256k1();
            let enr = Enr::builder().build(&key).expect("valid enr");
            let peer_id = peer_id_from_enr(&enr).expect("secp256k1 peer id");
            assert_eq!(node_id_from_peer_id(&peer_id), Some(enr.node_id()));
        }
    }

    #[test]
    fn node_id_is_unknown_without_a_secp256k1_identity() {
        assert_eq!(node_id_from_peer_id(&PeerId::random()), None);
        let ed25519 = Keypair::generate_ed25519().public().to_peer_id();
        assert_eq!(node_id_from_peer_id(&ed25519), None);
    }

    #[test]
    fn meta_data_takes_precedence_over_the_enr() {
        let key = CombinedKey::generate_secp256k1();
        let enr = advertised_enr(&key, NUM_CUSTODY_GROUPS);
        let node_id = Some(enr.node_id());

        let from_enr = PeerCustody::derive(node_id, None, Some(&enr));
        assert!(matches!(
            from_enr,
            PeerCustody::Advertised { source: CustodySource::Enr, ref groups }
                if groups.custody_group_count == NUM_CUSTODY_GROUPS
        ));

        let from_meta_data = PeerCustody::derive(node_id, Some(&meta_data(1, 4)), Some(&enr));
        let PeerCustody::Advertised { source, groups } = &from_meta_data else {
            panic!("MetaData count 4 is valid: {from_meta_data:?}");
        };
        assert_eq!(*source, CustodySource::MetaData);
        assert_eq!(
            groups,
            &PeerCustodyGroups::from_advertised(enr.node_id(), 4).expect("valid count")
        );
    }

    #[test]
    fn missing_or_invalid_advertisements_are_not_full_custody() {
        let key = CombinedKey::generate_secp256k1();
        let node_id = Some(node_id());

        assert_eq!(
            PeerCustody::derive(None, Some(&meta_data(0, 128)), None),
            PeerCustody::UnknownNodeId
        );
        assert_eq!(
            PeerCustody::derive(node_id, None, None),
            PeerCustody::NotAdvertised
        );
        let without_cgc = enr_with(&key, None, FORK_DIGEST, true);
        assert_eq!(
            PeerCustody::derive(node_id, None, Some(&without_cgc)),
            PeerCustody::NotAdvertised
        );
        let oversized_cgc = enr_with(&key, Some(&[1; 9]), FORK_DIGEST, true);
        assert_eq!(
            PeerCustody::derive(node_id, None, Some(&oversized_cgc)),
            PeerCustody::Invalid {
                source: CustodySource::Enr
            }
        );
        let too_many_groups = advertised_enr(&key, NUM_CUSTODY_GROUPS + 1);
        assert_eq!(
            PeerCustody::derive(node_id, None, Some(&too_many_groups)),
            PeerCustody::Invalid {
                source: CustodySource::Enr
            }
        );

        // An invalid MetaData count is not replaced by a valid ENR count.
        let valid_enr = advertised_enr(&key, 8);
        assert_eq!(
            PeerCustody::derive(node_id, Some(&meta_data(3, 129)), Some(&valid_enr)),
            PeerCustody::Invalid {
                source: CustodySource::MetaData
            }
        );

        for custody in [
            PeerCustody::UnknownNodeId,
            PeerCustody::NotAdvertised,
            PeerCustody::Invalid {
                source: CustodySource::MetaData,
            },
        ] {
            assert!(custody.groups().is_none());
            assert!((0..128).all(|column| !custody.custodies_column(column)));
        }
    }

    #[test]
    fn counts_below_custody_requirement_are_honored_as_advertised() {
        let custody = PeerCustody::derive(Some(node_id()), Some(&meta_data(0, 0)), None);
        let PeerCustody::Advertised { groups, .. } = &custody else {
            panic!("cgc 0 is a valid advertisement: {custody:?}");
        };
        assert!(groups.custody_columns.is_empty());
        assert!((0..128).all(|column| !custody.custodies_column(column)));

        let custody = PeerCustody::derive(Some(node_id()), Some(&meta_data(0, 1)), None);
        assert_eq!(
            custody.groups().expect("advertised").custody_columns.len(),
            1
        );
    }

    fn advertised(node_id: NodeId, custody_group_count: u64) -> PeerCustody {
        PeerCustody::derive(
            Some(node_id),
            Some(&meta_data(0, custody_group_count)),
            None,
        )
    }

    #[test]
    fn coverage_combines_partial_and_full_custody_peers() {
        let partial_a = (PeerId::random(), advertised(NodeId::new(&[1; 32]), 4));
        let partial_b = (PeerId::random(), advertised(NodeId::new(&[2; 32]), 4));
        let unknown = (PeerId::random(), PeerCustody::NotAdvertised);
        let a_columns = partial_a.1.groups().unwrap().custody_columns.clone();
        let b_columns = partial_b.1.groups().unwrap().custody_columns.clone();

        let mut requested = a_columns.clone();
        requested.extend(&b_columns);
        let outside_both = (0..128)
            .find(|column| !a_columns.contains(column) && !b_columns.contains(column))
            .expect("8 groups leave columns uncovered");
        requested.push(outside_both);
        requested.push(outside_both);

        let coverage = ColumnCoverage::compute(
            [&partial_a, &partial_b, &unknown]
                .into_iter()
                .map(|(peer_id, custody)| (*peer_id, custody)),
            &requested,
        );
        assert_eq!(coverage.uncovered_columns, [outside_both]);
        assert_eq!(coverage.uncovered_custody_groups(), [outside_both]);
        for column in &a_columns {
            assert!(coverage.peers_by_column[column].contains(&partial_a.0));
        }
        for column in &b_columns {
            assert!(coverage.peers_by_column[column].contains(&partial_b.0));
        }
        let mut expected_peers = vec![partial_a.0, partial_b.0];
        expected_peers.sort_unstable();
        assert_eq!(coverage.eligible_peers(), expected_peers);

        let full = (PeerId::random(), advertised(NodeId::new(&[3; 32]), 128));
        let coverage = ColumnCoverage::compute(
            [&partial_a, &partial_b, &unknown, &full]
                .into_iter()
                .map(|(peer_id, custody)| (*peer_id, custody)),
            &(0..128).collect::<Vec<_>>(),
        );
        assert!(coverage.uncovered_columns.is_empty());
        assert_eq!(coverage.peers_by_column.len(), 128);
        assert!(
            coverage
                .peers_by_column
                .values()
                .all(|peers| peers.contains(&full.0))
        );
    }

    #[test]
    fn coverage_lists_every_peer_for_overlapping_columns() {
        let node_id = NodeId::new(&[9; 32]);
        let small = (PeerId::random(), advertised(node_id, 4));
        let large = (PeerId::random(), advertised(node_id, 16));
        // Custody lists for one node ID are nested, so every column of `small` is shared.
        let shared = small.1.groups().unwrap().custody_columns.clone();

        let coverage = ColumnCoverage::compute(
            [&small, &large]
                .into_iter()
                .map(|(peer_id, custody)| (*peer_id, custody)),
            &shared,
        );
        let mut both = vec![small.0, large.0];
        both.sort_unstable();
        assert!(coverage.uncovered_columns.is_empty());
        for column in &shared {
            assert_eq!(coverage.peers_by_column[column], both);
        }
    }

    #[test]
    fn coverage_without_eligible_peers_reports_all_requested_columns() {
        let coverage = ColumnCoverage::compute(
            [(PeerId::random(), &PeerCustody::UnknownNodeId)],
            &[5, 3, 200],
        );
        assert!(coverage.peers_by_column.is_empty());
        assert!(coverage.eligible_peers().is_empty());
        assert_eq!(coverage.uncovered_columns, [3, 5, 200]);
        assert_eq!(coverage.uncovered_custody_groups(), [3, 5]);
    }

    #[test]
    fn discovery_predicate_selects_peers_covering_uncovered_groups() {
        let key = CombinedKey::generate_secp256k1();
        let partial = advertised_enr(&key, 4);
        let partial_groups = PeerCustodyGroups::from_advertised(partial.node_id(), 4)
            .expect("valid count")
            .custody_groups;
        let other_group = (0..128)
            .find(|group| !partial_groups.contains(group))
            .expect("4 groups leave others uncovered");

        assert!(custody_group_enr_predicate(
            FORK_DIGEST,
            vec![partial_groups[0]]
        )(&partial));
        assert!(custody_group_enr_predicate(
            FORK_DIGEST,
            vec![other_group, partial_groups[1]]
        )(&partial));
        assert!(!custody_group_enr_predicate(FORK_DIGEST, vec![other_group])(&partial));

        let supernode = advertised_enr(&CombinedKey::generate_secp256k1(), NUM_CUSTODY_GROUPS);
        assert!(custody_group_enr_predicate(FORK_DIGEST, vec![other_group])(
            &supernode
        ));
    }

    #[test]
    fn discovery_predicate_rejects_unusable_enrs() {
        let key = CombinedKey::generate_secp256k1();
        let all_groups = (0..128).collect::<Vec<_>>();
        let predicate = custody_group_enr_predicate(FORK_DIGEST, all_groups);

        let full = [0x80];
        assert!(predicate(&enr_with(&key, Some(&full), FORK_DIGEST, true)));
        assert!(!predicate(&enr_with(&key, None, FORK_DIGEST, true)));
        assert!(!predicate(&enr_with(
            &key,
            Some(&[1; 9]),
            FORK_DIGEST,
            true
        )));
        assert!(!predicate(&enr_with(
            &key,
            Some(&[0x81]),
            FORK_DIGEST,
            true
        )));
        assert!(!predicate(&enr_with(&key, Some(&full), B32::ZERO, true)));
        assert!(!predicate(&enr_with(&key, Some(&full), FORK_DIGEST, false)));
        // cgc 0 is a valid advertisement that covers no group.
        assert!(!predicate(&enr_with(&key, Some(&[]), FORK_DIGEST, true)));
    }
}
