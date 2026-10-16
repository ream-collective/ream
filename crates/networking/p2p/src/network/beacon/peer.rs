use std::time::Instant;

use discv5::{Enr, enr::NodeId};
use libp2p::{Multiaddr, PeerId};
use ream_peer::{ConnectionState, Direction};
use ream_req_resp::beacon::messages::{meta_data::GetMetaDataV3, status::Status};

use super::peer_custody::{PeerCustody, node_id_from_peer_id};
use crate::network::misc::peer_id_from_enr;

#[derive(Clone, Debug)]
pub struct CachedPeer {
    /// libp2p peer ID
    pub peer_id: PeerId,

    /// Last known multiaddress observed for the peer
    pub last_seen_p2p_address: Option<Multiaddr>,

    /// Current known connection state
    pub state: ConnectionState,

    /// Direction of the most recent connection (inbound/outbound)
    pub direction: Direction,

    /// Last time we received a message from this peer
    pub last_seen: Instant,

    pub status: Option<Status>,

    /// discv5 node ID recovered from `peer_id`, if its key type allows it
    node_id: Option<NodeId>,

    /// Ethereum Node Record (ENR), if known. Always signed by the key behind `peer_id`.
    enr: Option<Enr>,

    /// MetaData received on the current connection
    meta_data: Option<GetMetaDataV3>,

    /// Derived from `node_id`, `meta_data` and `enr`, and refreshed whenever one of them changes
    custody: PeerCustody,
}

impl CachedPeer {
    pub fn new(
        peer_id: PeerId,
        address: Option<Multiaddr>,
        state: ConnectionState,
        direction: Direction,
        enr: Option<Enr>,
    ) -> Self {
        let mut peer = CachedPeer {
            peer_id,
            last_seen_p2p_address: address,
            state,
            direction,
            last_seen: Instant::now(),
            status: None,
            node_id: node_id_from_peer_id(&peer_id),
            enr: enr.filter(|enr| peer_id_from_enr(enr) == Some(peer_id)),
            meta_data: None,
            custody: PeerCustody::UnknownNodeId,
        };
        peer.refresh_custody();
        peer
    }

    /// Update the last seen timestamp
    pub fn update_last_seen(&mut self) {
        self.last_seen = Instant::now();
    }

    pub fn node_id(&self) -> Option<NodeId> {
        self.node_id
    }

    pub fn enr(&self) -> Option<&Enr> {
        self.enr.as_ref()
    }

    pub fn meta_data(&self) -> Option<&GetMetaDataV3> {
        self.meta_data.as_ref()
    }

    pub fn custody(&self) -> &PeerCustody {
        &self.custody
    }

    /// Stores `enr` unless it belongs to a different peer ID or has a lower sequence number than
    /// the cached record. Returns whether it was stored.
    pub fn update_enr(&mut self, enr: Enr) -> bool {
        if peer_id_from_enr(&enr) != Some(self.peer_id) {
            return false;
        }
        if self
            .enr
            .as_ref()
            .is_some_and(|cached| enr.seq() < cached.seq())
        {
            return false;
        }
        self.enr = Some(enr);
        self.refresh_custody();
        true
    }

    /// Stores `meta_data` unless its sequence number is lower than the cached one, which means it
    /// answered an older request. Returns whether it was stored.
    pub fn update_meta_data(&mut self, meta_data: GetMetaDataV3) -> bool {
        if self
            .meta_data
            .as_ref()
            .is_some_and(|cached| meta_data.seq_number < cached.seq_number)
        {
            return false;
        }
        self.meta_data = Some(meta_data);
        self.refresh_custody();
        true
    }

    /// Forgets the MetaData of a closed connection. A peer may restart with a new sequence
    /// number and custody count, so the next connection must fetch it again.
    pub fn clear_meta_data(&mut self) {
        self.meta_data = None;
        self.refresh_custody();
    }

    fn refresh_custody(&mut self) {
        self.custody =
            PeerCustody::derive(self.node_id, self.meta_data.as_ref(), self.enr.as_ref());
    }
}

#[cfg(test)]
mod tests {
    use discv5::enr::CombinedKey;
    use ream_discv5::subnet::{CUSTODY_GROUP_COUNT_ENR_KEY, CustodyGroupCount};

    use super::*;
    use crate::network::beacon::peer_custody::CustodySource;

    fn enr(key: &CombinedKey, seq: u64, custody_group_count: u64) -> Enr {
        let mut builder = Enr::builder();
        builder.seq(seq);
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

    fn peer_for(key: &CombinedKey, enr: Option<Enr>) -> CachedPeer {
        let peer_id = peer_id_from_enr(&Enr::builder().build(key).expect("valid enr"))
            .expect("secp256k1 peer id");
        CachedPeer::new(
            peer_id,
            None,
            ConnectionState::Connected,
            Direction::Inbound,
            enr,
        )
    }

    fn custody_group_count(peer: &CachedPeer) -> Option<(CustodySource, u64)> {
        match peer.custody() {
            PeerCustody::Advertised { source, groups } => {
                Some((*source, groups.custody_group_count))
            }
            _ => None,
        }
    }

    #[test]
    fn inbound_peer_without_enr_derives_custody_from_meta_data() {
        let key = CombinedKey::generate_secp256k1();
        let mut peer = peer_for(&key, None);
        assert_eq!(peer.custody(), &PeerCustody::NotAdvertised);
        assert_eq!(peer.node_id(), Some(enr(&key, 1, 0).node_id()));

        assert!(peer.update_meta_data(meta_data(1, 8)));
        assert_eq!(
            custody_group_count(&peer),
            Some((CustodySource::MetaData, 8))
        );
    }

    #[test]
    fn enr_of_another_identity_is_ignored() {
        let key = CombinedKey::generate_secp256k1();
        let other_key = CombinedKey::generate_secp256k1();

        let peer = peer_for(&key, Some(enr(&other_key, 1, 128)));
        assert!(peer.enr().is_none());
        assert_eq!(peer.custody(), &PeerCustody::NotAdvertised);

        let mut peer = peer_for(&key, Some(enr(&key, 1, 4)));
        assert!(!peer.update_enr(enr(&other_key, 9, 128)));
        assert_eq!(custody_group_count(&peer), Some((CustodySource::Enr, 4)));
    }

    #[test]
    fn stale_enr_and_meta_data_do_not_replace_newer_ones() {
        let key = CombinedKey::generate_secp256k1();
        let mut peer = peer_for(&key, Some(enr(&key, 5, 8)));

        assert!(!peer.update_enr(enr(&key, 4, 128)));
        assert_eq!(custody_group_count(&peer), Some((CustodySource::Enr, 8)));
        assert!(peer.update_enr(enr(&key, 6, 16)));
        assert_eq!(custody_group_count(&peer), Some((CustodySource::Enr, 16)));

        assert!(peer.update_meta_data(meta_data(3, 32)));
        assert!(!peer.update_meta_data(meta_data(2, 128)));
        assert_eq!(
            custody_group_count(&peer),
            Some((CustodySource::MetaData, 32))
        );
        assert!(peer.update_meta_data(meta_data(4, 64)));
        assert_eq!(
            custody_group_count(&peer),
            Some((CustodySource::MetaData, 64))
        );
    }

    #[test]
    fn clearing_meta_data_falls_back_to_the_enr() {
        let key = CombinedKey::generate_secp256k1();
        let mut peer = peer_for(&key, Some(enr(&key, 1, 4)));
        assert!(peer.update_meta_data(meta_data(7, 128)));

        peer.clear_meta_data();
        assert!(peer.meta_data().is_none());
        assert_eq!(custody_group_count(&peer), Some((CustodySource::Enr, 4)));

        // A restarted peer may begin again from a lower sequence number.
        assert!(peer.update_meta_data(meta_data(0, 8)));
        assert_eq!(
            custody_group_count(&peer),
            Some((CustodySource::MetaData, 8))
        );
    }
}
