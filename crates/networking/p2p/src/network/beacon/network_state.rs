use std::{collections::HashMap, fs, path::PathBuf};

use anyhow::anyhow;
use discv5::Enr;
use libp2p::{Multiaddr, PeerId};
use parking_lot::RwLock;
use ream_peer::{ConnectionState, Direction};
use ream_req_resp::beacon::messages::{meta_data::GetMetaDataV3, status::Status};
use ssz::Encode;

use super::{
    peer::CachedPeer,
    peer_custody::{ColumnCoverage, PeerCustody},
    utils::META_DATA_FILE_NAME,
};

pub struct NetworkState {
    pub local_enr: RwLock<Enr>,
    pub peer_table: RwLock<HashMap<PeerId, CachedPeer>>,
    pub meta_data: RwLock<GetMetaDataV3>,
    pub status: RwLock<Status>,
    pub data_dir: PathBuf,
}

impl NetworkState {
    pub fn upsert_peer(
        &self,
        peer_id: PeerId,
        address: Option<Multiaddr>,
        state: ConnectionState,
        direction: Direction,
        enr: Option<Enr>,
    ) {
        self.peer_table
            .write()
            .entry(peer_id)
            .and_modify(|cached_peer| {
                if let Some(address_ref) = &address {
                    cached_peer.last_seen_p2p_address = Some(address_ref.clone());
                }
                cached_peer.state = state;
                cached_peer.direction = direction;
                if let Some(enr_ref) = &enr {
                    cached_peer.update_enr(enr_ref.clone());
                }
            })
            .or_insert(CachedPeer::new(peer_id, address, state, direction, enr));
    }

    pub fn update_peer_state(&self, peer_id: PeerId, state: ConnectionState) {
        self.peer_table
            .write()
            .entry(peer_id)
            .and_modify(|cached_peer| {
                cached_peer.state = state;
            });
    }

    /// Stores MetaData received from `peer_id` and refreshes its custody. Returns `false` when
    /// the peer is unknown or the MetaData is older than the cached one.
    pub fn update_peer_meta_data(&self, peer_id: PeerId, meta_data: GetMetaDataV3) -> bool {
        self.peer_table
            .write()
            .get_mut(&peer_id)
            .is_some_and(|cached_peer| cached_peer.update_meta_data(meta_data))
    }

    /// Marks the peer disconnected and drops the MetaData of the closed connection.
    pub fn peer_disconnected(&self, peer_id: PeerId) {
        if let Some(cached_peer) = self.peer_table.write().get_mut(&peer_id) {
            cached_peer.state = ConnectionState::Disconnected;
            cached_peer.clear_meta_data();
        }
    }

    /// Returns the custody derived for `peer_id`, if the peer is in the peer table.
    pub fn peer_custody(&self, peer_id: &PeerId) -> Option<PeerCustody> {
        self.peer_table
            .read()
            .get(peer_id)
            .map(|cached_peer| cached_peer.custody().clone())
    }

    /// Reports which connected peers are expected to serve each of `columns` and which columns
    /// none of them covers. Peers without a valid custody advertisement cover nothing.
    pub fn column_coverage(&self, columns: &[u64]) -> ColumnCoverage {
        let peer_table = self.peer_table.read();
        ColumnCoverage::compute(
            peer_table
                .values()
                .filter(|peer| peer.state == ConnectionState::Connected)
                .map(|peer| (peer.peer_id, peer.custody())),
            columns,
        )
    }

    pub fn write_meta_data_to_disk(&self) -> anyhow::Result<()> {
        let meta_data_path = self.data_dir.join(META_DATA_FILE_NAME);
        fs::write(meta_data_path, self.meta_data.read().as_ssz_bytes())
            .map_err(|err| anyhow!("Failed to write meta data to disk: {err:?}"))?;
        Ok(())
    }

    /// Gets a vector of all connected peers.
    pub fn connected_peers(&self) -> Vec<CachedPeer> {
        self.peer_table
            .read()
            .values()
            .filter(|peer| peer.state == ConnectionState::Connected)
            .cloned()
            .collect()
    }
}
