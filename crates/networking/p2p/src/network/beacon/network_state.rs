use std::{collections::HashMap, fs, path::PathBuf};

use anyhow::anyhow;
use discv5::Enr;
use libp2p::{Multiaddr, PeerId};
use parking_lot::RwLock;
use ream_peer::{ConnectionState, Direction};
use ream_req_resp::beacon::messages::{meta_data::GetMetaDataV3, status::Status};
use ssz::Encode;

use super::{peer::CachedPeer, utils::META_DATA_FILE_NAME};

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
                    cached_peer.enr = Some(enr_ref.clone());
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

    /// Applies `update`. On change, bumps `seq_number`, since peers refetch `MetaData` only when
    /// it grows. The new value is saved before it is served, so a failed save changes nothing
    /// and the next call retries it.
    pub fn update_meta_data(
        &self,
        update: impl FnOnce(&mut GetMetaDataV3),
    ) -> anyhow::Result<bool> {
        let mut meta_data = self.meta_data.write();
        let mut updated = meta_data.clone();
        update(&mut updated);
        updated.seq_number = meta_data.seq_number;
        if updated == *meta_data {
            return Ok(false);
        }
        updated.seq_number = updated.seq_number.saturating_add(1);
        self.save_meta_data(&updated)?;
        *meta_data = updated;
        Ok(true)
    }

    pub fn write_meta_data_to_disk(&self) -> anyhow::Result<()> {
        self.save_meta_data(&self.meta_data.read())
    }

    fn save_meta_data(&self, meta_data: &GetMetaDataV3) -> anyhow::Result<()> {
        let meta_data_path = self.data_dir.join(META_DATA_FILE_NAME);
        fs::write(meta_data_path, meta_data.as_ssz_bytes())
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
