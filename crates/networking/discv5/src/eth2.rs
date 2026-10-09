use alloy_primitives::{B256, aliases::B32};
use alloy_rlp::{BufMut, Decodable, Encodable, bytes::Bytes};
use ream_consensus_misc::constants::beacon::FAR_FUTURE_EPOCH;
use ream_network_spec::networks::{BeaconNetworkSpec, beacon_network_spec};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use tracing::warn;

pub const ENR_ETH2_KEY: &str = "eth2";

#[derive(Clone, Default, Debug, PartialEq, Eq, Encode, Decode)]
pub struct EnrForkId {
    pub fork_digest: B32,
    pub next_fork_version: B32,
    pub next_fork_epoch: u64,
}

impl EnrForkId {
    pub fn current(genesis_validators_root: B256, epoch: u64) -> Self {
        Self::at_epoch(&beacon_network_spec(), genesis_validators_root, epoch)
    }

    /// `eth2` value for the wall-clock `epoch`. Only regular forks change the version, so before a
    /// BPO fork `next_fork_version` stays the current one.
    pub fn at_epoch(spec: &BeaconNetworkSpec, genesis_validators_root: B256, epoch: u64) -> Self {
        let next_fork_epoch = spec.next_fork_epoch(epoch);
        Self {
            fork_digest: spec.fork_digest(epoch, genesis_validators_root),
            next_fork_version: spec.current_fork_version(next_fork_epoch.unwrap_or(epoch)),
            next_fork_epoch: next_fork_epoch.unwrap_or(FAR_FUTURE_EPOCH),
        }
    }
}

impl Encodable for EnrForkId {
    fn encode(&self, out: &mut dyn BufMut) {
        let ssz_bytes = self.as_ssz_bytes();
        let bytes = Bytes::from(ssz_bytes);
        bytes.encode(out);
    }
}

impl Decodable for EnrForkId {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let bytes = Bytes::decode(buf)?;
        let enr_fork_id = EnrForkId::from_ssz_bytes(&bytes).map_err(|err| {
            warn!("Failed to decode SSZ ENRForkID: {err:?}");
            alloy_rlp::Error::Custom("Failed to decode SSZ ENRForkID")
        })?;
        Ok(enr_fork_id)
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use ream_consensus_misc::blob_parameters::BlobParameters;
    use ream_network_spec::networks::{BeaconNetworkSpec, DEV};

    /// Electra at epoch 10, Fulu at 20, and BPO forks at 30 and 40.
    pub(crate) fn bpo_spec() -> BeaconNetworkSpec {
        let mut spec = (**DEV).clone();
        spec.altair_fork_epoch = 0;
        spec.bellatrix_fork_epoch = 0;
        spec.capella_fork_epoch = 0;
        spec.deneb_fork_epoch = 0;
        spec.electra_fork_epoch = 10;
        spec.fulu_fork_epoch = 20;
        spec.blob_schedule = [(30, 15), (40, 21)]
            .map(|(epoch, max_blobs_per_block)| BlobParameters {
                epoch,
                max_blobs_per_block,
            })
            .to_vec();
        spec
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;

    use super::{test_utils::bpo_spec, *};
    use crate::subnet::NextForkDigest;

    #[test]
    fn next_regular_fork_is_advertised_with_its_version() {
        let spec = bpo_spec();
        let fork_id = EnrForkId::at_epoch(&spec, B256::ZERO, 15);
        assert_eq!(fork_id.fork_digest, spec.fork_digest(15, B256::ZERO));
        assert_eq!(fork_id.next_fork_version, spec.fulu_fork_version);
        assert_eq!(fork_id.next_fork_epoch, 20);
        assert_eq!(
            NextForkDigest::at_epoch(&spec, B256::ZERO, 15),
            NextForkDigest(spec.fork_digest(20, B256::ZERO))
        );
    }

    #[test]
    fn next_bpo_fork_keeps_the_current_version() {
        let spec = bpo_spec();
        let fork_id = EnrForkId::at_epoch(&spec, B256::ZERO, 30);
        assert_eq!(fork_id.fork_digest, spec.fork_digest(30, B256::ZERO));
        assert_ne!(fork_id.fork_digest, spec.fork_digest(29, B256::ZERO));
        assert_eq!(fork_id.next_fork_version, spec.fulu_fork_version);
        assert_eq!(fork_id.next_fork_epoch, 40);
        assert_eq!(
            NextForkDigest::at_epoch(&spec, B256::ZERO, 30),
            NextForkDigest(spec.fork_digest(40, B256::ZERO))
        );
    }

    #[test]
    fn no_next_fork_advertises_the_current_version() {
        let spec = bpo_spec();
        let fork_id = EnrForkId::at_epoch(&spec, B256::ZERO, 40);
        assert_eq!(fork_id.next_fork_version, spec.fulu_fork_version);
        assert_eq!(fork_id.next_fork_epoch, FAR_FUTURE_EPOCH);
        assert_eq!(
            NextForkDigest::at_epoch(&spec, B256::ZERO, 40),
            NextForkDigest::default()
        );

        // An unscheduled fork is not a next fork, and neither are BPO entries without Fulu.
        let mut spec = bpo_spec();
        spec.fulu_fork_epoch = FAR_FUTURE_EPOCH;
        let fork_id = EnrForkId::at_epoch(&spec, B256::ZERO, 15);
        assert_eq!(fork_id.next_fork_version, spec.electra_fork_version);
        assert_eq!(fork_id.next_fork_epoch, FAR_FUTURE_EPOCH);
        assert_eq!(
            NextForkDigest::at_epoch(&spec, B256::ZERO, 15),
            NextForkDigest::default()
        );
    }

    #[test]
    fn test_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let fork_id = EnrForkId {
            fork_digest: B32::from_slice(&[1, 2, 3, 4]),
            next_fork_version: B32::from_slice(&[5, 6, 7, 8]),
            next_fork_epoch: 100,
        };

        let mut buffer = Vec::new();
        fork_id.encode(&mut buffer);
        let mut rlp_bytes_slice = buffer.as_slice();
        let deserialized = EnrForkId::decode(&mut rlp_bytes_slice)?;

        assert_eq!(fork_id.fork_digest, deserialized.fork_digest);
        assert_eq!(fork_id.next_fork_version, deserialized.next_fork_version);
        assert_eq!(fork_id.next_fork_epoch, deserialized.next_fork_epoch);
        Ok(())
    }
}
