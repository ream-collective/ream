use std::path::PathBuf;

use libp2p::connection_limits::ConnectionLimits;
use ream_discv5::config::DiscoveryConfig;

use crate::gossipsub::beacon::configurations::GossipsubConfig;

pub struct NetworkConfig {
    pub discv5_config: DiscoveryConfig,

    pub gossipsub_config: GossipsubConfig,

    pub data_dir: PathBuf,

    /// Genesis time of the chain in seconds, used to schedule subnet rotation
    pub genesis_time: u64,

    /// Peers the node keeps connected; the connection limits are derived from it.
    pub target_peers: usize,

    /// Active validators at startup, which set the expected message rates of the scored gossip
    /// topics. `None` leaves gossipsub peer scoring off.
    pub active_validators: Option<usize>,
}

/// Established connection limits derived from the target peer count, with Lighthouse v8's
/// factors (`PEER_EXCESS_FACTOR` 10%, `MIN_OUTBOUND_ONLY_FACTOR` 20%, `PRIORITY_PEER_EXCESS`
/// 20%). Connections beyond them are denied when they are established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerLimits {
    /// Inbound connections, leaving room for the outbound peers the node dials itself.
    pub max_incoming: u32,
    /// Outbound connections: the target plus 10%.
    pub max_outgoing: u32,
    /// All connections: the target plus 30%, for peers dialed to cover a subnet.
    pub max_established: u32,
}

impl PeerLimits {
    pub fn from_target_peers(target_peers: usize) -> Self {
        let percent_of_target = |percent: usize| {
            u32::try_from(target_peers.saturating_mul(percent).div_ceil(100)).unwrap_or(u32::MAX)
        };
        Self {
            max_incoming: percent_of_target(90),
            max_outgoing: percent_of_target(110),
            max_established: percent_of_target(130),
        }
    }

    pub fn connection_limits(&self) -> ConnectionLimits {
        ConnectionLimits::default()
            .with_max_pending_incoming(Some(5))
            .with_max_pending_outgoing(Some(16))
            .with_max_established_incoming(Some(self.max_incoming))
            .with_max_established_outgoing(Some(self.max_outgoing))
            .with_max_established(Some(self.max_established))
            .with_max_established_per_peer(Some(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_limits_follow_the_target() {
        assert_eq!(
            PeerLimits::from_target_peers(200),
            PeerLimits {
                max_incoming: 180,
                max_outgoing: 220,
                max_established: 260,
            }
        );
        // Rounded up, so a small target still admits a connection each way.
        assert_eq!(
            PeerLimits::from_target_peers(1),
            PeerLimits {
                max_incoming: 1,
                max_outgoing: 2,
                max_established: 2,
            }
        );
    }
}
