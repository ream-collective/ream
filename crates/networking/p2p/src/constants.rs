use std::time::Duration;

use alloy_primitives::{aliases::B32, fixed_bytes};

pub const MESSAGE_DOMAIN_VALID_SNAPPY: B32 = fixed_bytes!("0x01000000");
pub const MESSAGE_DOMAIN_INVALID_SNAPPY: B32 = fixed_bytes!("0x00000000");

pub const PING_INTERVAL_DURATION: Duration = Duration::from_secs(300);
/// Peers a beacon node keeps by default, as Lighthouse v8's `DEFAULT_TARGET_PEERS`.
pub const DEFAULT_TARGET_PEERS: usize = 200;
/// Fewest peers wanted on an attestation subnet a validator publishes to or aggregates on.
pub const TARGET_SUBNET_PEERS: usize = 3;
/// Peers requested from one attestation subnet discv5 query.
pub const SUBNET_DISCOVERY_TARGET_PEERS: usize = 8;
/// Messages a peer's full gossipsub send queue may drop in one heartbeat before it counts as slow.
pub const SLOW_PEER_DROPPED_MESSAGES: usize = 10;
/// Slow heartbeats, each within `SLOW_PEER_WINDOW` of the last, after which a peer is dropped.
pub const SLOW_PEER_STRIKES: u32 = 10;
pub const SLOW_PEER_WINDOW: Duration = Duration::from_secs(60);
/// Peers requested from one custody discv5 query. Queries start at most once per maintenance
/// tick, so this also bounds how many custody peers are dialed per tick.
pub const CUSTODY_DISCOVERY_TARGET_PEERS: usize = 8;

pub const QUIC_ENR_KEY: &[u8] = b"quic";
