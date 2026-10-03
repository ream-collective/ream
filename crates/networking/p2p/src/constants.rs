use std::time::Duration;

use alloy_primitives::{aliases::B32, fixed_bytes};

pub const MESSAGE_DOMAIN_VALID_SNAPPY: B32 = fixed_bytes!("0x01000000");
pub const MESSAGE_DOMAIN_INVALID_SNAPPY: B32 = fixed_bytes!("0x00000000");

pub const PING_INTERVAL_DURATION: Duration = Duration::from_secs(300);
pub const TARGET_PEER_COUNT: usize = 50;
/// Peers requested from one custody discv5 query. Queries start at most once per maintenance
/// tick, so this also bounds how many custody peers are dialed per tick.
pub const CUSTODY_DISCOVERY_TARGET_PEERS: usize = 8;

pub const QUIC_ENR_KEY: &[u8] = b"quic";
