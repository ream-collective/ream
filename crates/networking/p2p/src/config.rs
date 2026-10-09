use std::path::PathBuf;

use ream_discv5::config::DiscoveryConfig;

use crate::gossipsub::beacon::configurations::GossipsubConfig;

pub struct NetworkConfig {
    pub discv5_config: DiscoveryConfig,

    pub gossipsub_config: GossipsubConfig,

    pub data_dir: PathBuf,

    /// Genesis time of the chain in seconds, used to schedule subnet rotation
    pub genesis_time: u64,
}
