pub mod channel;
pub mod identity;
pub mod network_state;
pub mod peer;
pub mod peer_custody;
pub mod utils;

use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    num::{NonZeroU8, NonZeroUsize},
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, ensure};
use channel::{P2PCallbackError, P2PCallbackResponse, P2PMessage, P2PRequest, P2PResponse};
use delay_map::{HashMapDelay, HashSetDelay};
use discv5::Enr;
use futures::future::OptionFuture;
use identity::{ENR_FILE_NAME, load_or_create_network_key};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, connection_limits,
    core::ConnectedPoint,
    futures::StreamExt,
    gossipsub::{
        Event as GossipsubEvent, IdentTopic as Topic, Message, MessageAuthenticity, MessageId,
        PublishError, TopicHash,
    },
    identify,
    multiaddr::Protocol,
    swarm::{self, ConnectionId, NetworkBehaviour, SwarmEvent},
};
use libp2p_identity::{Keypair, PublicKey};
use network_state::NetworkState;
use parking_lot::{Mutex, RwLock};
use peer::CachedPeer;
use peer_custody::custody_group_enr_predicate;
use ream_consensus_beacon::custody_group::{CustodyAssignment, CustodyConfig};
use ream_consensus_misc::{
    constants::beacon::{SLOTS_PER_EPOCH, genesis_validators_root},
    misc::{compute_epoch_at_slot, compute_start_slot_at_epoch},
};
use ream_discv5::{
    config::DiscoveryConfig,
    discovery::{Discovery, DiscoveryOutEvent, QueryType},
    subnet::{
        ATTESTATION_BITFIELD_ENR_KEY, ATTESTATION_SUBNET_COUNT, AttestationSubnets,
        CustodyGroupCount, SYNC_COMMITTEE_BITFIELD_ENR_KEY, SyncCommitteeSubnets,
    },
};
use ream_executor::ReamExecutor;
use ream_metrics::{
    BEACON_GOSSIPSUB_LOWEST_PEER_SCORE, BEACON_GOSSIPSUB_PEERS_BY_SCORE, set_peer_count,
};
use ream_network_spec::networks::beacon_network_spec;
use ream_peer::{ConnectionState, Direction};
use ream_req_resp::{
    Chain, ReqResp, ReqRespMessage,
    beacon::messages::{
        BeaconRequestMessage, BeaconResponseMessage,
        blob_sidecars::BlobSidecarsByRootV1Request,
        blocks::{BeaconBlocksByRangeV2Request, BeaconBlocksByRootV2Request},
        data_column_sidecars::{
            DataColumnSidecarsByRangeV1Request, DataColumnSidecarsByRootV1Request,
        },
        meta_data::GetMetaDataV3,
        ping::Ping,
        status::Status,
    },
    configurations::REQUEST_TIMEOUT,
    handler::{ReqRespMessageError, ReqRespMessageReceived, RespMessage},
    messages::{RequestMessage, ResponseMessage},
};
use ssz_types::{
    BitVector, VariableList,
    typenum::{U4, U64},
};
use tokio::{
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    time::{interval, sleep},
};
use tracing::{debug, error, info, trace, warn};
use utils::read_meta_data_from_disk;

use crate::{
    config::{NetworkConfig, PeerLimits},
    constants::{
        CUSTODY_DISCOVERY_TARGET_PEERS, PING_INTERVAL_DURATION, SLOW_PEER_DROPPED_MESSAGES,
        SLOW_PEER_STRIKES, SLOW_PEER_WINDOW, SUBNET_DISCOVERY_TARGET_PEERS, TARGET_SUBNET_PEERS,
    },
    gossipsub::{
        GossipsubBehaviour,
        beacon::{
            scoring::{
                GOSSIP_THRESHOLD, GRAYLIST_THRESHOLD, PUBLISH_THRESHOLD, PeerScoreSettings,
                peer_score_thresholds,
            },
            topics::{GossipTopic, GossipTopicKind},
        },
        snappy::SnappyTransform,
    },
    network::misc::{Executor, build_transport, peer_id_from_enr},
};

/// The ENR advertises only the subnets joined through `topics`.
fn discovery_config_for_topics(
    config: &DiscoveryConfig,
    topics: &[GossipTopic],
) -> anyhow::Result<DiscoveryConfig> {
    let mut config = config.clone();
    config.attestation_subnets = AttestationSubnets::new();
    config.sync_committee_subnets = SyncCommitteeSubnets::new();
    for topic in topics {
        match topic.kind {
            GossipTopicKind::BeaconAttestation(subnet_id) => {
                config
                    .attestation_subnets
                    .enable_attestation_subnet(subnet_id)?;
            }
            GossipTopicKind::SyncCommittee(subnet_id) => {
                config
                    .sync_committee_subnets
                    .enable_sync_committee_subnet(subnet_id)?;
            }
            _ => {}
        }
    }
    Ok(config)
}

/// `MetaData` must mirror these ENR bitfields.
fn enr_subnet_bitfields(enr: &Enr) -> anyhow::Result<(BitVector<U64>, BitVector<U4>)> {
    let attestation_subnets = enr
        .get_decodable::<AttestationSubnets>(ATTESTATION_BITFIELD_ENR_KEY)
        .ok_or_else(|| anyhow!("Local ENR has no attnets field"))?
        .map_err(|err| anyhow!("Failed to decode local ENR attnets: {err:?}"))?;
    let sync_committee_subnets = enr
        .get_decodable::<SyncCommitteeSubnets>(SYNC_COMMITTEE_BITFIELD_ENR_KEY)
        .ok_or_else(|| anyhow!("Local ENR has no syncnets field"))?
        .map_err(|err| anyhow!("Failed to decode local ENR syncnets: {err:?}"))?;
    Ok((attestation_subnets.0, sync_committee_subnets.0))
}

/// Counts a heartbeat in which `dropped` messages to `peer_id` were dropped because its send queue
/// was full. Returns true once the peer has been slow for `SLOW_PEER_STRIKES` heartbeats in a row,
/// each within `SLOW_PEER_WINDOW` of the last, and forgets it.
fn record_slow_heartbeat(
    slow_peers: &mut HashMap<PeerId, (u32, Instant)>,
    peer_id: PeerId,
    dropped: usize,
    now: Instant,
) -> bool {
    slow_peers.retain(|_, (_, last)| now.duration_since(*last) < SLOW_PEER_WINDOW);
    if dropped <= SLOW_PEER_DROPPED_MESSAGES {
        return false;
    }
    let (strikes, last) = slow_peers.entry(peer_id).or_insert((0, now));
    *strikes += 1;
    *last = now;
    if *strikes < SLOW_PEER_STRIKES {
        return false;
    }
    slow_peers.remove(&peer_id);
    true
}

/// Duty subnets with fewer than `TARGET_SUBNET_PEERS` peers, in order.
fn subnets_needing_peers(duty_subnets: &HashMap<u64, u64>, peer_counts: &[usize]) -> Vec<u64> {
    let mut subnets: Vec<u64> = duty_subnets
        .keys()
        .copied()
        .filter(|subnet_id| {
            peer_counts
                .get(*subnet_id as usize)
                .is_some_and(|count| *count < TARGET_SUBNET_PEERS)
        })
        .collect();
    subnets.sort_unstable();
    subnets
}

/// Epoch at `now` for a chain that started at `genesis_time`, counted like the fork choice store.
/// Before genesis this is epoch 0, so the mesh for the first backbone subnets forms early.
fn epoch_at(genesis_time: u64, now: SystemTime) -> u64 {
    compute_epoch_at_slot(slot_at(genesis_time, now))
}

/// The slot at `now` for a chain that started at `genesis_time`, 0 before genesis.
fn slot_at(genesis_time: u64, now: SystemTime) -> u64 {
    let now = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    now.saturating_sub(genesis_time) / beacon_network_spec().seconds_per_slot()
}

/// Time from `now` until `epoch` starts on the clock of [`epoch_at`], so once it has elapsed
/// `epoch_at` returns at least `epoch`.
fn duration_to_epoch(genesis_time: u64, epoch: u64, now: SystemTime) -> Duration {
    let start_secs = compute_start_slot_at_epoch(epoch)
        .saturating_mul(beacon_network_spec().seconds_per_slot())
        .saturating_add(genesis_time);
    UNIX_EPOCH
        .checked_add(Duration::from_secs(start_secs))
        .and_then(|start| start.duration_since(now).ok())
        .unwrap_or_default()
}

fn status_is_plausible(status: &Status, current_epoch: u64) -> bool {
    // A checkpoint node may not have recovered its anchor columns yet.
    status.earliest_available_slot <= status.head_slot.saturating_add(1)
        && status.finalized_epoch <= current_epoch.saturating_add(1)
        && status.head_slot
            <= current_epoch
                .saturating_add(2)
                .saturating_mul(SLOTS_PER_EPOCH)
}

/// Peers a custody query may still ask for given `active_peers` connected or connecting peers. It
/// is `CUSTODY_DISCOVERY_TARGET_PEERS` at most, and zero once the active count is that many above
/// `target_peers`, so uncovered groups cannot grow the peer set without bound.
fn custody_discovery_target(active_peers: usize, target_peers: usize) -> usize {
    (target_peers + CUSTODY_DISCOVERY_TARGET_PEERS)
        .saturating_sub(active_peers)
        .min(CUSTODY_DISCOVERY_TARGET_PEERS)
}

/// The columns the local node samples each slot (fulu das-core.md, "Custody sampling"). Returns
/// no columns, which disables custody discovery, if the configured custody group count is not a
/// valid local assignment.
fn local_sampling_columns(local_enr: &Enr, config: &NetworkConfig) -> Vec<u64> {
    let custody_group_count = config.discv5_config.custody_group_count.0;
    match CustodyConfig::from_network_spec(&beacon_network_spec()).and_then(|custody_config| {
        CustodyAssignment::new(local_enr.node_id(), custody_group_count, &custody_config)
    }) {
        Ok(assignment) => assignment.sampling_columns,
        Err(err) => {
            warn!("Custody discovery disabled, invalid local custody configuration: {err:?}");
            Vec::new()
        }
    }
}

#[derive(NetworkBehaviour)]
pub(crate) struct ReamBehaviour {
    pub identify: identify::Behaviour,

    /// The discovery domain: discv5
    pub discovery: Discovery,

    /// The request-response domain
    pub req_resp: ReqResp,

    /// The gossip domain: gossipsub
    pub gossipsub: GossipsubBehaviour,

    pub connection_registry: connection_limits::Behaviour,
}

// TODO: these are stub events which needs to be replaced
#[derive(Debug)]
pub enum ReamNetworkEvent {
    PeerConnectedIncoming(PeerId),
    PeerConnectedOutgoing(PeerId),
    PeerDisconnected(PeerId),
    DisconnectPeer(PeerId),
    RequestMessage {
        peer_id: PeerId,
        stream_id: u64,
        connection_id: ConnectionId,
        message: BeaconRequestMessage,
    },
    GossipsubMessage {
        propagation_source: PeerId,
        message_id: MessageId,
        message: Message,
    },
}

pub struct Network {
    peer_id: PeerId,
    swarm: Swarm<ReamBehaviour>,
    subscribed_topics: Arc<Mutex<HashSet<GossipTopic>>>,
    callbacks: HashMapDelay<u64, mpsc::Sender<Result<P2PCallbackResponse, P2PCallbackError>>>,
    request_id: u64,
    network_state: Arc<NetworkState>,
    peers_to_ping: HashSetDelay<PeerId>,
    bootnodes: Vec<Enr>,
    /// Columns this node samples each slot. Custody discovery looks for peers covering them.
    sampling_columns: Vec<u64>,
    /// When the outstanding MetaData request to each peer was sent, so a peer gets at most one
    /// per `REQUEST_TIMEOUT`.
    meta_data_requests: HashMap<PeerId, Instant>,
    genesis_time: u64,
    /// Backbone subnet topics joined by `sync_attestation_subnets`, which only leaves these
    backbone_topics: HashMap<u64, GossipTopic>,
    /// Peers the node keeps; discovery runs while fewer are connected or connecting.
    target_peers: usize,
    /// Gossipsub peer scoring settings, `None` when scoring is off.
    peer_score_settings: Option<PeerScoreSettings>,
    /// Subnet topics joined for validator duties, with the last slot each is needed for.
    duty_topics: HashMap<GossipTopic, u64>,
    /// Attestation subnets validators publish to, with the last slot each is needed for.
    duty_subnets: HashMap<u64, u64>,
    /// Slow heartbeats per peer whose gossipsub send queue overflows, with the last one's time.
    slow_peers: HashMap<PeerId, (u32, Instant)>,
}

impl Network {
    /// Initializes the network by:
    /// - Loading or creating the local keypair in the data directory
    /// - Setting up the discovery, req_resp and gossipsub behaviours
    /// - Starting P2P listening and discovery
    /// - Connecting to the configured bootnodes
    /// - Subscribing to the configured gossipsub topics
    ///
    /// Note that this function starts P2P listening, but not handling network events yet.
    /// Event handling starts when `Network::start()` is called.
    pub async fn init(
        executor: ReamExecutor,
        config: &NetworkConfig,
        status: Status,
    ) -> anyhow::Result<Self> {
        let local_key = load_or_create_network_key(&config.data_dir)?;
        let discv5_config =
            discovery_config_for_topics(&config.discv5_config, &config.gossipsub_config.topics)?;

        let discovery = {
            let mut discovery = Discovery::with_persisted_enr(
                Keypair::from(local_key.clone()),
                &discv5_config,
                epoch_at(config.genesis_time, SystemTime::now()),
                config.data_dir.join(ENR_FILE_NAME),
            )
            .await?;
            discovery.discover_peers(QueryType::Peers, 16);
            discovery
        };

        let req_resp = ReqResp::new(Chain::Beacon);

        let peer_score_settings = config.active_validators.map(|active_validators| {
            PeerScoreSettings::new(
                config.gossipsub_config.config.mesh_n(),
                active_validators,
                slot_at(config.genesis_time, SystemTime::now()),
            )
        });

        let gossipsub = {
            let snappy_transform =
                SnappyTransform::new(config.gossipsub_config.config.max_transmit_size());
            let mut gossipsub = GossipsubBehaviour::new_with_transform(
                MessageAuthenticity::Anonymous,
                config.gossipsub_config.config.clone(),
                snappy_transform,
            )
            .map_err(|err| anyhow!("Failed to create gossipsub behaviour: {err:?}"))?;
            // Topics get their score parameters as they are subscribed to.
            if let Some(settings) = &peer_score_settings {
                gossipsub
                    .with_peer_score(settings.peer_score_params(&[]), peer_score_thresholds())
                    .map_err(|err| anyhow!("Invalid gossipsub peer score parameters: {err}"))?;
            }
            gossipsub
        };

        let connection_limits = connection_limits::Behaviour::new(
            PeerLimits::from_target_peers(config.target_peers).connection_limits(),
        );

        let identify = {
            let local_public_key = local_key.public();
            let identify_config = identify::Config::new(
                "eth2/1.0.0".into(),
                PublicKey::from(local_public_key.clone()),
            )
            .with_agent_version("0.0.1".to_string())
            .with_cache_size(0);

            identify::Behaviour::new(identify_config)
        };

        let local_enr = discovery.local_enr();
        let sampling_columns = local_sampling_columns(&local_enr, config);
        let behaviour = {
            ReamBehaviour {
                discovery,
                req_resp,
                gossipsub,
                identify,
                connection_registry: connection_limits,
            }
        };

        let transport = build_transport(Keypair::from(local_key.clone()))
            .map_err(|err| anyhow!("Failed to build transport: {err:?}"))?;

        let swarm = {
            let config = swarm::Config::with_executor(Executor(executor))
                .with_notify_handler_buffer_size(NonZeroUsize::new(7).expect("Not zero"))
                .with_per_connection_event_buffer_size(4)
                .with_dial_concurrency_factor(NonZeroU8::new(1).expect("Not zero"));

            let builder = SwarmBuilder::with_existing_identity(Keypair::from(local_key.clone()))
                .with_tokio()
                .with_other_transport(|_key| transport)
                .expect("initializing swarm");

            builder
                .with_behaviour(|_| behaviour)
                .expect("initializing swarm")
                .with_swarm_config(|_| config)
                .build()
        };

        let meta_data = read_meta_data_from_disk(config.data_dir.clone()).unwrap_or_else(|err| {
            error!("Failed to read meta data from disk: {err:?}");
            GetMetaDataV3::default()
        });
        let custody_group_count = config.discv5_config.custody_group_count.0;
        let (attnets, syncnets) = enr_subnet_bitfields(&local_enr)?;

        let network_state = Arc::new(NetworkState {
            local_enr: RwLock::new(local_enr),
            peer_table: RwLock::new(HashMap::new()),
            meta_data: RwLock::new(meta_data),
            status: RwLock::new(status),
            data_dir: config.data_dir.clone(),
        });
        network_state.update_meta_data(|meta_data| {
            meta_data.attnets = attnets;
            meta_data.syncnets = syncnets;
            meta_data.custody_group_count = custody_group_count;
        })?;

        let mut network = Network {
            peer_id: PeerId::from_public_key(&PublicKey::from(local_key.public().clone())),
            swarm,
            subscribed_topics: Arc::new(Mutex::new(HashSet::new())),
            callbacks: HashMapDelay::new(REQUEST_TIMEOUT),
            request_id: 0,
            network_state,
            peers_to_ping: HashSetDelay::new(PING_INTERVAL_DURATION),
            bootnodes: config.discv5_config.bootnodes.clone(),
            genesis_time: config.genesis_time,
            backbone_topics: HashMap::new(),
            target_peers: config.target_peers,
            duty_topics: HashMap::new(),
            duty_subnets: HashMap::new(),
            slow_peers: HashMap::new(),
            sampling_columns,
            meta_data_requests: HashMap::new(),
            peer_score_settings,
        };

        network.start_network_worker(config).await?;
        if let Err(err) = network.sync_attestation_subnets(SystemTime::now()) {
            warn!("Failed to sync attestation subnets, retrying on the next tick: {err:?}");
        }

        Ok(network)
    }

    async fn start_network_worker(&mut self, config: &NetworkConfig) -> anyhow::Result<()> {
        info!("Libp2p starting .... ");

        let mut multi_addr: Multiaddr = config.discv5_config.socket_address.into();
        multi_addr.push(Protocol::Tcp(config.discv5_config.socket_port));

        match self.swarm.listen_on(multi_addr.clone()) {
            Ok(listener_id) => {
                info!(
                    "Listening on {:?} with peer_id {:?} {listener_id:?}",
                    multi_addr, self.peer_id
                );
            }
            Err(err) => {
                error!("Failed to start libp2p peer listen on {multi_addr:?}, error: {err:?}",);
            }
        }

        let mut bootnodes = HashMap::new();
        for bootnode in config.discv5_config.bootnodes.clone() {
            bootnodes.insert(bootnode, None);
        }
        self.handle_discovered_peers(bootnodes);

        for topic in &config.gossipsub_config.topics {
            if self.subscribe_to_topic(*topic) {
                info!("Subscribed to topic: {topic}");
            } else {
                error!("Failed to subscribe to topic: {topic}");
            }
        }

        Ok(())
    }

    /// Returns the local node's peer id.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the local node's ENR.
    pub fn enr(&self) -> Enr {
        self.network_state.local_enr.read().clone()
    }

    fn request_id(&mut self) -> u64 {
        let request_id = self.request_id;
        self.request_id += 1;
        request_id
    }

    /// Returns the local node's network state such as peer table.
    pub fn network_state(&self) -> Arc<NetworkState> {
        self.network_state.clone()
    }

    /// Returns the cached peer from the peer table.
    pub fn cached_peer(&self, id: &PeerId) -> Option<CachedPeer> {
        self.network_state.peer_table.read().get(id).cloned()
    }

    /// Starts monitoring for network events. The network worker awaits for different types
    /// of network events:
    /// - A swarm event
    /// - A p2p message
    /// - A peer pinging
    /// - An interval tick to perform p2p maintenance e.g. peer pinging, peer clean up, peer
    ///   discovery, and attestation subnet subscription updates
    ///
    /// The network worker will then route each event to the appropriate handler. The handlers are
    /// defined in `NetworkManagerService`.
    pub async fn start(
        mut self,
        manager_sender: UnboundedSender<ReamNetworkEvent>,
        mut p2p_receiver: UnboundedReceiver<P2PMessage>,
    ) {
        let mut bootnode_redial_interval = interval(Duration::from_secs(20));
        let mut status_interval = interval(Duration::from_secs(30));
        let mut next_fork_update: Pin<Box<OptionFuture<_>>> =
            Box::pin(self.update_fork_enr(SystemTime::now()).map(sleep).into());
        loop {
            tokio::select! {
                Some(()) = &mut next_fork_update => {
                    next_fork_update.set(self.update_fork_enr(SystemTime::now()).map(sleep).into());
                }
                _ = bootnode_redial_interval.tick() => {
                    let bootnodes = self
                        .bootnodes
                        .iter()
                        .cloned()
                        .map(|bootnode| (bootnode, None))
                        .collect();
                    self.handle_discovered_peers(bootnodes);
                }
                Some(event) = self.swarm.next() => {
                    if let Some(event) = self.parse_swarm_event(event).await && let Err(err) = manager_sender.send(event) {
                        warn!("Failed to send event: {err:?}");
                    }
                }
                Some(event) = p2p_receiver.recv() => {
                    match event {
                        P2PMessage::Request(request) => match request {
                            P2PRequest::BlockRange { peer_id, start, count, callback } => {
                                if let Some(request_id) = self.send_request(peer_id, BeaconRequestMessage::BeaconBlocksByRange(BeaconBlocksByRangeV2Request::new(start, count))) {
                                    self.callbacks.insert(request_id, callback);
                                } else if let Err(err) = callback.send(Ok(P2PCallbackResponse::Disconnected)).await {
                                    warn!("Failed to send error response: {err:?}");
                                }
                            },
                            P2PRequest::BlockRoots { peer_id, roots, callback } => {
                                if let Some(request_id) = self.send_request(peer_id, BeaconRequestMessage::BeaconBlocksByRoot(BeaconBlocksByRootV2Request::new(roots))) {
                                    self.callbacks.insert(request_id, callback);
                                } else if let Err(err) = callback.send(Ok(P2PCallbackResponse::Disconnected)).await {
                                    warn!("Failed to send error response: {err:?}");
                                }
                            },
                            P2PRequest::BlobIdentifiers { peer_id, blob_identifiers, callback } => {
                                if let Some(request_id) = self.send_request(peer_id, BeaconRequestMessage::BlobSidecarsByRoot(BlobSidecarsByRootV1Request::new(blob_identifiers))) {
                                    self.callbacks.insert(request_id, callback);
                                } else if let Err(err) = callback.send(Ok(P2PCallbackResponse::Disconnected)).await {
                                    warn!("Failed to send error response: {err:?}");
                                }
                            },
                            P2PRequest::DataColumnRange { peer_id, start, count, columns, callback } => {
                                let request = DataColumnSidecarsByRangeV1Request {
                                    start_slot: start,
                                    count,
                                    columns: VariableList::new(columns)
                                        .expect("Too many columns were requested"),
                                };
                                if let Some(request_id) = self.send_request(peer_id, BeaconRequestMessage::DataColumnSidecarsByRange(request)) {
                                    self.callbacks.insert(request_id, callback);
                                } else if let Err(err) = callback.send(Ok(P2PCallbackResponse::Disconnected)).await {
                                    warn!("Failed to send error response: {err:?}");
                                }
                            },
                            P2PRequest::DataColumnIdentifiers { peer_id, column_identifiers, callback } => {
                                if let Some(request_id) = self.send_request(peer_id, BeaconRequestMessage::DataColumnSidecarsByRoot(DataColumnSidecarsByRootV1Request::new(column_identifiers))) {
                                    self.callbacks.insert(request_id, callback);
                                } else if let Err(err) = callback.send(Ok(P2PCallbackResponse::Disconnected)).await {
                                    warn!("Failed to send error response: {err:?}");
                                }
                            },
                            P2PRequest::Status { peer_id, status } => {
                                self.send_request(peer_id, BeaconRequestMessage::Status(status));
                            }
                        },
                        P2PMessage::Response(P2PResponse {peer_id, connection_id, stream_id, message}) => {
                            self.swarm.behaviour_mut().req_resp.send_response(peer_id, connection_id, stream_id, *message)
                        },
                        P2PMessage::RaiseCustody(custody) => self.raise_custody(custody),
                        P2PMessage::Gossip(message) => {
                            match self.swarm.behaviour_mut().gossipsub.publish(message.topic, message.data) {
                                Ok(_) => {}
                                // Gossipsub already holds this message, received from a peer.
                                // Cross-seeding a reconstructed column expects this.
                                Err(PublishError::Duplicate) => {
                                    debug!("Not publishing a gossip message gossipsub already has");
                                }
                                Err(err) => warn!("Failed to publish gossip message: {err}"),
                            }
                        }
                        P2PMessage::ReportGossipValidation { message_id, propagation_source, acceptance } => {
                            if !self
                                .swarm
                                .behaviour_mut()
                                .gossipsub
                                .report_message_validation_result(
                                    &message_id,
                                    &propagation_source,
                                    acceptance,
                                )
                            {
                                trace!("Gossipsub message was not in validation cache: {message_id}");
                            }
                        }
                        P2PMessage::SubscribeForDuty { topic, until_slot } => {
                            if !self.subscribe_for_duty(topic, until_slot) {
                                warn!("Failed to subscribe to {topic:?} for a validator duty");
                            }
                        }
                        P2PMessage::AttestationDutySubnets(subnets) => {
                            for (subnet_id, until_slot) in subnets {
                                let until = self.duty_subnets.entry(subnet_id).or_insert(until_slot);
                                *until = (*until).max(until_slot);
                            }
                            self.discover_duty_subnet_peers(SystemTime::now());
                        }
                    }
                }
                Some(Ok(peer_id)) = self.peers_to_ping.next() => {
                    if self.network_state.peer_table.read().get(&peer_id).is_none() {
                        warn!("Peer {peer_id} is not connected, skipping ping");
                        continue;
                    }

                    let ping_message = BeaconRequestMessage::Ping(Ping::new(self.network_state.meta_data.read().seq_number));

                    self.send_request(peer_id, ping_message);

                    self.peers_to_ping.insert(peer_id);
                }
                Some(Ok((_, callback))) = self.callbacks.next() => {
                    if let Err(err) = callback.send(Ok(P2PCallbackResponse::Timeout)).await {
                        warn!("Failed to send timeout response: {err:?}");
                    }
                }
                _ = status_interval.tick() => {
                    self.record_peer_scores();
                    let now = Instant::now();
                    let mut peer_table = self.network_state.peer_table.write();

                    // Clean up stale peers
                    peer_table.retain(|_, peer| now.duration_since(peer.last_seen) < Duration::from_secs(360));

                    // Compute peer state counts, status/meta counts in a single pass
                    let mut counts: HashMap<ConnectionState, usize> = HashMap::new();
                    let mut status_is_some_count = 0;
                    let mut meta_data_some_count = 0;

                    for peer in peer_table.values() {
                        *counts.entry(peer.state).or_insert(0) += 1;
                        if peer.status.is_some() {
                            status_is_some_count += 1;
                        }
                        if peer.meta_data().is_some() {
                            meta_data_some_count += 1;
                        }
                    }

                    let active_peer_count = counts
                        .get(&ConnectionState::Connected)
                        .copied()
                        .unwrap_or_default()
                        + counts
                            .get(&ConnectionState::Connecting)
                            .copied()
                            .unwrap_or_default();
                    let peers_to_ping_count = self.peers_to_ping.len();
                    let seq_number = self.network_state.meta_data.read().seq_number;

                    info!("Peer statuses: {counts:?}, Peers with Status {status_is_some_count}, Peers with MetaData {meta_data_some_count}, Peers to ping: {peers_to_ping_count}, MetaData seq_number: {seq_number}");
                    drop(peer_table);

                    if let Err(err) = self.sync_attestation_subnets(SystemTime::now()) {
                        warn!("Failed to sync attestation subnets: {err:?}");
                    }
                    self.expire_duty_topics(SystemTime::now());
                    self.discover_duty_subnet_peers(SystemTime::now());
                    // Retries a failed fork update and catches a boundary the timer slept past.
                    next_fork_update.set(self.update_fork_enr(SystemTime::now()).map(sleep).into());

                    if active_peer_count < self.target_peers {
                        info!("Active peer count is below target: {active_peer_count}, discovering more peers");
                        self.swarm
                            .behaviour_mut()
                            .discovery
                            .discover_peers(QueryType::Peers, 16);
                    }

                    self.meta_data_requests
                        .retain(|_, sent_at| sent_at.elapsed() < REQUEST_TIMEOUT);
                    self.request_missing_meta_data();
                    self.discover_custody_peers_if_uncovered();
                }
            }
        }
    }

    /// Advertises the fork of the epoch at `now` and returns the time until the next fork or BPO
    /// boundary, if one is scheduled.
    fn update_fork_enr(&mut self, now: SystemTime) -> Option<Duration> {
        let epoch = epoch_at(self.genesis_time, now);
        let discovery = &mut self.swarm.behaviour_mut().discovery;
        match discovery.update_fork_enr(epoch) {
            Ok(true) => *self.network_state.local_enr.write() = discovery.local_enr(),
            Ok(false) => {}
            Err(err) => warn!("Failed to update ENR fork entries: {err:?}"),
        }
        beacon_network_spec()
            .next_fork_epoch(epoch)
            .map(|next_fork_epoch| duration_to_epoch(self.genesis_time, next_fork_epoch, now))
    }

    fn send_request(&mut self, peer_id: PeerId, message: BeaconRequestMessage) -> Option<u64> {
        if !self.swarm.is_connected(&peer_id) {
            return None;
        }

        let request_id = self.request_id();
        self.swarm.behaviour_mut().req_resp.send_request(
            peer_id,
            request_id,
            RequestMessage::Beacon(message),
        );

        Some(request_id)
    }

    fn send_response(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        stream_id: u64,
        message: BeaconResponseMessage,
    ) {
        self.swarm.behaviour_mut().req_resp.send_response(
            peer_id,
            connection_id,
            stream_id,
            RespMessage::Response(Box::new(ResponseMessage::Beacon(message.into()))),
        );
    }

    async fn parse_swarm_event(
        &mut self,
        event: SwarmEvent<ReamBehaviourEvent>,
    ) -> Option<ReamNetworkEvent> {
        match event {
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer_id),
                ..
            } => {
                self.network_state.upsert_peer(
                    peer_id,
                    None,
                    ConnectionState::Disconnected,
                    Direction::Outbound,
                    None,
                );
                self.peers_to_ping.remove(&peer_id);
                None
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                if let ConnectedPoint::Listener { send_back_addr, .. } = &endpoint {
                    self.network_state.upsert_peer(
                        peer_id,
                        Some(send_back_addr.clone()),
                        ConnectionState::Connecting,
                        Direction::Inbound,
                        None,
                    );
                }
                // Both ends initiate Status. Some clients wait for our request before they
                // consider the connection ready, including when they dialed us.
                let status_message =
                    BeaconRequestMessage::Status(self.network_state.status.read().clone());
                self.send_request(peer_id, status_message);
                let ping_message = BeaconRequestMessage::Ping(Ping::new(
                    self.network_state.meta_data.read().seq_number,
                ));
                self.send_request(peer_id, ping_message);
                None
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } => {
                if num_established == 0 {
                    self.network_state.peer_disconnected(peer_id);
                    self.meta_data_requests.remove(&peer_id);
                    self.peers_to_ping.remove(&peer_id);
                    trace!("Peer {peer_id} connection closed. Removed from peers_to_ping.");
                    set_peer_count(self.network_state.connected_peers().len() as i64);
                    Some(ReamNetworkEvent::PeerDisconnected(peer_id))
                } else {
                    None
                }
            }
            SwarmEvent::Behaviour(behaviour_event) => match behaviour_event {
                ReamBehaviourEvent::Identify(_) => None,
                ReamBehaviourEvent::Discovery(discovery_event) => match discovery_event {
                    DiscoveryOutEvent::DiscoveredPeers { peers } => {
                        self.handle_discovered_peers(peers);
                        None
                    }
                    DiscoveryOutEvent::UpdatedEnr { enr } => {
                        *self.network_state.local_enr.write() = enr;
                        None
                    }
                },
                ReamBehaviourEvent::ReqResp(message) => {
                    self.handle_request_response_event(message).await
                }
                ReamBehaviourEvent::Gossipsub(event) => self.handle_gossipsub_event(event),
                ream_behavior_event => {
                    info!("Unhandled behaviour event: {ream_behavior_event:?}");
                    None
                }
            },
            swarm_event => {
                trace!("Unhandled swarm event: {swarm_event:?}");
                None
            }
        }
    }

    fn handle_discovered_peers(&mut self, peers: HashMap<Enr, Option<Instant>>) {
        trace!("Discovered peers: {peers:?}");
        for (enr, _) in peers {
            let Some(peer_id) = peer_id_from_enr(&enr) else {
                trace!("Skipping peer with no peer id in ENR: {enr:?}");
                continue;
            };
            if peer_id == self.peer_id {
                trace!("Skipping self peer: {peer_id:?}");
                continue;
            }

            let peer_state = self
                .network_state
                .peer_table
                .read()
                .get(&peer_id)
                .map(|peer| peer.state);
            if matches!(
                peer_state,
                Some(ConnectionState::Connected | ConnectionState::Connecting)
            ) {
                trace!("Peer {peer_id:?} is already {peer_state:?}, skipping dial");
                continue;
            }

            let mut multiaddrs: Vec<Multiaddr> = Vec::new();
            if let Some(ip) = enr.ip4()
                && let Some(tcp) = enr.tcp4()
            {
                let mut multiaddr: Multiaddr = ip.into();
                multiaddr.push(Protocol::Tcp(tcp));
                multiaddr.push(Protocol::P2p(peer_id));
                multiaddrs.push(multiaddr);
            }
            if let Some(ip6) = enr.ip6()
                && let Some(tcp6) = enr.tcp6()
            {
                let mut multiaddr: Multiaddr = ip6.into();
                multiaddr.push(Protocol::Tcp(tcp6));
                multiaddr.push(Protocol::P2p(peer_id));
                multiaddrs.push(multiaddr);
            }

            let mut dialed_address = None;
            for multiaddr in multiaddrs {
                let address = multiaddr.clone();
                if let Err(err) = self.swarm.dial(multiaddr) {
                    warn!("Failed to dial peer: {err:?}");
                } else {
                    dialed_address.get_or_insert(address);
                }
            }

            let Some(address) = dialed_address else {
                trace!("Failed to dial any multiaddr for peer: {:?}", enr);
                continue;
            };

            self.network_state.upsert_peer(
                peer_id,
                Some(address),
                ConnectionState::Connecting,
                Direction::Outbound,
                Some(enr.clone()),
            );
        }
    }

    async fn handle_request_response_event(
        &mut self,
        message: ReqRespMessage,
    ) -> Option<ReamNetworkEvent> {
        let ReqRespMessage {
            peer_id,
            connection_id,
            message,
        } = message;

        // update last seen time for the peer
        self.network_state
            .peer_table
            .write()
            .entry(peer_id)
            .and_modify(|cached_peer| {
                cached_peer.update_last_seen();
            });

        let message = match message {
            Ok(message) => message,
            Err(err) => {
                if let ReqRespMessageError::Outbound { request_id, err } = err
                    && let Some(callback) = self.callbacks.remove(&request_id)
                    && let Err(err) = callback.send(Err(P2PCallbackError::ReqResp(err))).await
                {
                    warn!("Failed to send error response: {err:?}");
                }
                return None;
            }
        };

        match message {
            ReqRespMessageReceived::Request { stream_id, message } => {
                if let RequestMessage::Beacon(message) = *message {
                    match message {
                        BeaconRequestMessage::MetaData(get_meta_data) => {
                            trace!(
                                ?peer_id,
                                ?stream_id,
                                ?connection_id,
                                ?get_meta_data,
                                "Received GetMetaData request"
                            );
                            let response = BeaconResponseMessage::MetaData(
                                self.network_state.meta_data.read().clone().into(),
                            );
                            self.send_response(peer_id, connection_id, stream_id, response);
                            None
                        }
                        BeaconRequestMessage::Ping(ping) => {
                            trace!(
                                ?peer_id,
                                ?stream_id,
                                ?connection_id,
                                ?ping,
                                "Received Ping request"
                            );
                            let response = BeaconResponseMessage::Ping(Ping::new(
                                self.network_state.meta_data.read().seq_number,
                            ));
                            self.send_response(peer_id, connection_id, stream_id, response);
                            self.request_meta_data_if_outdated(peer_id, Some(ping.sequence_number));
                            None
                        }
                        BeaconRequestMessage::Goodbye(goodbye) => {
                            trace!(
                                ?peer_id,
                                ?stream_id,
                                ?connection_id,
                                ?goodbye,
                                "Received Goodbye message"
                            );
                            None
                        }
                        BeaconRequestMessage::Status(status) => {
                            trace!(
                                ?peer_id,
                                ?stream_id,
                                ?connection_id,
                                ?status,
                                "Received Status request"
                            );

                            self.handle_status_req_resp_event(peer_id, status.clone());

                            Some(ReamNetworkEvent::RequestMessage {
                                peer_id,
                                stream_id,
                                connection_id,
                                message: BeaconRequestMessage::Status(status),
                            })
                        }
                        _ => Some(ReamNetworkEvent::RequestMessage {
                            peer_id,
                            stream_id,
                            connection_id,
                            message,
                        }),
                    }
                } else {
                    warn!(
                        "Received unexpected Lean request message: {:?} from peer: {:?}",
                        message, peer_id
                    );
                    None
                }
            }
            ReqRespMessageReceived::Response {
                request_id,
                message,
            } => {
                if let ResponseMessage::Beacon(beacon_response_message) = *message {
                    match beacon_response_message.as_ref() {
                        BeaconResponseMessage::MetaData(meta_data) => {
                            trace!(
                                ?peer_id,
                                ?request_id,
                                "Received MetaData response: seq_number: {}",
                                meta_data.seq_number
                            );

                            self.meta_data_requests.remove(&peer_id);
                            if !self
                                .network_state
                                .update_peer_meta_data(peer_id, meta_data.as_ref().clone())
                            {
                                trace!(
                                    ?peer_id,
                                    "Ignored MetaData from an unknown or disconnected peer, or with a stale seq_number"
                                );
                            }
                        }
                        BeaconResponseMessage::Ping(ping) => {
                            trace!(
                                ?peer_id,
                                ?request_id,
                                "Received Ping response: seq_number: {}",
                                ping.sequence_number
                            );

                            self.request_meta_data_if_outdated(peer_id, Some(ping.sequence_number));
                        }
                        BeaconResponseMessage::Status(status) => {
                            trace!(
                                ?peer_id,
                                ?request_id,
                                "Received Status response: fork_digest: {}, head_slot: {}",
                                status.fork_digest,
                                status.head_slot
                            );

                            self.handle_status_req_resp_event(peer_id, status.clone());
                        }
                        _ => {}
                    }

                    self.callbacks.update_timeout(&request_id, REQUEST_TIMEOUT);
                    if let Some(callback) = self.callbacks.get(&request_id)
                        && let Err(err) = callback
                            .send(Ok(P2PCallbackResponse::ResponseMessage(
                                beacon_response_message,
                            )))
                            .await
                    {
                        // The consumer cancelled or hit its receive budget. Release the RPC
                        // stream instead of decoding the rest of a now unwanted response.
                        self.callbacks.remove(&request_id);
                        self.swarm.behaviour_mut().req_resp.cancel_request(
                            peer_id,
                            connection_id,
                            request_id,
                        );
                        trace!("Response consumer dropped: {err:?}");
                    }
                } else {
                    warn!(
                        "Received unexpected Lean response message: {:?} from peer: {:?}",
                        message, peer_id
                    );
                }

                None
            }
            ReqRespMessageReceived::EndOfStream { request_id } => {
                let callback = self.callbacks.remove(&request_id);
                if let Some(callback) = callback
                    && let Err(err) = callback.send(Ok(P2PCallbackResponse::EndOfStream)).await
                {
                    warn!("Failed to send end of stream: {err:?}");
                }
                None
            }
        }
    }

    fn handle_status_req_resp_event(&mut self, peer_id: PeerId, status: Status) {
        if self.network_state.peer_table.read().get(&peer_id).is_some() {
            // We only want to have peers on the same network as us
            let current_epoch = beacon_network_spec().current_epoch();
            let fork_digest =
                beacon_network_spec().fork_digest(current_epoch, genesis_validators_root());
            if status.fork_digest != fork_digest {
                warn!(
                    "Peer {peer_id} is not on the same network as us, removing from peer table, fork_digest: {}, our fork_digest: {fork_digest}",
                    status.fork_digest,
                );
                self.network_state.peer_table.write().remove(&peer_id);
            } else if !status_is_plausible(&status, current_epoch) {
                warn!(
                    "Peer {peer_id} sent an impossible Status (finalized_epoch={}, head_slot={}, earliest_available_slot={}), removing from peer table",
                    status.finalized_epoch, status.head_slot, status.earliest_available_slot
                );
                self.network_state.peer_table.write().remove(&peer_id);
            } else {
                self.network_state
                    .peer_table
                    .write()
                    .entry(peer_id)
                    .and_modify(|cached_peer| {
                        cached_peer.state = ConnectionState::Connected;
                        cached_peer.status = Some(status);
                    });
                self.peers_to_ping.insert(peer_id);
                // Ask for MetaData now so custody is known right after the handshake. An inbound
                // peer would otherwise wait for our first Ping, one ping interval later.
                self.request_meta_data_if_outdated(peer_id, None);
            }
            // A transport connection is only counted after a compatible Status exchange.
            set_peer_count(self.network_state.connected_peers().len() as i64);
        }
    }

    /// Requests the peer's MetaData when none is cached for this connection or `seq_number` from
    /// a Ping differs from the cached one (phase0 p2p-interface, "Ping v1"). Only peers that
    /// passed the Status check are asked.
    fn request_meta_data_if_outdated(&mut self, peer_id: PeerId, seq_number: Option<u64>) {
        let cached_seq_number = {
            let peer_table = self.network_state.peer_table.read();
            let Some(cached_peer) = peer_table
                .get(&peer_id)
                .filter(|cached_peer| cached_peer.state == ConnectionState::Connected)
            else {
                return;
            };
            cached_peer
                .meta_data()
                .map(|meta_data| meta_data.seq_number)
        };
        let outdated = match (cached_seq_number, seq_number) {
            (None, _) => true,
            (Some(cached), Some(advertised)) => cached != advertised,
            (Some(_), None) => false,
        };
        if !outdated
            || self
                .meta_data_requests
                .get(&peer_id)
                .is_some_and(|sent_at| sent_at.elapsed() < REQUEST_TIMEOUT)
        {
            return;
        }

        let meta_data_message =
            BeaconRequestMessage::MetaData(self.network_state.meta_data.read().clone().into());
        if self.send_request(peer_id, meta_data_message).is_some() {
            self.meta_data_requests.insert(peer_id, Instant::now());
        }
    }

    /// Re-requests MetaData from connected peers that have none cached. A peer is only asked
    /// again on a Ping response otherwise, one `PING_INTERVAL_DURATION` later, so a timed-out or
    /// failed request would leave its custody unknown, which counts as custodying nothing.
    /// `request_meta_data_if_outdated` still allows one request per peer per `REQUEST_TIMEOUT`.
    fn request_missing_meta_data(&mut self) {
        let peers_without_meta_data: Vec<PeerId> = self
            .network_state
            .peer_table
            .read()
            .iter()
            .filter(|(_, cached_peer)| {
                cached_peer.state == ConnectionState::Connected && cached_peer.meta_data().is_none()
            })
            .map(|(peer_id, _)| *peer_id)
            .collect();
        for peer_id in peers_without_meta_data {
            self.request_meta_data_if_outdated(peer_id, None);
        }
    }

    /// Starts a bounded discv5 query for peers custodying the groups of sampling columns that no
    /// connected peer covers. Runs from the periodic maintenance tick, and `Discovery` keeps at
    /// most one custody query in flight.
    /// Starts a discovery query for duty subnets with fewer than `TARGET_SUBNET_PEERS` peers,
    /// after dropping subnets whose last slot has passed.
    fn discover_duty_subnet_peers(&mut self, now: SystemTime) {
        let current_slot = slot_at(self.genesis_time, now);
        self.duty_subnets
            .retain(|_, until_slot| *until_slot >= current_slot);
        if self.duty_subnets.is_empty() {
            return;
        }
        let peer_counts = self.attestation_subnet_peer_counts();
        let subnets = subnets_needing_peers(&self.duty_subnets, &peer_counts);
        if subnets.is_empty() {
            return;
        }
        let counts: Vec<usize> = subnets
            .iter()
            .map(|subnet_id| peer_counts[*subnet_id as usize])
            .collect();
        if self
            .swarm
            .behaviour_mut()
            .discovery
            .discover_attestation_subnet_peers(subnets.clone(), SUBNET_DISCOVERY_TARGET_PEERS)
        {
            info!(
                "Duty attestation subnets {subnets:?} have {counts:?} peers, discovering peers for them"
            );
        }
    }

    /// Connected peers subscribed to each attestation subnet of the current fork.
    fn attestation_subnet_peer_counts(&self) -> [usize; ATTESTATION_SUBNET_COUNT] {
        let fork = beacon_network_spec().fork_digest(
            beacon_network_spec().current_epoch(),
            genesis_validators_root(),
        );
        let subnet_of: HashMap<TopicHash, usize> = (0..ATTESTATION_SUBNET_COUNT)
            .map(|subnet_id| {
                let topic = GossipTopic {
                    fork,
                    kind: GossipTopicKind::BeaconAttestation(subnet_id as u64),
                };
                (topic.into(), subnet_id)
            })
            .collect();
        let mut counts = [0; ATTESTATION_SUBNET_COUNT];
        for (_, topics) in self.swarm.behaviour().gossipsub.all_peers() {
            for topic in topics {
                if let Some(subnet_id) = subnet_of.get(topic) {
                    counts[*subnet_id] += 1;
                }
            }
        }
        counts
    }

    fn discover_custody_peers_if_uncovered(&mut self) {
        if self.sampling_columns.is_empty()
            || self.swarm.behaviour().discovery.custody_query_active()
        {
            return;
        }
        let active_peers = self
            .network_state
            .peer_table
            .read()
            .values()
            .filter(|peer| {
                matches!(
                    peer.state,
                    ConnectionState::Connected | ConnectionState::Connecting
                )
            })
            .count();
        let target_peers = custody_discovery_target(active_peers, self.target_peers);
        if target_peers == 0 {
            return;
        }
        let uncovered_groups = self
            .network_state
            .column_coverage(&self.sampling_columns)
            .uncovered_custody_groups();
        if uncovered_groups.is_empty() {
            return;
        }

        let fork_digest = beacon_network_spec().fork_digest(
            beacon_network_spec().current_epoch(),
            genesis_validators_root(),
        );
        info!(
            "No connected peer custodies {} sampling custody groups, discovering peers for them",
            uncovered_groups.len()
        );
        let predicate = custody_group_enr_predicate(fork_digest, uncovered_groups.clone());
        self.swarm.behaviour_mut().discovery.discover_custody_peers(
            uncovered_groups,
            Box::new(predicate),
            target_peers,
        );
    }

    fn handle_gossipsub_event(&mut self, event: GossipsubEvent) -> Option<ReamNetworkEvent> {
        match event {
            GossipsubEvent::Message {
                propagation_source,
                message_id,
                message,
            } => Some(ReamNetworkEvent::GossipsubMessage {
                propagation_source,
                message_id,
                message,
            }),
            GossipsubEvent::Subscribed { peer_id, topic } => {
                trace!("Peer {peer_id} subscribed to topic: {topic:?}");
                None
            }
            GossipsubEvent::Unsubscribed { peer_id, topic } => {
                trace!("Peer {peer_id} unsubscribed from topic: {topic:?}");
                None
            }
            GossipsubEvent::SlowPeer {
                peer_id,
                failed_messages,
            } => {
                if record_slow_heartbeat(
                    &mut self.slow_peers,
                    peer_id,
                    failed_messages.total_queue_full(),
                    Instant::now(),
                ) {
                    info!("Disconnecting peer {peer_id}: its gossipsub send queue stays full");
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                }
                None
            }
            _ => None,
        }
    }

    /// Advertises `custody` in the ENR `cgc` and the MetaData, subscribes to its sampled column
    /// subnets and looks for peers covering its sampled columns (fulu validator.md, "Validator
    /// custody"). The ENR and the MetaData change together, since peers treat a mismatch between
    /// them as a fault.
    fn raise_custody(&mut self, custody: CustodyAssignment) {
        let advertised = self.network_state.meta_data.read().custody_group_count;
        if custody.custody_group_count <= advertised {
            return;
        }
        let discovery = &mut self.swarm.behaviour_mut().discovery;
        match discovery.set_custody_group_count(CustodyGroupCount(custody.custody_group_count)) {
            Ok(_) => *self.network_state.local_enr.write() = discovery.local_enr(),
            Err(err) => {
                warn!("Failed to advertise custody group count in ENR: {err:?}");
                return;
            }
        }
        if let Err(err) = self.network_state.update_meta_data(|meta_data| {
            meta_data.custody_group_count = custody.custody_group_count;
        }) {
            warn!("Failed to advertise custody group count in MetaData: {err:?}");
        }

        let fork = beacon_network_spec().fork_digest(
            epoch_at(self.genesis_time, SystemTime::now()),
            genesis_validators_root(),
        );
        for subnet_id in &custody.data_column_subnet_ids {
            self.subscribe_to_topic(GossipTopic {
                fork,
                kind: GossipTopicKind::DataColumnSidecar(*subnet_id),
            });
        }
        self.sampling_columns = custody.sampling_columns;
        info!(
            custody_group_count = custody.custody_group_count,
            sampling_columns = self.sampling_columns.len(),
            "Raised data column custody"
        );
    }

    /// Records how connected peers stand against the gossipsub score thresholds. Gossipsub also
    /// keeps the scores of disconnected peers for a while; those are left out.
    fn record_peer_scores(&self) {
        if self.peer_score_settings.is_none() {
            return;
        }
        let gossipsub = &self.swarm.behaviour().gossipsub;
        let mut bands: HashMap<&'static str, i64> = [
            "graylisted",
            "below_publish",
            "below_gossip",
            "negative",
            "non_negative",
        ]
        .into_iter()
        .map(|band| (band, 0))
        .collect();
        let mut lowest = f64::INFINITY;
        for peer_id in gossipsub
            .all_peers()
            .map(|(peer_id, _)| *peer_id)
            .collect::<Vec<_>>()
        {
            if !self.swarm.is_connected(&peer_id) {
                continue;
            }
            let Some(score) = gossipsub.peer_score(&peer_id) else {
                continue;
            };
            lowest = lowest.min(score);
            let band = if score < GRAYLIST_THRESHOLD {
                "graylisted"
            } else if score < PUBLISH_THRESHOLD {
                "below_publish"
            } else if score < GOSSIP_THRESHOLD {
                "below_gossip"
            } else if score < 0.0 {
                "negative"
            } else {
                "non_negative"
            };
            *bands.entry(band).or_default() += 1;
        }
        for (band, peers) in &bands {
            BEACON_GOSSIPSUB_PEERS_BY_SCORE
                .with_label_values(&[band])
                .set(*peers);
        }
        if lowest.is_finite() {
            BEACON_GOSSIPSUB_LOWEST_PEER_SCORE.set(lowest.round() as i64);
        }
        debug!(?bands, lowest, "Gossipsub peer scores");
    }

    /// Returns true if the node is subscribed afterwards, including when it already was.
    pub fn subscribe_to_topic(&mut self, topic: GossipTopic) -> bool {
        match self
            .swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic.into())
        {
            Ok(_) => {
                self.subscribed_topics.lock().insert(topic);
                if let Some(params) = self
                    .peer_score_settings
                    .and_then(|settings| settings.topic_score_params(&topic.kind))
                    && let Err(err) = self
                        .swarm
                        .behaviour_mut()
                        .gossipsub
                        .set_topic_params(Topic::from(topic), params)
                {
                    warn!("Could not set the score parameters of {topic}: {err}");
                }
                true
            }
            Err(err) => {
                warn!("Gossipsub rejected subscription to {topic}: {err:?}");
                false
            }
        }
    }

    /// Joins `topic` for a validator duty and stays subscribed until `until_slot` has passed.
    pub fn subscribe_for_duty(&mut self, topic: GossipTopic, until_slot: u64) -> bool {
        if !self.subscribe_to_topic(topic) {
            return false;
        }
        let until = self.duty_topics.entry(topic).or_insert(until_slot);
        *until = (*until).max(until_slot);
        if matches!(topic.kind, GossipTopicKind::SyncCommittee(_))
            && let Err(err) = self.advertise_sync_committee_subnets()
        {
            warn!("Failed to advertise sync committee subnets: {err:?}");
        }
        true
    }

    /// Advertises the joined sync committee subnets in the ENR and `MetaData`.
    fn advertise_sync_committee_subnets(&mut self) -> anyhow::Result<()> {
        let mut subnets = SyncCommitteeSubnets::new();
        for topic in self.subscribed_topics.lock().iter() {
            if let GossipTopicKind::SyncCommittee(subnet_id) = topic.kind {
                subnets.enable_sync_committee_subnet(subnet_id)?;
            }
        }
        let discovery = &mut self.swarm.behaviour_mut().discovery;
        discovery.set_sync_committee_subnets(subnets)?;
        let local_enr = discovery.local_enr();
        let (attnets, syncnets) = enr_subnet_bitfields(&local_enr)?;
        *self.network_state.local_enr.write() = local_enr;
        self.network_state.update_meta_data(|meta_data| {
            meta_data.attnets = attnets;
            meta_data.syncnets = syncnets;
        })?;
        Ok(())
    }

    /// Leaves duty topics whose last slot has passed, unless they are backbone subnets.
    fn expire_duty_topics(&mut self, now: SystemTime) {
        let current_slot = slot_at(self.genesis_time, now);
        let expired: Vec<GossipTopic> = self
            .duty_topics
            .iter()
            .filter(|(_, until_slot)| **until_slot < current_slot)
            .map(|(topic, _)| *topic)
            .collect();
        let mut left_sync_subnet = false;
        for topic in expired {
            self.duty_topics.remove(&topic);
            if !self
                .backbone_topics
                .values()
                .any(|backbone| *backbone == topic)
            {
                self.unsubscribe_from_topic(topic);
                left_sync_subnet |= matches!(topic.kind, GossipTopicKind::SyncCommittee(_));
            }
        }
        if left_sync_subnet && let Err(err) = self.advertise_sync_committee_subnets() {
            warn!("Failed to advertise sync committee subnets: {err:?}");
        }
    }

    pub fn unsubscribe_from_topic(&mut self, topic: GossipTopic) -> bool {
        self.subscribed_topics.lock().remove(&topic);

        let topic: Topic = topic.into();

        self.swarm.behaviour_mut().gossipsub.unsubscribe(&topic)
    }

    /// Advertises the subnets assigned for the epoch at `now`. Order: join new subnets, advertise
    /// only joined ones in the ENR and `MetaData`, then leave dropped backbone subnets. Every
    /// step compares against the target state, so a failed step is retried on the next call.
    ///
    /// The ENR is served before it is saved, so a crash in between can reuse its seq on restart.
    fn sync_attestation_subnets(&mut self, now: SystemTime) -> anyhow::Result<()> {
        let epoch = epoch_at(self.genesis_time, now);
        let desired = self
            .swarm
            .behaviour()
            .discovery
            .attestation_subnets_at(epoch)?;
        let fork_digest = beacon_network_spec().fork_digest(
            beacon_network_spec().current_epoch(),
            genesis_validators_root(),
        );

        let mut joined = AttestationSubnets::new();
        for topic in self.subscribed_topics.lock().iter() {
            if let GossipTopicKind::BeaconAttestation(subnet_id) = topic.kind {
                joined.enable_attestation_subnet(subnet_id)?;
            }
        }
        let mut failed = vec![];
        for subnet_id in 0..ATTESTATION_SUBNET_COUNT as u64 {
            if !desired.is_attestation_subnet_enabled(subnet_id)? {
                continue;
            }
            let topic = GossipTopic {
                fork: fork_digest,
                kind: GossipTopicKind::BeaconAttestation(subnet_id),
            };
            if joined.is_attestation_subnet_enabled(subnet_id)? {
                // Joined for a duty, it must outlive that duty.
                if self.subscribed_topics.lock().contains(&topic) {
                    self.backbone_topics.insert(subnet_id, topic);
                }
                continue;
            }
            if self.subscribe_to_topic(topic) {
                joined.enable_attestation_subnet(subnet_id)?;
                self.backbone_topics.insert(subnet_id, topic);
            } else {
                failed.push(subnet_id);
            }
        }

        let advertised = AttestationSubnets(desired.0.intersection(&joined.0));
        let discovery = &mut self.swarm.behaviour_mut().discovery;
        discovery.set_attestation_subnets(advertised)?;
        let local_enr = discovery.local_enr();
        let (attnets, syncnets) = enr_subnet_bitfields(&local_enr)?;
        *self.network_state.local_enr.write() = local_enr;
        self.network_state.update_meta_data(|meta_data| {
            meta_data.attnets = attnets;
            meta_data.syncnets = syncnets;
        })?;

        let dropped: Vec<u64> = self
            .backbone_topics
            .keys()
            .copied()
            .filter(|subnet_id| !desired.0.get(*subnet_id as usize).unwrap_or(false))
            .collect();
        for subnet_id in dropped {
            if let Some(topic) = self.backbone_topics.remove(&subnet_id)
                && !self.duty_topics.contains_key(&topic)
            {
                self.unsubscribe_from_topic(topic);
            }
        }

        ensure!(
            failed.is_empty(),
            "Failed to join attestation subnets {failed:?}"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, net::IpAddr, path::Path};

    use alloy_primitives::aliases::B32;
    use discv5::enr::CombinedKey;
    use k256::ecdsa::SigningKey;
    use libp2p_identity::{Keypair, PeerId};
    use ream_consensus_misc::constants::beacon::NUM_CUSTODY_GROUPS;
    use ream_discv5::{
        config::DiscoveryConfig,
        eth2::{ENR_ETH2_KEY, EnrForkId},
        persisted_enr::load_enr,
        subnet::{
            AttestationSubnets, CustodyGroupCount, EPOCHS_PER_SUBNET_SUBSCRIPTION,
            NEXT_FORK_DIGEST_ENR_KEY, NextForkDigest, SyncCommitteeSubnets,
        },
    };
    use ream_executor::ReamExecutor;
    use ream_network_spec::networks::beacon::initialize_test_network_spec;
    use ssz::Encode;
    use tokio::{runtime::Runtime, time::sleep};

    use super::*;
    use crate::{
        config::NetworkConfig,
        constants::DEFAULT_TARGET_PEERS,
        gossipsub::beacon::{configurations::GossipsubConfig, topics::GossipTopicKind},
        network::beacon::identity::{NETWORK_KEY_FILE_NAME, test_utils::TestDataDir},
    };

    #[test]
    fn status_sanity_rejects_impossible_history_and_future_progress() {
        let current_epoch = 100;
        assert!(status_is_plausible(
            &Status {
                finalized_epoch: 98,
                head_slot: 100 * SLOTS_PER_EPOCH,
                earliest_available_slot: 90 * SLOTS_PER_EPOCH,
                ..Default::default()
            },
            current_epoch
        ));
        assert!(status_is_plausible(
            &Status {
                head_slot: 10,
                earliest_available_slot: 11,
                ..Default::default()
            },
            current_epoch
        ));
        assert!(!status_is_plausible(
            &Status {
                head_slot: 10,
                earliest_available_slot: 12,
                ..Default::default()
            },
            current_epoch
        ));
        assert!(!status_is_plausible(
            &Status {
                finalized_epoch: current_epoch + 2,
                ..Default::default()
            },
            current_epoch
        ));
        assert!(!status_is_plausible(
            &Status {
                head_slot: (current_epoch + 3) * SLOTS_PER_EPOCH,
                ..Default::default()
            },
            current_epoch
        ));
    }

    async fn create_network(
        socket_address: IpAddr,
        socket_port: u16,
        discovery_port: u16,
        bootnodes: Vec<Enr>,
        disable_discovery: bool,
        topics: Vec<GossipTopic>,
        data_dir: &Path,
    ) -> anyhow::Result<Network> {
        create_network_with_custody(
            socket_address,
            socket_port,
            discovery_port,
            bootnodes,
            disable_discovery,
            topics,
            data_dir,
            NUM_CUSTODY_GROUPS,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_network_with_custody(
        socket_address: IpAddr,
        socket_port: u16,
        discovery_port: u16,
        bootnodes: Vec<Enr>,
        disable_discovery: bool,
        topics: Vec<GossipTopic>,
        data_dir: &Path,
        custody_group_count: u64,
    ) -> anyhow::Result<Network> {
        build_network(
            socket_address,
            socket_port,
            discovery_port,
            bootnodes,
            disable_discovery,
            topics,
            data_dir,
            DEFAULT_TARGET_PEERS,
            custody_group_count,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_network_with_target_peers(
        socket_address: IpAddr,
        socket_port: u16,
        discovery_port: u16,
        bootnodes: Vec<Enr>,
        disable_discovery: bool,
        topics: Vec<GossipTopic>,
        data_dir: &Path,
        target_peers: usize,
    ) -> anyhow::Result<Network> {
        build_network(
            socket_address,
            socket_port,
            discovery_port,
            bootnodes,
            disable_discovery,
            topics,
            data_dir,
            target_peers,
            NUM_CUSTODY_GROUPS,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_network(
        socket_address: IpAddr,
        socket_port: u16,
        discovery_port: u16,
        bootnodes: Vec<Enr>,
        disable_discovery: bool,
        topics: Vec<GossipTopic>,
        data_dir: &Path,
        target_peers: usize,
        custody_group_count: u64,
    ) -> anyhow::Result<Network> {
        let executor = ReamExecutor::new().unwrap();

        let discv5_config = discv5::ConfigBuilder::new(discv5::ListenConfig::from_ip(
            socket_address,
            discovery_port,
        ))
        .build();

        let config = NetworkConfig {
            discv5_config: DiscoveryConfig {
                discv5_config,
                bootnodes,
                socket_address,
                socket_port,
                discovery_port,
                disable_discovery,
                attestation_subnets: AttestationSubnets::new(),
                sync_committee_subnets: SyncCommitteeSubnets::new(),
                custody_group_count: CustodyGroupCount(custody_group_count),
            },
            gossipsub_config: GossipsubConfig {
                topics,
                ..Default::default()
            },
            data_dir: data_dir.to_path_buf(),
            genesis_time: beacon_network_spec().min_genesis_time,
            target_peers,
            // Scoring runs in the network tests as it does on a live node.
            active_validators: Some(64),
        };

        std::fs::create_dir_all(&config.data_dir)?;

        Network::init(
            executor,
            &config,
            Status {
                fork_digest: beacon_network_spec().fork_digest(
                    beacon_network_spec().current_epoch(),
                    genesis_validators_root(),
                ),
                ..Default::default()
            },
        )
        .await
    }

    #[test]
    fn dropped_response_consumer_cancels_only_its_rpc_stream() {
        initialize_test_network_spec();
        let runtime = Runtime::new().unwrap();
        let data_dir = TestDataDir::new();
        let mut network = runtime
            .block_on(create_network(
                "127.0.0.1".parse().unwrap(),
                0,
                0,
                vec![],
                true,
                vec![],
                data_dir.path(),
            ))
            .unwrap();
        let peer_id = PeerId::random();
        let connection_id = libp2p::swarm::ConnectionId::new_unchecked(42);
        let (callback, receiver) = mpsc::channel(1);
        drop(receiver);
        runtime.block_on(async {
            network.callbacks.insert(17, callback);
            network
                .handle_request_response_event(ReqRespMessage {
                    peer_id,
                    connection_id,
                    message: Ok(ReqRespMessageReceived::Response {
                        request_id: 17,
                        message: Box::new(ResponseMessage::Beacon(Arc::new(
                            BeaconResponseMessage::BeaconBlocksByRange(
                                ream_consensus_beacon::electra::beacon_block::SignedBeaconBlock {
                                    message: Default::default(),
                                    signature: Default::default(),
                                },
                            ),
                        ))),
                    }),
                })
                .await;
        });
        assert!(network.callbacks.get(&17).is_none());
        assert!(
            network
                .swarm
                .behaviour()
                .req_resp
                .events
                .iter()
                .any(|event| {
                    matches!(event, libp2p::swarm::ToSwarm::NotifyHandler {
                peer_id: peer,
                handler: libp2p::swarm::NotifyHandler::One(connection),
                event: ream_req_resp::ConnectionRequest::CancelRequest { request_id: 17 },
            } if *peer == peer_id && *connection == connection_id)
                })
        );
    }

    #[test]
    fn peer_id_derived_from_enr_matches_libp2p() {
        let libp2p_keypair = Keypair::generate_secp256k1();
        let secret = libp2p_keypair
            .clone()
            .try_into_secp256k1()
            .unwrap()
            .secret()
            .to_bytes();
        let signing = SigningKey::from_slice(&secret).unwrap();

        let enr_key = CombinedKey::Secp256k1(signing);
        let enr = Enr::builder().build(&enr_key).unwrap();

        let expected = PeerId::from_public_key(&libp2p_keypair.public());
        let actual = peer_id_from_enr(&enr).expect("peer id");

        assert_eq!(expected, actual);
    }

    #[test]
    fn insert_then_read_returns_snapshot() {
        initialize_test_network_spec();

        let tokio_runtime = Runtime::new().unwrap();

        let data_dir = TestDataDir::new();
        let network = tokio_runtime.block_on(async {
            create_network(
                "127.0.0.1".parse().unwrap(),
                0,
                0,
                vec![],
                true,
                vec![],
                data_dir.path(),
            )
            .await
            .unwrap()
        });

        let peer_id = PeerId::random();
        let address: Multiaddr = "/ip4/1.2.3.4/tcp/9000".parse().unwrap();

        network.network_state.upsert_peer(
            peer_id,
            Some(address.clone()),
            ConnectionState::Connecting,
            Direction::Outbound,
            None,
        );

        let cached_peer_snapshot = network.cached_peer(&peer_id).expect("peer should exist");

        assert_eq!(cached_peer_snapshot.peer_id, peer_id);
        assert_eq!(cached_peer_snapshot.state, ConnectionState::Connecting);
        assert_eq!(cached_peer_snapshot.direction, Direction::Outbound);
        assert_eq!(cached_peer_snapshot.last_seen_p2p_address, Some(address));
        assert!(cached_peer_snapshot.enr().is_none());
    }

    #[test]
    fn update_existing_peer() {
        initialize_test_network_spec();

        let tokio_runtime = Runtime::new().unwrap();

        let data_dir = TestDataDir::new();
        let network = tokio_runtime.block_on(async {
            create_network(
                "127.0.0.1".parse().unwrap(),
                0,
                0,
                vec![],
                true,
                vec![],
                data_dir.path(),
            )
            .await
            .unwrap()
        });

        let peer_id = PeerId::random();

        network.network_state.upsert_peer(
            peer_id,
            None,
            ConnectionState::Connecting,
            Direction::Outbound,
            None,
        );

        network.network_state.upsert_peer(
            peer_id,
            None,
            ConnectionState::Connected,
            Direction::Outbound,
            None,
        );

        let cached_peer_snapshot = network.cached_peer(&peer_id).expect("peer exists in cache");

        assert_eq!(cached_peer_snapshot.state, ConnectionState::Connected);
        assert_eq!(cached_peer_snapshot.direction, Direction::Outbound);
    }

    #[test]
    fn cached_peer_unknown_returns_none() {
        initialize_test_network_spec();

        let tokio_runtime = Runtime::new().unwrap();

        let data_dir = TestDataDir::new();
        let network = tokio_runtime.block_on(async {
            create_network(
                "127.0.0.1".parse().unwrap(),
                0,
                0,
                vec![],
                true,
                vec![],
                data_dir.path(),
            )
            .await
            .unwrap()
        });

        let peer_id = PeerId::random();

        assert!(network.cached_peer(&peer_id).is_none());
    }

    #[test]
    fn test_p2p_gossipsub() {
        initialize_test_network_spec();

        let runtime = Runtime::new().unwrap();

        let gossip_topics = vec![GossipTopic {
            fork: B32::ZERO,
            kind: GossipTopicKind::BeaconBlock,
        }];

        let data_dir_1 = TestDataDir::new();
        let data_dir_2 = TestDataDir::new();

        let mut network_1 = runtime
            .block_on(create_network(
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                9090,
                9091,
                vec![],
                true,
                gossip_topics.clone(),
                data_dir_1.path(),
            ))
            .unwrap();
        let network_1_enr = network_1.enr();
        let mut network_2 = runtime
            .block_on(create_network(
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                9092,
                9093,
                vec![network_1_enr],
                false,
                gossip_topics.clone(),
                data_dir_2.path(),
            ))
            .unwrap();

        runtime.block_on(async {
            let network_1_future = async {
                while let Some(event) = network_1.swarm.next().await {
                    if let SwarmEvent::Behaviour(ReamBehaviourEvent::Gossipsub(
                        GossipsubEvent::Subscribed { peer_id: _, topic },
                    )) = &event
                    {
                        let _ = network_1
                            .swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(topic.clone(), vec![]);
                    }
                    let _ = network_1.parse_swarm_event(event).await;
                }
            };

            let network_2_future = async {
                while let Some(event) = network_2.swarm.next().await {
                    if let SwarmEvent::Behaviour(ReamBehaviourEvent::Gossipsub(
                        GossipsubEvent::Message { .. },
                    )) = &event
                    {
                        break;
                    }
                    let _ = network_2.parse_swarm_event(event).await;
                }
            };

            tokio::select! {
                _ = network_1_future => {}
                _ = network_2_future => {}
            }
        });
    }

    #[test]
    fn test_peer_table_lifecycle() {
        initialize_test_network_spec();

        let tokio_runtime = Runtime::new().unwrap();

        let data_dir_1 = TestDataDir::new();
        let data_dir_2 = TestDataDir::new();

        let mut network_1 = tokio_runtime
            .block_on(create_network(
                "127.0.0.1".parse().unwrap(),
                9300,
                9301,
                vec![],
                true,
                vec![],
                data_dir_1.path(),
            ))
            .unwrap();

        let mut network_2 = tokio_runtime
            .block_on(create_network(
                "127.0.0.1".parse().unwrap(),
                9302,
                9303,
                vec![],
                true,
                vec![],
                data_dir_2.path(),
            ))
            .unwrap();

        let peer_id_network_1 = network_1.peer_id();
        let peer_id_network_2 = network_2.peer_id();

        let mut inbound_initiated_status = false;
        let inbound_ready = std::sync::atomic::AtomicBool::new(false);
        tokio_runtime.block_on(async {
            let peers = HashMap::from([(network_1.enr(), None)]);
            network_2.handle_discovered_peers(peers);

            let network_1_poll_task =  async   {
                while let Some(event) = network_1.swarm.next().await {
                    if let Some(ReamNetworkEvent::RequestMessage {
                        peer_id,
                        stream_id,
                        connection_id,
                        message: BeaconRequestMessage::Status(status) ,
                    }) = network_1.parse_swarm_event(event).await {
                                inbound_ready.store(true, std::sync::atomic::Ordering::Relaxed);
                                network_1
                                    .swarm
                                    .behaviour_mut()
                                    .req_resp
                                    .send_response(
                                        peer_id,
                                        connection_id,
                                        stream_id,
                                        RespMessage::Response(Box::new(ResponseMessage::Beacon(BeaconResponseMessage::Status(status).into()))),
                                    );
                    }
                }};

            let network_2_poll_task =  async   {
                while let Some(event) = network_2.swarm.next().await {
                    if let Some(ReamNetworkEvent::RequestMessage {
                        message: BeaconRequestMessage::Status(_), ..
                    }) = network_2.parse_swarm_event(event).await {
                        inbound_initiated_status = true;
                    }
                    if inbound_initiated_status
                        && inbound_ready.load(std::sync::atomic::Ordering::Relaxed)
                        && matches!(
                        network_2.cached_peer(&peer_id_network_1),
                        Some(peer) if peer.state == ConnectionState::Connected && peer.direction == Direction::Outbound
                    ) {
                        break;
                    }
                }
            };


            tokio::select! {
                _ = network_1_poll_task => {}
                _ = network_2_poll_task => {}
                _ = sleep(Duration::from_secs(10)) => {}
            }
        }
       );

        assert!(
            inbound_initiated_status,
            "inbound connection must initiate Status"
        );
        let peer_from_network_1 = network_1
            .cached_peer(&peer_id_network_2)
            .expect("network_1 peer exists");
        let peer_from_network_2 = network_2
            .cached_peer(&peer_id_network_1)
            .expect("network_2 peer exists");

        assert_eq!(peer_from_network_1.state, ConnectionState::Connected);
        assert_eq!(peer_from_network_1.direction, Direction::Inbound);

        assert_eq!(peer_from_network_2.state, ConnectionState::Connected);
        assert_eq!(peer_from_network_2.direction, Direction::Outbound);
        assert_eq!(ream_metrics::BEACON_PEER_COUNT.get(), 1);
        assert_eq!(ream_metrics::LIBP2P_PEERS.get(), 1);
    }

    #[test]
    fn a_raised_custody_is_advertised_and_subscribed() {
        initialize_test_network_spec();
        let tokio_runtime = Runtime::new().unwrap();
        let data_dir = TestDataDir::new();
        let mut network = tokio_runtime.block_on(async {
            create_network_with_custody(
                "127.0.0.1".parse().unwrap(),
                0,
                0,
                vec![],
                true,
                vec![],
                data_dir.path(),
                4,
            )
            .await
            .unwrap()
        });
        use ream_discv5::subnet::CUSTODY_GROUP_COUNT_ENR_KEY;

        let custody_config = CustodyConfig::from_network_spec(&beacon_network_spec()).unwrap();
        let node_id = network.network_state.local_enr.read().node_id();
        let enr_count = |network: &Network| {
            network
                .network_state
                .local_enr
                .read()
                .get_decodable::<CustodyGroupCount>(CUSTODY_GROUP_COUNT_ENR_KEY)
                .and_then(Result::ok)
        };
        let seq_before = network.network_state.meta_data.read().seq_number;

        let raised = CustodyAssignment::new(node_id, 64, &custody_config).unwrap();
        tokio_runtime.block_on(async { network.raise_custody(raised.clone()) });
        assert_eq!(enr_count(&network), Some(CustodyGroupCount(64)));
        let meta_data = network.network_state.meta_data.read().clone();
        assert_eq!(meta_data.custody_group_count, 64);
        assert_eq!(meta_data.seq_number, seq_before + 1);
        assert_eq!(network.sampling_columns, raised.sampling_columns);
        let subscribed = network
            .subscribed_topics
            .lock()
            .iter()
            .filter_map(|topic| match topic.kind {
                GossipTopicKind::DataColumnSidecar(subnet_id) => Some(subnet_id),
                _ => None,
            })
            .collect::<HashSet<_>>();
        assert!(
            raised
                .data_column_subnet_ids
                .iter()
                .all(|subnet_id| subscribed.contains(subnet_id))
        );

        // A smaller custody changes nothing: the count never decreases.
        let lower = CustodyAssignment::new(node_id, 8, &custody_config).unwrap();
        tokio_runtime.block_on(async { network.raise_custody(lower) });
        assert_eq!(enr_count(&network), Some(CustodyGroupCount(64)));
        assert_eq!(
            network.network_state.meta_data.read().custody_group_count,
            64
        );
        assert_eq!(network.sampling_columns, raised.sampling_columns);
    }

    #[test]
    fn custody_discovery_stops_above_the_target_peer_count() {
        let target = DEFAULT_TARGET_PEERS;
        assert_eq!(
            custody_discovery_target(0, target),
            CUSTODY_DISCOVERY_TARGET_PEERS
        );
        assert_eq!(
            custody_discovery_target(target, target),
            CUSTODY_DISCOVERY_TARGET_PEERS
        );
        assert_eq!(custody_discovery_target(target + 5, target), 3);
        assert_eq!(
            custody_discovery_target(target + CUSTODY_DISCOVERY_TARGET_PEERS, target),
            0
        );
        assert_eq!(custody_discovery_target(usize::MAX, target), 0);
    }

    #[test]
    fn inbound_connections_beyond_the_limit_are_denied() {
        initialize_test_network_spec();
        let tokio_runtime = Runtime::new().unwrap();
        let data_dirs = [TestDataDir::new(), TestDataDir::new(), TestDataDir::new()];

        // A target of one peer admits one inbound connection.
        let mut listener = tokio_runtime
            .block_on(create_network_with_target_peers(
                "127.0.0.1".parse().unwrap(),
                9320,
                9321,
                vec![],
                true,
                vec![],
                data_dirs[0].path(),
                1,
            ))
            .unwrap();
        let mut dialers = [(9322, 9323), (9324, 9325)]
            .into_iter()
            .zip(&data_dirs[1..])
            .map(|((socket_port, discovery_port), data_dir)| {
                tokio_runtime
                    .block_on(create_network(
                        "127.0.0.1".parse().unwrap(),
                        socket_port,
                        discovery_port,
                        vec![],
                        true,
                        vec![],
                        data_dir.path(),
                    ))
                    .unwrap()
            })
            .collect::<Vec<_>>();

        let denied = tokio_runtime.block_on(async {
            for dialer in &mut dialers {
                dialer.handle_discovered_peers(HashMap::from([(listener.enr(), None)]));
            }
            let [dialer_1, dialer_2] = dialers.as_mut_slice() else {
                unreachable!("two dialers were created");
            };
            let mut denied = 0;
            let deadline = sleep(Duration::from_secs(10));
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    Some(event) = listener.swarm.next() => {
                        if let SwarmEvent::IncomingConnectionError {
                            error: libp2p::swarm::ListenError::Denied { .. },
                            ..
                        } = &event
                        {
                            denied += 1;
                        }
                        listener.parse_swarm_event(event).await;
                    }
                    Some(event) = dialer_1.swarm.next() => {
                        dialer_1.parse_swarm_event(event).await;
                    }
                    Some(event) = dialer_2.swarm.next() => {
                        dialer_2.parse_swarm_event(event).await;
                    }
                    _ = &mut deadline => break,
                }
                if denied > 0 && listener.swarm.connected_peers().count() == 1 {
                    break;
                }
            }
            denied
        });

        assert_eq!(listener.swarm.connected_peers().count(), 1);
        assert!(denied > 0, "the second inbound connection should be denied");
    }

    #[test]
    fn inbound_peer_custody_comes_from_meta_data_and_is_dropped_on_disconnect() {
        initialize_test_network_spec();

        let data_dir_1 = TestDataDir::new();
        let data_dir_2 = TestDataDir::new();
        let tokio_runtime = Runtime::new().unwrap();
        let mut network_1 = tokio_runtime
            .block_on(create_network(
                "127.0.0.1".parse().unwrap(),
                9310,
                9311,
                vec![],
                true,
                vec![],
                data_dir_1.path(),
            ))
            .unwrap();
        let mut network_2 = tokio_runtime
            .block_on(create_network(
                "127.0.0.1".parse().unwrap(),
                9312,
                9313,
                vec![],
                true,
                vec![],
                data_dir_2.path(),
            ))
            .unwrap();
        let peer_id_network_1 = network_1.peer_id();
        let peer_id_network_2 = network_2.peer_id();
        let all_columns = (0..128).collect::<Vec<_>>();

        let inbound_custody = |network: &Network| {
            network
                .cached_peer(&peer_id_network_2)
                .map(|peer| peer.custody().clone())
        };

        tokio_runtime.block_on(async {
            network_2.handle_discovered_peers(HashMap::from([(network_1.enr(), None)]));

            // network_1 sees network_2 as an inbound peer with no ENR, so custody can only come
            // from the MetaData it requests once the Status exchange succeeds.
            let network_1_task = async {
                while let Some(event) = network_1.swarm.next().await {
                    if let Some(ReamNetworkEvent::RequestMessage {
                        peer_id,
                        stream_id,
                        connection_id,
                        message: BeaconRequestMessage::Status(status),
                    }) = network_1.parse_swarm_event(event).await
                    {
                        network_1.swarm.behaviour_mut().req_resp.send_response(
                            peer_id,
                            connection_id,
                            stream_id,
                            RespMessage::Response(Box::new(ResponseMessage::Beacon(
                                BeaconResponseMessage::Status(status).into(),
                            ))),
                        );
                    }
                    if matches!(
                        inbound_custody(&network_1),
                        Some(peer_custody::PeerCustody::Advertised {
                            source: peer_custody::CustodySource::MetaData,
                            ..
                        })
                    ) {
                        break;
                    }
                }
            };
            let network_2_task = async {
                while let Some(event) = network_2.swarm.next().await {
                    network_2.parse_swarm_event(event).await;
                }
            };
            tokio::select! {
                _ = network_1_task => {}
                _ = network_2_task => {}
                _ = sleep(Duration::from_secs(10)) => {}
            }
        });

        let peer = network_1
            .cached_peer(&peer_id_network_2)
            .expect("network_1 tracks network_2");
        assert_eq!(peer.direction, Direction::Inbound);
        assert!(peer.enr().is_none());
        assert_eq!(
            peer.custody()
                .groups()
                .expect("custody from MetaData")
                .custody_group_count,
            NUM_CUSTODY_GROUPS
        );
        let coverage = network_1.network_state.column_coverage(&all_columns);
        assert!(coverage.uncovered_columns.is_empty());
        assert_eq!(coverage.eligible_peers(), [peer_id_network_2]);

        tokio_runtime.block_on(async {
            let _ = network_2.swarm.disconnect_peer_id(peer_id_network_1);
            let network_1_task = async {
                while let Some(event) = network_1.swarm.next().await {
                    network_1.parse_swarm_event(event).await;
                    if network_1
                        .cached_peer(&peer_id_network_2)
                        .is_some_and(|peer| peer.state == ConnectionState::Disconnected)
                    {
                        break;
                    }
                }
            };
            let network_2_task = async {
                while let Some(event) = network_2.swarm.next().await {
                    network_2.parse_swarm_event(event).await;
                }
            };
            tokio::select! {
                _ = network_1_task => {}
                _ = network_2_task => {}
                _ = sleep(Duration::from_secs(10)) => {}
            }
        });

        let peer = network_1
            .cached_peer(&peer_id_network_2)
            .expect("disconnected peers stay cached until pruned");
        assert_eq!(peer.state, ConnectionState::Disconnected);
        assert!(peer.meta_data().is_none());
        assert_eq!(peer.custody(), &peer_custody::PeerCustody::NotAdvertised);
        assert_eq!(
            network_1
                .network_state
                .column_coverage(&all_columns)
                .uncovered_columns,
            all_columns
        );
    }

    fn create_local_network(runtime: &Runtime, data_dir: &Path) -> anyhow::Result<Network> {
        create_local_network_with_topics(runtime, data_dir, vec![])
    }

    fn create_local_network_with_topics(
        runtime: &Runtime,
        data_dir: &Path,
        topics: Vec<GossipTopic>,
    ) -> anyhow::Result<Network> {
        runtime.block_on(create_network(
            "127.0.0.1".parse().unwrap(),
            0,
            0,
            vec![],
            true,
            topics,
            data_dir,
        ))
    }

    /// All subnet topics, as a node joined to every subnet has them.
    fn all_subnet_topics() -> Vec<GossipTopic> {
        let fork = beacon_network_spec().fork_digest(
            beacon_network_spec().current_epoch(),
            genesis_validators_root(),
        );
        (0..ATTESTATION_SUBNET_COUNT as u64)
            .map(GossipTopicKind::BeaconAttestation)
            .chain((0..4).map(GossipTopicKind::SyncCommittee))
            .map(|kind| GossipTopic { fork, kind })
            .collect()
    }

    /// Attestation and sync committee subnets gossipsub is subscribed to.
    fn subscribed_subnets(network: &Network) -> (BitVector<U64>, BitVector<U4>) {
        let mut subscribed_attnets = BitVector::<U64>::new();
        let mut subscribed_syncnets = BitVector::<U4>::new();
        for topic_hash in network.swarm.behaviour().gossipsub.topics() {
            match GossipTopic::from_topic_hash(topic_hash).unwrap().kind {
                GossipTopicKind::BeaconAttestation(subnet_id) => {
                    subscribed_attnets.set(subnet_id as usize, true).unwrap()
                }
                GossipTopicKind::SyncCommittee(subnet_id) => {
                    subscribed_syncnets.set(subnet_id as usize, true).unwrap()
                }
                _ => {}
            }
        }
        (subscribed_attnets, subscribed_syncnets)
    }

    /// Topics, ENR, cached ENR and saved `MetaData` must agree.
    fn assert_subnets_consistent(network: &Network, data_dir: &Path) {
        let enr = network.swarm.behaviour().discovery.local_enr();
        assert_eq!(network.enr(), enr);

        let (subscribed_attnets, subscribed_syncnets) = subscribed_subnets(network);
        let (attnets, syncnets) = enr_subnet_bitfields(&enr).unwrap();
        assert_eq!(attnets, subscribed_attnets);
        assert_eq!(syncnets, subscribed_syncnets);

        let meta_data = network.network_state.meta_data.read().clone();
        assert_eq!(meta_data.attnets, attnets);
        assert_eq!(meta_data.syncnets, syncnets);
        assert_eq!(
            read_meta_data_from_disk(data_dir.to_path_buf()).unwrap(),
            meta_data
        );
    }

    fn meta_data_seq(network: &Network) -> u64 {
        network.network_state.meta_data.read().seq_number
    }

    fn epoch_start(epoch: u64) -> SystemTime {
        let spec = beacon_network_spec();
        UNIX_EPOCH
            + Duration::from_secs(
                spec.min_genesis_time + epoch * SLOTS_PER_EPOCH * spec.seconds_per_slot(),
            )
    }

    fn advertised(network: &Network) -> AttestationSubnets {
        network
            .swarm
            .behaviour()
            .discovery
            .current_attestation_subnets()
            .clone()
    }

    /// Returns the first epoch after `epoch` with a different backbone assignment.
    fn next_assignment_change(network: &Network, epoch: u64) -> u64 {
        let discovery = &network.swarm.behaviour().discovery;
        let assignment = discovery.attestation_subnets_at(epoch).unwrap();
        (epoch + 1..)
            .find(|epoch| discovery.attestation_subnets_at(*epoch).unwrap() != assignment)
            .unwrap()
    }

    #[test]
    fn subscribing_to_all_subnets_advertises_all_subnets() {
        initialize_test_network_spec();

        let runtime = Runtime::new().unwrap();
        let data_dir = TestDataDir::new();

        let (enr, seq) = {
            let mut network =
                create_local_network_with_topics(&runtime, data_dir.path(), all_subnet_topics())
                    .unwrap();
            let (attnets, syncnets) = enr_subnet_bitfields(&network.enr()).unwrap();
            assert_eq!(attnets.num_set_bits(), ATTESTATION_SUBNET_COUNT);
            assert_eq!(syncnets.num_set_bits(), 4);
            assert_subnets_consistent(&network, data_dir.path());

            // The backbone is already included.
            let (enr, seq) = (network.enr(), meta_data_seq(&network));
            for period in 0..4 {
                network
                    .sync_attestation_subnets(epoch_start(period * EPOCHS_PER_SUBNET_SUBSCRIPTION))
                    .unwrap();
            }
            assert_eq!(network.enr(), enr);
            assert_eq!(meta_data_seq(&network), seq);
            (enr, seq)
        };

        let network =
            create_local_network_with_topics(&runtime, data_dir.path(), all_subnet_topics())
                .unwrap();
        assert_eq!(network.enr(), enr);
        assert_eq!(meta_data_seq(&network), seq);
        assert_subnets_consistent(&network, data_dir.path());
    }

    #[test]
    fn peers_with_a_full_send_queue_for_ten_heartbeats_are_dropped() {
        let mut slow_peers = HashMap::new();
        let peer = PeerId::random();
        let start = Instant::now();
        let heartbeat = |n: u64| start + Duration::from_millis(700 * n);

        // Small drops do not count.
        assert!(!record_slow_heartbeat(
            &mut slow_peers,
            peer,
            SLOW_PEER_DROPPED_MESSAGES,
            start
        ));
        for n in 0..SLOW_PEER_STRIKES as u64 - 1 {
            assert!(!record_slow_heartbeat(
                &mut slow_peers,
                peer,
                50,
                heartbeat(n)
            ));
        }
        // A quiet minute resets the count.
        let later = heartbeat(SLOW_PEER_STRIKES as u64) + SLOW_PEER_WINDOW;
        assert!(!record_slow_heartbeat(&mut slow_peers, peer, 50, later));
        assert_eq!(slow_peers[&peer].0, 1);

        for n in 1..SLOW_PEER_STRIKES as u64 - 1 {
            assert!(!record_slow_heartbeat(
                &mut slow_peers,
                peer,
                50,
                later + Duration::from_millis(700 * n)
            ));
        }
        assert!(record_slow_heartbeat(
            &mut slow_peers,
            peer,
            50,
            later + Duration::from_secs(10)
        ));
        assert!(slow_peers.is_empty());
    }

    #[test]
    fn duty_subnets_with_few_peers_need_discovery() {
        let mut peer_counts = [TARGET_SUBNET_PEERS; ATTESTATION_SUBNET_COUNT];
        peer_counts[5] = 0;
        peer_counts[9] = TARGET_SUBNET_PEERS - 1;
        let duty_subnets = HashMap::from([(9, 100), (5, 100), (7, 100)]);

        assert_eq!(
            subnets_needing_peers(&duty_subnets, &peer_counts),
            vec![5, 9]
        );
        assert!(subnets_needing_peers(&HashMap::new(), &peer_counts).is_empty());
    }

    #[test]
    fn duty_subnets_are_left_after_their_last_slot() {
        initialize_test_network_spec();

        let runtime = Runtime::new().unwrap();
        let data_dir = TestDataDir::new();
        let mut network = create_local_network(&runtime, data_dir.path()).unwrap();
        let backbone = advertised(&network);
        let duty_subnet = (0..ATTESTATION_SUBNET_COUNT as u64)
            .find(|subnet_id| !backbone.is_attestation_subnet_enabled(*subnet_id).unwrap())
            .unwrap();
        let backbone_subnet = (0..ATTESTATION_SUBNET_COUNT as u64)
            .find(|subnet_id| backbone.is_attestation_subnet_enabled(*subnet_id).unwrap())
            .unwrap();
        let fork = beacon_network_spec().fork_digest(0, genesis_validators_root());
        let topic = |subnet_id| GossipTopic {
            fork,
            kind: GossipTopicKind::BeaconAttestation(subnet_id),
        };
        let slot_start = |slot: u64| {
            epoch_start(0) + Duration::from_secs(slot * beacon_network_spec().seconds_per_slot())
        };
        let joined = |network: &Network, subnet_id: u64| {
            subscribed_subnets(network)
                .0
                .get(subnet_id as usize)
                .unwrap()
        };

        assert!(!joined(&network, duty_subnet));
        assert!(network.subscribe_for_duty(topic(duty_subnet), 10));
        assert!(network.subscribe_for_duty(topic(duty_subnet), 8));
        assert!(network.subscribe_for_duty(topic(backbone_subnet), 10));

        network.expire_duty_topics(slot_start(10));
        assert!(joined(&network, duty_subnet));
        network.expire_duty_topics(slot_start(11));
        assert!(!joined(&network, duty_subnet));
        assert!(joined(&network, backbone_subnet));
        assert!(network.duty_topics.is_empty());
    }

    #[test]
    fn a_duty_subnet_that_becomes_backbone_stays_joined() {
        initialize_test_network_spec();

        let runtime = Runtime::new().unwrap();
        let data_dir = TestDataDir::new();
        let mut network = create_local_network(&runtime, data_dir.path()).unwrap();
        let boundary = next_assignment_change(&network, 0);
        let discovery = &network.swarm.behaviour().discovery;
        let before = discovery.attestation_subnets_at(boundary - 1).unwrap();
        let after = discovery.attestation_subnets_at(boundary).unwrap();
        let subnet_id = (0..ATTESTATION_SUBNET_COUNT as u64)
            .find(|subnet_id| {
                after.is_attestation_subnet_enabled(*subnet_id).unwrap()
                    && !before.is_attestation_subnet_enabled(*subnet_id).unwrap()
            })
            .unwrap();
        let topic = GossipTopic {
            fork: beacon_network_spec().fork_digest(
                beacon_network_spec().current_epoch(),
                genesis_validators_root(),
            ),
            kind: GossipTopicKind::BeaconAttestation(subnet_id),
        };

        network
            .sync_attestation_subnets(epoch_start(boundary - 1))
            .unwrap();
        assert!(network.subscribe_for_duty(topic, boundary * SLOTS_PER_EPOCH));
        network
            .sync_attestation_subnets(epoch_start(boundary))
            .unwrap();
        network.expire_duty_topics(epoch_start(boundary + 1));

        assert!(network.duty_topics.is_empty());
        assert_eq!(network.backbone_topics.get(&subnet_id), Some(&topic));
        assert_eq!(advertised(&network), after);
        assert_subnets_consistent(&network, data_dir.path());
    }

    #[test]
    fn sync_duty_subnets_are_advertised_while_joined() {
        initialize_test_network_spec();

        let runtime = Runtime::new().unwrap();
        let data_dir = TestDataDir::new();
        let mut network = create_local_network(&runtime, data_dir.path()).unwrap();
        let seq = meta_data_seq(&network);
        let topic = GossipTopic {
            fork: beacon_network_spec().fork_digest(0, genesis_validators_root()),
            kind: GossipTopicKind::SyncCommittee(2),
        };
        let syncnets = |network: &Network| enr_subnet_bitfields(&network.enr()).unwrap().1;

        assert!(network.subscribe_for_duty(topic, 10));
        assert_eq!(syncnets(&network).num_set_bits(), 1);
        assert!(syncnets(&network).get(2).unwrap());
        assert_eq!(meta_data_seq(&network), seq + 1);
        assert_subnets_consistent(&network, data_dir.path());

        let slot_start = |slot: u64| {
            epoch_start(0) + Duration::from_secs(slot * beacon_network_spec().seconds_per_slot())
        };
        network.expire_duty_topics(slot_start(10));
        assert!(syncnets(&network).get(2).unwrap());
        network.expire_duty_topics(slot_start(11));
        assert_eq!(syncnets(&network).num_set_bits(), 0);
        assert_eq!(meta_data_seq(&network), seq + 2);
        assert_subnets_consistent(&network, data_dir.path());
    }

    #[test]
    fn backbone_rotation_updates_topics_enr_and_meta_data() {
        initialize_test_network_spec();

        let runtime = Runtime::new().unwrap();
        let data_dir = TestDataDir::new();

        let mut network = create_local_network(&runtime, data_dir.path()).unwrap();
        // No subnet topics: only the backbone is joined.
        assert_eq!(advertised(&network).0.num_set_bits(), 2);
        assert_subnets_consistent(&network, data_dir.path());

        // Assignments change where (epoch + node_id % 256) % 256 == 0.
        let node_offset = network.enr().node_id().raw()[31] as u64;
        let boundary = next_assignment_change(&network, 0);
        assert_eq!((boundary + node_offset) % EPOCHS_PER_SUBNET_SUBSCRIPTION, 0);
        let assignment_at = |network: &Network, epoch| {
            network
                .swarm
                .behaviour()
                .discovery
                .attestation_subnets_at(epoch)
                .unwrap()
        };

        network
            .sync_attestation_subnets(epoch_start(boundary - 1))
            .unwrap();
        assert_eq!(advertised(&network), assignment_at(&network, boundary - 1));
        assert_subnets_consistent(&network, data_dir.path());
        let (enr_seq, seq) = (network.enr().seq(), meta_data_seq(&network));
        network
            .sync_attestation_subnets(epoch_start(boundary - 1) + Duration::from_secs(10))
            .unwrap();
        assert_eq!(
            (network.enr().seq(), meta_data_seq(&network)),
            (enr_seq, seq)
        );

        // One epoch later the boundary rotates the subnets.
        network
            .sync_attestation_subnets(epoch_start(boundary))
            .unwrap();
        assert_eq!(advertised(&network), assignment_at(&network, boundary));
        assert_eq!(network.enr().seq(), enr_seq + 1);
        assert_eq!(meta_data_seq(&network), seq + 1);
        assert_subnets_consistent(&network, data_dir.path());

        // A late tick skips boundaries, and before genesis epoch 0 applies.
        let late = boundary + 3 * EPOCHS_PER_SUBNET_SUBSCRIPTION + 7;
        for (now, epoch) in [
            (epoch_start(late), late),
            (epoch_start(0) - Duration::from_secs(100), 0),
        ] {
            network.sync_attestation_subnets(now).unwrap();
            assert_eq!(advertised(&network), assignment_at(&network, epoch));
            assert_subnets_consistent(&network, data_dir.path());
        }
        drop(network);

        let restarted_seq = {
            let network = create_local_network(&runtime, data_dir.path()).unwrap();
            assert_subnets_consistent(&network, data_dir.path());
            meta_data_seq(&network)
        };
        let network = create_local_network(&runtime, data_dir.path()).unwrap();
        assert_eq!(meta_data_seq(&network), restarted_seq);
        assert_subnets_consistent(&network, data_dir.path());
    }

    #[test]
    fn failed_subnet_sync_is_retried_on_the_next_tick() {
        initialize_test_network_spec();

        let runtime = Runtime::new().unwrap();
        let data_dir = TestDataDir::new();
        let mut network = create_local_network(&runtime, data_dir.path()).unwrap();
        let mut epoch = next_assignment_change(&network, 0) - 1;
        network
            .sync_attestation_subnets(epoch_start(epoch))
            .unwrap();

        // Each phase blocks one save with a directory in place of its file, during a rotation.
        for (file, enr_published) in [(ENR_FILE_NAME, false), (utils::META_DATA_FILE_NAME, true)] {
            let published = network.swarm.behaviour().discovery.local_enr();
            let meta_data = network.network_state.meta_data.read().clone();
            let old_subnets = advertised(&network);
            epoch = next_assignment_change(&network, epoch);
            let path = data_dir.path().join(file);
            fs::remove_file(&path).unwrap();
            fs::create_dir(&path).unwrap();

            assert!(
                network
                    .sync_attestation_subnets(epoch_start(epoch))
                    .is_err()
            );
            // The ENR changes only once saved. `MetaData` and the old backbone topics stay until
            // `MetaData` is saved.
            assert_eq!(
                network.swarm.behaviour().discovery.local_enr() != published,
                enr_published
            );
            assert_eq!(*network.network_state.meta_data.read(), meta_data);
            let (subscribed, _) = subscribed_subnets(&network);
            assert_eq!(old_subnets.0.intersection(&subscribed), old_subnets.0);

            // The assignment is unchanged, but the next tick finishes the update.
            fs::remove_dir(&path).unwrap();
            network
                .sync_attestation_subnets(epoch_start(epoch))
                .unwrap();
            assert_eq!(meta_data_seq(&network), meta_data.seq_number + 1);
            assert_subnets_consistent(&network, data_dir.path());
            assert_eq!(
                load_enr(&data_dir.path().join(ENR_FILE_NAME)).unwrap(),
                Some(network.enr())
            );
        }
    }

    #[test]
    fn network_identity_persists_across_restarts() {
        initialize_test_network_spec();

        let runtime = Runtime::new().unwrap();
        let data_dir = TestDataDir::new();

        let (first_peer_id, first_node_id) = {
            let network = create_local_network(&runtime, data_dir.path()).unwrap();
            let enr = network.enr();
            // discv5 and libp2p share the same key.
            assert_eq!(peer_id_from_enr(&enr), Some(network.peer_id()));
            (network.peer_id(), enr.node_id())
        };
        assert!(data_dir.path().join(NETWORK_KEY_FILE_NAME).is_file());

        let network = create_local_network(&runtime, data_dir.path()).unwrap();
        assert_eq!(network.peer_id(), first_peer_id);
        assert_eq!(network.enr().node_id(), first_node_id);
        assert_eq!(peer_id_from_enr(&network.enr()), Some(first_peer_id));
    }

    #[test]
    fn enr_seq_never_regresses_across_restarts() {
        initialize_test_network_spec();

        let runtime = Runtime::new().unwrap();
        let data_dir = TestDataDir::new();

        let first = create_local_network(&runtime, data_dir.path())
            .unwrap()
            .enr();
        let unchanged = create_local_network(&runtime, data_dir.path())
            .unwrap()
            .enr();
        assert_eq!(unchanged, first);

        let updated = {
            let mut network = create_local_network(&runtime, data_dir.path()).unwrap();
            let epoch = next_assignment_change(&network, 0);
            network.sync_attestation_subnets(epoch_start(0)).unwrap();
            network
                .sync_attestation_subnets(epoch_start(epoch))
                .unwrap();
            network.enr()
        };
        assert!(updated.seq() > first.seq());

        let restarted = create_local_network(&runtime, data_dir.path())
            .unwrap()
            .enr();
        assert_eq!(restarted.node_id(), first.node_id());
        assert!(restarted.seq() > updated.seq() || restarted == updated);
        assert!(data_dir.path().join(ENR_FILE_NAME).is_file());
    }

    fn fork_entries(enr: &Enr) -> (EnrForkId, NextForkDigest) {
        (
            enr.get_decodable(ENR_ETH2_KEY).unwrap().unwrap(),
            enr.get_decodable(NEXT_FORK_DIGEST_ENR_KEY)
                .unwrap()
                .unwrap(),
        )
    }

    #[test]
    fn fork_enr_follows_the_wall_clock_and_keeps_cached_enr_in_sync() {
        initialize_test_network_spec();
        let spec = beacon_network_spec();
        let gvr = genesis_validators_root();
        let epoch_duration = Duration::from_secs(SLOTS_PER_EPOCH * spec.seconds_per_slot());
        let runtime = Runtime::new().unwrap();
        let data_dir = TestDataDir::new();
        let mut network = create_local_network(&runtime, data_dir.path()).unwrap();
        let assert_cache_in_sync = |network: &Network| {
            assert_eq!(
                network.enr(),
                network.swarm.behaviour().discovery.local_enr()
            );
        };

        // The Status head is at slot 0, but the ENR follows the wall clock.
        let now = SystemTime::now();
        assert_eq!(
            fork_entries(&network.enr()).0,
            EnrForkId::current(gvr, epoch_at(network.genesis_time, now))
        );

        let before_genesis = epoch_start(0) - Duration::from_secs(100);
        assert_eq!(
            network.update_fork_enr(before_genesis),
            Some(Duration::from_secs(100) + epoch_duration * spec.altair_fork_epoch as u32)
        );
        assert_eq!(
            fork_entries(&network.enr()).0.fork_digest,
            spec.fork_digest(0, gvr)
        );
        assert_cache_in_sync(&network);

        let before_fulu = epoch_start(spec.fulu_fork_epoch - 1);
        assert_eq!(network.update_fork_enr(before_fulu), Some(epoch_duration));
        let electra = network.enr();
        assert_cache_in_sync(&network);
        assert_eq!(
            fork_entries(&electra),
            (
                EnrForkId::current(gvr, spec.fulu_fork_epoch - 1),
                NextForkDigest(spec.fork_digest(spec.fulu_fork_epoch, gvr))
            )
        );

        let later = before_fulu + Duration::from_secs(10);
        assert_eq!(
            network.update_fork_enr(later),
            Some(epoch_duration - Duration::from_secs(10))
        );
        assert_eq!(network.enr(), electra);

        // A late wake-up lands well after the Fulu boundary.
        assert_eq!(
            network.update_fork_enr(epoch_start(spec.fulu_fork_epoch + 5)),
            None
        );
        let fulu = network.enr();
        assert_cache_in_sync(&network);
        assert!(fulu.seq() > electra.seq());
        assert_eq!(
            fork_entries(&fulu),
            (
                EnrForkId::current(gvr, spec.fulu_fork_epoch),
                NextForkDigest::default()
            )
        );
        assert_eq!(
            load_enr(&data_dir.path().join(ENR_FILE_NAME)).unwrap(),
            Some(fulu.clone())
        );
        drop(network);

        // The real wall clock is also past Fulu, so a restart rebuilds the same record.
        let restarted = create_local_network(&runtime, data_dir.path())
            .unwrap()
            .enr();
        assert_eq!(restarted, fulu);
    }

    #[test]
    fn independent_data_directories_have_distinct_identities() {
        initialize_test_network_spec();

        let runtime = Runtime::new().unwrap();
        let data_dir_1 = TestDataDir::new();
        let data_dir_2 = TestDataDir::new();

        let network_1 = create_local_network(&runtime, data_dir_1.path()).unwrap();
        let network_2 = create_local_network(&runtime, data_dir_2.path()).unwrap();

        assert_ne!(network_1.peer_id(), network_2.peer_id());
        assert_ne!(network_1.enr().node_id(), network_2.enr().node_id());
    }

    #[test]
    fn existing_data_directory_without_key_gets_new_identity() {
        initialize_test_network_spec();

        let runtime = Runtime::new().unwrap();
        let data_dir = TestDataDir::new();
        // A data directory from before the key was persisted.
        fs::write(
            data_dir.path().join(utils::META_DATA_FILE_NAME),
            GetMetaDataV3::default().as_ssz_bytes(),
        )
        .unwrap();

        let peer_id = create_local_network(&runtime, data_dir.path())
            .unwrap()
            .peer_id();

        assert_eq!(
            create_local_network(&runtime, data_dir.path())
                .unwrap()
                .peer_id(),
            peer_id
        );
    }

    #[test]
    fn malformed_network_key_fails_init_without_replacement() {
        initialize_test_network_spec();

        let data_dir = TestDataDir::new();
        let key_path = data_dir.path().join(NETWORK_KEY_FILE_NAME);
        fs::write(&key_path, "malformed").unwrap();

        // `create_network` owns a tokio runtime; dropping it inside tokio's `block_on` panics.
        let err = futures::executor::block_on(create_network(
            "127.0.0.1".parse().unwrap(),
            0,
            0,
            vec![],
            true,
            vec![],
            data_dir.path(),
        ))
        .err()
        .expect("init should fail with a malformed key");

        assert!(err.to_string().contains(NETWORK_KEY_FILE_NAME));
        assert_eq!(fs::read_to_string(&key_path).unwrap(), "malformed");
    }
}
