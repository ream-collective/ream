use std::{
    collections::HashMap,
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
    time::Instant,
};

use anyhow::{Result, anyhow};
use discv5::{
    Discv5, Enr, Event,
    enr::{CombinedKey, EnrKey, NodeId, k256::ecdsa::SigningKey},
};
use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    identity::Keypair,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm, dummy::ConnectionHandler,
    },
};
use ream_consensus_misc::{
    constants::beacon::genesis_validators_root, misc::compute_epoch_at_slot,
};
use tokio::sync::mpsc;
use tracing::{error, info, trace, warn};

use crate::{
    config::DiscoveryConfig,
    eth2::{ENR_ETH2_KEY, EnrForkId},
    persisted_enr::{advertised_ip, continue_enr_seq, load_enr, save_enr},
    subnet::{
        ATTESTATION_BITFIELD_ENR_KEY, AttestationSubnets, CUSTODY_GROUP_COUNT_ENR_KEY,
        NEXT_FORK_DIGEST_ENR_KEY, SYNC_COMMITTEE_BITFIELD_ENR_KEY, attestation_subnet_predicate,
        compute_subscribed_subnets, next_fork_digest, sync_committee_subnet_predicate,
    },
};

#[derive(Debug)]
pub enum DiscoveryOutEvent {
    DiscoveredPeers {
        peers: HashMap<Enr, Option<Instant>>,
    },
    UpdatedEnr {
        enr: Enr,
    },
}

enum EventStream {
    Inactive,
    Awaiting(
        Pin<Box<dyn Future<Output = Result<mpsc::Receiver<discv5::Event>, discv5::Error>> + Send>>,
    ),
    Present(mpsc::Receiver<discv5::Event>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum QueryType {
    Peers,
    AttestationSubnetPeers(Vec<u64>),
    SyncCommitteeSubnetPeers(Vec<u64>),
}

struct QueryResult {
    query_type: QueryType,
    result: Result<Vec<Enr>, discv5::QueryError>,
}

pub struct Discovery {
    discv5: Discv5,
    event_stream: EventStream,
    discovery_queries: FuturesUnordered<Pin<Box<dyn Future<Output = QueryResult> + Send>>>,
    find_peer_active: bool,
    pub started: bool,
    long_lived_attestation_subnets: AttestationSubnets,
    /// Attestation subnets advertised in the local ENR
    current_attestation_subnets: AttestationSubnets,
    /// Saved after every local ENR change when set
    enr_path: Option<PathBuf>,
    /// The last save failed and is retried by [`Discovery::set_attestation_subnets`]
    enr_save_pending: AtomicBool,
}

impl Discovery {
    /// The ENR advertises the backbone subnets assigned for `subnet_epoch`.
    pub async fn new(
        local_key: Keypair,
        config: &DiscoveryConfig,
        current_slot: u64,
        subnet_epoch: u64,
    ) -> anyhow::Result<Self> {
        Self::init(local_key, config, current_slot, subnet_epoch, None).await
    }

    /// Like [`Discovery::new`], but keeps the local ENR at `enr_path` so its sequence number
    /// keeps increasing across restarts.
    pub async fn with_persisted_enr(
        local_key: Keypair,
        config: &DiscoveryConfig,
        current_slot: u64,
        subnet_epoch: u64,
        enr_path: PathBuf,
    ) -> anyhow::Result<Self> {
        Self::init(
            local_key,
            config,
            current_slot,
            subnet_epoch,
            Some(enr_path),
        )
        .await
    }

    async fn init(
        local_key: Keypair,
        config: &DiscoveryConfig,
        current_slot: u64,
        subnet_epoch: u64,
        enr_path: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        let enr_local =
            convert_to_enr(local_key).map_err(|err| anyhow!("Failed to convert key: {err:?}"))?;
        let current_epoch = compute_epoch_at_slot(current_slot);
        let attestation_subnets = advertised_attestation_subnets(
            &config.attestation_subnets,
            NodeId::from(enr_local.public()),
            subnet_epoch,
        )?;

        // A saved ENR from another node, e.g. after a key change, is not reused.
        let previous_enr = match &enr_path {
            Some(enr_path) => {
                load_enr(enr_path)?.filter(|enr| enr.node_id() == NodeId::from(enr_local.public()))
            }
            None => None,
        };

        let mut enr_builder = Enr::builder();
        let ip = advertised_ip(config.socket_address, previous_enr.as_ref());
        enr_builder.ip(ip);
        if ip.is_ipv4() {
            enr_builder.tcp4(config.socket_port);
            enr_builder.udp4(config.discovery_port);
        } else {
            enr_builder.tcp6(config.socket_port);
            enr_builder.udp6(config.discovery_port);
        }

        let mut enr = enr_builder
            .add_value(
                ENR_ETH2_KEY,
                &EnrForkId::current(genesis_validators_root(), current_epoch),
            )
            .add_value(ATTESTATION_BITFIELD_ENR_KEY, &attestation_subnets)
            .add_value(
                SYNC_COMMITTEE_BITFIELD_ENR_KEY,
                &config.sync_committee_subnets,
            )
            .add_value(CUSTODY_GROUP_COUNT_ENR_KEY, &config.custody_group_count)
            .add_value(NEXT_FORK_DIGEST_ENR_KEY, &next_fork_digest(current_epoch))
            .build(&enr_local)
            .map_err(|err| anyhow!("Failed to build ENR: {err}"))?;

        if let Some(enr_path) = &enr_path {
            if let Some(previous) = &previous_enr {
                continue_enr_seq(&mut enr, previous, &enr_local)?;
            }
            save_enr(enr_path, &enr)?;
        }

        let node_local_id = enr.node_id();

        let mut discv5 = Discv5::new(enr.clone(), enr_local, config.discv5_config.clone())
            .map_err(|err| anyhow!("Failed to create discv5: {err:?}"))?;

        // adding bootnodes to discv5
        for enr in config.bootnodes.clone() {
            // Skip adding ourselves to the routing table if we are a bootnode
            if enr.node_id() == node_local_id {
                continue;
            }
            if let Err(err) = discv5.add_enr(enr) {
                error!("Failed to add bootnode to Discv5 {err:?}");
            }
        }

        let event_stream = if !config.disable_discovery {
            discv5
                .start()
                .await
                .map_err(|err| anyhow!("Failed to start discv5: {err:?}"))?;
            info!("Started discovery with ENR: {:?}", discv5.local_enr());
            EventStream::Awaiting(Box::pin(discv5.event_stream()))
        } else {
            EventStream::Inactive
        };

        Ok(Self {
            discv5,
            event_stream,
            discovery_queries: FuturesUnordered::new(),
            find_peer_active: false,
            started: !config.disable_discovery,
            long_lived_attestation_subnets: config.attestation_subnets.clone(),
            current_attestation_subnets: attestation_subnets,
            enr_path,
            enr_save_pending: AtomicBool::new(false),
        })
    }

    fn persist_local_enr(&self) {
        if let Some(enr_path) = &self.enr_path {
            let result = save_enr(enr_path, &self.discv5.local_enr());
            self.enr_save_pending
                .store(result.is_err(), Ordering::Relaxed);
            if let Err(err) = result {
                warn!("Failed to persist local ENR: {err:?}");
            }
        }
    }

    /// Returns the configured subnets plus the backbone subnets assigned for `epoch`.
    pub fn attestation_subnets_at(&self, epoch: u64) -> Result<AttestationSubnets> {
        advertised_attestation_subnets(
            &self.long_lived_attestation_subnets,
            self.discv5.local_enr().node_id(),
            epoch,
        )
    }

    /// Advertises `subnets` in the local ENR. Returns whether the ENR changed. Also retries a
    /// failed ENR save.
    pub fn set_attestation_subnets(&mut self, subnets: AttestationSubnets) -> Result<bool> {
        if subnets == self.current_attestation_subnets {
            if self.enr_save_pending.load(Ordering::Relaxed) {
                self.persist_local_enr();
            }
            return Ok(false);
        }

        // `enr_insert` RLP-encodes the value itself.
        self.discv5
            .enr_insert(ATTESTATION_BITFIELD_ENR_KEY, &subnets)
            .map_err(|err| anyhow!("Failed to update local ENR attnets: {err:?}"))?;
        info!("Advertising attestation subnets {subnets:?}");
        self.current_attestation_subnets = subnets;
        self.persist_local_enr();
        Ok(true)
    }

    /// Subnets advertised in the local ENR. The caller must stay subscribed to all of them.
    pub fn current_attestation_subnets(&self) -> &AttestationSubnets {
        &self.current_attestation_subnets
    }

    pub fn discover_peers(&mut self, query: QueryType, target_peers: usize) {
        // If the discv5 service isn't running or we are in the process of a query, don't bother
        // queuing a new one.
        if !self.started || self.find_peer_active {
            return;
        }
        self.find_peer_active = true;

        self.start_query(query, target_peers);
    }

    fn start_query(&mut self, query: QueryType, target_peers: usize) {
        let query_future = self
            .discv5
            .find_node_predicate(
                NodeId::random(),
                match query.clone() {
                    QueryType::Peers => {
                        let Some(Ok(fork_id)) = self
                            .discv5
                            .local_enr()
                            .get_decodable::<EnrForkId>(ENR_ETH2_KEY)
                        else {
                            warn!("ENR missing or invalid ENR_ETH2_KEY, skipping peer query");
                            return;
                        };
                        let fork_digest = fork_id.fork_digest;

                        Box::new(move |enr: &Enr| {
                            enr.get_decodable::<EnrForkId>(ENR_ETH2_KEY)
                                .and_then(Result::ok)
                                .map(|id| id.fork_digest == fork_digest)
                                .unwrap_or(false)
                                && (enr.tcp4().is_some() || enr.tcp6().is_some())
                        })
                    }
                    QueryType::AttestationSubnetPeers(subnet_ids) => {
                        Box::new(attestation_subnet_predicate(subnet_ids))
                    }
                    QueryType::SyncCommitteeSubnetPeers(subnet_ids) => {
                        Box::new(sync_committee_subnet_predicate(subnet_ids))
                    }
                },
                target_peers,
            )
            .map(move |result| QueryResult {
                query_type: query,
                result,
            });

        self.discovery_queries.push(Box::pin(query_future));
    }

    fn process_queries(&mut self, cx: &mut Context) -> Option<HashMap<Enr, Option<Instant>>> {
        while let Poll::Ready(Some(query)) = self.discovery_queries.poll_next_unpin(cx) {
            let result = match query.query_type {
                QueryType::Peers => {
                    self.find_peer_active = false;
                    match query.result {
                        Ok(peers) => {
                            info!("Found {} peers", peers.len());
                            let mut peer_map = HashMap::new();
                            for peer in peers {
                                peer_map.insert(peer, None);
                            }
                            Some(peer_map)
                        }
                        Err(err) => {
                            warn!("Failed to find peers: {err:?}");
                            None
                        }
                    }
                }
                QueryType::AttestationSubnetPeers(subnet_ids) => {
                    self.find_peer_active = false;
                    match query.result {
                        Ok(peers) => {
                            let predicate = attestation_subnet_predicate(subnet_ids);
                            let filtered_peers = peers
                                .into_iter()
                                .filter(|enr| predicate(enr))
                                .collect::<Vec<_>>();
                            info!("Found {} peers for subnets", filtered_peers.len());
                            let mut peer_map = HashMap::new();
                            for peer in filtered_peers {
                                peer_map.insert(peer, None);
                            }
                            Some(peer_map)
                        }
                        Err(err) => {
                            warn!("Failed to find subnet peers: {err:?}");
                            None
                        }
                    }
                }
                QueryType::SyncCommitteeSubnetPeers(subnet_ids) => {
                    self.find_peer_active = false;
                    match query.result {
                        Ok(peers) => {
                            let predicate = sync_committee_subnet_predicate(subnet_ids);
                            let filtered_peers = peers
                                .into_iter()
                                .filter(|enr| predicate(enr))
                                .collect::<Vec<_>>();
                            info!(
                                "Found {} peers for sync committee subnets",
                                filtered_peers.len(),
                            );
                            let mut peer_map = HashMap::new();
                            for peer in filtered_peers {
                                peer_map.insert(peer, None);
                            }
                            Some(peer_map)
                        }
                        Err(err) => {
                            warn!("Failed to find sync committee subnet peers: {err:?}");
                            None
                        }
                    }
                }
            };
            if result.is_some() {
                return result;
            }
        }
        None
    }

    pub fn local_enr(&self) -> Enr {
        self.discv5.local_enr()
    }
}

impl NetworkBehaviour for Discovery {
    type ConnectionHandler = ConnectionHandler;
    type ToSwarm = DiscoveryOutEvent;

    fn handle_pending_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        trace!("Discv5 on swarm event gotten: {event:?}");
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        _event: THandlerOutEvent<Self>,
    ) {
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if !self.started {
            return Poll::Pending;
        }

        if let Some(peers) = self.process_queries(cx) {
            return Poll::Ready(ToSwarm::GenerateEvent(DiscoveryOutEvent::DiscoveredPeers {
                peers,
            }));
        }

        match &mut self.event_stream {
            EventStream::Inactive => {}
            EventStream::Awaiting(fut) => {
                if let Poll::Ready(event_stream) = fut.poll_unpin(cx) {
                    match event_stream {
                        Ok(stream) => {
                            self.event_stream = EventStream::Present(stream);
                        }
                        Err(err) => {
                            error!("Failed to start discovery event stream: {err:?}");
                            self.event_stream = EventStream::Inactive;
                        }
                    }
                }
            }
            EventStream::Present(receiver) => match receiver.try_recv() {
                Ok(event) => {
                    if let Event::SocketUpdated(_) = event {
                        self.persist_local_enr();
                        return Poll::Ready(ToSwarm::GenerateEvent(
                            DiscoveryOutEvent::UpdatedEnr {
                                enr: self.local_enr(),
                            },
                        ));
                    }
                }
                Err(err) => {
                    warn!("No discovery event found: {err:?}");
                    self.event_stream = EventStream::Inactive;
                }
            },
        };

        Poll::Pending
    }
}

fn advertised_attestation_subnets(
    long_lived: &AttestationSubnets,
    node_id: NodeId,
    epoch: u64,
) -> Result<AttestationSubnets> {
    let mut subnets = long_lived.clone();
    for subnet_id in compute_subscribed_subnets(node_id, epoch)? {
        subnets.enable_attestation_subnet(subnet_id)?;
    }
    Ok(subnets)
}

pub fn empty_predicate() -> impl Fn(&Enr) -> bool + Send + Sync {
    move |_enr: &Enr| true
}

fn convert_to_enr(key: Keypair) -> anyhow::Result<CombinedKey> {
    let key = key
        .try_into_secp256k1()
        .map_err(|err| anyhow!("Failed to get secp256k1 keypair: {err:?}"))?;
    let secret = SigningKey::from_slice(&key.secret().to_bytes())
        .map_err(|err| anyhow!("Failed to convert keypair to SigningKey: {err:?}"))?;
    Ok(CombinedKey::Secp256k1(secret))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use alloy_primitives::B256;
    use libp2p::identity::Keypair;
    use ream_consensus_misc::constants::beacon::GENESIS_VALIDATORS_ROOT;
    use ream_network_spec::networks::initialize_test_network_spec;
    use ssz::Encode;

    use super::*;
    use crate::{
        config::DiscoveryConfig,
        persisted_enr::test_utils::TestDir,
        subnet::{
            ATTESTATION_SUBNET_COUNT, AttestationSubnets, CustodyGroupCount, SyncCommitteeSubnets,
        },
    };

    #[tokio::test]
    async fn test_initial_subnet_setup() -> anyhow::Result<()> {
        let _ = GENESIS_VALIDATORS_ROOT.set(B256::ZERO);
        initialize_test_network_spec();
        let key = Keypair::generate_secp256k1();
        let mut config = DiscoveryConfig {
            disable_discovery: true,
            ..DiscoveryConfig::default()
        };
        config.attestation_subnets = AttestationSubnets::new();
        config.attestation_subnets.enable_attestation_subnet(5)?;

        let discovery = Discovery::new(key, &config, 0, 0).await.unwrap();
        let enr_subnets = enr_attestation_subnets(&discovery.local_enr())?;

        let mut expected = config.attestation_subnets.clone();
        for subnet_id in compute_subscribed_subnets(discovery.local_enr().node_id(), 0)? {
            expected.enable_attestation_subnet(subnet_id)?;
        }
        assert_eq!(enr_subnets, expected);
        assert_eq!(discovery.current_attestation_subnets(), &expected);
        Ok(())
    }

    #[tokio::test]
    async fn enr_ports_match_socket_address_ip_version() -> anyhow::Result<()> {
        let _ = GENESIS_VALIDATORS_ROOT.set(B256::ZERO);
        initialize_test_network_spec();
        for socket_address in [
            IpAddr::from(Ipv4Addr::new(192, 0, 2, 1)),
            Ipv4Addr::UNSPECIFIED.into(),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into(),
            Ipv6Addr::UNSPECIFIED.into(),
        ] {
            let config = DiscoveryConfig {
                disable_discovery: true,
                socket_address,
                socket_port: 9100,
                discovery_port: 9101,
                ..DiscoveryConfig::default()
            };
            let enr = Discovery::new(Keypair::generate_secp256k1(), &config, 0, 0)
                .await?
                .local_enr();

            let tcp: Vec<_> = [
                enr.tcp4_socket().map(SocketAddr::V4),
                enr.tcp6_socket().map(SocketAddr::V6),
            ]
            .into_iter()
            .flatten()
            .collect();
            let udp: Vec<_> = [
                enr.udp4_socket().map(SocketAddr::V4),
                enr.udp6_socket().map(SocketAddr::V6),
            ]
            .into_iter()
            .flatten()
            .collect();
            assert_eq!(
                tcp,
                [SocketAddr::new(socket_address, 9100)],
                "{socket_address}"
            );
            assert_eq!(
                udp,
                [SocketAddr::new(socket_address, 9101)],
                "{socket_address}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_attestation_subnet_predicate() -> anyhow::Result<()> {
        initialize_test_network_spec();
        let key = Keypair::generate_secp256k1();
        let mut config = DiscoveryConfig::default();
        config.attestation_subnets.enable_attestation_subnet(0)?; // Local node on subnet 0
        config.attestation_subnets.disable_attestation_subnet(1)?;
        config.disable_discovery = true;

        let discovery = Discovery::new(key, &config, 0, 0).await.unwrap();
        let local_enr = discovery.local_enr();

        // Predicate for subnet 0 should match
        let predicate = attestation_subnet_predicate(vec![0]);
        assert!(predicate(&local_enr));

        let unadvertised = (0..ATTESTATION_SUBNET_COUNT as u64)
            .find(|subnet_id| {
                !discovery
                    .current_attestation_subnets()
                    .is_attestation_subnet_enabled(*subnet_id)
                    .unwrap()
            })
            .unwrap();
        let predicate = attestation_subnet_predicate(vec![unadvertised]);
        assert!(!predicate(&local_enr));
        Ok(())
    }

    #[tokio::test]
    async fn test_discovery_with_subnets() -> anyhow::Result<()> {
        initialize_test_network_spec();
        let key = Keypair::generate_secp256k1();
        let discv5_config = discv5::ConfigBuilder::new(discv5::ListenConfig::default())
            .table_filter(|_| true)
            .build();

        let mut config = DiscoveryConfig {
            disable_discovery: false,
            discv5_config: discv5_config.clone(),
            ..DiscoveryConfig::default()
        };

        config.attestation_subnets.enable_attestation_subnet(0)?; // Local node on subnet 0
        config.disable_discovery = false;
        let mut discovery = Discovery::new(key, &config, 0, 0).await.unwrap();

        // Simulate a peer with another Discovery instance
        let peer_key = Keypair::generate_secp256k1();
        let mut peer_config = DiscoveryConfig {
            attestation_subnets: AttestationSubnets::new(),
            sync_committee_subnets: SyncCommitteeSubnets::new(),
            disable_discovery: true,
            discv5_config,
            ..DiscoveryConfig::default()
        };

        peer_config
            .attestation_subnets
            .enable_attestation_subnet(0)?;
        peer_config.socket_address = Ipv4Addr::new(192, 168, 1, 100).into(); // Non-localhost IP
        peer_config.socket_port = 9001; // Different port
        peer_config.disable_discovery = true;

        let peer_discovery = Discovery::new(peer_key, &peer_config, 0, 0).await.unwrap();
        let peer_enr = peer_discovery.local_enr().clone();

        // Add peer to discv5
        discovery.discv5.add_enr(peer_enr.clone()).unwrap();

        // Mock the query result to bypass async polling
        discovery.discovery_queries.clear();
        let query_result = QueryResult {
            query_type: QueryType::AttestationSubnetPeers(vec![0]),
            result: Ok(vec![peer_enr.clone()]),
        };
        discovery
            .discovery_queries
            .push(Box::pin(async move { query_result }));

        // Poll the discovery to process the query
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        if let Poll::Ready(ToSwarm::GenerateEvent(DiscoveryOutEvent::DiscoveredPeers { peers })) =
            discovery.poll(&mut cx)
        {
            assert_eq!(peers.len(), 1);
            assert!(peers.contains_key(&peer_discovery.local_enr()));
        } else {
            panic!("Expected peers to be discovered");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_subnet_subscription_determinism() -> anyhow::Result<()> {
        let _ = GENESIS_VALIDATORS_ROOT.set(B256::ZERO);
        initialize_test_network_spec();

        let key = Keypair::generate_secp256k1();
        let config = DiscoveryConfig {
            disable_discovery: true,
            ..DiscoveryConfig::default()
        };

        let initial_slot = 0;
        let discovery = Discovery::new(key.clone(), &config, initial_slot, 0).await?;
        let subnets1 = discovery.current_attestation_subnets().clone();

        // Create another discovery instance with the same key
        let discovery2 = Discovery::new(key, &config, initial_slot, 0).await?;
        let subnets2 = discovery2.current_attestation_subnets().clone();

        // Should have the same subnets since they have the same node_id
        assert_eq!(
            subnets1, subnets2,
            "Subnet subscriptions should be deterministic"
        );

        Ok(())
    }

    fn enr_attestation_subnets(enr: &Enr) -> anyhow::Result<AttestationSubnets> {
        enr.get_decodable::<AttestationSubnets>(ATTESTATION_BITFIELD_ENR_KEY)
            .ok_or_else(|| anyhow!("Missing attestation subnet field"))?
            .map_err(|err| anyhow!("Failed to decode attestation subnets: {err:?}"))
    }

    #[tokio::test]
    async fn rotated_attnets_are_a_single_ssz_byte_string() -> anyhow::Result<()> {
        let _ = GENESIS_VALIDATORS_ROOT.set(B256::ZERO);
        initialize_test_network_spec();
        let config = DiscoveryConfig {
            disable_discovery: true,
            attestation_subnets: AttestationSubnets::new(),
            ..DiscoveryConfig::default()
        };
        let mut discovery = Discovery::new(Keypair::generate_secp256k1(), &config, 0, 0).await?;
        let seq = discovery.local_enr().seq();

        rotate_attestation_subnets(&mut discovery)?;
        let enr = discovery.local_enr();
        let current = discovery.current_attestation_subnets();

        // 0x88 is the RLP string header for the 8 byte SSZ bitvector.
        let mut expected_rlp = vec![0x88];
        expected_rlp.extend_from_slice(&current.0.as_ssz_bytes());
        assert_eq!(
            enr.get_raw_rlp(ATTESTATION_BITFIELD_ENR_KEY),
            Some(expected_rlp.as_slice())
        );
        assert_eq!(&enr_attestation_subnets(&enr)?, current);
        assert_eq!(enr.seq(), seq + 1);
        Ok(())
    }

    /// Advertises the first assignment after epoch 0 that differs and returns its epoch.
    fn rotate_attestation_subnets(discovery: &mut Discovery) -> anyhow::Result<u64> {
        let mut epoch = 0;
        loop {
            epoch += 1;
            let subnets = discovery.attestation_subnets_at(epoch)?;
            if discovery.set_attestation_subnets(subnets)? {
                return Ok(epoch);
            }
        }
    }

    #[tokio::test]
    async fn persisted_enr_seq_survives_runtime_updates_and_restarts() -> anyhow::Result<()> {
        let _ = GENESIS_VALIDATORS_ROOT.set(B256::ZERO);
        initialize_test_network_spec();
        let dir = TestDir::new();
        let enr_path = dir.path().join("enr");
        let key = Keypair::generate_secp256k1();
        let config = DiscoveryConfig {
            disable_discovery: true,
            ..DiscoveryConfig::default()
        };

        let mut discovery =
            Discovery::with_persisted_enr(key.clone(), &config, 0, 0, enr_path.clone()).await?;
        let epoch = rotate_attestation_subnets(&mut discovery)?;
        let updated = discovery.local_enr();
        assert_eq!(updated.seq(), 2);
        assert_eq!(load_enr(&enr_path)?, Some(updated.clone()));
        drop(discovery);

        // Same epoch: same record and seq.
        let restarted =
            Discovery::with_persisted_enr(key.clone(), &config, 0, epoch, enr_path.clone())
                .await?
                .local_enr();
        assert_eq!(restarted, updated);

        // Other subscription period: other subnets, higher seq.
        let later = Discovery::with_persisted_enr(key, &config, 0, 0, enr_path)
            .await?
            .local_enr();
        assert_ne!(
            enr_attestation_subnets(&later)?,
            enr_attestation_subnets(&updated)?
        );
        assert_eq!(later.seq(), updated.seq() + 1);
        Ok(())
    }

    #[tokio::test]
    async fn changed_enr_on_restart_increments_seq() -> anyhow::Result<()> {
        let _ = GENESIS_VALIDATORS_ROOT.set(B256::ZERO);
        initialize_test_network_spec();
        let dir = TestDir::new();
        let enr_path = dir.path().join("enr");
        let key = Keypair::generate_secp256k1();
        let mut config = DiscoveryConfig {
            disable_discovery: true,
            custody_group_count: CustodyGroupCount(128),
            ..DiscoveryConfig::default()
        };

        let first = Discovery::with_persisted_enr(key.clone(), &config, 0, 0, enr_path.clone())
            .await?
            .local_enr();
        config.custody_group_count = CustodyGroupCount(4);
        let restarted = Discovery::with_persisted_enr(key, &config, 0, 0, enr_path.clone())
            .await?
            .local_enr();

        assert_eq!(restarted.node_id(), first.node_id());
        assert_eq!(restarted.seq(), first.seq() + 1);
        assert_eq!(
            restarted.get_decodable::<CustodyGroupCount>(CUSTODY_GROUP_COUNT_ENR_KEY),
            Some(Ok(CustodyGroupCount(4)))
        );
        assert_eq!(load_enr(&enr_path)?, Some(restarted));
        Ok(())
    }

    /// Simulates discv5 learning `ip` from PONG votes, as handled on `Event::SocketUpdated`.
    fn learn_external_ip(discovery: &Discovery, ip: Ipv4Addr, udp_port: u16) {
        assert!(
            discovery
                .discv5
                .update_local_enr_socket((ip, udp_port).into(), false)
        );
        discovery.persist_local_enr();
    }

    #[tokio::test]
    async fn learned_ip_and_seq_survive_restart_with_unspecified_address() -> anyhow::Result<()> {
        let _ = GENESIS_VALIDATORS_ROOT.set(B256::ZERO);
        initialize_test_network_spec();
        let dir = TestDir::new();
        let enr_path = dir.path().join("enr");
        let key = Keypair::generate_secp256k1();
        let config = DiscoveryConfig {
            disable_discovery: true,
            socket_address: Ipv4Addr::UNSPECIFIED.into(),
            ..DiscoveryConfig::default()
        };
        let external_ip = Ipv4Addr::new(203, 0, 113, 7);

        let discovery =
            Discovery::with_persisted_enr(key.clone(), &config, 0, 0, enr_path.clone()).await?;
        assert_eq!(discovery.local_enr().ip4(), Some(Ipv4Addr::UNSPECIFIED));
        learn_external_ip(&discovery, external_ip, config.discovery_port);
        let learned = discovery.local_enr();
        assert_eq!(load_enr(&enr_path)?, Some(learned.clone()));
        drop(discovery);

        let restarted = Discovery::with_persisted_enr(key, &config, 0, 0, enr_path)
            .await?
            .local_enr();
        assert_eq!(restarted.ip4(), Some(external_ip));
        assert_eq!(restarted.udp4(), Some(config.discovery_port));
        assert_eq!(restarted.seq(), learned.seq());
        assert_eq!(restarted, learned);
        Ok(())
    }

    #[tokio::test]
    async fn learned_ip_is_kept_with_new_configured_udp_port() -> anyhow::Result<()> {
        let _ = GENESIS_VALIDATORS_ROOT.set(B256::ZERO);
        initialize_test_network_spec();
        let dir = TestDir::new();
        let enr_path = dir.path().join("enr");
        let key = Keypair::generate_secp256k1();
        let mut config = DiscoveryConfig {
            disable_discovery: true,
            socket_address: Ipv4Addr::UNSPECIFIED.into(),
            ..DiscoveryConfig::default()
        };
        let external_ip = Ipv4Addr::new(203, 0, 113, 7);

        let discovery =
            Discovery::with_persisted_enr(key.clone(), &config, 0, 0, enr_path.clone()).await?;
        learn_external_ip(&discovery, external_ip, config.discovery_port);
        let learned = discovery.local_enr();
        drop(discovery);

        config.discovery_port += 1;
        let restarted = Discovery::with_persisted_enr(key, &config, 0, 0, enr_path)
            .await?
            .local_enr();
        assert_eq!(restarted.ip4(), Some(external_ip));
        assert_eq!(restarted.udp4(), Some(config.discovery_port));
        assert_eq!(restarted.seq(), learned.seq() + 1);
        Ok(())
    }

    #[tokio::test]
    async fn configured_ip_replaces_learned_ip_on_restart() -> anyhow::Result<()> {
        let _ = GENESIS_VALIDATORS_ROOT.set(B256::ZERO);
        initialize_test_network_spec();
        let dir = TestDir::new();
        let enr_path = dir.path().join("enr");
        let key = Keypair::generate_secp256k1();
        let mut config = DiscoveryConfig {
            disable_discovery: true,
            socket_address: Ipv4Addr::UNSPECIFIED.into(),
            ..DiscoveryConfig::default()
        };

        let discovery =
            Discovery::with_persisted_enr(key.clone(), &config, 0, 0, enr_path.clone()).await?;
        learn_external_ip(
            &discovery,
            Ipv4Addr::new(203, 0, 113, 7),
            config.discovery_port,
        );
        let learned = discovery.local_enr();
        drop(discovery);

        let configured_ip = Ipv4Addr::new(198, 51, 100, 1);
        config.socket_address = configured_ip.into();
        let restarted = Discovery::with_persisted_enr(key, &config, 0, 0, enr_path)
            .await?
            .local_enr();
        assert_eq!(restarted.ip4(), Some(configured_ip));
        assert_eq!(restarted.seq(), learned.seq() + 1);
        Ok(())
    }
}
