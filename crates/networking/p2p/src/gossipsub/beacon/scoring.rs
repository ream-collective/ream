//! Gossipsub peer scoring parameters, as Lighthouse sets them
//! (`lighthouse_network::service::gossipsub_scoring_parameters`).
//!
//! A peer's score rises with the time it spends in our mesh and the first deliveries it brings,
//! and falls with invalid messages (messages reported as REJECT), with too few deliveries while in
//! the mesh, and with protocol misbehaviour. Below the thresholds gossipsub stops gossiping to the
//! peer, stops publishing to it, and at last ignores it (graylist).
//!
//! Only the topics Lighthouse scores are scored: blocks, aggregates, attestation subnets, exits
//! and slashings. Blob sidecar, data column, sync committee and light client topics are not.

use std::{collections::HashMap, time::Duration};

use libp2p::gossipsub::{PeerScoreParams, PeerScoreThresholds, TopicHash, TopicScoreParams};
use ream_consensus_misc::constants::beacon::{
    MAX_COMMITTEES_PER_SLOT, SLOTS_PER_EPOCH, TARGET_COMMITTEE_SIZE,
};
use ream_network_spec::networks::beacon_network_spec;

use super::topics::{GossipTopic, GossipTopicKind};

/// `ATTESTATION_SUBNET_COUNT` from the phase0 p2p spec.
const ATTESTATION_SUBNET_COUNT: u64 = 64;
/// `TARGET_AGGREGATORS_PER_COMMITTEE` from the phase0 validator spec.
const TARGET_AGGREGATORS_PER_COMMITTEE: u64 = 16;

const MAX_IN_MESH_SCORE: f64 = 10.0;
const MAX_FIRST_MESSAGE_DELIVERIES_SCORE: f64 = 40.0;
const BEACON_BLOCK_WEIGHT: f64 = 0.5;
const BEACON_AGGREGATE_PROOF_WEIGHT: f64 = 0.5;
const VOLUNTARY_EXIT_WEIGHT: f64 = 0.05;
const PROPOSER_SLASHING_WEIGHT: f64 = 0.05;
const ATTESTER_SLASHING_WEIGHT: f64 = 0.05;
const BEACON_ATTESTATION_SUBNET_WEIGHT: f64 = 1.0 / ATTESTATION_SUBNET_COUNT as f64;

/// The time window in which a mesh peer is expected to forward a message we already had.
const MESH_MESSAGE_DELIVERIES_WINDOW: Duration = Duration::from_secs(2);
const DECAY_TO_ZERO: f64 = 0.01;

/// Below this score gossipsub ignores everything from the peer.
pub const GRAYLIST_THRESHOLD: f64 = -16000.0;
/// Below this score gossipsub stops gossiping to the peer.
pub const GOSSIP_THRESHOLD: f64 = -4000.0;
/// Below this score our own messages are not published to the peer.
pub const PUBLISH_THRESHOLD: f64 = -8000.0;

pub fn peer_score_thresholds() -> PeerScoreThresholds {
    PeerScoreThresholds {
        gossip_threshold: GOSSIP_THRESHOLD,
        publish_threshold: PUBLISH_THRESHOLD,
        graylist_threshold: GRAYLIST_THRESHOLD,
        accept_px_threshold: 100.0,
        opportunistic_graft_threshold: 5.0,
    }
}

/// The score a peer reaches at most from a scored topic's in-mesh time and first deliveries,
/// summed over the topics' weights.
fn max_positive_score() -> f64 {
    (MAX_IN_MESH_SCORE + MAX_FIRST_MESSAGE_DELIVERIES_SCORE)
        * (BEACON_BLOCK_WEIGHT
            + BEACON_AGGREGATE_PROOF_WEIGHT
            + BEACON_ATTESTATION_SUBNET_WEIGHT * ATTESTATION_SUBNET_COUNT as f64
            + VOLUNTARY_EXIT_WEIGHT
            + PROPOSER_SLASHING_WEIGHT
            + ATTESTER_SLASHING_WEIGHT)
}

/// What the topic parameters depend on: the mesh size, the number of active validators, which
/// sets the expected message rates, and the current slot, since mesh delivery penalties wait until
/// the chain is old enough to have filled their decay window.
#[derive(Debug, Clone, Copy)]
pub struct PeerScoreSettings {
    slot: Duration,
    epoch: Duration,
    decay_interval: Duration,
    mesh_n: usize,
    active_validators: usize,
    current_slot: u64,
}

impl PeerScoreSettings {
    pub fn new(mesh_n: usize, active_validators: usize, current_slot: u64) -> Self {
        let slot = Duration::from_secs(beacon_network_spec().seconds_per_slot());
        Self {
            slot,
            epoch: slot * SLOTS_PER_EPOCH as u32,
            decay_interval: slot.max(Duration::from_secs(1)),
            mesh_n: mesh_n.max(1),
            active_validators: active_validators.max(1),
            current_slot,
        }
    }

    /// Peer score parameters with the given topics scored, those whose kind is scored.
    pub fn peer_score_params<'a>(
        &self,
        topics: impl IntoIterator<Item = &'a GossipTopic>,
    ) -> PeerScoreParams {
        let thresholds = peer_score_thresholds();
        let mut params = PeerScoreParams {
            decay_interval: self.decay_interval,
            decay_to_zero: DECAY_TO_ZERO,
            retain_score: self.epoch * 100,
            app_specific_weight: 1.0,
            // Up to 8 nodes may share an IP address before it counts against them.
            ip_colocation_factor_threshold: 8.0,
            behaviour_penalty_threshold: 6.0,
            behaviour_penalty_decay: self.decay(self.epoch * 10),
            slow_peer_decay: 0.1,
            slow_peer_weight: -10.0,
            slow_peer_threshold: 0.0,
            ..Default::default()
        };
        let target_value = decay_convergence(
            params.behaviour_penalty_decay,
            10.0 / SLOTS_PER_EPOCH as f64,
        ) - params.behaviour_penalty_threshold;
        params.behaviour_penalty_weight = thresholds.gossip_threshold / target_value.powi(2);
        params.topic_score_cap = max_positive_score() * 0.5;
        params.ip_colocation_factor_weight = -params.topic_score_cap;
        params.topics = topics
            .into_iter()
            .filter_map(|topic| {
                self.topic_score_params(&topic.kind)
                    .map(|topic_params| (TopicHash::from(*topic), topic_params))
            })
            .collect::<HashMap<_, _>>();
        params
    }

    /// The score parameters of a topic of `kind`, or `None` for a kind that is not scored.
    pub fn topic_score_params(&self, kind: &GossipTopicKind) -> Option<TopicScoreParams> {
        let slots_per_epoch = SLOTS_PER_EPOCH as f64;
        Some(match kind {
            GossipTopicKind::BeaconBlock => self.topic_params(
                BEACON_BLOCK_WEIGHT,
                1.0,
                self.epoch * 20,
                Some(MeshDeliveries {
                    decay_slots: SLOTS_PER_EPOCH * 5,
                    cap_factor: 3.0,
                    activation: self.epoch,
                }),
            ),
            GossipTopicKind::AggregateAndProof => self.topic_params(
                BEACON_AGGREGATE_PROOF_WEIGHT,
                self.aggregators_per_slot(),
                self.epoch,
                Some(MeshDeliveries {
                    decay_slots: SLOTS_PER_EPOCH * 2,
                    cap_factor: 4.0,
                    activation: self.epoch,
                }),
            ),
            GossipTopicKind::BeaconAttestation(_) => {
                let multiple_bursts_per_subnet_per_epoch =
                    self.committees_per_slot() >= 2 * ATTESTATION_SUBNET_COUNT / SLOTS_PER_EPOCH;
                self.topic_params(
                    BEACON_ATTESTATION_SUBNET_WEIGHT,
                    self.active_validators as f64
                        / ATTESTATION_SUBNET_COUNT as f64
                        / slots_per_epoch,
                    self.epoch
                        * if multiple_bursts_per_subnet_per_epoch {
                            1
                        } else {
                            4
                        },
                    Some(MeshDeliveries {
                        decay_slots: SLOTS_PER_EPOCH
                            * if multiple_bursts_per_subnet_per_epoch {
                                4
                            } else {
                                16
                            },
                        cap_factor: 16.0,
                        activation: if multiple_bursts_per_subnet_per_epoch {
                            self.slot * (SLOTS_PER_EPOCH as u32 / 2 + 1)
                        } else {
                            self.epoch * 3
                        },
                    }),
                )
            }
            GossipTopicKind::VoluntaryExit => self.topic_params(
                VOLUNTARY_EXIT_WEIGHT,
                4.0 / slots_per_epoch,
                self.epoch * 100,
                None,
            ),
            GossipTopicKind::AttesterSlashing => self.topic_params(
                ATTESTER_SLASHING_WEIGHT,
                1.0 / 5.0 / slots_per_epoch,
                self.epoch * 100,
                None,
            ),
            GossipTopicKind::ProposerSlashing => self.topic_params(
                PROPOSER_SLASHING_WEIGHT,
                1.0 / 5.0 / slots_per_epoch,
                self.epoch * 100,
                None,
            ),
            _ => return None,
        })
    }

    fn decay(&self, decay_time: Duration) -> f64 {
        let ticks = decay_time.as_secs_f64() / self.decay_interval.as_secs_f64();
        DECAY_TO_ZERO.powf(1.0 / ticks)
    }

    /// ``get_committee_count_per_slot`` for the active validator count.
    fn committees_per_slot(&self) -> u64 {
        (self.active_validators as u64 / SLOTS_PER_EPOCH / TARGET_COMMITTEE_SIZE)
            .clamp(1, MAX_COMMITTEES_PER_SLOT)
    }

    /// The expected number of aggregates per slot: each committee member aggregates with
    /// probability ``TARGET_AGGREGATORS_PER_COMMITTEE / committee size``.
    fn aggregators_per_slot(&self) -> f64 {
        let committees = (self.committees_per_slot() * SLOTS_PER_EPOCH) as usize;
        let smaller_committee_size = self.active_validators / committees;
        let larger_committees = self.active_validators - smaller_committee_size * committees;
        let target = TARGET_AGGREGATORS_PER_COMMITTEE as usize;
        let modulo_smaller = (smaller_committee_size / target).max(1);
        let modulo_larger = ((smaller_committee_size + 1) / target).max(1);
        (((committees - larger_committees) * smaller_committee_size) as f64 / modulo_smaller as f64
            + (larger_committees * (smaller_committee_size + 1)) as f64 / modulo_larger as f64)
            / SLOTS_PER_EPOCH as f64
    }

    fn topic_params(
        &self,
        topic_weight: f64,
        expected_message_rate: f64,
        first_message_decay_time: Duration,
        mesh_deliveries: Option<MeshDeliveries>,
    ) -> TopicScoreParams {
        let mut params = TopicScoreParams {
            topic_weight,
            time_in_mesh_quantum: self.slot,
            ..Default::default()
        };
        params.time_in_mesh_cap = 3600.0 / params.time_in_mesh_quantum.as_secs_f64();
        params.time_in_mesh_weight = MAX_IN_MESH_SCORE / params.time_in_mesh_cap;

        params.first_message_deliveries_decay = self.decay(first_message_decay_time);
        params.first_message_deliveries_cap = decay_convergence(
            params.first_message_deliveries_decay,
            2.0 * expected_message_rate / self.mesh_n as f64,
        );
        params.first_message_deliveries_weight =
            MAX_FIRST_MESSAGE_DELIVERIES_SCORE / params.first_message_deliveries_cap;

        match mesh_deliveries {
            Some(mesh) => {
                params.mesh_message_deliveries_decay =
                    self.decay(self.slot * mesh.decay_slots as u32);
                params.mesh_message_deliveries_threshold = decay_convergence(
                    params.mesh_message_deliveries_decay,
                    expected_message_rate / 50.0,
                ) * params.mesh_message_deliveries_decay;
                params.mesh_message_deliveries_cap =
                    (mesh.cap_factor * params.mesh_message_deliveries_threshold).max(2.0);
                params.mesh_message_deliveries_activation = mesh.activation;
                params.mesh_message_deliveries_window = MESH_MESSAGE_DELIVERIES_WINDOW;
                params.mesh_failure_penalty_decay = params.mesh_message_deliveries_decay;
                params.mesh_message_deliveries_weight = -topic_weight;
                params.mesh_failure_penalty_weight = params.mesh_message_deliveries_weight;
                // A chain younger than the decay window cannot have filled it yet.
                if mesh.decay_slots >= self.current_slot {
                    params.mesh_message_deliveries_threshold = 0.0;
                    params.mesh_message_deliveries_weight = 0.0;
                }
            }
            None => {
                params.mesh_message_deliveries_weight = 0.0;
                params.mesh_message_deliveries_threshold = 0.0;
                params.mesh_message_deliveries_decay = 0.0;
                params.mesh_message_deliveries_cap = 0.0;
                params.mesh_message_deliveries_window = Duration::ZERO;
                params.mesh_message_deliveries_activation = Duration::ZERO;
                params.mesh_failure_penalty_decay = 0.0;
                params.mesh_failure_penalty_weight = 0.0;
            }
        }

        params.invalid_message_deliveries_weight = -max_positive_score() / topic_weight;
        params.invalid_message_deliveries_decay = self.decay(self.epoch * 50);
        params
    }
}

/// How a topic penalizes mesh peers that deliver too few of its messages.
#[derive(Debug, Clone, Copy)]
struct MeshDeliveries {
    /// Slots over which the delivery counter decays to zero.
    decay_slots: u64,
    /// The counter's cap, in multiples of the threshold.
    cap_factor: f64,
    /// Time in the mesh before the penalty applies.
    activation: Duration,
}

/// The value a counter that gains `rate` per decay interval and decays by `decay` converges to.
fn decay_convergence(decay: f64, rate: f64) -> f64 {
    rate / (1.0 - decay)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::aliases::B32;
    use ream_network_spec::networks::beacon::initialize_test_network_spec;

    use super::*;

    const MAINNET_ACTIVE_VALIDATORS: usize = 1_000_000;

    fn topics() -> Vec<GossipTopic> {
        let fork = B32::from([1, 2, 3, 4]);
        let mut kinds = vec![
            GossipTopicKind::BeaconBlock,
            GossipTopicKind::AggregateAndProof,
            GossipTopicKind::VoluntaryExit,
            GossipTopicKind::ProposerSlashing,
            GossipTopicKind::AttesterSlashing,
            GossipTopicKind::SyncCommitteeContributionAndProof,
            GossipTopicKind::DataColumnSidecar(3),
        ];
        kinds.extend((0..ATTESTATION_SUBNET_COUNT).map(GossipTopicKind::BeaconAttestation));
        kinds
            .into_iter()
            .map(|kind| GossipTopic { fork, kind })
            .collect()
    }

    #[test]
    fn the_parameters_are_valid_for_mainnet_and_small_networks() {
        initialize_test_network_spec();
        assert!(peer_score_thresholds().validate().is_ok());
        for active_validators in [64, 10_000, MAINNET_ACTIVE_VALIDATORS] {
            for current_slot in [0, 100, 15_000_000] {
                let params = PeerScoreSettings::new(8, active_validators, current_slot)
                    .peer_score_params(&topics());
                assert!(
                    params.validate().is_ok(),
                    "{active_validators} validators at slot {current_slot}: {:?}",
                    params.validate()
                );
            }
        }
    }

    #[test]
    fn only_the_topics_lighthouse_scores_are_scored() {
        initialize_test_network_spec();
        let params = PeerScoreSettings::new(8, MAINNET_ACTIVE_VALIDATORS, 15_000_000)
            .peer_score_params(&topics());
        // Block, aggregate, exit, two slashings and the attestation subnets.
        assert_eq!(params.topics.len(), 5 + ATTESTATION_SUBNET_COUNT as usize);
        let unscored = |kind| GossipTopic {
            fork: B32::from([1, 2, 3, 4]),
            kind,
        };
        assert!(!params.topics.contains_key(&TopicHash::from(unscored(
            GossipTopicKind::DataColumnSidecar(3)
        ))));
        assert!(!params.topics.contains_key(&TopicHash::from(unscored(
            GossipTopicKind::SyncCommitteeContributionAndProof
        ))));
    }

    /// Lighthouse's values for a mainnet chain with a million active validators.
    #[test]
    fn mainnet_values_match_lighthouse() {
        initialize_test_network_spec();
        let settings = PeerScoreSettings::new(8, MAINNET_ACTIVE_VALIDATORS, 15_000_000);
        let block = settings
            .topic_score_params(&GossipTopicKind::BeaconBlock)
            .unwrap();
        assert_eq!(block.time_in_mesh_cap, 300.0);
        // An invalid block costs as much as the most a peer can earn from all topics.
        assert!(
            (block.invalid_message_deliveries_weight * block.topic_weight + max_positive_score())
                .abs()
                < 1e-9
        );
        assert_eq!(settings.committees_per_slot(), 64);
        // 2048 committees of about 488, each with 16 expected aggregators: 16 per committee per
        // slot, 64 committees per slot.
        let aggregators = settings.aggregators_per_slot();
        assert!((aggregators - 64.0 * 16.27).abs() < 64.0, "{aggregators}");
    }
}
