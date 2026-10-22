use std::collections::HashMap;

use anyhow::anyhow;
use libp2p::{
    PeerId,
    gossipsub::{MessageAcceptance, MessageId},
    swarm::ConnectionId,
};
use ream_consensus_beacon::custody_group::CustodyAssignment;
use ream_p2p::{
    gossipsub::beacon::topics::GossipTopic,
    network::beacon::channel::{GossipMessage, P2PMessage, P2PResponse},
};
use ream_req_resp::{
    beacon::messages::BeaconResponseMessage, error::ReqRespError, handler::RespMessage,
    messages::ResponseMessage,
};
use tokio::sync::mpsc;
use tracing::warn;

#[derive(Clone)]
pub struct P2PSender(pub mpsc::UnboundedSender<P2PMessage>);

impl P2PSender {
    pub fn raise_custody(&self, custody: CustodyAssignment) {
        if let Err(err) = self.0.send(P2PMessage::RaiseCustody(custody)) {
            warn!("Failed to send a custody raise: {err}");
        }
    }

    pub fn send_gossip(&self, message: GossipMessage) {
        if let Err(err) = self.0.send(P2PMessage::Gossip(message)) {
            warn!("Failed to send gossip message: {err}");
        }
    }

    pub fn subscribe_for_duty(&self, topic: GossipTopic, until_slot: u64) {
        if let Err(err) = self
            .0
            .send(P2PMessage::SubscribeForDuty { topic, until_slot })
        {
            warn!("Failed to send duty subscription: {err}");
        }
    }

    pub fn attestation_duty_subnets(&self, subnets: HashMap<u64, u64>) {
        if let Err(err) = self.0.send(P2PMessage::AttestationDutySubnets(subnets)) {
            warn!("Failed to send attestation duty subnets: {err}");
        }
    }

    pub fn report_gossip_validation(
        &self,
        message_id: MessageId,
        propagation_source: PeerId,
        acceptance: MessageAcceptance,
    ) {
        if let Err(err) = self.0.send(P2PMessage::ReportGossipValidation {
            message_id,
            propagation_source,
            acceptance,
        }) {
            warn!("Failed to send gossip validation report: {err}");
        }
    }

    pub fn send_response(
        &self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        stream_id: u64,
        message: BeaconResponseMessage,
    ) {
        if let Err(err) = self.0.send(P2PMessage::Response(P2PResponse {
            peer_id,
            connection_id,
            stream_id,
            message: Box::new(RespMessage::Response(Box::new(ResponseMessage::Beacon(
                message.into(),
            )))),
        })) {
            warn!("Failed to send P2P response: {err}");
        }
    }

    pub fn send_end_of_stream_response(
        &self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        stream_id: u64,
    ) {
        if let Err(err) = self.0.send(P2PMessage::Response(P2PResponse {
            peer_id,
            connection_id,
            stream_id,
            message: Box::new(RespMessage::EndOfStream),
        })) {
            warn!("Failed to send end of stream response: {err}");
        }
    }

    pub fn send_error_response(
        &self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        stream_id: u64,
        error: &str,
    ) {
        if let Err(err) = self.0.send(P2PMessage::Response(P2PResponse {
            peer_id,
            connection_id,
            stream_id,
            message: Box::new(RespMessage::Error(ReqRespError::Anyhow(anyhow!(
                error.to_string()
            )))),
        })) {
            warn!("Failed to send error response: {err}");
        }
    }

    pub fn send_resource_unavailable(
        &self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        stream_id: u64,
        error: &str,
    ) {
        if let Err(err) = self.0.send(P2PMessage::Response(P2PResponse {
            peer_id,
            connection_id,
            stream_id,
            message: Box::new(RespMessage::Error(ReqRespError::ResourceUnavailable(
                error.to_string(),
            ))),
        })) {
            warn!("Failed to send resource-unavailable response: {err}");
        }
    }

    pub fn send_invalid_request(
        &self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        stream_id: u64,
        error: &str,
    ) {
        if let Err(err) = self.0.send(P2PMessage::Response(P2PResponse {
            peer_id,
            connection_id,
            stream_id,
            message: Box::new(RespMessage::Error(ReqRespError::InvalidData(
                error.to_string(),
            ))),
        })) {
            warn!("Failed to send invalid-request response: {err}");
        }
    }
}
