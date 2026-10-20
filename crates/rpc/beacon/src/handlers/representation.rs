use actix_web::{HttpRequest, HttpResponse, http::header::ACCEPT};
use ream_api_types_beacon::responses::{BeaconVersionedResponse, ETH_CONSENSUS_VERSION_HEADER};
use ream_api_types_common::content_type::{ContentType, SSZ_CONTENT_TYPE};
use ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH;
use ream_network_spec::networks::beacon_network_spec;
use serde::Serialize;
use ssz::Encode;

/// State and block checkpoint responses use the same SSZ negotiation and fork metadata.
pub(super) fn checkpoint_response<T: Serialize + Encode>(
    request: &HttpRequest,
    slot: u64,
    data: T,
) -> HttpResponse {
    let spec = beacon_network_spec();
    let version = if slot / SLOTS_PER_EPOCH >= spec.fulu_fork_epoch {
        "fulu"
    } else {
        "electra"
    };
    let mut response = HttpResponse::Ok();
    response.insert_header((ETH_CONSENSUS_VERSION_HEADER, version));
    match ContentType::from(request.headers().get(ACCEPT)) {
        ContentType::Ssz => response
            .content_type(SSZ_CONTENT_TYPE)
            .body(data.as_ssz_bytes()),
        ContentType::Json => {
            let mut body = BeaconVersionedResponse::new(data);
            body.version = version.into();
            response.json(body)
        }
    }
}

#[cfg(test)]
mod tests {
    use actix_web::{body::to_bytes, test::TestRequest};

    use super::*;

    #[actix_web::test]
    async fn returns_ssz_bytes_for_checkpoint_clients() {
        ream_network_spec::networks::initialize_test_network_spec();
        let request = TestRequest::default()
            .insert_header((
                ACCEPT,
                "application/octet-stream;q=1.0,application/json;q=0.9",
            ))
            .to_http_request();
        let response = checkpoint_response(&request, 0, 42_u64);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            SSZ_CONTENT_TYPE
        );
        assert!(
            response
                .headers()
                .contains_key(ETH_CONSENSUS_VERSION_HEADER)
        );
        assert_eq!(
            to_bytes(response.into_body()).await.unwrap().as_ref(),
            42_u64.as_ssz_bytes()
        );
    }
}
