use actix_web::web::{ServiceConfig, scope};

pub mod beacon;
pub mod config;
pub mod debug;
pub mod node;
pub mod validator;

pub fn get_v1_routes(config: &mut ServiceConfig) {
    config.service(
        scope("/eth/v1")
            .configure(beacon::register_beacon_routes)
            .configure(node::register_node_routes)
            .configure(config::register_config_routes)
            .configure(validator::register_validator_routes_v1)
            .configure(debug::register_debug_routes_v1),
    );
}

pub fn get_v2_routes(config: &mut ServiceConfig) {
    config.service(
        scope("/eth/v2")
            .configure(debug::register_debug_routes_v2)
            .configure(beacon::register_beacon_routes_v2)
            .configure(validator::register_validator_routes_v2),
    );
}

pub fn get_v3_routes(config: &mut ServiceConfig) {
    config.service(scope("/eth/v3").configure(validator::register_validator_routes_v3));
}

pub fn register_routers(config: &mut ServiceConfig) {
    config
        .configure(get_v1_routes)
        .configure(get_v2_routes)
        .configure(get_v3_routes);
}

#[cfg(test)]
mod tests {
    use actix_web::{App, http::StatusCode, test};

    use super::*;

    #[actix_web::test]
    async fn validator_client_routes_use_the_spec_paths() {
        let app = test::init_service(App::new().configure(register_routers)).await;

        for uri in [
            "/eth/v2/validator/duties/proposer/0",
            "/eth/v1/beacon/states/head/validators/0",
        ] {
            let request = test::TestRequest::get().uri(uri).to_request();
            let response = test::call_service(&app, request).await;
            assert_ne!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        }

        let request = test::TestRequest::get()
            .uri("/eth/v1/beacon/states/head/validator/0")
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
