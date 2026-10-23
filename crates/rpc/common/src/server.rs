use std::{io::Result, net::SocketAddr, sync::Arc, time::Duration};

use actix_web::{
    App, HttpServer,
    middleware::Logger,
    web::{Data, ServiceConfig},
};
use tracing::info;

const HTTP_KEEP_ALIVE: Duration = Duration::from_secs(120);

/// A type alias for a function that configures the actix-web ServiceConfig.
type Configurator = dyn Fn(&mut ServiceConfig) + Send + Sync;

/// A builder for configuring and starting an RPC server.
pub struct RpcServerBuilder {
    http_socket_address: SocketAddr,
    http_allow_origin: bool,
    configurators: Vec<Arc<Configurator>>,
}

impl RpcServerBuilder {
    /// Create a new RpcServerBuilder with the given configuration.
    pub fn new(http_socket_address: SocketAddr) -> Self {
        Self {
            http_socket_address,
            http_allow_origin: false,
            configurators: Vec::new(),
        }
    }

    /// Set whether to allow CORS for all origins.
    pub fn allow_origin(mut self, allow: bool) -> Self {
        self.http_allow_origin = allow;
        self
    }

    /// Configure actix-web App by providing a closure that takes a mutable ref ServiceConfig.
    pub fn configure<F>(mut self, f: F) -> Self
    where
        F: Fn(&mut ServiceConfig) + Send + Sync + 'static,
    {
        self.configurators.push(Arc::new(f));
        self
    }

    /// Add app data to the ServiceConfig.
    pub fn with_data<T>(mut self, value: T) -> Self
    where
        T: Clone + Send + Sync + 'static,
    {
        self.configurators
            .push(Arc::new(move |config: &mut ServiceConfig| {
                config.app_data(Data::new(value.clone()));
            }));
        self
    }

    /// Add prebuilt app data to the ServiceConfig.
    pub fn with_app_data<T>(mut self, value: Data<T>) -> Self
    where
        T: Send + Sync + 'static,
    {
        self.configurators
            .push(Arc::new(move |config: &mut ServiceConfig| {
                config.app_data(value.clone());
            }));
        self
    }

    /// Start the RPC server by applying all configurations.
    pub async fn start(self) -> Result<()> {
        let configurators = self.configurators.clone();
        let configure_all = move |config: &mut ServiceConfig| {
            for configurator in &configurators {
                configurator(config);
            }
        };

        info!("starting HTTP server on {:?}", self.http_socket_address);

        let server = HttpServer::new(move || {
            App::new()
                .wrap(Logger::default())
                .configure(configure_all.clone())
        })
        // actix's default 5 s closes connections that validator clients reuse every slot, and a
        // request sent as it closes fails. Clients keep idle connections for up to 90 s.
        .keep_alive(HTTP_KEEP_ALIVE)
        .bind(self.http_socket_address)?
        // The node handles SIGINT and SIGTERM and stops this server by cancelling its task, so
        // the server ending on its own is always a failure.
        .disable_signals()
        .run();

        server.await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread::sleep,
    };

    use actix_web::{HttpResponse, web};

    use super::*;

    fn get(stream: &mut TcpStream) -> String {
        stream
            .write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("writes request");
        let mut response = [0; 256];
        let read = stream.read(&mut response).expect("reads response");
        String::from_utf8_lossy(&response[..read]).into_owned()
    }

    /// actix's default keep-alive would close the connection after 5 s.
    #[test]
    fn idle_connections_stay_open_past_five_seconds() {
        let address = TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("finds a free port");
        std::thread::spawn(move || {
            let server = RpcServerBuilder::new(address).configure(|config| {
                config.route("/ping", web::get().to(HttpResponse::Ok));
            });
            actix_web::rt::System::new().block_on(server.start())
        });
        let mut stream = (0..50)
            .find_map(|_| {
                sleep(Duration::from_millis(100));
                TcpStream::connect(address).ok()
            })
            .expect("connects to the server");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("sets read timeout");

        assert!(get(&mut stream).starts_with("HTTP/1.1 200"));
        sleep(Duration::from_secs(6));
        assert!(get(&mut stream).starts_with("HTTP/1.1 200"));
    }
}
