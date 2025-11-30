use async_trait::async_trait;
use log::{error, info};
use pingora::server::configuration::Opt;
use pingora::server::Server;
use pingora::services::Service;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use bytes::BytesMut;

use cloud_gateway_32960_rs::protocol::{GbtFrame, Command};

pub struct GbtGateway;

#[async_trait]
impl Service for GbtGateway {
    async fn start_service(&mut self, _fds: Option<Arc<tokio::sync::Mutex<pingora::server::Fds>>>, _shutdown: tokio::sync::watch::Receiver<bool>) {
        let addr = "0.0.0.0:32960";
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => {
                info!("GB/T 32960 Gateway listening on {}", addr);
                l
            }
            Err(e) => {
                error!("Failed to bind to {}: {}", addr, e);
                return;
            }
        };

        loop {
            // Check for shutdown signal if needed, but for now just accept
            // In a real implementation, you'd use tokio::select! with _shutdown
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    info!("New connection from {}", peer_addr);
                    tokio::spawn(handle_connection(stream));
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                }
            }
        }
    }

    fn name(&self) -> &str {
        "GbtGateway"
    }

    fn threads(&self) -> Option<usize> {
        None 
    }
}

async fn handle_connection(mut stream: TcpStream) {
    let mut buffer = BytesMut::with_capacity(4096);
    let mut read_buf = [0u8; 1024];

    loop {
        match stream.read(&mut read_buf).await {
            Ok(n) if n == 0 => {
                info!("Connection closed");
                return;
            },
            Ok(n) => {
                buffer.extend_from_slice(&read_buf[0..n]);
                
                // Try to decode frames from the buffer
                loop {
                    match GbtFrame::decode(&mut buffer) {
                        Ok(Some(frame)) => {
                            info!("Received Frame: Cmd={:?}, VIN={}, Len={}", frame.command, frame.vin, frame.payload.len());
                            
                            // Simple response for Login (CMD 0x01)
                            if let Command::Login = frame.command {
                                info!("Replying to Login for VIN: {}", frame.vin);
                                // Construct Login Response: Success (0x01)
                                // Data: 6 bytes time (Year, Month, Day, Hour, Min, Sec)
                                // Dummy time: 2023-10-27 12:00:00 -> 17 0A 1B 0C 00 00 (Year is relative to 2000?) No, usually byte value.
                                // Let's just send 6 zero bytes or something simple for demo.
                                let response_payload = bytes::Bytes::from_static(&[23, 10, 27, 12, 00, 00]);
                                
                                let response = GbtFrame::new(
                                    Command::Login,
                                    0x01, // Success
                                    &frame.vin,
                                    frame.encrypt_mode,
                                    response_payload
                                );
                                
                                let encoded_resp = response.encode();
                                if let Err(e) = stream.write_all(&encoded_resp).await {
                                    error!("Failed to write response: {}", e);
                                    return;
                                }
                            }
                        },
                        Ok(None) => break, // Need more data
                        Err(e) => {
                            error!("Protocol error: {}", e);
                            return; // Close connection on protocol error
                        }
                    }
                }
            }
            Err(e) => {
                error!("Connection error: {}", e);
                return;
            }
        }
    }
}

fn main() {
    // Initialize logger if not already initialized (use RUST_LOG=info)
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::try_init().ok();

    // Pingora Server setup
    let opt = Opt::default();
    let mut my_server = Server::new(Some(opt)).unwrap();
    
    my_server.bootstrap();
    
    let gateway_service = GbtGateway;
    my_server.add_service(gateway_service);
    
    info!("Starting GB/T 32960 Gateway...");
    my_server.run_forever();
}
