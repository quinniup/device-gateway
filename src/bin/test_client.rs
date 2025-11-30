use bytes::{BufMut, Bytes, BytesMut};
use cloud_gateway_32960_rs::protocol::{Command, GbtFrame};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::time::Duration;
use log::{info, error, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logger if not already initialized (use RUST_LOG=info)
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::try_init().ok();

    let addr = "127.0.0.1:32960";
    info!("Connecting to {}...", addr);

    let mut stream = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to {}: {}", addr, e);
            return Ok(());
        }
    };
    info!("Connected to server!");

    // Shared VIN for this session
    let vin = "L0123456789ABCDEF";

    // --- Scenario 1: Login ---
    info!("\n[1] Sending Login Request (0x01)...");
    // Payload: Collection Time (6) + Serial (2) + ICCID (20) + ...
    let mut login_payload = BytesMut::new();
    login_payload.extend_from_slice(&[23, 11, 30, 12, 00, 00]); // Time: 2023-11-30 12:00:00
    login_payload.extend_from_slice(&[0x00, 0x01]); // Serial No
    login_payload.extend_from_slice(&[b'I', b'C', b'C', b'I', b'D', b'1', b'2', b'3', b'4', b'5', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // ICCID (padded)
    login_payload.extend_from_slice(&[0x01, 0x02, 0x03]); // Sub-system components count etc (dummy)

    send_frame(&mut stream, Command::Login, vin, login_payload.freeze()).await?;

    // Expect Login Response
    info!("Waiting for Login Response...");
    match read_frame(&mut stream).await? {
        Some(resp) => {
            info!("Received Response: Cmd={:?}, VIN={}", resp.command, resp.vin);
            if matches!(resp.command, Command::Login) {
                info!("Login Successful!");
            } else {
                warn!("Unexpected response command");
            }
        },
        None => warn!("Server closed connection before sending login response"),
    }

    tokio::time::sleep(Duration::from_secs(1)).await;

    // --- Scenario 2: Real-time Data ---
    info!("\n[2] Sending Real-time Data (0x02)...");
    // Payload: Time (6) + Info Type (1) + Info Payload (...)
    let mut realtime_data = BytesMut::new();
    realtime_data.extend_from_slice(&[23, 11, 30, 12, 00, 05]); // Time
    // Mock Vehicle Data (Type 0x01)
    realtime_data.put_u8(0x01); // Type 1: Whole Vehicle Data
    // For simplicity, just putting some dummy bytes as the "content" of vehicle data
    // In reality, this follows specific structure: [Operation Mode] [Speed] [Total Km] [Voltage] ...
    realtime_data.extend_from_slice(&[0x01, 0x00, 0x64, 0x03, 0xE8]); // Dummy values
    
    send_frame(&mut stream, Command::RealtimeData, vin, realtime_data.freeze()).await?;
    info!("Real-time data sent.");
    
    tokio::time::sleep(Duration::from_secs(1)).await;

    // --- Scenario 3: Heartbeat ---
    info!("\n[3] Sending Heartbeat (0x07)...");
    // Heartbeat usually empty payload (just header)
    send_frame(&mut stream, Command::Heartbeat, vin, Bytes::new()).await?;
    info!("Heartbeat sent.");

    tokio::time::sleep(Duration::from_secs(1)).await;

    // --- Scenario 4: Resend Data ---
    info!("\n[4] Sending Resend Data (0x03)...");
    // Structure similar to Real-time but indicates historical data
    let mut resend_data = BytesMut::new();
    resend_data.extend_from_slice(&[23, 11, 30, 11, 59, 00]); // Older Time
    resend_data.put_u8(0x02); // Type 2: Drive Motor Data (Mock)
    resend_data.extend_from_slice(&[0x01, 0x02, 0x03]); // Dummy motor data
    
    send_frame(&mut stream, Command::ResendData, vin, resend_data.freeze()).await?;
    info!("Resend data sent.");

    tokio::time::sleep(Duration::from_secs(1)).await;

    // --- Scenario 5: Logout ---
    info!("\n[5] Sending Logout Request (0x04)...");
    // Payload: Time (6) + Serial (2)
    let mut logout_payload = BytesMut::new();
    logout_payload.extend_from_slice(&[23, 11, 30, 12, 10, 00]);
    logout_payload.put_u16(0x0005); // Serial
    
    send_frame(&mut stream, Command::Logout, vin, logout_payload.freeze()).await?;
    info!("Logout sent. Closing connection.");

    // Allow some time for server to process before we close
    tokio::time::sleep(Duration::from_secs(1)).await;
    
    Ok(())
}

async fn send_frame(stream: &mut TcpStream, cmd: Command, vin: &str, payload: Bytes) -> Result<(), Box<dyn std::error::Error>> {
    let frame = GbtFrame::new(cmd, 0xFE, vin, 0x01, payload);
    let encoded = frame.encode();
    // print hex dump for debug
    // println!("Sending bytes: {:02X?}", encoded.as_ref());
    stream.write_all(&encoded).await?;
    Ok(())
}

async fn read_frame(stream: &mut TcpStream) -> Result<Option<GbtFrame>, Box<dyn std::error::Error>> {
    let mut buf = BytesMut::with_capacity(1024);
    let mut temp_buf = [0u8; 1024];
    
    loop {
        // Try decoding existing buffer first
        match GbtFrame::decode(&mut buf) {
            Ok(Some(frame)) => return Ok(Some(frame)),
            Ok(None) => {
                // Need more data
                let n = stream.read(&mut temp_buf).await?;
                if n == 0 {
                    return Ok(None); // EOF
                }
                buf.extend_from_slice(&temp_buf[0..n]);
            }
            Err(e) => return Err(format!("Protocol Error: {}", e).into()),
        }
    }
}
