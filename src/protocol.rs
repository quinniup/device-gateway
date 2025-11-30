use bytes::{BufMut, Bytes, BytesMut};
#[derive(Debug, Clone)]
pub enum Command {
    Login = 0x01,
    RealtimeData = 0x02,
    ResendData = 0x03,
    Logout = 0x04,
    PlatformLogin = 0x05,
    PlatformLogout = 0x06,
    Heartbeat = 0x07,
    TimeSync = 0x08,
    Unknown = 0xFF,
}

impl From<u8> for Command {
    fn from(v: u8) -> Self {
        match v {
            0x01 => Command::Login,
            0x02 => Command::RealtimeData,
            0x03 => Command::ResendData,
            0x04 => Command::Logout,
            0x05 => Command::PlatformLogin,
            0x06 => Command::PlatformLogout,
            0x07 => Command::Heartbeat,
            0x08 => Command::TimeSync,
            _ => Command::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GbtFrame {
    pub command: Command,
    pub response_indicator: u8,
    pub vin: String,
    pub encrypt_mode: u8,
    pub payload: Bytes,
}

impl GbtFrame {
    pub fn new(cmd: Command, resp: u8, vin: &str, encrypt: u8, payload: Bytes) -> Self {
        Self {
            command: cmd,
            response_indicator: resp,
            vin: vin.to_string(),
            encrypt_mode: encrypt,
            payload,
        }
    }

    pub fn decode(src: &mut BytesMut) -> Result<Option<Self>, String> {
        if src.len() < 24 { // Minimal length: 2 (##) + 1 (cmd) + 1 (resp) + 17 (vin) + 1 (enc) + 2 (len) + 0 (data) + 1 (bcc) = 25 actually.
             // Wait for more data
             return Ok(None);
        }

        // Check start bytes
        if src[0] != 0x23 || src[1] != 0x23 {
            // Invalid start, maybe need to skip bytes or error
            // For simplicity, let's assume we consume bad bytes or fail
            return Err("Invalid start bytes".to_string());
        }

        // We need at least the header to know length
        // 2 + 1 + 1 + 17 + 1 + 2 = 24 bytes header
        if src.len() < 24 {
            return Ok(None);
        }

        let data_len = u16::from_be_bytes([src[22], src[23]]) as usize;
        let full_len = 24 + data_len + 1; // Header + Data + BCC

        if src.len() < full_len {
            return Ok(None);
        }

        // We have a full frame
        let mut frame_data = src.split_to(full_len);
        
        // Verify BCC
        let mut bcc = 0u8;
        for i in 2..full_len-1 { // BCC is XOR from Command (index 2) to Data end
            bcc ^= frame_data[i];
        }
        
        if bcc != frame_data[full_len-1] {
            return Err(format!("BCC mismatch: expected {:02X}, got {:02X}", bcc, frame_data[full_len-1]));
        }

        let cmd = Command::from(frame_data[2]);
        let resp_ind = frame_data[3];
        let vin_bytes = &frame_data[4..21];
        let vin = String::from_utf8_lossy(vin_bytes).to_string();
        let encrypt = frame_data[21];
        let payload = frame_data.split_off(24).split_to(data_len).freeze();

        Ok(Some(GbtFrame {
            command: cmd,
            response_indicator: resp_ind,
            vin,
            encrypt_mode: encrypt,
            payload,
        }))
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u8(0x23);
        buf.put_u8(0x23);
        
        let cmd_u8 = match self.command {
            Command::Login => 0x01,
            Command::RealtimeData => 0x02,
            Command::ResendData => 0x03,
            Command::Logout => 0x04,
            Command::PlatformLogin => 0x05,
            Command::PlatformLogout => 0x06,
            Command::Heartbeat => 0x07,
            Command::TimeSync => 0x08,
            Command::Unknown => 0xFF, // Should probably not send Unknown
        };
        buf.put_u8(cmd_u8);
        buf.put_u8(self.response_indicator);
        
        // Pad or truncate VIN to 17 bytes
        let mut vin_bytes = [0u8; 17];
        let v = self.vin.as_bytes();
        let len = v.len().min(17);
        vin_bytes[0..len].copy_from_slice(&v[0..len]);
        buf.put_slice(&vin_bytes);
        
        buf.put_u8(self.encrypt_mode);
        
        let data_len = self.payload.len() as u16;
        buf.put_u16(data_len);
        
        buf.put(self.payload.clone());
        
        // Calculate BCC
        let mut bcc = 0u8;
        // Skip first 2 bytes (##)
        for b in &buf[2..] {
            bcc ^= *b;
        }
        buf.put_u8(bcc);
        
        buf.freeze()
    }
}
