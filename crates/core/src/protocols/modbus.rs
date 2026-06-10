//! Modbus TCP (MBAP + PDU) parsing.
//!
//! Frames are parsed without TCP reassembly: a frame split across segments
//! fails the header checks and is skipped, while multiple frames packed into
//! one segment (common with polling traffic) are all decoded.

pub const MODBUS_PORT: u16 = 502;

/// Function codes that modify coils or registers.
const WRITE_FUNCTIONS: [u8; 6] = [0x05, 0x06, 0x0F, 0x10, 0x16, 0x17];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModbusFrame {
    pub transaction_id: u16,
    pub unit_id: u8,
    pub function_code: u8,
    pub is_exception: bool,
    pub exception_code: Option<u8>,
    pub start_address: Option<u16>,
    pub quantity: Option<u16>,
    pub is_write: bool,
}

#[must_use]
pub fn function_name(code: u8) -> &'static str {
    match code {
        0x01 => "Read Coils",
        0x02 => "Read Discrete Inputs",
        0x03 => "Read Holding Registers",
        0x04 => "Read Input Registers",
        0x05 => "Write Single Coil",
        0x06 => "Write Single Register",
        0x07 => "Read Exception Status",
        0x08 => "Diagnostics",
        0x0B => "Get Comm Event Counter",
        0x0C => "Get Comm Event Log",
        0x0F => "Write Multiple Coils",
        0x10 => "Write Multiple Registers",
        0x11 => "Report Server ID",
        0x14 => "Read File Record",
        0x15 => "Write File Record",
        0x16 => "Mask Write Register",
        0x17 => "Read/Write Multiple Registers",
        0x18 => "Read FIFO Queue",
        0x2B => "Encapsulated Interface Transport",
        _ => "Unknown Function",
    }
}

/// Quick check used to gate deeper parsing: port 502 plus a sane MBAP header.
#[must_use]
pub fn is_modbus_tcp(src_port: u16, dst_port: u16, payload: &[u8]) -> bool {
    if src_port != MODBUS_PORT && dst_port != MODBUS_PORT {
        return false;
    }
    has_valid_mbap(payload)
}

fn has_valid_mbap(payload: &[u8]) -> bool {
    if payload.len() < 8 {
        return false;
    }
    // MBAP: transaction_id (2) | protocol_id (2) | length (2) | unit_id (1)
    let protocol_id = u16::from_be_bytes([payload[2], payload[3]]);
    if protocol_id != 0x0000 {
        return false;
    }
    let length = u16::from_be_bytes([payload[4], payload[5]]);
    (2..=253).contains(&length)
}

/// Parse every complete MBAP frame in a TCP segment.
/// `is_request` should be true when the segment travels toward port 502;
/// request and response PDUs share function codes but differ in body layout.
#[must_use]
pub fn parse_frames(payload: &[u8], is_request: bool) -> Vec<ModbusFrame> {
    let mut frames = Vec::new();
    let mut offset = 0;

    while payload.len() - offset >= 8 {
        let chunk = &payload[offset..];
        if !has_valid_mbap(chunk) {
            break;
        }

        let transaction_id = u16::from_be_bytes([chunk[0], chunk[1]]);
        let length = u16::from_be_bytes([chunk[4], chunk[5]]) as usize;
        let unit_id = chunk[6];

        // length counts unit_id + PDU; the PDU starts at byte 7
        let frame_end = 6 + length;
        if chunk.len() < frame_end {
            break; // truncated frame, likely split across segments
        }
        let pdu = &chunk[7..frame_end];

        if let Some(frame) = parse_pdu(pdu, transaction_id, unit_id, is_request) {
            frames.push(frame);
        }

        offset += frame_end;
    }

    frames
}

fn parse_pdu(pdu: &[u8], transaction_id: u16, unit_id: u8, is_request: bool) -> Option<ModbusFrame> {
    let raw_code = *pdu.first()?;
    let is_exception = raw_code & 0x80 != 0;
    let function_code = raw_code & 0x7F;
    let body = &pdu[1..];

    let mut frame = ModbusFrame {
        transaction_id,
        unit_id,
        function_code,
        is_exception,
        exception_code: None,
        start_address: None,
        quantity: None,
        is_write: WRITE_FUNCTIONS.contains(&function_code),
    };

    if is_exception {
        frame.exception_code = body.first().copied();
        return Some(frame);
    }

    let be16 = |i: usize| -> Option<u16> {
        Some(u16::from_be_bytes([*body.get(i)?, *body.get(i + 1)?]))
    };

    match function_code {
        // Reads: request carries start + quantity, response only data
        0x01..=0x04 if is_request => {
            frame.start_address = be16(0);
            frame.quantity = be16(2);
        }
        // Single writes: both request and response carry address + value
        0x05 | 0x06 | 0x16 => {
            frame.start_address = be16(0);
            frame.quantity = Some(1);
        }
        // Multiple writes: request and response both lead with start + quantity
        0x0F | 0x10 => {
            frame.start_address = be16(0);
            frame.quantity = be16(2);
        }
        // Read/write multiple registers: record the write portion of the request
        0x17 if is_request => {
            frame.start_address = be16(4);
            frame.quantity = be16(6);
        }
        // Address-less functions (diagnostics, server id, ...) keep code only
        _ => {}
    }

    Some(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mbap(tid: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tid.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // protocol id
        buf.extend_from_slice(&((pdu.len() as u16 + 1).to_be_bytes()));
        buf.push(unit);
        buf.extend_from_slice(pdu);
        buf
    }

    #[test]
    fn read_holding_registers_request() {
        let payload = mbap(0x0001, 1, &[0x03, 0x00, 0x64, 0x00, 0x0A]);
        let frames = parse_frames(&payload, true);
        assert_eq!(frames.len(), 1);
        let f = &frames[0];
        assert_eq!(f.function_code, 0x03);
        assert_eq!(f.start_address, Some(100));
        assert_eq!(f.quantity, Some(10));
        assert!(!f.is_write);
        assert!(!f.is_exception);
    }

    #[test]
    fn write_single_coil_request() {
        let payload = mbap(0x0002, 3, &[0x05, 0x00, 0x10, 0xFF, 0x00]);
        let frames = parse_frames(&payload, true);
        assert_eq!(frames.len(), 1);
        let f = &frames[0];
        assert_eq!(f.function_code, 0x05);
        assert_eq!(f.start_address, Some(16));
        assert_eq!(f.quantity, Some(1));
        assert!(f.is_write);
        assert_eq!(f.unit_id, 3);
    }

    #[test]
    fn write_multiple_registers_request() {
        let payload = mbap(
            0x0010,
            1,
            &[0x10, 0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x0A, 0x01, 0x02],
        );
        let frames = parse_frames(&payload, true);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].start_address, Some(1));
        assert_eq!(frames[0].quantity, Some(2));
        assert!(frames[0].is_write);
    }

    #[test]
    fn exception_response() {
        let payload = mbap(0x0003, 1, &[0x83, 0x02]);
        let frames = parse_frames(&payload, false);
        assert_eq!(frames.len(), 1);
        let f = &frames[0];
        assert!(f.is_exception);
        assert_eq!(f.function_code, 0x03);
        assert_eq!(f.exception_code, Some(0x02));
    }

    #[test]
    fn multiple_frames_in_one_segment() {
        let mut payload = mbap(0x0001, 1, &[0x01, 0x00, 0x00, 0x00, 0x08]);
        payload.extend(mbap(0x0002, 1, &[0x03, 0x00, 0x00, 0x00, 0x02]));
        let frames = parse_frames(&payload, true);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].function_code, 0x01);
        assert_eq!(frames[1].function_code, 0x03);
    }

    #[test]
    fn truncated_frame_is_skipped() {
        let full = mbap(0x0001, 1, &[0x03, 0x00, 0x64, 0x00, 0x0A]);
        let frames = parse_frames(&full[..9], true);
        assert!(frames.is_empty());
    }

    #[test]
    fn empty_tcp_segment_is_not_modbus() {
        assert!(!is_modbus_tcp(45000, 502, &[]));
    }

    #[test]
    fn read_response_has_no_address() {
        // Response to read holding registers: fc, byte count, data
        let payload = mbap(0x0001, 1, &[0x03, 0x04, 0x00, 0x01, 0x00, 0x02]);
        let frames = parse_frames(&payload, false);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].start_address, None);
    }
}
