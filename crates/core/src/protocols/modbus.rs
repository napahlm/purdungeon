/// Check if a TCP segment looks like Modbus TCP.
///
/// Criteria:
/// - Either source or destination port is 502
/// - Payload is at least 7 bytes (minimum MBAP header)
/// - MBAP protocol identifier (bytes 2-3) is 0x0000
/// - MBAP length field (bytes 4-5) is between 1 and 253
#[must_use]
pub fn is_modbus_tcp(src_port: u16, dst_port: u16, payload: &[u8]) -> bool {
    if src_port != 502 && dst_port != 502 {
        return false;
    }

    if payload.len() < 7 {
        return false;
    }

    // MBAP header: transaction_id (2) | protocol_id (2) | length (2) | unit_id (1)
    let protocol_id = u16::from_be_bytes([payload[2], payload[3]]);
    if protocol_id != 0x0000 {
        return false;
    }

    let length = u16::from_be_bytes([payload[4], payload[5]]);
    (1..=253).contains(&length)
}
