// wifisentinel-capture/src/dot11.rs
// 802.11 MAC frame parser.

use macaddr::MacAddr6;
use wifisentinel_core::models::{FrameSubtype, FrameType, PacketMetadata, ManagementFrameInfo};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Parse an 802.11 frame (without Radiotap header).
/// Returns a partially-filled PacketMetadata.
pub fn parse_dot11_frame(
    data: &[u8],
    session_id: Uuid,
    timestamp: DateTime<Utc>,
    channel: Option<u8>,
    rssi_dbm: Option<i16>,
    data_rate_mbps: Option<f32>,
    has_radiotap: bool,
) -> Option<PacketMetadata> {
    // 802.11 MAC header is at minimum 10 bytes (some control frames).
    // Standard management/data: 24 bytes.
    if data.len() < 10 {
        return None;
    }

    let frame_control = u16::from_le_bytes([data[0], data[1]]);
    let type_bits = ((frame_control >> 2) & 0x03) as u8;
    let subtype_bits = ((frame_control >> 4) & 0x0F) as u8;

    let frame_type = FrameType::from_bits(type_bits);
    let frame_subtype = FrameSubtype::from_bits(type_bits, subtype_bits);

    let is_protected = (frame_control >> 14) & 1 == 1; // Protected frame bit
    let is_retry = (frame_control >> 11) & 1 == 1;

    // Sequence control (bytes 22-23 for most frames).
    let sequence_number = if data.len() >= 24 {
        let seq_ctrl = u16::from_le_bytes([data[22], data[23]]);
        Some(seq_ctrl >> 4) // Upper 12 bits
    } else {
        None
    };

    // MAC addresses depend on frame type and To DS/From DS bits.
    let to_ds = (frame_control >> 8) & 1 == 1;
    let from_ds = (frame_control >> 9) & 1 == 1;

    let (addr1, addr2, addr3) = if data.len() >= 22 {
        (
            Some(parse_mac(&data[4..10])),
            Some(parse_mac(&data[10..16])),
            Some(parse_mac(&data[16..22])),
        )
    } else if data.len() >= 10 {
        (Some(parse_mac(&data[4..10])), None, None)
    } else {
        (None, None, None)
    };

    // Derive source, destination, BSSID based on DS bits.
    let (source, destination, bssid) = match (to_ds, from_ds) {
        (false, false) => (addr2, addr1, addr3),      // IBSS / management
        (true, false) => (addr2, addr3, addr1),       // STA to AP
        (false, true) => (addr3, addr1, addr2),       // AP to STA
        (true, true) => (addr3, addr2, addr1),        // WDS
    };

    // Parse management frame body if applicable.
    let management_info = if matches!(frame_type, FrameType::Management) && data.len() > 24 {
        parse_management_body(&frame_subtype, &data[24..])
    } else {
        None
    };

    Some(PacketMetadata {
        id: Uuid::new_v4(),
        capture_session_id: session_id,
        timestamp,
        frame_type,
        frame_subtype,
        source_mac: source,
        destination_mac: destination,
        bssid,
        channel,
        rssi_dbm,
        data_rate_mbps,
        has_radiotap,
        payload_bytes: data.len() as u32,
        is_encrypted: is_protected,
        is_retry,
        sequence_number,
        management_info,
    })
}

fn parse_mac(bytes: &[u8]) -> MacAddr6 {
    MacAddr6::from([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]])
}

/// Parse management frame body into ManagementFrameInfo.
fn parse_management_body(subtype: &FrameSubtype, body: &[u8]) -> Option<ManagementFrameInfo> {
    match subtype {
        FrameSubtype::Beacon | FrameSubtype::ProbeResponse => {
            parse_beacon_probe_body(body)
        }
        FrameSubtype::ProbeRequest => {
            // Probe request: fixed params (0 bytes) then IEs.
            parse_probe_request_body(body)
        }
        FrameSubtype::Disassociation | FrameSubtype::Deauthentication => {
            if body.len() >= 2 {
                Some(ManagementFrameInfo {
                    ssid: None,
                    supported_rates: vec![],
                    reason_code: Some(u16::from_le_bytes([body[0], body[1]])),
                    status_code: None,
                    beacon_interval: None,
                    capability_info: None,
                    ds_channel: None,
                    rsn_info: None,
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

fn parse_beacon_probe_body(body: &[u8]) -> Option<ManagementFrameInfo> {
    // Fixed parameters: 8 bytes (timestamp) + 2 (beacon interval) + 2 (capability).
    if body.len() < 12 {
        return None;
    }

    let beacon_interval = u16::from_le_bytes([body[8], body[9]]);
    let capability_info = u16::from_le_bytes([body[10], body[11]]);

    let mut info = ManagementFrameInfo {
        ssid: None,
        supported_rates: vec![],
        reason_code: None,
        status_code: None,
        beacon_interval: Some(beacon_interval),
        capability_info: Some(capability_info),
        ds_channel: None,
        rsn_info: None,
    };

    // Parse IEs starting at offset 12.
    parse_info_elements(&body[12..], &mut info);

    Some(info)
}

fn parse_probe_request_body(body: &[u8]) -> Option<ManagementFrameInfo> {
    let mut info = ManagementFrameInfo {
        ssid: None,
        supported_rates: vec![],
        reason_code: None,
        status_code: None,
        beacon_interval: None,
        capability_info: None,
        ds_channel: None,
        rsn_info: None,
    };
    parse_info_elements(body, &mut info);
    Some(info)
}

fn parse_info_elements(ies: &[u8], info: &mut ManagementFrameInfo) {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let id = ies[i];
        let len = ies[i + 1] as usize;
        i += 2;
        if i + len > ies.len() { break; }
        let data = &ies[i..i + len];

        match id {
            // SSID
            0 => {
                if let Ok(s) = std::str::from_utf8(data) {
                    let trimmed = s.trim_matches('\0');
                    if !trimmed.is_empty() {
                        info.ssid = Some(trimmed.to_string());
                    }
                }
            }
            // Supported Rates
            1 => {
                for &rate_byte in data {
                    let rate = (rate_byte & 0x7F) as f32 * 0.5;
                    info.supported_rates.push(rate);
                }
            }
            // DS Parameter Set (channel)
            3 if len == 1 => {
                info.ds_channel = Some(data[0]);
            }
            _ => {}
        }

        i += len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_too_short_frame() {
        let result = parse_dot11_frame(
            &[0u8; 5], Uuid::new_v4(), Utc::now(), None, None, None, false
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_beacon_frame_type() {
        // Minimal beacon frame: FC = 0x0080 (Management, Beacon subtype)
        let mut data = vec![0u8; 24];
        data[0] = 0x80; // type/subtype
        data[1] = 0x00; // frame control high byte
        let result = parse_dot11_frame(
            &data, Uuid::new_v4(), Utc::now(), None, None, None, false
        );
        assert!(result.is_some());
        let pkt = result.unwrap();
        assert!(matches!(pkt.frame_type, FrameType::Management));
        assert!(matches!(pkt.frame_subtype, FrameSubtype::Beacon));
    }
}
