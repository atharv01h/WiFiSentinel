// wifisentinel-core/src/models/packet.rs
// PacketMetadata domain model — parsed from raw 802.11 frames.

use chrono::{DateTime, Utc};
use macaddr::MacAddr6;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Metadata extracted from an 802.11 frame during live capture or PCAP analysis.
///
/// This never contains raw payload bytes — only structural metadata safe to
/// store and display. Content reconstruction is explicitly out of scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketMetadata {
    pub id: Uuid,

    /// Capture session this packet belongs to.
    pub capture_session_id: Uuid,

    /// Frame reception timestamp.
    pub timestamp: DateTime<Utc>,

    /// Frame type (Management / Control / Data / Extension).
    pub frame_type: FrameType,

    /// Frame subtype.
    pub frame_subtype: FrameSubtype,

    /// Transmitter address (TA) / source MAC.
    pub source_mac: Option<MacAddr6>,

    /// Receiver address (RA) / destination MAC.
    pub destination_mac: Option<MacAddr6>,

    /// BSSID field from 802.11 header.
    pub bssid: Option<MacAddr6>,

    /// Channel the frame was captured on.
    pub channel: Option<u8>,

    /// Signal strength from Radiotap header.
    pub rssi_dbm: Option<i16>,

    /// Data rate in Mbps from Radiotap header.
    pub data_rate_mbps: Option<f32>,

    /// Whether a valid Radiotap header was present.
    pub has_radiotap: bool,

    /// Size of the frame payload in bytes (excludes FCS when stripped).
    pub payload_bytes: u32,

    /// Whether the frame was encrypted (Protected bit set).
    pub is_encrypted: bool,

    /// Retry bit.
    pub is_retry: bool,

    /// Sequence number from MAC header.
    pub sequence_number: Option<u16>,

    /// Management frame-specific information.
    pub management_info: Option<ManagementFrameInfo>,
}

/// 802.11 frame types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameType {
    Management,
    Control,
    Data,
    Extension,
    Unknown(u8),
}

impl FrameType {
    pub fn from_bits(type_bits: u8) -> Self {
        match type_bits & 0x03 {
            0 => FrameType::Management,
            1 => FrameType::Control,
            2 => FrameType::Data,
            3 => FrameType::Extension,
            _ => FrameType::Unknown(type_bits),
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            FrameType::Management => "Management",
            FrameType::Control => "Control",
            FrameType::Data => "Data",
            FrameType::Extension => "Extension",
            FrameType::Unknown(_) => "Unknown",
        }
    }
}

/// 802.11 frame subtypes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameSubtype {
    // Management subtypes
    AssociationRequest,
    AssociationResponse,
    ReassociationRequest,
    ReassociationResponse,
    ProbeRequest,
    ProbeResponse,
    Beacon,
    Atim,
    Disassociation,
    Authentication,
    Deauthentication,
    Action,
    // Control subtypes
    BlockAckRequest,
    BlockAck,
    PsPoll,
    Rts,
    Cts,
    Ack,
    CfEnd,
    // Data subtypes
    Data,
    DataCfAck,
    DataCfPoll,
    Null,
    QosData,
    QosNull,
    // Other
    Unknown(u8),
}

impl FrameSubtype {
    pub fn from_bits(frame_type: u8, subtype_bits: u8) -> Self {
        match (frame_type & 0x03, subtype_bits & 0x0F) {
            // Management
            (0, 0) => FrameSubtype::AssociationRequest,
            (0, 1) => FrameSubtype::AssociationResponse,
            (0, 2) => FrameSubtype::ReassociationRequest,
            (0, 3) => FrameSubtype::ReassociationResponse,
            (0, 4) => FrameSubtype::ProbeRequest,
            (0, 5) => FrameSubtype::ProbeResponse,
            (0, 8) => FrameSubtype::Beacon,
            (0, 9) => FrameSubtype::Atim,
            (0, 10) => FrameSubtype::Disassociation,
            (0, 11) => FrameSubtype::Authentication,
            (0, 12) => FrameSubtype::Deauthentication,
            (0, 13) => FrameSubtype::Action,
            // Control
            (1, 8) => FrameSubtype::BlockAckRequest,
            (1, 9) => FrameSubtype::BlockAck,
            (1, 10) => FrameSubtype::PsPoll,
            (1, 11) => FrameSubtype::Rts,
            (1, 12) => FrameSubtype::Cts,
            (1, 13) => FrameSubtype::Ack,
            (1, 14) => FrameSubtype::CfEnd,
            // Data
            (2, 0) => FrameSubtype::Data,
            (2, 1) => FrameSubtype::DataCfAck,
            (2, 2) => FrameSubtype::DataCfPoll,
            (2, 4) => FrameSubtype::Null,
            (2, 8) => FrameSubtype::QosData,
            (2, 12) => FrameSubtype::QosNull,
            (_, s) => FrameSubtype::Unknown(s),
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            FrameSubtype::AssociationRequest => "Association Request",
            FrameSubtype::AssociationResponse => "Association Response",
            FrameSubtype::ReassociationRequest => "Reassociation Request",
            FrameSubtype::ReassociationResponse => "Reassociation Response",
            FrameSubtype::ProbeRequest => "Probe Request",
            FrameSubtype::ProbeResponse => "Probe Response",
            FrameSubtype::Beacon => "Beacon",
            FrameSubtype::Atim => "ATIM",
            FrameSubtype::Disassociation => "Disassociation",
            FrameSubtype::Authentication => "Authentication",
            FrameSubtype::Deauthentication => "Deauthentication",
            FrameSubtype::Action => "Action",
            FrameSubtype::BlockAckRequest => "Block Ack Request",
            FrameSubtype::BlockAck => "Block Ack",
            FrameSubtype::PsPoll => "PS-Poll",
            FrameSubtype::Rts => "RTS",
            FrameSubtype::Cts => "CTS",
            FrameSubtype::Ack => "ACK",
            FrameSubtype::CfEnd => "CF-End",
            FrameSubtype::Data => "Data",
            FrameSubtype::DataCfAck => "Data+CF-Ack",
            FrameSubtype::DataCfPoll => "Data+CF-Poll",
            FrameSubtype::Null => "Null",
            FrameSubtype::QosData => "QoS Data",
            FrameSubtype::QosNull => "QoS Null",
            FrameSubtype::Unknown(_) => "Unknown",
        }
    }
}

/// Information extracted from management frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementFrameInfo {
    /// SSID element (from Beacon / Probe Response / Probe Request).
    pub ssid: Option<String>,

    /// Supported rates (in Mbps).
    pub supported_rates: Vec<f32>,

    /// Reason code (for Disassociation / Deauthentication).
    pub reason_code: Option<u16>,

    /// Status code (for Association / Authentication responses).
    pub status_code: Option<u16>,

    /// Beacon interval in TUs.
    pub beacon_interval: Option<u16>,

    /// Capability info field.
    pub capability_info: Option<u16>,

    /// DS Parameter Set — channel.
    pub ds_channel: Option<u8>,

    /// RSN (WPA2/3) information, if present.
    pub rsn_info: Option<RsnInfo>,
}

/// Parsed RSN/WPA2 information element.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsnInfo {
    pub version: u16,
    pub group_cipher: String,
    pub pairwise_ciphers: Vec<String>,
    pub akm_suites: Vec<String>,
    pub pmf_capable: bool,
    pub pmf_required: bool,
}
