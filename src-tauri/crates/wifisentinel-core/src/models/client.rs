// wifisentinel-core/src/models/client.rs
// ClientDevice domain model.

use chrono::{DateTime, Utc};
use macaddr::MacAddr6;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A wireless client device observed during scanning or capture.
///
/// Client observation is only possible during active packet capture.
/// During passive WLAN scanning, clients are not directly observable —
/// only the AP they are associated with is reported.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientDevice {
    /// Unique internal identifier.
    pub id: Uuid,

    /// Client hardware MAC address.
    pub mac_address: MacAddr6,

    /// OUI-based vendor lookup.
    pub vendor: Option<String>,

    /// BSSID the client is currently or most recently associated with.
    pub associated_bssid: Option<MacAddr6>,

    /// SSID of the associated network.
    pub associated_ssid: Option<String>,

    /// Internal ID of the associated AP.
    pub associated_ap_id: Option<Uuid>,

    /// Last observed signal strength in dBm (as seen by the sniffer).
    pub rssi_dbm: Option<i16>,

    /// Whether this is a locally administered (possibly spoofed/randomized) MAC.
    pub is_randomized_mac: bool,

    /// Whether the user has marked this client as trusted.
    pub is_trusted: bool,

    /// Observed anomaly flags.
    pub anomaly_flags: Vec<ClientAnomalyFlag>,

    /// AP associations history.
    pub association_history: Vec<AssociationEvent>,

    /// When this client was first observed.
    pub first_seen: DateTime<Utc>,

    /// When this client was last observed.
    pub last_seen: DateTime<Utc>,

    /// Number of frames observed from/to this client.
    pub frame_count: u64,

    /// Whether client was observed via probe requests.
    pub probe_requests_observed: Vec<String>,
}

/// An anomaly flag associated with a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientAnomalyFlag {
    RandomizedMac,
    RapidApRoaming,
    UnexpectedVendor,
    SuspiciousProbes,
    Other(String),
}

/// An AP association event for a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssociationEvent {
    pub timestamp: DateTime<Utc>,
    pub bssid: MacAddr6,
    pub ssid: Option<String>,
    pub event_type: AssociationEventType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssociationEventType {
    Associated,
    Disassociated,
    Reassociated,
    ProbeRequest,
}

impl ClientDevice {
    /// Returns true if the MAC address appears to be a locally-administered
    /// (randomized/spoofed) address.
    ///
    /// Per IEEE 802, locally administered addresses have bit 1 of the first
    /// octet set.
    pub fn is_locally_administered(mac: &MacAddr6) -> bool {
        let octets = mac.as_bytes();
        octets[0] & 0x02 != 0
    }
}
