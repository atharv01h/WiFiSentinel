// wifisentinel-core/src/models/adapter.rs
// WirelessAdapter domain model.

use chrono::{DateTime, Utc};
use macaddr::MacAddr6;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::common::{AdapterState, Band, Capability, Phy};

/// Represents a wireless network adapter detected on the system.
///
/// All capability fields use `Capability` enum rather than bool to avoid
/// fabricating claims when the information cannot be reliably determined.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessAdapter {
    /// Unique internal identifier.
    pub id: Uuid,

    /// Short adapter name (e.g. "Wi-Fi").
    pub name: String,

    /// Full driver description (e.g. "Realtek 8822CE Wireless LAN 802.11ac PCI-E NIC").
    pub description: String,

    /// Windows interface GUID as string (e.g. "{81091cd2-4dd8-4cb0-83a7-93085cf5ceb9}").
    pub guid: String,

    /// Hardware MAC address when available.
    pub mac_address: Option<MacAddr6>,

    /// Manufacturer/vendor string from driver info.
    pub manufacturer: Option<String>,

    /// Driver version string.
    pub driver_version: Option<String>,

    /// Driver date (YYYY-MM-DD).
    pub driver_date: Option<String>,

    /// INF file name used by the driver.
    pub inf_file: Option<String>,

    /// Driver type (e.g. "Native Wi-Fi Driver").
    pub driver_type: Option<String>,

    /// Current operational state.
    pub state: AdapterState,

    /// Currently connected SSID, if any.
    pub connected_ssid: Option<String>,

    /// Currently connected BSSID, if any.
    pub connected_bssid: Option<String>,

    /// Currently active band, if connected.
    pub active_band: Option<Band>,

    /// Currently active channel, if connected.
    pub active_channel: Option<u8>,

    /// PHY/protocol in use on current connection.
    pub active_phy: Option<Phy>,

    /// Signal strength in dBm for current connection.
    pub signal_dbm: Option<i16>,

    /// Signal quality percentage (0-100) for current connection.
    pub signal_percent: Option<u8>,

    /// Receive link speed in Mbps.
    pub rx_rate_mbps: Option<f64>,

    /// Transmit link speed in Mbps.
    pub tx_rate_mbps: Option<f64>,

    /// Supported frequency bands.
    pub supported_bands: Vec<Band>,

    /// Supported PHY modes.
    pub supported_phys: Vec<Phy>,

    /// Whether the adapter supports FIPS 140 mode.
    pub fips_supported: Option<bool>,

    /// Whether the adapter supports 802.11w (Management Frame Protection).
    pub pmf_supported: Option<bool>,

    /// Whether the adapter can act as a hosted network / software AP.
    pub hosted_network_supported: Option<bool>,

    /// Raw 802.11 packet capture capability.
    pub capture_capability: Capability,

    /// Monitor mode capability.
    pub monitor_mode_capability: Capability,

    /// Compatibility score 0-100. 100 = all features supported.
    pub compatibility_score: u8,

    /// Human-readable notes explaining compatibility decisions.
    pub compatibility_notes: Vec<String>,

    /// Authentication / cipher combinations supported.
    pub supported_auth_ciphers: Vec<AuthCipherPair>,

    /// When this adapter was first observed by WiFiSentinel.
    pub first_seen: DateTime<Utc>,

    /// When this adapter was last observed.
    pub last_seen: DateTime<Utc>,
}

/// An authentication mode + cipher suite combination the adapter supports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCipherPair {
    pub auth: String,
    pub cipher: String,
}

impl WirelessAdapter {
    /// Compute a compatibility score based on actual detected capabilities.
    /// Score is deterministic given the same input — no fabrication.
    pub fn compute_compatibility_score(
        capture: &Capability,
        monitor: &Capability,
        fips: Option<bool>,
        pmf: Option<bool>,
        bands: &[Band],
    ) -> (u8, Vec<String>) {
        let mut score: u8 = 0;
        let mut notes = Vec::new();

        // Capture capability: 40 points
        match capture {
            Capability::Supported => {
                score = score.saturating_add(40);
                notes.push("Raw packet capture: Supported (+40)".into());
            }
            Capability::DriverDependent => {
                score = score.saturating_add(20);
                notes.push("Raw packet capture: Driver dependent (+20) — may require Npcap".into());
            }
            Capability::Unsupported => {
                notes.push("Raw packet capture: Unsupported (+0)".into());
            }
            Capability::Unknown => {
                score = score.saturating_add(10);
                notes.push("Raw packet capture: Unknown (+10)".into());
            }
        }

        // Monitor mode: 30 points
        match monitor {
            Capability::Supported => {
                score = score.saturating_add(30);
                notes.push("Monitor mode: Supported (+30)".into());
            }
            Capability::DriverDependent => {
                score = score.saturating_add(15);
                notes.push("Monitor mode: Driver dependent (+15)".into());
            }
            Capability::Unsupported => {
                notes.push("Monitor mode: Unsupported (+0)".into());
            }
            Capability::Unknown => {
                score = score.saturating_add(10);
                notes.push("Monitor mode: Unknown (+10)".into());
            }
        }

        // PMF: 15 points
        if let Some(true) = pmf {
            score = score.saturating_add(15);
            notes.push("Management Frame Protection (PMF/802.11w): Supported (+15)".into());
        } else if pmf.is_none() {
            score = score.saturating_add(5);
            notes.push("Management Frame Protection: Unknown (+5)".into());
        } else {
            notes.push("Management Frame Protection: Not supported (+0)".into());
        }

        // FIPS: 5 points
        if let Some(true) = fips {
            score = score.saturating_add(5);
            notes.push("FIPS 140 mode: Supported (+5)".into());
        }

        // Dual band: 10 points
        let has_5ghz = bands.contains(&Band::Band5Ghz);
        let has_6ghz = bands.contains(&Band::Band6Ghz);
        if has_6ghz {
            score = score.saturating_add(10);
            notes.push("6 GHz band: Supported (+10)".into());
        } else if has_5ghz {
            score = score.saturating_add(7);
            notes.push("5 GHz band: Supported (+7)".into());
        } else {
            notes.push("Only 2.4 GHz detected (+0)".into());
        }

        (score.min(100), notes)
    }
}
