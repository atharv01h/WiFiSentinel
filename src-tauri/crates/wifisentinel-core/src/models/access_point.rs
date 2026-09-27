// wifisentinel-core/src/models/access_point.rs
// AccessPoint domain model.

use chrono::{DateTime, Utc};
use macaddr::MacAddr6;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::common::{AuthMode, Band, ChannelWidth, CipherSuite, Phy, PmfMode};

/// An observed wireless access point (BSSID-level entity).
///
/// One WirelessNetwork (SSID) may have many AccessPoints (BSSIDs).
/// This model tracks per-BSSID information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPoint {
    /// Unique internal identifier.
    pub id: Uuid,

    /// Network BSSID (MAC address of the AP radio).
    pub bssid: MacAddr6,

    /// SSID. None indicates a hidden network.
    pub ssid: Option<String>,

    /// OUI-based vendor lookup result.
    pub vendor: Option<String>,

    /// Frequency band.
    pub band: Band,

    /// Primary channel number.
    pub channel: u8,

    /// Secondary channel offset (for HT/VHT/HE).
    pub channel_width: Option<ChannelWidth>,

    /// Signal strength in dBm (negative, closer to 0 = stronger).
    pub rssi_dbm: i16,

    /// Signal quality as percentage (0-100).
    pub signal_percent: u8,

    /// PHY/protocol generation.
    pub phy: Option<Phy>,

    /// Authentication mode.
    pub auth_mode: AuthMode,

    /// Cipher suite.
    pub cipher: CipherSuite,

    /// Protected Management Frames status.
    pub pmf: Option<PmfMode>,

    /// Beacon interval in TUs (1 TU = 1024 µs). Typical: 100.
    pub beacon_interval_tu: Option<u16>,

    /// 802.11 capability flags (raw).
    pub capability_flags: Option<u16>,

    /// Whether this AP is currently transmitting (recently seen).
    pub is_active: bool,

    /// Whether the user has marked this BSSID as trusted.
    pub is_trusted: bool,

    /// ID of the adapter that observed this AP.
    pub observed_by_adapter: Uuid,

    /// ID of the WirelessNetwork this AP belongs to.
    pub network_id: Option<Uuid>,

    /// When this AP was first observed.
    pub first_seen: DateTime<Utc>,

    /// When this AP was last seen.
    pub last_seen: DateTime<Utc>,

    /// Number of times this BSSID has been observed.
    pub observation_count: u64,

    /// Signal history (timestamp, dBm) — capped at last N readings.
    pub signal_history: Vec<SignalSample>,

    /// Channel changes recorded for this BSSID.
    pub channel_history: Vec<ChannelSample>,

    /// Security configuration changes.
    pub security_history: Vec<SecuritySample>,
}

/// A point-in-time signal measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalSample {
    pub timestamp: DateTime<Utc>,
    pub rssi_dbm: i16,
}

/// A recorded channel change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSample {
    pub timestamp: DateTime<Utc>,
    pub channel: u8,
    pub band: Band,
}

/// A recorded security configuration snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySample {
    pub timestamp: DateTime<Utc>,
    pub auth_mode: AuthMode,
    pub cipher: CipherSuite,
}

impl AccessPoint {
    /// Returns true if this AP presents a hidden (non-broadcast) SSID.
    pub fn is_hidden(&self) -> bool {
        self.ssid.as_deref().map_or(true, |s| s.is_empty())
    }

    /// Derive signal percentage from dBm value using a standard formula.
    /// Range: -100 dBm (0%) to -50 dBm (100%).
    pub fn signal_pct_from_dbm(dbm: i16) -> u8 {
        let clamped = dbm.max(-100).min(-50);
        let pct = ((clamped + 100) * 2) as u8;
        pct.min(100)
    }

    /// Returns a security risk summary string.
    pub fn security_summary(&self) -> &'static str {
        match (&self.auth_mode, &self.cipher) {
            (AuthMode::Open, _) => "Open — No encryption",
            (AuthMode::Wep, _) => "WEP — Critically insecure",
            (AuthMode::WpaPersonal, c) if matches!(c, CipherSuite::Tkip) => "WPA/TKIP — Deprecated",
            (AuthMode::Wpa2Personal, _) => "WPA2-Personal",
            (AuthMode::Wpa3Personal, _) => "WPA3-Personal",
            (AuthMode::Wpa2Enterprise, _) => "WPA2-Enterprise",
            (AuthMode::Wpa3Enterprise, _) => "WPA3-Enterprise",
            _ => "Mixed/Unknown",
        }
    }

    /// Frequency in MHz for the primary channel.
    pub fn frequency_mhz(&self) -> Option<u32> {
        match self.band {
            Band::Band2_4Ghz => {
                // Channel 1 = 2412 MHz, step 5 MHz
                if self.channel >= 1 && self.channel <= 13 {
                    Some(2407 + (self.channel as u32 * 5))
                } else if self.channel == 14 {
                    Some(2484)
                } else {
                    None
                }
            }
            Band::Band5Ghz => {
                // 5 GHz channels: 5000 + channel * 5
                if self.channel >= 32 {
                    Some(5000 + (self.channel as u32 * 5))
                } else {
                    None
                }
            }
            Band::Band6Ghz => {
                // 6 GHz: 5950 + channel * 5
                Some(5950 + (self.channel as u32 * 5))
            }
            Band::Unknown => None,
        }
    }
}

/// A discovered wireless network (SSID-level entity).
/// One SSID may span multiple BSSIDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessNetwork {
    pub id: Uuid,
    pub ssid: String,
    /// Access point IDs belonging to this network.
    pub ap_ids: Vec<Uuid>,
    /// Dominant security profile across all APs.
    pub security_profile: SecurityProfile,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// Whether the user has marked this SSID as trusted/known.
    pub is_trusted: bool,
    /// Notes from detection engine.
    pub anomaly_flags: Vec<String>,
}

/// Security profile for a wireless network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProfile {
    pub auth_mode: AuthMode,
    pub cipher: CipherSuite,
    pub pmf: Option<PmfMode>,
    pub has_inconsistent_aps: bool,
}
