// wifisentinel-core/src/models/common.rs
// Shared enumerations and value types used across all domain models.

use serde::{Deserialize, Serialize};

/// Wireless frequency band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Band {
    /// 2.4 GHz (802.11b/g/n/ax)
    Band2_4Ghz,
    /// 5 GHz (802.11a/n/ac/ax)
    Band5Ghz,
    /// 6 GHz (802.11ax/be)
    Band6Ghz,
    /// Unknown or could not be determined
    Unknown,
}

impl Band {
    pub fn display_name(&self) -> &'static str {
        match self {
            Band::Band2_4Ghz => "2.4 GHz",
            Band::Band5Ghz => "5 GHz",
            Band::Band6Ghz => "6 GHz",
            Band::Unknown => "Unknown",
        }
    }

    /// Infer band from channel number (best-effort; 6 GHz requires explicit indication).
    pub fn from_channel(channel: u8) -> Self {
        match channel {
            1..=14 => Band::Band2_4Ghz,
            32..=177 => Band::Band5Ghz,
            _ => Band::Unknown,
        }
    }
}

impl std::fmt::Display for Band {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// 802.11 PHY/protocol generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phy {
    B,
    G,
    A,
    N,
    Ac,
    Ax,
    Be,
    Unknown,
}

impl Phy {
    pub fn display_name(&self) -> &'static str {
        match self {
            Phy::B => "802.11b",
            Phy::G => "802.11g",
            Phy::A => "802.11a",
            Phy::N => "802.11n (Wi-Fi 4)",
            Phy::Ac => "802.11ac (Wi-Fi 5)",
            Phy::Ax => "802.11ax (Wi-Fi 6/6E)",
            Phy::Be => "802.11be (Wi-Fi 7)",
            Phy::Unknown => "Unknown",
        }
    }

    /// Parse from the string returned by Windows WLAN API.
    pub fn from_wlan_str(s: &str) -> Self {
        let s = s.to_lowercase();
        if s.contains("802.11be") || s.contains("wi-fi 7") {
            Phy::Be
        } else if s.contains("802.11ax") || s.contains("wi-fi 6") {
            Phy::Ax
        } else if s.contains("802.11ac") || s.contains("wi-fi 5") {
            Phy::Ac
        } else if s.contains("802.11n") || s.contains("wi-fi 4") {
            Phy::N
        } else if s.contains("802.11g") {
            Phy::G
        } else if s.contains("802.11a") {
            Phy::A
        } else if s.contains("802.11b") {
            Phy::B
        } else {
            Phy::Unknown
        }
    }
}

impl std::fmt::Display for Phy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Channel width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelWidth {
    Mhz20,
    Mhz40,
    Mhz80,
    Mhz160,
    Mhz320,
    Unknown,
}

impl ChannelWidth {
    pub fn display_name(&self) -> &'static str {
        match self {
            ChannelWidth::Mhz20 => "20 MHz",
            ChannelWidth::Mhz40 => "40 MHz",
            ChannelWidth::Mhz80 => "80 MHz",
            ChannelWidth::Mhz160 => "160 MHz",
            ChannelWidth::Mhz320 => "320 MHz",
            ChannelWidth::Unknown => "Unknown",
        }
    }
}

/// Authentication mode.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    Open,
    Wep,
    WpaPersonal,
    WpaEnterprise,
    Wpa2Personal,
    Wpa2Enterprise,
    Wpa3Personal,
    Wpa3Enterprise,
    Owe,
    Unknown(String),
}

impl AuthMode {
    pub fn display_name(&self) -> String {
        match self {
            AuthMode::Open => "Open (No authentication)".into(),
            AuthMode::Wep => "WEP (Deprecated)".into(),
            AuthMode::WpaPersonal => "WPA-Personal".into(),
            AuthMode::WpaEnterprise => "WPA-Enterprise".into(),
            AuthMode::Wpa2Personal => "WPA2-Personal".into(),
            AuthMode::Wpa2Enterprise => "WPA2-Enterprise".into(),
            AuthMode::Wpa3Personal => "WPA3-Personal".into(),
            AuthMode::Wpa3Enterprise => "WPA3-Enterprise".into(),
            AuthMode::Owe => "OWE (Enhanced Open)".into(),
            AuthMode::Unknown(s) => format!("Unknown ({})", s),
        }
    }

    pub fn security_level(&self) -> SecurityLevel {
        match self {
            AuthMode::Open => SecurityLevel::None,
            AuthMode::Wep => SecurityLevel::Critical,
            AuthMode::WpaPersonal => SecurityLevel::Low,
            AuthMode::WpaEnterprise => SecurityLevel::Medium,
            AuthMode::Wpa2Personal => SecurityLevel::Good,
            AuthMode::Wpa2Enterprise => SecurityLevel::Good,
            AuthMode::Wpa3Personal => SecurityLevel::Excellent,
            AuthMode::Wpa3Enterprise => SecurityLevel::Excellent,
            AuthMode::Owe => SecurityLevel::Good,
            AuthMode::Unknown(_) => SecurityLevel::Unknown,
        }
    }

    /// Parse from the string returned by Windows WLAN API / netsh.
    pub fn from_wlan_str(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "open" => AuthMode::Open,
            "wep" => AuthMode::Wep,
            "wpa-personal" | "wpapsk" => AuthMode::WpaPersonal,
            "wpa-enterprise" | "wpa" => AuthMode::WpaEnterprise,
            "wpa2-personal" | "wpa2psk" | "rsna-psk" => AuthMode::Wpa2Personal,
            "wpa2-enterprise" | "wpa2" | "rsna" => AuthMode::Wpa2Enterprise,
            "wpa3-personal" | "wpa3sae" => AuthMode::Wpa3Personal,
            "wpa3-enterprise" => AuthMode::Wpa3Enterprise,
            "owe" => AuthMode::Owe,
            other => AuthMode::Unknown(other.to_string()),
        }
    }
}

impl std::fmt::Display for AuthMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Cipher suite.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CipherSuite {
    None,
    Wep40,
    Wep104,
    Tkip,
    Ccmp,
    Gcmp128,
    Gcmp256,
    Unknown(String),
}

impl CipherSuite {
    pub fn display_name(&self) -> String {
        match self {
            CipherSuite::None => "None".into(),
            CipherSuite::Wep40 => "WEP-40 (Deprecated)".into(),
            CipherSuite::Wep104 => "WEP-104 (Deprecated)".into(),
            CipherSuite::Tkip => "TKIP (Deprecated)".into(),
            CipherSuite::Ccmp => "CCMP (AES-128)".into(),
            CipherSuite::Gcmp128 => "GCMP-128".into(),
            CipherSuite::Gcmp256 => "GCMP-256".into(),
            CipherSuite::Unknown(s) => format!("Unknown ({})", s),
        }
    }

    pub fn from_wlan_str(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "none" => CipherSuite::None,
            "wep" | "wep-40bit" | "wep40" => CipherSuite::Wep40,
            "wep-104bit" | "wep104" => CipherSuite::Wep104,
            "tkip" => CipherSuite::Tkip,
            "ccmp" | "ccmp-128" | "aes" => CipherSuite::Ccmp,
            "gcmp" | "gcmp-128" => CipherSuite::Gcmp128,
            "gcmp-256" => CipherSuite::Gcmp256,
            other => CipherSuite::Unknown(other.to_string()),
        }
    }
}

/// Protected Management Frames configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PmfMode {
    Disabled,
    Optional,
    Required,
    Unknown,
}

/// Security level classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityLevel {
    None,
    Critical,
    Low,
    Medium,
    Good,
    Excellent,
    Unknown,
}

impl SecurityLevel {
    pub fn display_name(&self) -> &'static str {
        match self {
            SecurityLevel::None => "None",
            SecurityLevel::Critical => "Critical (Insecure)",
            SecurityLevel::Low => "Low",
            SecurityLevel::Medium => "Medium",
            SecurityLevel::Good => "Good",
            SecurityLevel::Excellent => "Excellent",
            SecurityLevel::Unknown => "Unknown",
        }
    }
}

/// Finding severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn display_name(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    pub fn color_class(&self) -> &'static str {
        match self {
            Severity::Info => "severity-info",
            Severity::Low => "severity-low",
            Severity::Medium => "severity-medium",
            Severity::High => "severity-high",
            Severity::Critical => "severity-critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Capability status — avoids fabricating unsupported capability claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Feature is confirmed supported.
    Supported,
    /// Feature is available but depends on driver configuration.
    DriverDependent,
    /// Feature is confirmed unsupported.
    Unsupported,
    /// Status could not be determined from available information.
    Unknown,
}

impl Capability {
    pub fn display_name(&self) -> &'static str {
        match self {
            Capability::Supported => "Supported",
            Capability::DriverDependent => "Driver dependent",
            Capability::Unsupported => "Unsupported",
            Capability::Unknown => "Unknown / Driver dependent",
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(self, Capability::Supported)
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Adapter operational state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterState {
    Up,
    Down,
    Disconnected,
    Connecting,
    Connected,
    Authenticating,
    Unavailable,
    Unknown,
}

impl AdapterState {
    pub fn display_name(&self) -> &'static str {
        match self {
            AdapterState::Up => "Up",
            AdapterState::Down => "Down",
            AdapterState::Disconnected => "Disconnected",
            AdapterState::Connecting => "Connecting",
            AdapterState::Connected => "Connected",
            AdapterState::Authenticating => "Authenticating",
            AdapterState::Unavailable => "Unavailable",
            AdapterState::Unknown => "Unknown",
        }
    }

    pub fn is_operational(&self) -> bool {
        matches!(self, AdapterState::Up | AdapterState::Connected | AdapterState::Disconnected)
    }
}
