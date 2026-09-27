// wifisentinel-core/src/error.rs
// Unified error type for the entire application.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    // Database errors
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Database migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    // Configuration errors
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    // I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // Serialization errors
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    // WLAN errors
    #[error("WLAN API error: {message} (code: {code})")]
    WlanApi { message: String, code: u32 },

    #[error("WLAN interface not found: {guid}")]
    WlanInterfaceNotFound { guid: String },

    #[error("WLAN scan failed: {reason}")]
    WlanScanFailed { reason: String },

    // Capture errors
    #[error("Capture unavailable: {reason}. {suggestion}")]
    CaptureUnavailable { reason: String, suggestion: String },

    #[error("Capture error: {0}")]
    CaptureError(String),

    #[error("Monitor mode unavailable on adapter '{adapter}': {reason}. Suggested action: {action}")]
    MonitorModeUnavailable {
        adapter: String,
        reason: String,
        action: String,
    },

    #[error("Npcap not installed. Please install Npcap from https://npcap.com to enable packet capture.")]
    NpcapNotInstalled,

    // PCAP parsing errors
    #[error("Malformed PCAP file: {reason}")]
    PcapMalformed { reason: String },

    #[error("Unsupported PCAP link type: {link_type}")]
    PcapUnsupportedLinkType { link_type: u32 },

    // Detection errors
    #[error("Detection engine error: {0}")]
    Detection(String),

    // Reporting errors
    #[error("Report generation failed: {0}")]
    Reporting(String),

    // Permission errors
    #[error("Insufficient permissions: {reason}. Required: {required}")]
    InsufficientPermissions { reason: String, required: String },

    // Generic / catch-all
    #[error("{0}")]
    Other(String),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl Error {
    /// Returns a user-facing short description of the error category.
    pub fn category(&self) -> &'static str {
        match self {
            Error::Database(_) | Error::Migration(_) => "Database",
            Error::Config(_) => "Configuration",
            Error::Io(_) => "I/O",
            Error::Serialization(_) => "Serialization",
            Error::WlanApi { .. } | Error::WlanInterfaceNotFound { .. } | Error::WlanScanFailed { .. } => "WLAN",
            Error::CaptureUnavailable { .. } | Error::CaptureError(_) | Error::MonitorModeUnavailable { .. } | Error::NpcapNotInstalled => "Capture",
            Error::PcapMalformed { .. } | Error::PcapUnsupportedLinkType { .. } => "PCAP",
            Error::Detection(_) => "Detection",
            Error::Reporting(_) => "Reporting",
            Error::InsufficientPermissions { .. } => "Permissions",
            Error::Other(_) | Error::Anyhow(_) => "General",
        }
    }

    /// Returns a suggested action string for the user when available.
    pub fn suggested_action(&self) -> Option<String> {
        match self {
            Error::NpcapNotInstalled => Some(
                "Download and install Npcap from https://npcap.com, then restart WiFiSentinel.".into()
            ),
            Error::MonitorModeUnavailable { action, .. } => Some(action.clone()),
            Error::CaptureUnavailable { suggestion, .. } => Some(suggestion.clone()),
            Error::InsufficientPermissions { required, .. } => Some(format!(
                "Run WiFiSentinel as Administrator, or grant: {required}"
            )),
            Error::WlanScanFailed { reason } => Some(format!(
                "Verify the wireless adapter is enabled and not in airplane mode. Detail: {reason}"
            )),
            _ => None,
        }
    }
}

/// Serialize Error to JSON for IPC transport.
impl serde::Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("Error", 4)?;
        s.serialize_field("category", self.category())?;
        s.serialize_field("message", &self.to_string())?;
        s.serialize_field("suggested_action", &self.suggested_action())?;
        s.end()
    }
}
