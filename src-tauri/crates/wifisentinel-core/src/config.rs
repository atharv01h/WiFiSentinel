// wifisentinel-core/src/config.rs
// Application configuration management.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// General application settings.
    pub general: GeneralConfig,

    /// Scan settings.
    pub scan: ScanConfig,

    /// Capture settings.
    pub capture: CaptureConfig,

    /// Detection engine settings.
    pub detection: DetectionConfig,

    /// Database settings.
    pub database: DatabaseConfig,

    /// Privacy settings.
    pub privacy: PrivacyConfig,

    /// AI assistant settings.
    pub ai: AiConfig,

    /// Report settings.
    pub reporting: ReportingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Show advanced mode by default.
    pub advanced_mode: bool,
    /// Log level: trace/debug/info/warn/error.
    pub log_level: String,
    /// Directory for log files.
    pub log_dir: Option<PathBuf>,
    /// Theme: dark/light (dark by default).
    pub theme: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Interval between automatic scans in seconds. 0 = manual only.
    pub auto_scan_interval_secs: u64,
    /// Whether to keep scanning in the background.
    pub background_scanning: bool,
    /// How long to retain observation history (days). 0 = forever.
    pub history_retention_days: u32,
    /// Maximum signal history samples per AP.
    pub max_signal_history: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    /// Default output directory for capture files.
    pub output_dir: PathBuf,
    /// Maximum capture file size in MB. 0 = unlimited.
    pub max_file_size_mb: u64,
    /// Whether to automatically save captures.
    pub auto_save: bool,
    /// Default BPF filter (empty = capture all).
    pub default_filter: String,
    /// Queue capacity for backpressure.
    pub queue_capacity: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Detection sensitivity: low/medium/high.
    pub sensitivity: String,
    /// Minimum confidence % to emit a finding.
    pub min_confidence: u8,
    /// Whether to emit INFO-severity findings.
    pub show_info_findings: bool,
    /// SSIDs explicitly marked as trusted by the user.
    pub trusted_ssids: Vec<String>,
    /// BSSIDs explicitly marked as trusted by the user.
    pub trusted_bssids: Vec<String>,
    /// Vendor strings to trust.
    pub trusted_vendors: Vec<String>,
    /// SSIDs to ignore entirely.
    pub ignored_ssids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// SQLite database file path.
    pub db_path: PathBuf,
    /// Batch write interval in milliseconds.
    pub batch_write_interval_ms: u64,
    /// WAL mode for better concurrent access.
    pub wal_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Whether to persist observation history to disk.
    pub persist_history: bool,
    /// Whether to strip MAC addresses from exported logs.
    pub strip_macs_in_logs: bool,
    /// Whether to anonymize SSIDs in reports.
    pub anonymize_ssids_in_reports: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// Whether the AI assistant is enabled.
    pub enabled: bool,
    /// AI provider: "openai" / "local" / "none".
    pub provider: String,
    /// API endpoint (for custom/local providers).
    pub api_endpoint: Option<String>,
    /// Model name.
    pub model: Option<String>,
    /// Whether AI analysis is done locally only.
    pub local_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingConfig {
    /// Default output directory for reports.
    pub output_dir: PathBuf,
    /// Include raw evidence in reports.
    pub include_raw_evidence: bool,
    /// Include packet statistics in reports.
    pub include_packet_stats: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        let data_dir = dirs_data_dir();
        Self {
            general: GeneralConfig {
                advanced_mode: false,
                log_level: "info".into(),
                log_dir: Some(data_dir.join("logs")),
                theme: "dark".into(),
            },
            scan: ScanConfig {
                auto_scan_interval_secs: 30,
                background_scanning: true,
                history_retention_days: 30,
                max_signal_history: 200,
            },
            capture: CaptureConfig {
                output_dir: data_dir.join("captures"),
                max_file_size_mb: 500,
                auto_save: true,
                default_filter: String::new(),
                queue_capacity: 4096,
            },
            detection: DetectionConfig {
                sensitivity: "medium".into(),
                min_confidence: 30,
                show_info_findings: true,
                trusted_ssids: vec![],
                trusted_bssids: vec![],
                trusted_vendors: vec![],
                ignored_ssids: vec![],
            },
            database: DatabaseConfig {
                db_path: data_dir.join("wifisentinel.db"),
                batch_write_interval_ms: 500,
                wal_mode: true,
            },
            privacy: PrivacyConfig {
                persist_history: true,
                strip_macs_in_logs: true,
                anonymize_ssids_in_reports: false,
            },
            ai: AiConfig {
                enabled: false,
                provider: "none".into(),
                api_endpoint: None,
                model: None,
                local_only: true,
            },
            reporting: ReportingConfig {
                output_dir: data_dir.join("reports"),
                include_raw_evidence: true,
                include_packet_stats: true,
            },
        }
    }
}

/// Platform-specific application data directory.
fn dirs_data_dir() -> PathBuf {
    // %APPDATA%\WiFiSentinel on Windows
    let base = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("WiFiSentinel")
}

impl AppConfig {
    /// Load configuration from file, falling back to defaults.
    pub fn load(path: &std::path::Path) -> crate::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)
            .map_err(crate::Error::Io)?;

        let config: Self = toml::from_str(&content)
            .map_err(|e| crate::Error::Other(format!("Config parse error: {}", e)))?;

        Ok(config)
    }

    /// Save configuration to file.
    pub fn save(&self, path: &std::path::Path) -> crate::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(crate::Error::Io)?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| crate::Error::Other(format!("Config serialize error: {}", e)))?;

        std::fs::write(path, content).map_err(crate::Error::Io)?;
        Ok(())
    }
}
