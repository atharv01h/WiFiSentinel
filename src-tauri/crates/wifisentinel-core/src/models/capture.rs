// wifisentinel-core/src/models/capture.rs
// CaptureSession domain model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A packet capture session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSession {
    pub id: Uuid,

    /// Name of the adapter/interface being captured on.
    pub adapter_name: String,

    /// Npcap device name (e.g. "\Device\NPF_{GUID}").
    pub device_name: String,

    /// Whether monitor mode was active.
    pub monitor_mode: bool,

    /// BPF filter applied.
    pub filter: Option<String>,

    /// Output file path for PCAP/PCAPNG.
    pub output_path: Option<String>,

    /// When the capture started.
    pub started_at: DateTime<Utc>,

    /// When the capture ended (None if still running).
    pub ended_at: Option<DateTime<Utc>>,

    /// Current state.
    pub state: CaptureState,

    /// Total packets captured.
    pub packet_count: u64,

    /// Packets dropped due to queue overflow.
    pub dropped_count: u64,

    /// Current packet rate (packets per second).
    pub packet_rate: f64,

    /// Output file size in bytes.
    pub file_size_bytes: u64,

    /// Any error that caused the capture to stop.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureState {
    Initializing,
    Running,
    Paused,
    Stopping,
    Stopped,
    Failed,
    Unavailable,
}

impl CaptureState {
    pub fn is_active(&self) -> bool {
        matches!(self, CaptureState::Running | CaptureState::Paused)
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            CaptureState::Initializing => "Initializing",
            CaptureState::Running => "Running",
            CaptureState::Paused => "Paused",
            CaptureState::Stopping => "Stopping",
            CaptureState::Stopped => "Stopped",
            CaptureState::Failed => "Failed",
            CaptureState::Unavailable => "Unavailable",
        }
    }
}

impl CaptureSession {
    /// Returns the duration of the capture in seconds.
    pub fn duration_secs(&self) -> f64 {
        let end = self.ended_at.unwrap_or_else(Utc::now);
        (end - self.started_at).num_milliseconds() as f64 / 1000.0
    }
}
