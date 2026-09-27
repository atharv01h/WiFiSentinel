// wifisentinel-core/src/models/timeline.rs
// TimelineEvent domain model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::common::Severity;

/// A discrete event in the wireless timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub description: String,
    pub severity: Severity,

    /// Related access point, if applicable.
    pub related_ap_id: Option<Uuid>,
    pub related_ap_bssid: Option<String>,
    pub related_ap_ssid: Option<String>,

    /// Related client, if applicable.
    pub related_client_id: Option<Uuid>,
    pub related_client_mac: Option<String>,

    /// Related security finding, if applicable.
    pub related_finding_id: Option<Uuid>,

    /// Additional structured metadata.
    pub metadata: serde_json::Value,
}

/// Categories of timeline events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    // Access point events
    ApDiscovered,
    ApDisappeared,
    ApChannelChanged,
    ApSecurityChanged,
    ApBssidChanged,
    ApSignalChanged,

    // Client events
    ClientDiscovered,
    ClientDisappeared,
    ClientRoamed,
    ClientProbeObserved,

    // Detection events
    FindingGenerated,
    AnomalyDetected,
    SuspiciousApDetected,
    SecurityDowngradeDetected,

    // Capture events
    CaptureStarted,
    CaptureStopped,
    CaptureError,

    // Scan events
    ScanCompleted,
    ScanFailed,

    // System events
    AdapterConnected,
    AdapterDisconnected,
    ApplicationStarted,

    /// Catch-all for future event types.
    Other(String),
}

impl EventType {
    pub fn display_name(&self) -> String {
        match self {
            EventType::ApDiscovered => "AP Discovered".into(),
            EventType::ApDisappeared => "AP Disappeared".into(),
            EventType::ApChannelChanged => "AP Channel Changed".into(),
            EventType::ApSecurityChanged => "AP Security Changed".into(),
            EventType::ApBssidChanged => "AP BSSID Changed".into(),
            EventType::ApSignalChanged => "AP Signal Changed".into(),
            EventType::ClientDiscovered => "Client Discovered".into(),
            EventType::ClientDisappeared => "Client Disappeared".into(),
            EventType::ClientRoamed => "Client Roamed".into(),
            EventType::ClientProbeObserved => "Client Probe Request".into(),
            EventType::FindingGenerated => "Finding Generated".into(),
            EventType::AnomalyDetected => "Anomaly Detected".into(),
            EventType::SuspiciousApDetected => "Suspicious AP Detected".into(),
            EventType::SecurityDowngradeDetected => "Security Downgrade Detected".into(),
            EventType::CaptureStarted => "Capture Started".into(),
            EventType::CaptureStopped => "Capture Stopped".into(),
            EventType::CaptureError => "Capture Error".into(),
            EventType::ScanCompleted => "Scan Completed".into(),
            EventType::ScanFailed => "Scan Failed".into(),
            EventType::AdapterConnected => "Adapter Connected".into(),
            EventType::AdapterDisconnected => "Adapter Disconnected".into(),
            EventType::ApplicationStarted => "Application Started".into(),
            EventType::Other(s) => s.clone(),
        }
    }

    pub fn default_severity(&self) -> Severity {
        match self {
            EventType::SuspiciousApDetected | EventType::SecurityDowngradeDetected => Severity::High,
            EventType::AnomalyDetected | EventType::FindingGenerated => Severity::Medium,
            EventType::CaptureError | EventType::ScanFailed => Severity::Low,
            _ => Severity::Info,
        }
    }
}

impl TimelineEvent {
    /// Convenience constructor for AP-related events.
    pub fn ap_event(
        event_type: EventType,
        description: impl Into<String>,
        ap_id: Uuid,
        bssid: impl Into<String>,
        ssid: Option<String>,
    ) -> Self {
        let severity = event_type.default_severity();
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            description: description.into(),
            severity,
            related_ap_id: Some(ap_id),
            related_ap_bssid: Some(bssid.into()),
            related_ap_ssid: ssid,
            related_client_id: None,
            related_client_mac: None,
            related_finding_id: None,
            metadata: serde_json::Value::Null,
        }
    }

    /// Convenience constructor for finding events.
    pub fn finding_event(
        description: impl Into<String>,
        finding_id: Uuid,
        severity: Severity,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: EventType::FindingGenerated,
            description: description.into(),
            severity,
            related_ap_id: None,
            related_ap_bssid: None,
            related_ap_ssid: None,
            related_client_id: None,
            related_client_mac: None,
            related_finding_id: Some(finding_id),
            metadata: serde_json::Value::Null,
        }
    }
}
