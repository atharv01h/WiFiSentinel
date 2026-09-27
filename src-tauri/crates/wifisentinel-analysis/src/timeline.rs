// wifisentinel-analysis/src/timeline.rs
// Timeline query and aggregation utilities.

use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};

/// Timeline filter parameters.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TimelineFilter {
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub event_types: Vec<String>,
    pub severity: Option<String>,
    pub ap_bssid: Option<String>,
    pub limit: Option<usize>,
}

impl TimelineFilter {
    pub fn last_hours(hours: i64) -> Self {
        Self {
            start: Some(Utc::now() - Duration::hours(hours)),
            ..Default::default()
        }
    }
}
