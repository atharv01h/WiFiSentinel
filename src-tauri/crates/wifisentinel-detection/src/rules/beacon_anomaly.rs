// wifisentinel-detection/src/rules/beacon_anomaly.rs
// Rule: Beacon Interval Anomaly

use wifisentinel_core::models::{Confidence, Evidence, Severity};
use crate::engine::{DetectionContext, DetectionRule, Finding};

pub struct BeaconAnomalyRule;

impl DetectionRule for BeaconAnomalyRule {
    fn rule_id(&self) -> &str { "beacon.interval_anomaly" }
    fn name(&self) -> &str { "Unusual Beacon Interval" }
    fn description(&self) -> &str {
        "Detects APs with beacon intervals far outside the standard range (95-110 TUs)."
    }

    fn evaluate(&self, ctx: &DetectionContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for ap in &ctx.access_points {
            let interval = match ap.beacon_interval_tu {
                Some(i) => i,
                None => continue,
            };

            // Standard beacon interval is 100 TUs (102.4 ms).
            // Range 50-200 TUs is reasonable. Outside this is unusual.
            if interval < 50 || interval > 200 {
                let ssid = ap.ssid.as_deref().unwrap_or("Hidden");
                findings.push(Finding {
                    rule_id: self.rule_id().to_string(),
                    title: format!("Unusual Beacon Interval: \"{}\" ({} TUs)", ssid, interval),
                    description: format!(
                        "AP {} has a beacon interval of {} TUs, \
                         which is outside the normal range (50-200 TUs).",
                        ap.bssid, interval
                    ),
                    severity: Severity::Low,
                    confidence: Confidence::new(
                        70,
                        format!("Beacon interval {} TU is outside normal 50-200 range.", interval)
                    ),
                    evidence: vec![
                        Evidence::supporting("Beacon Interval", format!("{} TUs (normal: ~100)", interval)),
                        Evidence::supporting("BSSID", ap.bssid.to_string()),
                    ],
                    recommendation: "Review AP configuration. Some APs set non-standard beacon intervals for power-saving or evasion purposes.".into(),
                    technical_detail: format!(
                        "Rule: {}. BSSID: {}. Beacon: {} TU. Expected: 100 TU.",
                        self.rule_id(), ap.bssid, interval
                    ),
                    plain_explanation: format!(
                        "\"{}\" sends periodic signals (beacons) at an unusual rate. \
                         Normal APs send about 10 beacons per second. \
                         This AP sends them at an unusual interval of {} TUs.",
                        ssid, interval
                    ),
                    affected_ap_id: Some(ap.id),
                    affected_client_id: None,
                });
            }
        }

        findings
    }
}
