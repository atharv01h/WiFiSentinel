// wifisentinel-detection/src/rules/channel_anomaly.rs
// Rule: Channel Anomaly Detection

use wifisentinel_core::models::{Band, Confidence, Evidence, Severity};
use crate::engine::{DetectionContext, DetectionRule, Finding};

pub struct ChannelAnomalyRule;

impl DetectionRule for ChannelAnomalyRule {
    fn rule_id(&self) -> &str { "channel.anomaly" }
    fn name(&self) -> &str { "Channel Anomaly" }
    fn description(&self) -> &str {
        "Detects APs operating on non-standard channels, which may indicate misconfiguration or evasion."
    }

    fn evaluate(&self, ctx: &DetectionContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for ap in &ctx.access_points {
            let ssid = ap.ssid.as_deref().unwrap_or("Hidden");

            // Non-overlapping 2.4 GHz channels are 1, 6, 11 (and 14 in Japan).
            // Operating on other channels causes maximum overlap and is unusual.
            if ap.band == Band::Band2_4Ghz {
                let standard_channels = [1u8, 6, 11, 14];
                if !standard_channels.contains(&ap.channel) {
                    findings.push(Finding {
                        rule_id: format!("{}.non_standard_24ghz", self.rule_id()),
                        title: format!("Non-Standard 2.4 GHz Channel: \"{}\" (ch {})", ssid, ap.channel),
                        description: format!(
                            "AP {} is on 2.4 GHz channel {}, which is not a standard \
                             non-overlapping channel (1, 6, 11).",
                            ap.bssid, ap.channel
                        ),
                        severity: Severity::Info,
                        confidence: Confidence::new(
                            80,
                            "2.4 GHz channel outside standard 1/6/11 set detected."
                        ),
                        evidence: vec![
                            Evidence::supporting("Channel", ap.channel.to_string()),
                            Evidence::supporting("Band", "2.4 GHz"),
                        ],
                        recommendation: "Check if this is intentional. Non-standard channels can increase interference.".into(),
                        technical_detail: format!("BSSID: {}. Channel: {}. Standard: 1, 6, 11.", ap.bssid, ap.channel),
                        plain_explanation: format!(
                            "The network \"{}\" is using channel {} on 2.4 GHz, which is \
                             not one of the standard channels (1, 6, or 11). This may \
                             cause interference with neighboring networks.",
                            ssid, ap.channel
                        ),
                        affected_ap_id: Some(ap.id),
                        affected_client_id: None,
                    });
                }
            }
        }

        findings
    }
}
