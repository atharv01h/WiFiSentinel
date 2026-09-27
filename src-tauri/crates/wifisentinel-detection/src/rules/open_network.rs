// wifisentinel-detection/src/rules/open_network.rs
// Rule: Open Network Detection

use wifisentinel_core::models::{AuthMode, Confidence, Evidence, Severity};
use crate::engine::{DetectionContext, DetectionRule, Finding};

pub struct OpenNetworkRule;

impl DetectionRule for OpenNetworkRule {
    fn rule_id(&self) -> &str { "security.open_network" }
    fn name(&self) -> &str { "Open Network (No Encryption)" }
    fn description(&self) -> &str {
        "Detects networks with no authentication or encryption."
    }

    fn evaluate(&self, ctx: &DetectionContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for ap in &ctx.access_points {
            if !matches!(ap.auth_mode, AuthMode::Open) { continue; }

            let ssid = ap.ssid.as_deref().unwrap_or("Hidden");

            // OWE (Enhanced Open) is not insecure — skip it.
            // (OWE would be classified as Owe, not Open.)

            findings.push(Finding {
                rule_id: self.rule_id().to_string(),
                title: format!("Open Network: \"{}\"", ssid),
                description: format!(
                    "AP {} ({}) has no authentication or encryption. \
                     All traffic is transmitted in plaintext.",
                    ssid, ap.bssid
                ),
                severity: Severity::High,
                confidence: Confidence::new(
                    99,
                    "Open authentication mode detected — no ambiguity."
                ),
                evidence: vec![
                    Evidence::supporting("Authentication", "Open — no authentication"),
                    Evidence::supporting("BSSID", ap.bssid.to_string()),
                    Evidence::supporting("Channel", ap.channel.to_string()),
                ],
                recommendation: "If this is your AP, enable WPA2 or WPA3. \
                    Avoid connecting to open networks for sensitive activities. \
                    Consider using a VPN if connection is necessary.".into(),
                technical_detail: format!(
                    "Rule: {}. BSSID: {}. Auth: Open. Cipher: {}. \
                     Signal: {}%.",
                    self.rule_id(), ap.bssid, ap.cipher.display_name(), ap.signal_percent
                ),
                plain_explanation: format!(
                    "\"{}\" is an open Wi-Fi network with no password or encryption. \
                     Anyone on the network can see the traffic of other users. \
                     Sensitive data like passwords and emails can be intercepted. \
                     Only use this network for activities where privacy doesn't matter.",
                    ssid
                ),
                affected_ap_id: Some(ap.id),
                affected_client_id: None,
            });
        }

        findings
    }
}
