// wifisentinel-detection/src/rules/security_downgrade.rs
// Rule: Security Downgrade Detection

use wifisentinel_core::models::{AuthMode, CipherSuite, Confidence, Evidence, Severity};
use crate::engine::{DetectionContext, DetectionRule, Finding};

pub struct SecurityDowngradeRule;

impl DetectionRule for SecurityDowngradeRule {
    fn rule_id(&self) -> &str { "security.downgrade_detected" }
    fn name(&self) -> &str { "Security Downgrade Detected" }
    fn description(&self) -> &str {
        "Detects APs using legacy or deprecated authentication and cipher modes."
    }

    fn evaluate(&self, ctx: &DetectionContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for ap in &ctx.access_points {
            let ssid = ap.ssid.as_deref().unwrap_or("Hidden");

            // WEP: critical.
            if matches!(ap.auth_mode, AuthMode::Wep) {
                findings.push(Finding {
                    rule_id: self.rule_id().to_string(),
                    title: format!("WEP Encryption: \"{}\"", ssid),
                    description: format!(
                        "AP {} ({}) uses WEP encryption, which is completely broken \
                         and can be cracked in minutes with widely available tools.",
                        ssid, ap.bssid
                    ),
                    severity: Severity::Critical,
                    confidence: Confidence::new(99, "WEP detected — certainty is near-absolute."),
                    evidence: vec![
                        Evidence::supporting("Authentication", ap.auth_mode.display_name()),
                        Evidence::supporting("BSSID", ap.bssid.to_string()),
                    ],
                    recommendation: "Immediately upgrade to WPA2 or WPA3. WEP provides no meaningful security.".into(),
                    technical_detail: format!("Rule: {}. BSSID: {}. Auth: WEP. Cipher: {}.", self.rule_id(), ap.bssid, ap.cipher.display_name()),
                    plain_explanation: "This network uses WEP, an encryption method broken since 2001. Anyone nearby can read traffic on this network. Upgrade the router immediately.".into(),
                    affected_ap_id: Some(ap.id),
                    affected_client_id: None,
                });
            }

            // TKIP: high.
            if matches!(ap.cipher, CipherSuite::Tkip) && !matches!(ap.auth_mode, AuthMode::Open) {
                findings.push(Finding {
                    rule_id: format!("{}.tkip", self.rule_id()),
                    title: format!("TKIP Cipher: \"{}\"", ssid),
                    description: format!(
                        "AP {} ({}) uses TKIP cipher, which is deprecated and \
                         vulnerable to several attacks.",
                        ssid, ap.bssid
                    ),
                    severity: Severity::High,
                    confidence: Confidence::new(95, "TKIP cipher detected — known deprecated."),
                    evidence: vec![
                        Evidence::supporting("Cipher", "TKIP (deprecated)"),
                        Evidence::supporting("BSSID", ap.bssid.to_string()),
                    ],
                    recommendation: "Upgrade to CCMP/AES cipher. Configure WPA2-Personal with AES or migrate to WPA3.".into(),
                    technical_detail: format!("Rule: {}.tkip. BSSID: {}. Cipher: TKIP.", self.rule_id(), ap.bssid),
                    plain_explanation: "This network uses TKIP, an outdated encryption method. Modern routers support AES encryption which is much stronger. Update the router configuration.".into(),
                    affected_ap_id: Some(ap.id),
                    affected_client_id: None,
                });
            }

            // WPA1: high.
            if matches!(ap.auth_mode, AuthMode::WpaPersonal | AuthMode::WpaEnterprise) {
                findings.push(Finding {
                    rule_id: format!("{}.wpa1", self.rule_id()),
                    title: format!("WPA1 (Deprecated): \"{}\"", ssid),
                    description: format!(
                        "AP {} ({}) uses WPA (original) which has known weaknesses.",
                        ssid, ap.bssid
                    ),
                    severity: Severity::Medium,
                    confidence: Confidence::new(90, "WPA1 protocol detected."),
                    evidence: vec![
                        Evidence::supporting("Authentication", ap.auth_mode.display_name()),
                    ],
                    recommendation: "Upgrade to WPA2-Personal (AES) or WPA3-Personal.".into(),
                    technical_detail: format!("Rule: {}.wpa1. Auth: {}.", self.rule_id(), ap.auth_mode.display_name()),
                    plain_explanation: "This network uses an older version of WPA security. While better than WEP, WPA2 or WPA3 should be used instead.".into(),
                    affected_ap_id: Some(ap.id),
                    affected_client_id: None,
                });
            }
        }

        findings
    }
}
