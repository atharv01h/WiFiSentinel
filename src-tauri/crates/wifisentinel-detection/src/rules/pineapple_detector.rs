// wifisentinel-detection/src/rules/pineapple_detector.rs
// Rule: Known Malicious Hardware OUI
//
// Detects Access Points using MAC address OUIs associated with known 
// penetration testing and offensive hardware (e.g., Hak5 WiFi Pineapple).

use wifisentinel_core::models::{Confidence, Evidence, Severity};
use crate::engine::{DetectionContext, DetectionRule, Finding};

pub struct PineappleDetectorRule;

impl DetectionRule for PineappleDetectorRule {
    fn rule_id(&self) -> &str { "rogue_ap.malicious_oui" }

    fn name(&self) -> &str { "Malicious Hardware OUI Detected" }

    fn description(&self) -> &str {
        "Detects Access Points using MAC address OUIs associated with known offensive security hardware."
    }

    fn evaluate(&self, ctx: &DetectionContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Known offensive hardware OUIs (e.g., classic Hak5 Pineapple OUI)
        let malicious_ouis = vec!["00:13:37"]; 

        for ap in &ctx.access_points {
            let bssid_upper = ap.bssid.to_string().to_uppercase();
            
            for oui in &malicious_ouis {
                if bssid_upper.starts_with(oui) {
                    let ssid_display = ap.ssid.clone().unwrap_or_else(|| "<Hidden>".to_string());
                    
                    findings.push(Finding {
                        rule_id: self.rule_id().to_string(),
                        title: format!("Hostile Hardware Detected: \"{}\"", ssid_display),
                        description: "An Access Point was detected using a MAC address associated with penetration testing hardware (e.g., WiFi Pineapple).".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::new(95, "OUI perfectly matches known offensive hardware signatures.".to_string()),
                        evidence: vec![
                            Evidence::supporting("BSSID (MAC)", ap.bssid.to_string()),
                            Evidence::supporting("Vendor OUI", format!("Matched Signature: {}", oui))
                        ],
                        recommendation: "Immediately investigate the physical area for rogue hardware. Do not connect to this network. Alert your security team.".to_string(),
                        technical_detail: format!("Rule: {}. BSSID {} matched malicious OUI {}.", self.rule_id(), ap.bssid, oui),
                        plain_explanation: "We detected a Wi-Fi network being broadcast by specialized hardware typically used by hackers to intercept data (like a Hak5 WiFi Pineapple). This is highly suspicious and indicates a likely active attack in your physical vicinity.".to_string(),
                        affected_ap_id: Some(ap.id),
                        affected_client_id: None,
                    });
                }
            }
        }

        findings
    }
}
