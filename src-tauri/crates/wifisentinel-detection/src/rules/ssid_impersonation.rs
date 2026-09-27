// wifisentinel-detection/src/rules/ssid_impersonation.rs
// Rule: SSID Impersonation / Evil Twin Indicator
//
// Detects when multiple BSSIDs share the same SSID but have materially
// different security configurations, suggesting infrastructure inconsistency
// or potential impersonation.
//
// IMPORTANT: This does NOT claim a confirmed "evil twin" attack.
// It surfaces evidence for the user to investigate.

use std::collections::HashMap;
use wifisentinel_core::models::{AuthMode, Confidence, Evidence, Severity};
use crate::engine::{DetectionContext, DetectionRule, Finding};

pub struct SsidImpersonationRule;

impl DetectionRule for SsidImpersonationRule {
    fn rule_id(&self) -> &str { "ssid.inconsistent_security" }

    fn name(&self) -> &str { "SSID Security Inconsistency" }

    fn description(&self) -> &str {
        "Detects multiple access points sharing an SSID but advertising \
         materially different security configurations, which may indicate \
         infrastructure inconsistency or SSID impersonation."
    }

    fn evaluate(&self, ctx: &DetectionContext) -> Vec<Finding> {
        // Group APs by SSID.
        let mut by_ssid: HashMap<&str, Vec<&wifisentinel_core::models::AccessPoint>> = HashMap::new();
        for ap in &ctx.access_points {
            if let Some(ssid) = &ap.ssid {
                if !ssid.is_empty() {
                    by_ssid.entry(ssid).or_default().push(ap);
                }
            }
        }

        let mut findings = Vec::new();

        for (ssid, aps) in by_ssid {
            if aps.len() < 2 {
                continue;
            }

            // Check for inconsistent security across BSSIDs.
            let first_auth = &aps[0].auth_mode;
            let inconsistent: Vec<&&wifisentinel_core::models::AccessPoint> = aps.iter()
                .skip(1)
                .filter(|ap| {
                    // Material difference: one is open/WEP while another is WPA2+
                    is_materially_different(&aps[0].auth_mode, &ap.auth_mode)
                })
                .collect();

            if inconsistent.is_empty() {
                continue;
            }

            let mut score: u8 = 40;
            let mut evidence = vec![
                Evidence::supporting(
                    "SSID",
                    format!("\"{}\" — multiple BSSIDs with different security", ssid),
                ),
                Evidence::contextual(
                    "Reference AP",
                    format!("{} — Auth: {}", aps[0].bssid, aps[0].auth_mode.display_name()),
                ),
            ];

            for mismatch_ap in &inconsistent {
                score = score.saturating_add(25);
                evidence.push(Evidence::mismatch(
                    "Inconsistent BSSID",
                    format!("{} — Auth: {}", mismatch_ap.bssid, mismatch_ap.auth_mode.display_name()),
                    format!("Expected: {}", first_auth.display_name()),
                ));

                // Open network appearing alongside encrypted: higher score.
                if matches!(mismatch_ap.auth_mode, AuthMode::Open) {
                    score = score.saturating_add(20);
                    evidence.push(Evidence::supporting(
                        "Open AP with matching SSID",
                        "An open (unencrypted) AP shares the same SSID as an encrypted network",
                    ));
                }
            }

            score = score.min(90);

            let severity = if score >= 80 { Severity::High }
                else if score >= 60 { Severity::Medium }
                else { Severity::Low };

            findings.push(Finding {
                rule_id: self.rule_id().to_string(),
                title: format!("SSID Security Inconsistency: \"{}\"", ssid),
                description: format!(
                    "{} access points share SSID \"{}\" but advertise different \
                     security configurations.",
                    aps.len(), ssid
                ),
                severity,
                confidence: Confidence::new(
                    score,
                    format!(
                        "Base: multiple BSSIDs with same SSID (+40). \
                         Security mismatch detected (+25 per mismatch). \
                         {} inconsistent AP(s) found.",
                        inconsistent.len()
                    ),
                ),
                evidence,
                recommendation: format!(
                    "Verify that all access points for \"{}\" are part of your \
                     authorized infrastructure. An AP with a weaker or different \
                     security mode may be unauthorized. Audit your AP inventory.",
                    ssid
                ),
                technical_detail: format!(
                    "Rule: {}. SSID: '{}'. Reference BSSID: {} ({}). \
                     Inconsistent BSSIDs: {}",
                    self.rule_id(),
                    ssid,
                    aps[0].bssid,
                    aps[0].auth_mode.display_name(),
                    inconsistent.iter().map(|a| a.bssid.to_string()).collect::<Vec<_>>().join(", ")
                ),
                plain_explanation: format!(
                    "Multiple Wi-Fi access points are broadcasting the same network name \
                     \"{}\" but using different security settings. \
                     In a legitimate network, all APs for the same SSID should use \
                     consistent security. A mismatch may indicate an unauthorized AP \
                     or impersonation attempt.",
                    ssid
                ),
                affected_ap_id: inconsistent.first().map(|a| a.id),
                affected_client_id: None,
            });
        }

        findings
    }
}

/// Returns true if two auth modes represent a material security difference.
fn is_materially_different(a: &AuthMode, b: &AuthMode) -> bool {
    use AuthMode::*;
    // Open vs any encrypted is material.
    let a_open = matches!(a, Open | Wep);
    let b_open = matches!(b, Open | Wep);
    if a_open != b_open { return true; }

    // WPA vs WPA2/3 is material.
    let a_gen = auth_gen(a);
    let b_gen = auth_gen(b);
    (a_gen - b_gen).abs() >= 2
}

fn auth_gen(a: &AuthMode) -> i32 {
    match a {
        AuthMode::Open => 0,
        AuthMode::Wep => 1,
        AuthMode::WpaPersonal | AuthMode::WpaEnterprise => 2,
        AuthMode::Wpa2Personal | AuthMode::Wpa2Enterprise => 3,
        AuthMode::Wpa3Personal | AuthMode::Wpa3Enterprise | AuthMode::Owe => 4,
        AuthMode::Unknown(_) => 1,
    }
}
