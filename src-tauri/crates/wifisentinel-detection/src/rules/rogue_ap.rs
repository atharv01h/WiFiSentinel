// wifisentinel-detection/src/rules/rogue_ap.rs
// Rule: Potential Rogue AP
//
// Detects an AP with an SSID that matches a trusted network but a BSSID
// that has not been previously observed.
//
// Evidence chain: SSID match + new BSSID + optional: different security, channel.
// This does NOT automatically call the AP malicious. It flags it for review.

use std::collections::HashSet;
use wifisentinel_core::models::{AuthMode, Confidence, Evidence, Severity};
use crate::engine::{DetectionContext, DetectionRule, Finding};

pub struct RogueApRule;

impl DetectionRule for RogueApRule {
    fn rule_id(&self) -> &str { "rogue_ap.new_bssid_known_ssid" }

    fn name(&self) -> &str { "Possible Rogue AP — New BSSID for Known SSID" }

    fn description(&self) -> &str {
        "Detects an access point whose SSID matches a trusted or previously-seen network \
         but whose BSSID has not been previously observed."
    }

    fn evaluate(&self, ctx: &DetectionContext) -> Vec<Finding> {
        if ctx.trusted_ssids.is_empty() {
            // Without a trusted baseline, we cannot make this determination.
            return vec![];
        }

        let mut findings = Vec::new();

        // Build map: SSID → set of trusted BSSIDs.
        let trusted_bssid_set: HashSet<String> = ctx.trusted_bssids
            .iter()
            .map(|b| b.to_lowercase())
            .collect();

        for ap in &ctx.access_points {
            let ssid = match &ap.ssid {
                Some(s) if !s.is_empty() => s.clone(),
                _ => continue,
            };

            // Only evaluate APs whose SSID matches a trusted network.
            if !ctx.trusted_ssids.iter().any(|ts| ts.eq_ignore_ascii_case(&ssid)) {
                continue;
            }

            let bssid_lower = ap.bssid.to_string().to_lowercase();

            // Is this BSSID trusted?
            if trusted_bssid_set.contains(&bssid_lower) {
                continue;
            }

            // This BSSID is NOT in the trusted list for this SSID.
            let mut evidence = vec![
                Evidence::mismatch(
                    "SSID",
                    &ssid,
                    "Matches trusted network",
                ),
                Evidence::supporting(
                    "BSSID",
                    format!("{} — not in trusted BSSID list", ap.bssid),
                ),
            ];

            let mut score: u8 = 50; // Base: SSID matches trusted network, BSSID unknown

            // Higher confidence if security differs from known profile.
            // (We check if the network is open or uses legacy auth.)
            if matches!(ap.auth_mode, AuthMode::Open | AuthMode::Wep) {
                score = score.saturating_add(20);
                evidence.push(Evidence::supporting(
                    "Security",
                    format!(
                        "Weak authentication: {} — unusual for enterprise networks",
                        ap.auth_mode.display_name()
                    ),
                ));
            }

            // Adjust by sensitivity.
            let (severity, threshold) = match ctx.sensitivity.as_str() {
                "high" => (Severity::High, 40u8),
                "low" => (Severity::Medium, 70u8),
                _ => (Severity::Medium, 50u8),
            };

            if score < threshold { continue; }

            findings.push(Finding {
                rule_id: self.rule_id().to_string(),
                title: format!("Possible Rogue AP: \"{}\"", ssid),
                description: format!(
                    "An access point with SSID \"{}\" was detected with BSSID {} \
                     which is not in the trusted infrastructure list.",
                    ssid, ap.bssid
                ),
                severity,
                confidence: Confidence::new(
                    score,
                    format!(
                        "SSID matches trusted network (+50), \
                         BSSID not in trusted list (core indicator). \
                         Sensitivity: {}.",
                        ctx.sensitivity
                    ),
                ),
                evidence,
                recommendation: format!(
                    "Verify whether BSSID {} is a legitimate access point for \
                     the \"{}\" network. Check your AP inventory. \
                     Do not connect to this AP until verified.",
                    ap.bssid, ssid
                ),
                technical_detail: format!(
                    "Rule: {}. SSID '{}' is marked trusted. \
                     BSSID {} was not previously associated with this SSID. \
                     Auth: {}. Channel: {}.",
                    self.rule_id(), ssid, ap.bssid, ap.auth_mode.display_name(), ap.channel
                ),
                plain_explanation: format!(
                    "An access point claiming to be your network \"{}\" was found, \
                     but its hardware address ({}) doesn't match any known access \
                     point. This could mean someone set up an unauthorized AP, \
                     or it could be a new legitimate AP you haven't added yet. \
                     Verify before connecting.",
                    ssid, ap.bssid
                ),
                affected_ap_id: Some(ap.id),
                affected_client_id: None,
            });
        }

        findings
    }
}
