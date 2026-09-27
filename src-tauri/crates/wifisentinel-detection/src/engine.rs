// wifisentinel-detection/src/engine.rs
// Detection rule engine and core types.

use chrono::Utc;
use uuid::Uuid;

use wifisentinel_core::models::{
    AccessPoint, ClientDevice, SecurityFinding, WirelessNetwork,
    Confidence, Evidence, Severity,
};

/// Context provided to each detection rule.
/// Rules have read-only access to the current observation snapshot.
pub struct DetectionContext {
    /// All currently known access points.
    pub access_points: Vec<AccessPoint>,
    /// All currently known networks.
    pub networks: Vec<WirelessNetwork>,
    /// All currently known clients.
    pub clients: Vec<ClientDevice>,
    /// BSSIDs the user has marked as trusted.
    pub trusted_bssids: Vec<String>,
    /// SSIDs the user has marked as trusted/known.
    pub trusted_ssids: Vec<String>,
    /// Detection sensitivity: "low" | "medium" | "high".
    pub sensitivity: String,
    /// Minimum confidence to emit a finding.
    pub min_confidence: u8,
}

/// A security finding produced by a rule evaluation.
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
    pub recommendation: String,
    pub technical_detail: String,
    pub plain_explanation: String,
    pub affected_ap_id: Option<Uuid>,
    pub affected_client_id: Option<Uuid>,
}

impl Finding {
    pub fn into_security_finding(self) -> SecurityFinding {
        SecurityFinding {
            id: Uuid::new_v4(),
            rule_id: self.rule_id,
            title: self.title,
            description: self.description,
            severity: self.severity,
            confidence: self.confidence,
            evidence: self.evidence,
            recommendation: self.recommendation,
            technical_detail: self.technical_detail,
            plain_explanation: self.plain_explanation,
            affected_ap_id: self.affected_ap_id,
            affected_client_id: self.affected_client_id,
            related_finding_ids: vec![],
            is_acknowledged: false,
            created_at: Utc::now(),
            is_active: true,
        }
    }
}

/// Trait all detection rules must implement.
pub trait DetectionRule: Send + Sync {
    /// Unique identifier for this rule (e.g. "rogue_ap.ssid_mismatch").
    fn rule_id(&self) -> &str;

    /// Human-readable rule name.
    fn name(&self) -> &str;

    /// Human-readable description of what this rule detects.
    fn description(&self) -> &str;

    /// Evaluate the context and return zero or more findings.
    fn evaluate(&self, ctx: &DetectionContext) -> Vec<Finding>;
}

/// The detection engine. Runs all registered rules and collects findings.
pub struct DetectionEngine {
    rules: Vec<Box<dyn DetectionRule>>,
}

impl DetectionEngine {
    /// Create a new engine with the default built-in rules.
    pub fn with_default_rules() -> Self {
        use crate::rules::{
            rogue_ap::RogueApRule,
            ssid_impersonation::SsidImpersonationRule,
            security_downgrade::SecurityDowngradeRule,
            channel_anomaly::ChannelAnomalyRule,
            open_network::OpenNetworkRule,
            beacon_anomaly::BeaconAnomalyRule,
            pineapple_detector::PineappleDetectorRule,
        };

        let mut engine = Self { rules: vec![] };
        engine.add_rule(Box::new(RogueApRule));
        engine.add_rule(Box::new(SsidImpersonationRule));
        engine.add_rule(Box::new(SecurityDowngradeRule));
        engine.add_rule(Box::new(ChannelAnomalyRule));
        engine.add_rule(Box::new(OpenNetworkRule));
        engine.add_rule(Box::new(BeaconAnomalyRule));
        engine.add_rule(Box::new(PineappleDetectorRule));
        engine
    }

    /// Add a custom rule.
    pub fn add_rule(&mut self, rule: Box<dyn DetectionRule>) {
        self.rules.push(rule);
    }

    /// Run all rules against the given context.
    /// Returns all findings that meet the minimum confidence threshold.
    pub fn evaluate(&self, ctx: &DetectionContext) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        for rule in &self.rules {
            let raw = rule.evaluate(ctx);
            for f in raw {
                if f.confidence.score >= ctx.min_confidence {
                    findings.push(f.into_security_finding());
                }
            }
        }

        // Sort by severity descending.
        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        findings
    }

    /// Returns metadata about all registered rules.
    pub fn rules_metadata(&self) -> Vec<RuleMetadata> {
        self.rules
            .iter()
            .map(|r| RuleMetadata {
                rule_id: r.rule_id().to_string(),
                name: r.name().to_string(),
                description: r.description().to_string(),
            })
            .collect()
    }
}

#[derive(Debug, serde::Serialize)]
pub struct RuleMetadata {
    pub rule_id: String,
    pub name: String,
    pub description: String,
}
