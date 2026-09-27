// wifisentinel-core/src/models/finding.rs
// SecurityFinding domain model and Evidence types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::common::Severity;

/// A security finding produced by the detection engine.
///
/// Every finding MUST contain an evidence chain — the engine never
/// emits findings without supporting evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    /// Unique identifier for this finding.
    pub id: Uuid,

    /// Unique ID of the rule that generated this finding.
    pub rule_id: String,

    /// Short human-readable title.
    pub title: String,

    /// Detailed description of what was detected.
    pub description: String,

    /// Severity classification.
    pub severity: Severity,

    /// Confidence percentage (0-100) with explanation.
    pub confidence: Confidence,

    /// Evidence chain supporting this finding.
    pub evidence: Vec<Evidence>,

    /// Recommended action for the user.
    pub recommendation: String,

    /// Technical explanation (for advanced users).
    pub technical_detail: String,

    /// Plain-language explanation (for beginners).
    pub plain_explanation: String,

    /// Affected access point, if applicable.
    pub affected_ap_id: Option<Uuid>,

    /// Affected client, if applicable.
    pub affected_client_id: Option<Uuid>,

    /// Related finding IDs (for correlated findings).
    pub related_finding_ids: Vec<Uuid>,

    /// Whether the user has acknowledged/dismissed this finding.
    pub is_acknowledged: bool,

    /// When this finding was generated.
    pub created_at: DateTime<Utc>,

    /// Whether the finding is still active (ongoing observation).
    pub is_active: bool,
}

/// Confidence value with explanation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Confidence {
    /// 0-100 score.
    pub score: u8,
    /// Human-readable explanation of how confidence was calculated.
    pub explanation: String,
}

impl Confidence {
    pub fn new(score: u8, explanation: impl Into<String>) -> Self {
        Self {
            score: score.min(100),
            explanation: explanation.into(),
        }
    }

    pub fn level(&self) -> ConfidenceLevel {
        match self.score {
            0..=29 => ConfidenceLevel::Low,
            30..=59 => ConfidenceLevel::Medium,
            60..=84 => ConfidenceLevel::High,
            85..=100 => ConfidenceLevel::VeryHigh,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
    VeryHigh,
}

/// A single piece of evidence supporting a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Short label for this evidence item.
    pub label: String,
    /// The observed value.
    pub observed: String,
    /// The expected / known-good value, if applicable.
    pub expected: Option<String>,
    /// Whether this evidence contributes to or against the finding.
    pub weight: EvidenceWeight,
    /// Timestamp of the observation.
    pub timestamp: Option<DateTime<Utc>>,
}

impl Evidence {
    pub fn supporting(label: impl Into<String>, observed: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            observed: observed.into(),
            expected: None,
            weight: EvidenceWeight::Supporting,
            timestamp: Some(Utc::now()),
        }
    }

    pub fn mismatch(
        label: impl Into<String>,
        observed: impl Into<String>,
        expected: impl Into<String>,
    ) -> Self {
        Self {
            label: label.into(),
            observed: observed.into(),
            expected: Some(expected.into()),
            weight: EvidenceWeight::StronglySupporting,
            timestamp: Some(Utc::now()),
        }
    }

    pub fn contextual(label: impl Into<String>, observed: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            observed: observed.into(),
            expected: None,
            weight: EvidenceWeight::Contextual,
            timestamp: Some(Utc::now()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceWeight {
    /// Evidence strongly supports the finding.
    StronglySupporting,
    /// Evidence supports the finding.
    Supporting,
    /// Context information — neither confirms nor denies.
    Contextual,
    /// Evidence argues against the finding.
    Contradicting,
}
