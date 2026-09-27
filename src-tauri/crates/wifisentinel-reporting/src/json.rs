// wifisentinel-reporting/src/json.rs
// JSON report generator.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use wifisentinel_core::{Result, Error};
use wifisentinel_core::models::{AccessPoint, SecurityFinding, WirelessAdapter};
use wifisentinel_detection::posture::PostureReport;

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonReport {
    pub generated_at: String,
    pub report_version: String,
    pub summary: ReportSummary,
    pub adapters: Vec<serde_json::Value>,
    pub access_points: Vec<serde_json::Value>,
    pub findings: Vec<serde_json::Value>,
    pub posture: PostureReport,
    pub disclaimer: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_aps: usize,
    pub total_findings: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub posture_grade: String,
    pub posture_score: u8,
}

pub struct JsonReporter;

impl JsonReporter {
    pub fn generate(
        adapters: &[WirelessAdapter],
        aps: &[AccessPoint],
        findings: &[SecurityFinding],
    ) -> Result<String> {
        let posture = wifisentinel_detection::posture::analyze_posture(aps);

        let critical = findings.iter().filter(|f| matches!(f.severity, wifisentinel_core::models::Severity::Critical)).count();
        let high = findings.iter().filter(|f| matches!(f.severity, wifisentinel_core::models::Severity::High)).count();

        let report = JsonReport {
            generated_at: Utc::now().to_rfc3339(),
            report_version: "1.0".into(),
            summary: ReportSummary {
                total_aps: aps.len(),
                total_findings: findings.len(),
                critical_findings: critical,
                high_findings: high,
                posture_grade: posture.overall_grade.clone(),
                posture_score: posture.overall_score,
            },
            adapters: adapters.iter()
                .map(|a| serde_json::to_value(a).unwrap_or_default())
                .collect(),
            access_points: aps.iter()
                .map(|a| serde_json::to_value(a).unwrap_or_default())
                .collect(),
            findings: findings.iter()
                .map(|f| serde_json::to_value(f).unwrap_or_default())
                .collect(),
            posture,
            disclaimer: "This report is for authorized security assessment only. \
                Only perform wireless testing on networks you own or have explicit written permission to assess.".into(),
        };

        serde_json::to_string_pretty(&report)
            .map_err(|e| Error::Reporting(e.to_string()))
    }
}
