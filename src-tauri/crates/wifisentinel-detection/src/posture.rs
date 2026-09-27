// wifisentinel-detection/src/posture.rs
// Security posture analysis for the environment as a whole.

use serde::{Deserialize, Serialize};
use wifisentinel_core::models::{AccessPoint, AuthMode, CipherSuite, PmfMode, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureReport {
    pub overall_score: u8,
    pub overall_grade: String,
    pub ap_count: usize,
    pub open_network_count: usize,
    pub wep_count: usize,
    pub tkip_count: usize,
    pub wpa2_count: usize,
    pub wpa3_count: usize,
    pub pmf_enabled_count: usize,
    pub hidden_ssid_count: usize,
    pub issues: Vec<PostureIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureIssue {
    pub severity: Severity,
    pub message: String,
    pub count: usize,
}

/// Compute security posture for the current AP set.
pub fn analyze_posture(aps: &[AccessPoint]) -> PostureReport {
    let ap_count = aps.len();
    let mut score: i32 = 100;
    let mut issues = Vec::new();

    let open_count = aps.iter().filter(|ap| matches!(ap.auth_mode, AuthMode::Open)).count();
    let wep_count = aps.iter().filter(|ap| matches!(ap.auth_mode, AuthMode::Wep)).count();
    let tkip_count = aps.iter().filter(|ap| matches!(ap.cipher, CipherSuite::Tkip)).count();
    let wpa2_count = aps.iter().filter(|ap| matches!(ap.auth_mode, AuthMode::Wpa2Personal | AuthMode::Wpa2Enterprise)).count();
    let wpa3_count = aps.iter().filter(|ap| matches!(ap.auth_mode, AuthMode::Wpa3Personal | AuthMode::Wpa3Enterprise)).count();
    let pmf_count = aps.iter().filter(|ap| matches!(ap.pmf, Some(PmfMode::Required) | Some(PmfMode::Optional))).count();
    let hidden_count = aps.iter().filter(|ap| ap.is_hidden()).count();

    if open_count > 0 {
        let deduction = (open_count as i32 * 15).min(40);
        score -= deduction;
        issues.push(PostureIssue {
            severity: Severity::High,
            message: format!("{} open (unencrypted) network(s) detected", open_count),
            count: open_count,
        });
    }

    if wep_count > 0 {
        let deduction = (wep_count as i32 * 20).min(50);
        score -= deduction;
        issues.push(PostureIssue {
            severity: Severity::Critical,
            message: format!("{} WEP (broken) network(s) detected", wep_count),
            count: wep_count,
        });
    }

    if tkip_count > 0 {
        let deduction = (tkip_count as i32 * 10).min(30);
        score -= deduction;
        issues.push(PostureIssue {
            severity: Severity::High,
            message: format!("{} network(s) using deprecated TKIP cipher", tkip_count),
            count: tkip_count,
        });
    }

    // Bonus for WPA3.
    if wpa3_count > 0 {
        score += (wpa3_count as i32 * 3).min(10);
    }

    // Bonus for PMF.
    if pmf_count > 0 && ap_count > 0 {
        let pct = (pmf_count * 100) / ap_count;
        if pct > 50 {
            score += 5;
        }
    } else if ap_count > 0 {
        issues.push(PostureIssue {
            severity: Severity::Medium,
            message: "No networks with Management Frame Protection (PMF/802.11w) detected".into(),
            count: 0,
        });
    }

    let score = score.max(0).min(100) as u8;
    let grade = match score {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    };

    PostureReport {
        overall_score: score,
        overall_grade: grade.into(),
        ap_count,
        open_network_count: open_count,
        wep_count,
        tkip_count,
        wpa2_count,
        wpa3_count,
        pmf_enabled_count: pmf_count,
        hidden_ssid_count: hidden_count,
        issues,
    }
}
