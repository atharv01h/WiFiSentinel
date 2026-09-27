// wifisentinel-reporting/src/html.rs
// HTML report generator.

use chrono::Utc;
use wifisentinel_core::Result;
use wifisentinel_core::models::{AccessPoint, SecurityFinding, Severity, WirelessAdapter};
use wifisentinel_detection::posture::analyze_posture;

pub struct HtmlReporter;

impl HtmlReporter {
    pub fn generate(
        adapters: &[WirelessAdapter],
        aps: &[AccessPoint],
        findings: &[SecurityFinding],
    ) -> Result<String> {
        let posture = analyze_posture(aps);
        let now = Utc::now();

        let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == Severity::High).count();
        let _medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();

        let mut html = String::new();

        html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WiFiSentinel Report</title>
<style>
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f1117; color: #e0e0e0; margin: 0; padding: 2rem; }
h1 { color: #00d4ff; font-size: 2rem; margin-bottom: 0.25rem; }
h2 { color: #a0c4ff; border-bottom: 1px solid #2a2f45; padding-bottom: 0.5rem; }
.subtitle { color: #7a8190; font-size: 0.9rem; margin-bottom: 2rem; }
.card { background: #1a1f2e; border: 1px solid #2a2f45; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
.stat { background: #1a1f2e; border: 1px solid #2a2f45; border-radius: 8px; padding: 1rem; text-align: center; }
.stat-value { font-size: 2rem; font-weight: bold; color: #00d4ff; }
.stat-label { font-size: 0.8rem; color: #7a8190; margin-top: 0.25rem; }
.severity-critical { color: #ff4444; font-weight: bold; }
.severity-high { color: #ff8800; font-weight: bold; }
.severity-medium { color: #ffcc00; font-weight: bold; }
.severity-low { color: #44aaff; }
.severity-info { color: #888; }
table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.9rem; }
th { background: #2a2f45; padding: 0.75rem; text-align: left; color: #a0c4ff; }
td { padding: 0.6rem 0.75rem; border-bottom: 1px solid #2a2f45; }
tr:hover td { background: #1e2335; }
.finding { margin-bottom: 1rem; padding: 1rem; border-radius: 6px; border-left: 4px solid; }
.finding-critical { border-color: #ff4444; background: #1f1015; }
.finding-high { border-color: #ff8800; background: #1f1810; }
.finding-medium { border-color: #ffcc00; background: #1f1e10; }
.finding-low { border-color: #44aaff; background: #10151f; }
.finding-info { border-color: #555; background: #151515; }
.evidence { font-size: 0.85rem; color: #8a8f9a; margin-top: 0.5rem; }
.grade { font-size: 3rem; font-weight: bold; }
.grade-A { color: #00cc44; }
.grade-B { color: #88cc00; }
.grade-C { color: #ffcc00; }
.grade-D { color: #ff8800; }
.grade-F { color: #ff4444; }
.disclaimer { background: #1a1500; border: 1px solid #665500; border-radius: 6px; padding: 1rem; font-size: 0.85rem; color: #ccaa44; margin-bottom: 1.5rem; }
</style>
</head>
<body>
"#);

        // Header
        html.push_str(&format!(r#"
<h1>WiFiSentinel</h1>
<div class="subtitle">Windows-native wireless security intelligence &mdash; Generated: {}</div>
<div class="disclaimer">
  ⚠️ <strong>Authorized Use Only.</strong>
  This report is for authorized security assessment only.
  Only perform wireless testing on networks you own or have explicit written permission to assess.
</div>
"#, now.format("%Y-%m-%d %H:%M UTC")));

        // Summary grid
        html.push_str("<div class=\"grid\">");
        html.push_str(&stat_card(&aps.len().to_string(), "Access Points"));
        html.push_str(&stat_card(&adapters.len().to_string(), "Adapters"));
        html.push_str(&stat_card(&findings.len().to_string(), "Findings"));
        html.push_str(&stat_card(&format!("{} / {}", critical, high), "Critical / High"));
        html.push_str("</div>");

        // Posture
        html.push_str("<h2>Security Posture</h2>\n<div class=\"card\">");
        html.push_str(&format!(
            "<span class=\"grade grade-{grade}\">{grade}</span> — Score: {score}/100",
            grade = posture.overall_grade,
            score = posture.overall_score,
        ));
        if !posture.issues.is_empty() {
            html.push_str("<ul style='margin-top:1rem'>");
            for issue in &posture.issues {
                let cls = format!("severity-{}", format!("{:?}", issue.severity).to_lowercase());
                html.push_str(&format!("<li class='{}'>{}</li>", cls, html_escape(&issue.message)));
            }
            html.push_str("</ul>");
        }
        html.push_str("</div>\n");

        // Adapters
        html.push_str("<h2>Wireless Adapters</h2>\n<div class=\"card\">\n<table>\n");
        html.push_str("<tr><th>Name</th><th>Description</th><th>Driver</th><th>State</th><th>Capture</th><th>Score</th></tr>\n");
        for adapter in adapters {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}%</td></tr>\n",
                html_escape(&adapter.name),
                html_escape(&adapter.description),
                html_escape(adapter.driver_version.as_deref().unwrap_or("Unknown")),
                html_escape(adapter.state.display_name()),
                html_escape(adapter.capture_capability.display_name()),
                adapter.compatibility_score,
            ));
        }
        html.push_str("</table></div>\n");

        // Access Points
        html.push_str("<h2>Access Points</h2>\n<div class=\"card\">\n<table>\n");
        html.push_str("<tr><th>SSID</th><th>BSSID</th><th>Band</th><th>Ch</th><th>Signal</th><th>Auth</th><th>First Seen</th></tr>\n");
        for ap in aps {
            html.push_str(&format!(
                "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}%</td><td>{}</td><td>{}</td></tr>\n",
                html_escape(ap.ssid.as_deref().unwrap_or("[Hidden]")),
                ap.bssid,
                ap.band.display_name(),
                ap.channel,
                ap.signal_percent,
                html_escape(&ap.auth_mode.display_name()),
                ap.first_seen.format("%H:%M:%S"),
            ));
        }
        html.push_str("</table></div>\n");

        // Findings
        html.push_str("<h2>Security Findings</h2>\n");
        if findings.is_empty() {
            html.push_str("<div class=\"card\"><em>No findings.</em></div>\n");
        } else {
            for f in findings {
                let sev_class = f.severity.color_class();
                let finding_class = format!("finding finding-{}", format!("{:?}", f.severity).to_lowercase());
                html.push_str(&format!(
                    r#"<div class="{fc}">
<strong class="{sev}">[{sev_name}]</strong> {title}
<p>{desc}</p>
<div class="evidence"><strong>Evidence:</strong><ul>"#,
                    fc = finding_class,
                    sev = sev_class,
                    sev_name = f.severity.display_name(),
                    title = html_escape(&f.title),
                    desc = html_escape(&f.plain_explanation),
                ));
                for ev in &f.evidence {
                    html.push_str(&format!("<li><strong>{}</strong>: {}", html_escape(&ev.label), html_escape(&ev.observed)));
                    if let Some(exp) = &ev.expected {
                        html.push_str(&format!(" (expected: {})", html_escape(exp)));
                    }
                    html.push_str("</li>");
                }
                html.push_str(&format!(
                    r#"</ul></div>
<p><strong>Recommendation:</strong> {}</p>
<p><small>Confidence: {}% — Rule: {}</small></p>
</div>"#,
                    html_escape(&f.recommendation),
                    f.confidence.score,
                    html_escape(&f.rule_id),
                ));
            }
        }

        html.push_str("\n</body></html>");
        Ok(html)
    }
}

fn stat_card(value: &str, label: &str) -> String {
    format!(
        r#"<div class="stat"><div class="stat-value">{}</div><div class="stat-label">{}</div></div>"#,
        value, label
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
