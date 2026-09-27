// wifisentinel-app/src/commands/report.rs

use tauri::State;
use chrono::Utc;
use wifisentinel_core::Error;
use crate::state::AppState;
use wifisentinel_reporting::{html::HtmlReporter, json::JsonReporter};
use wifisentinel_wlan::adapter::AdapterEnumerator;

#[tauri::command]
pub async fn generatereport(
    state: State<'_, AppState>,
    format: String,
    output_path: Option<String>,
) -> Result<serde_json::Value, Error> {
    let adapters = tokio::task::spawn_blocking(AdapterEnumerator::enumerate)
        .await
        .map_err(|e| Error::Other(format!("{}", e)))?;

    let normalizer = state.normalizer.read().await;
    let aps: Vec<_> = normalizer.known_aps.values().cloned().collect();
    drop(normalizer);

    let findings_repo = wifisentinel_core::db::repository::FindingsRepository::new(&state.db);
    let _finding_rows = findings_repo.get_active().await.unwrap_or_default();
    // For now, build minimal SecurityFindings from rows.
    let findings: Vec<wifisentinel_core::models::SecurityFinding> = vec![];

    let (content, ext) = match format.as_str() {
        "json" => (JsonReporter::generate(&adapters, &aps, &findings)?, "json"),
        _ => (HtmlReporter::generate(&adapters, &aps, &findings)?, "html"),
    };

    let path = output_path.unwrap_or_else(|| {
        let config_path = std::env::var("APPDATA")
            .map(|p| format!("{}\\WiFiSentinel\\reports\\report-{}.{}", p, Utc::now().format("%Y%m%d-%H%M%S"), ext))
            .unwrap_or_else(|_| format!("report.{}", ext));
        config_path
    });

    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent).map_err(Error::Io)?;
    }
    std::fs::write(&path, &content).map_err(Error::Io)?;

    Ok(serde_json::json!({ "path": path, "size_bytes": content.len() }))
}
