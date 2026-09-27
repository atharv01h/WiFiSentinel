// wifisentinel-app/src/commands/diagnostics.rs

use tauri::State;
use wifisentinel_core::Error;
use crate::state::AppState;

#[tauri::command]
pub async fn getdiagnostics(state: State<'_, AppState>) -> Result<serde_json::Value, Error> {
    let capture_status = state.capture.status().await;
    let rules = state.detection.rules_metadata();

    Ok(serde_json::json!({
        "capture": capture_status,
        "detection_rules": rules,
        "npcap_available": capture_status.npcap_available,
        "db_path": state.config.read().await.database.db_path.display().to_string(),
    }))
}
