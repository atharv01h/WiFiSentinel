// wifisentinel-app/src/commands/timeline.rs

use tauri::State;
use wifisentinel_core::Error;
use crate::state::AppState;

#[tauri::command]
pub async fn gettimeline(
    state: State<'_, AppState>,
    limit: Option<i64>,
    offset: Option<i64>,
    severity: Option<String>,
    bssid: Option<String>,
) -> Result<serde_json::Value, Error> {
    let repo = wifisentinel_core::db::repository::TimelineRepository::new(&state.db);
    let rows = repo.query(
        limit.unwrap_or(100),
        offset.unwrap_or(0),
        severity.as_deref(),
        bssid.as_deref(),
    ).await?;
    Ok(serde_json::to_value(rows).unwrap_or_default())
}
