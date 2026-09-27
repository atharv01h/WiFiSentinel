// wifisentinel-app/src/commands/findings.rs

use tauri::State;
use wifisentinel_core::Error;
use crate::state::AppState;

#[tauri::command]
pub async fn getfindings(state: State<'_, AppState>) -> Result<serde_json::Value, Error> {
    let repo = wifisentinel_core::db::repository::FindingsRepository::new(&state.db);
    let rows = repo.get_active().await?;
    Ok(serde_json::to_value(rows).unwrap_or_default())
}
