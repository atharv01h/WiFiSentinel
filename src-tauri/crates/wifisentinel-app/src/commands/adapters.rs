// wifisentinel-app/src/commands/adapters.rs

use tauri::State;
use wifisentinel_core::Error;
use wifisentinel_wlan::adapter::AdapterEnumerator;
use crate::state::AppState;

#[tauri::command]
pub async fn getadapters(state: State<'_, AppState>) -> Result<serde_json::Value, Error> {
    let adapters = tokio::task::spawn_blocking(AdapterEnumerator::enumerate)
        .await
        .map_err(|e| Error::Other(format!("Adapter enumeration failed: {}", e)))?;

    // Persist to database.
    let repo = wifisentinel_core::db::repository::AdapterRepository::new(&state.db);
    for adapter in &adapters {
        if let Err(e) = repo.upsert(adapter).await {
            tracing::warn!("Failed to persist adapter {}: {}", adapter.name, e);
        }
    }

    Ok(serde_json::to_value(&adapters).unwrap_or_default())
}
