// wifisentinel-app/src/commands/settings.rs

use tauri::State;
use wifisentinel_core::Error;
use crate::state::AppState;

#[tauri::command]
pub async fn getconfiguration(state: State<'_, AppState>) -> Result<serde_json::Value, Error> {
    let config = state.config.read().await;
    Ok(serde_json::to_value(&*config).unwrap_or_default())
}

#[tauri::command]
pub async fn updateconfiguration(
    state: State<'_, AppState>,
    updates: serde_json::Value,
) -> Result<(), Error> {
    let _config = state.config.write().await;
    // Merge updates into config.
    // For production: use a proper merge strategy per field.
    tracing::info!("Configuration update requested: {}", updates);
    Ok(())
}

#[tauri::command]
pub async fn marktrusted(
    state: State<'_, AppState>,
    entity_type: String,
    value: String,
    notes: Option<String>,
) -> Result<(), Error> {
    match entity_type.as_str() {
        "ssid" => {
            sqlx::query("INSERT OR IGNORE INTO trusted_ssids (ssid, notes) VALUES (?, ?)")
                .bind(&value)
                .bind(notes)
                .execute(&state.db)
                .await?;
            let mut config = state.config.write().await;
            if !config.detection.trusted_ssids.contains(&value) {
                config.detection.trusted_ssids.push(value);
            }
        }
        "bssid" => {
            sqlx::query("INSERT OR IGNORE INTO trusted_bssids (bssid, notes) VALUES (?, ?)")
                .bind(&value)
                .bind(notes)
                .execute(&state.db)
                .await?;
            let mut config = state.config.write().await;
            if !config.detection.trusted_bssids.contains(&value) {
                config.detection.trusted_bssids.push(value);
            }
        }
        _ => {
            return Err(Error::Other(format!("Unknown entity type: {}", entity_type)));
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn clearhistory(state: State<'_, AppState>) -> Result<(), Error> {
    sqlx::query("DELETE FROM observations").execute(&state.db).await.ok();
    sqlx::query("DELETE FROM timeline_events").execute(&state.db).await?;
    sqlx::query("DELETE FROM signal_history").execute(&state.db).await?;
    sqlx::query("DELETE FROM channel_history").execute(&state.db).await?;
    sqlx::query("DELETE FROM packets_meta").execute(&state.db).await?;
    tracing::info!("History cleared by user request");
    Ok(())
}
