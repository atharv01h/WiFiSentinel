// wifisentinel-app/src/commands/capture.rs

use tauri::State;
use wifisentinel_core::Error;
use crate::state::AppState;
use wifisentinel_capture::queue::BoundedQueue;

#[tauri::command]
pub async fn getcapturestatus(state: State<'_, AppState>) -> Result<serde_json::Value, Error> {
    let status = state.capture.status().await;
    Ok(serde_json::to_value(status).unwrap_or_default())
}

#[tauri::command]
pub async fn startcapture(
    state: State<'_, AppState>,
    adapter_name: String,
    device_name: String,
    output_path: Option<String>,
    filter: Option<String>,
) -> Result<serde_json::Value, Error> {
    let config = state.config.read().await;
    let capacity = config.capture.queue_capacity;
    drop(config);

    let mut queue = BoundedQueue::new(capacity);

    let session_id = state.capture.start_capture(
        adapter_name, device_name, output_path, filter, &mut queue
    ).await?;

    Ok(serde_json::json!({ "session_id": session_id.to_string() }))
}

#[tauri::command]
pub async fn stopcapture(state: State<'_, AppState>) -> Result<(), Error> {
    state.capture.stop_capture().await
}
