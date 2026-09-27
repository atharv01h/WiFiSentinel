// wifisentinel-app/src/commands/analysis.rs

use tauri::State;
use wifisentinel_core::Error;
use crate::state::AppState;
use wifisentinel_analysis::{statistics::ScanStatistics, channel_analysis::ChannelAnalysis};
use wifisentinel_detection::posture::analyze_posture;

#[tauri::command]
pub async fn getstatistics(state: State<'_, AppState>) -> Result<serde_json::Value, Error> {
    let normalizer = state.normalizer.read().await;
    let aps: Vec<_> = normalizer.known_aps.values().cloned().collect();
    drop(normalizer);
    let stats = ScanStatistics::compute(&aps);
    Ok(serde_json::to_value(stats).unwrap_or_default())
}

#[tauri::command]
pub async fn getchannelanalysis(state: State<'_, AppState>) -> Result<serde_json::Value, Error> {
    let normalizer = state.normalizer.read().await;
    let aps: Vec<_> = normalizer.known_aps.values().cloned().collect();
    drop(normalizer);
    let analysis = ChannelAnalysis::compute(&aps);
    Ok(serde_json::to_value(analysis).unwrap_or_default())
}

#[tauri::command]
pub async fn getposture(state: State<'_, AppState>) -> Result<serde_json::Value, Error> {
    let normalizer = state.normalizer.read().await;
    let aps: Vec<_> = normalizer.known_aps.values().cloned().collect();
    drop(normalizer);
    let posture = analyze_posture(&aps);
    Ok(serde_json::to_value(posture).unwrap_or_default())
}
