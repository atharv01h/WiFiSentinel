// wifisentinel-app/src/commands/pcap.rs

use tauri::State;
use wifisentinel_core::Error;
use crate::state::AppState;
use wifisentinel_pcap_analysis::PcapAnalyzer;

#[tauri::command]
pub async fn analyzepcap(
    _state: State<'_, AppState>,
    file_path: String,
) -> Result<serde_json::Value, Error> {
    let result = PcapAnalyzer::analyze(&file_path).await?;
    Ok(serde_json::to_value(result).unwrap_or_default())
}
