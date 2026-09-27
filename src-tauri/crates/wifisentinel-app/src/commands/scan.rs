// wifisentinel-app/src/commands/scan.rs

use tauri::State;
use wifisentinel_core::Error;
use wifisentinel_wlan::{adapter::AdapterEnumerator, scan::BssScanner};
use crate::state::AppState;

#[tauri::command]
pub async fn scannetworks(state: State<'_, AppState>) -> Result<serde_json::Value, Error> {
    let adapters = tokio::task::spawn_blocking(AdapterEnumerator::enumerate)
        .await
        .map_err(|e| Error::Other(format!("{}", e)))?;

    let adapter = adapters.into_iter().next()
        .ok_or(Error::WlanScanFailed { reason: "No wireless adapter found".into() })?;

    let aps = BssScanner::scan(adapter.id, &adapter.guid).await?;

    // Run through normalizer.
    let mut normalizer = state.normalizer.write().await;
    let result = normalizer.process(aps.clone());

    // Persist new APs.
    let ap_repo = wifisentinel_core::db::repository::ApRepository::new(&state.db);
    for ap in result.new_aps.iter().chain(result.updated_aps.iter()) {
        let _ = ap_repo.upsert(ap).await;
    }

    // Persist timeline events.
    let timeline_repo = wifisentinel_core::db::repository::TimelineRepository::new(&state.db);
    for event in &normalizer.timeline_events {
        let _ = timeline_repo.insert(event).await;
    }
    normalizer.timeline_events.clear();

    // Run detection.
    let config = state.config.read().await;
    let ctx = wifisentinel_detection::engine::DetectionContext {
        access_points: aps.clone(),
        networks: vec![],
        clients: vec![],
        trusted_bssids: config.detection.trusted_bssids.clone(),
        trusted_ssids: config.detection.trusted_ssids.clone(),
        sensitivity: config.detection.sensitivity.clone(),
        min_confidence: config.detection.min_confidence,
    };
    drop(config);

    let findings = state.detection.evaluate(&ctx);
    let findings_repo = wifisentinel_core::db::repository::FindingsRepository::new(&state.db);
    for finding in &findings {
        let _ = findings_repo.insert(finding).await;
    }

    Ok(serde_json::json!({
        "access_points": &aps,
        "new_count": result.new_aps.len(),
        "total_count": aps.len(),
        "findings_count": findings.len(),
    }))
}

#[tauri::command]
pub async fn getaccesspoints(state: State<'_, AppState>) -> Result<serde_json::Value, Error> {
    let repo = wifisentinel_core::db::repository::ApRepository::new(&state.db);
    let rows = repo.get_all().await?;
    Ok(serde_json::to_value(rows).unwrap_or_default())
}

#[tauri::command]
pub async fn getnetworks(_state: State<'_, AppState>) -> Result<serde_json::Value, Error> {
    // Return network list from normalizer state.
    Ok(serde_json::json!([]))
}
