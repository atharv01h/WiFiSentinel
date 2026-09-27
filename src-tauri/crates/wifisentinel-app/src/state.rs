// wifisentinel-app/src/state.rs
// Shared application state accessible to all Tauri commands.

use std::sync::Arc;
use tokio::sync::RwLock;

use wifisentinel_core::{
    config::AppConfig,
    db::{self, DbPool},
    Result,
};
use wifisentinel_capture::session::CaptureManager;
use wifisentinel_detection::engine::DetectionEngine;
use wifisentinel_wlan::normalizer::ScanNormalizer;

pub struct AppState {
    pub config: Arc<RwLock<AppConfig>>,
    pub db: DbPool,
    pub capture: Arc<CaptureManager>,
    pub detection: Arc<DetectionEngine>,
    pub normalizer: Arc<RwLock<ScanNormalizer>>,
}

impl AppState {
    pub async fn initialize(config: &AppConfig) -> Result<Self> {
        // Initialize database.
        let db = db::init_database(
            &config.database.db_path,
            config.database.wal_mode,
        ).await?;

        // Initialize capture manager.
        let capture = Arc::new(CaptureManager::new());

        // Initialize detection engine with default rules.
        let detection = Arc::new(DetectionEngine::with_default_rules());

        // Initialize scan normalizer.
        let normalizer = Arc::new(RwLock::new(ScanNormalizer::new()));

        Ok(Self {
            config: Arc::new(RwLock::new(config.clone())),
            db,
            capture,
            detection,
            normalizer,
        })
    }
}
