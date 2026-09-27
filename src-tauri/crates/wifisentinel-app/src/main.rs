// wifisentinel-app/src/main.rs
// Tauri application entry point.

/*
 * Created and maintained by Atharv Hatwar.
 * Purpose: Application entry point, Tauri setup, and IPC command registration.
 */
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod state;

use state::AppState;
use tauri::Manager;
use tracing::info;

fn main() {
    // Initialize logging before anything else.
    let config = wifisentinel_core::config::AppConfig::default();
    if let Err(e) = wifisentinel_core::logging::init_logging(
        &config.general.log_level,
        config.general.log_dir.as_deref(),
    ) {
        eprintln!("Failed to initialize logging: {}", e);
    }

    info!("WiFiSentinel starting...");
    info!("AUTHORIZED USE ONLY: Only scan networks you own or have permission to assess.");

    tauri::Builder::default()
        .setup(|app| {
            let handle = app.handle().clone();
            tauri::async_runtime::block_on(async {
                match AppState::initialize(&wifisentinel_core::config::AppConfig::default()).await {
                    Ok(state) => {
                        app.manage(state);
                        info!("AppState initialized successfully");
                    }
                    Err(e) => {
                        tracing::error!("Failed to initialize AppState: {}", e);
                    }
                }
            });
            if let Some(w) = app.get_webview_window("main") {
                w.show().unwrap_or(());
                w.set_focus().unwrap_or(());
                tracing::info!("Explicitly showed window using get_webview_window");
            } else {
                tracing::error!("Main window not found!");
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::adapters::getadapters,
            commands::scan::scannetworks,
            commands::scan::getaccesspoints,
            commands::scan::getnetworks,
            commands::capture::getcapturestatus,
            commands::capture::startcapture,
            commands::capture::stopcapture,
            commands::findings::getfindings,
            commands::timeline::gettimeline,
            commands::analysis::getstatistics,
            commands::analysis::getchannelanalysis,
            commands::analysis::getposture,
            commands::pcap::analyzepcap,
            commands::report::generatereport,
            commands::settings::getconfiguration,
            commands::settings::updateconfiguration,
            commands::settings::marktrusted,
            commands::settings::clearhistory,
            commands::diagnostics::getdiagnostics,
            commands::profiles::getsavedprofiles,
        ])
        .run(tauri::generate_context!())
        .expect("WiFiSentinel application error");
}
