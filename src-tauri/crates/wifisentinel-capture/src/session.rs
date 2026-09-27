use std::os::windows::process::CommandExt;
const CREATE_NO_WINDOW: u32 = 0x08000000;
// wifisentinel-capture/src/session.rs
// Capture session management.
//
// Handles Npcap availability detection, session lifecycle,
// graceful degradation when Npcap is absent.

use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use chrono::Utc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

use wifisentinel_core::{
    models::{CaptureSession, CaptureState},
    Error, Result,
};

use crate::queue::BoundedQueue;

/// Current capture status (for IPC).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CaptureStatus {
    pub state: CaptureState,
    pub adapter_name: String,
    pub packet_count: u64,
    pub dropped_count: u64,
    pub packet_rate: f64,
    pub file_size_bytes: u64,
    pub duration_secs: f64,
    pub npcap_available: bool,
    pub error: Option<String>,
}

/// Manages capture session lifecycle.
pub struct CaptureManager {
    npcap_available: bool,
    current_session: Arc<RwLock<Option<CaptureSession>>>,
    stop_signal: Arc<AtomicBool>,
}

impl CaptureManager {
    /// Initialize the capture manager, probing Npcap availability.
    pub fn new() -> Self {
        let npcap_available = Self::probe_npcap();
        if !npcap_available {
            warn!("Npcap not detected. Packet capture will be unavailable.");
        } else {
            info!("Npcap detected. Packet capture available.");
        }

        Self {
            npcap_available,
            current_session: Arc::new(RwLock::new(None)),
            stop_signal: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Returns true if Npcap is installed and the service is running.
    pub fn is_npcap_available(&self) -> bool {
        self.npcap_available
    }

    /// Returns a diagnostic explanation of capture availability.
    pub fn capture_availability_message(&self) -> String {
        if self.npcap_available {
            "Npcap is installed. Raw packet capture is available on supported adapters.".into()
        } else {
            "Npcap is not installed. To enable packet capture:\n\
             1. Download Npcap from https://npcap.com\n\
             2. Install with 'WinPcap API-compatible mode' enabled\n\
             3. Restart WiFiSentinel\n\n\
             Note: Some features (WLAN scanning, detection, timeline) work without Npcap.".into()
        }
    }

    /// Start a capture session.
    ///
    /// Returns an error with actionable message if capture is unavailable.
    pub async fn start_capture(
        &self,
        adapter_name: String,
        device_name: String,
        output_path: Option<String>,
        filter: Option<String>,
        _queue: &mut BoundedQueue,
    ) -> Result<Uuid> {
        // Enforce custom output path requirement
        if output_path.is_none() || output_path.as_ref().unwrap().trim().is_empty() {
            return Err(Error::CaptureError("A custom output path must be provided to save packets.".into()));
        }

        let mut session_guard = self.current_session.write().await;
        if session_guard.as_ref().map_or(false, |s| s.state.is_active()) {
            return Err(Error::CaptureError(
                "A capture session is already running. Stop it before starting a new one.".into()
            ));
        }

        let session_id = Uuid::new_v4();
        let session = CaptureSession {
            id: session_id,
            adapter_name: adapter_name.clone(),
            device_name: device_name.clone(),
            monitor_mode: false,
            filter: filter.clone(),
            output_path: output_path.clone(),
            started_at: Utc::now(),
            ended_at: None,
            state: CaptureState::Initializing,
            packet_count: 0,
            dropped_count: 0,
            packet_rate: 0.0,
            file_size_bytes: 0,
            error: None,
        };

        *session_guard = Some(session);
        drop(session_guard);

        self.stop_signal.store(false, Ordering::SeqCst);

        // Run the capture loop and catch errors
        match self.start_pcap_loop(session_id, device_name, filter, output_path, _queue).await {
            Ok(_) => {
                info!("Capture session {} started on {}", session_id, adapter_name);
                Ok(session_id)
            }
            Err(e) => {
                let mut error_guard = self.current_session.write().await;
                if let Some(ref mut s) = *error_guard {
                    s.state = CaptureState::Stopped;
                    s.error = Some(format!("Failed to start capture: {}. Note: Packet capture on Windows requires running the app as Administrator.", e));
                }
                Err(e)
            }
        }
    }

    async fn start_pcap_loop(
        &self,
        session_id: Uuid,
        device_name: String,
        filter: Option<String>,
        output_path: Option<String>,
        _queue: &mut BoundedQueue,
    ) -> Result<()> {
        let actual_device_name = if cfg!(windows) && !device_name.starts_with("\\Device\\NPF_") {
            format!("\\Device\\NPF_{}", device_name)
        } else {
            device_name.clone()
        };

        let mut cap = pcap::Capture::from_device(actual_device_name.as_str())
            .map_err(|e| Error::CaptureError(format!("Failed to open device: {}", e)))?
            .promisc(true)
            .snaplen(65535)
            .timeout(100)
            .open()
            .map_err(|e| Error::CaptureError(format!("Failed to start capture: {}", e)))?;

        if let Some(f) = filter {
            cap.filter(&f, true)
                .map_err(|e| Error::CaptureError(format!("Failed to set filter: {}", e)))?;
        }

        let mut guard = self.current_session.write().await;
        if let Some(ref mut s) = *guard {
            s.state = CaptureState::Running;
        }
        drop(guard);
        
        let stop_signal = self.stop_signal.clone();
        let session = self.current_session.clone();
        
        tokio::task::spawn_blocking(move || {
            let mut count = 0;
            let mut bytes = 0;
            
            // Create a savefile if an output path was provided
            let mut savefile = output_path.and_then(|path| {
                cap.savefile(&path).ok()
            });

            while !stop_signal.load(Ordering::SeqCst) {
                match cap.next_packet() {
                    Ok(packet) => {
                        count += 1;
                        bytes += packet.header.caplen as u64;
                        
                        if let Some(ref mut sf) = savefile {
                            sf.write(&packet);
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // Just loop around to check stop_signal
                    }
                    Err(e) => {
                        tracing::error!("Capture error: {}", e);
                        break;
                    }
                }

                if count % 100 == 0 {
                    if let Ok(mut g) = session.try_write() {
                        if let Some(ref mut s) = *g {
                            s.packet_count = count;
                            s.file_size_bytes = bytes;
                            let elapsed = s.duration_secs();
                            if elapsed > 0.0 {
                                s.packet_rate = count as f64 / elapsed;
                            }
                        }
                    }
                }
            }
        });
        
        Ok(())
    }

    /// Stop the current capture session gracefully.
    pub async fn stop_capture(&self) -> Result<()> {
        self.stop_signal.store(true, Ordering::SeqCst);

        let mut guard = self.current_session.write().await;
        if let Some(ref mut s) = *guard {
            s.state = CaptureState::Stopped;
            s.ended_at = Some(Utc::now());
        }

        info!("Capture session stop requested");
        Ok(())
    }

    /// Get current capture status.
    pub async fn status(&self) -> CaptureStatus {
        let guard = self.current_session.read().await;
        match &*guard {
            None => CaptureStatus {
                state: CaptureState::Unavailable,
                adapter_name: String::new(),
                packet_count: 0,
                dropped_count: 0,
                packet_rate: 0.0,
                file_size_bytes: 0,
                duration_secs: 0.0,
                npcap_available: self.npcap_available,
                error: if !self.npcap_available {
                    Some(self.capture_availability_message())
                } else {
                    None
                },
            },
            Some(s) => CaptureStatus {
                state: s.state,
                adapter_name: s.adapter_name.clone(),
                packet_count: s.packet_count,
                dropped_count: s.dropped_count,
                packet_rate: s.packet_rate,
                file_size_bytes: s.file_size_bytes,
                duration_secs: s.duration_secs(),
                npcap_available: self.npcap_available,
                error: s.error.clone(),
            },
        }
    }

    /// Probe whether Npcap is installed on this system.
    fn probe_npcap() -> bool {
        // Check 1: Service.
        let sc = std::process::Command::new("sc").creation_flags(CREATE_NO_WINDOW)
            .args(["query", "npcap"])
            .output();
        if let Ok(out) = sc {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains("RUNNING") || stdout.contains("STOPPED") {
                return true;
            }
        }

        // Check 2: Registry.
        let reg = std::process::Command::new("reg").creation_flags(CREATE_NO_WINDOW)
            .args(["query", r"HKLM\SOFTWARE\Npcap"])
            .output();
        if let Ok(out) = reg {
            if out.status.success() {
                return true;
            }
        }

        // Check 3: DLL presence.
        std::path::Path::new(r"C:\Windows\System32\Npcap\wpcap.dll").exists()
            || std::path::Path::new(r"C:\Windows\System32\wpcap.dll").exists()
    }
}

impl Default for CaptureManager {
    fn default() -> Self {
        Self::new()
    }
}

