// wifisentinel-pcap-analysis/src/indexer.rs
// Offline PCAP analysis pipeline.
//
// Processes PCAP files in chunks to avoid freezing the UI.
// All heavy processing runs on a blocking thread pool.

use std::path::Path;
use chrono::{DateTime, Utc, TimeZone};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use wifisentinel_core::{Error, Result};
use wifisentinel_capture::pcap_io::PcapReader;
use wifisentinel_capture::dot11::parse_dot11_frame;
use wifisentinel_capture::radiotap::RadiotapHeader;
use wifisentinel_core::models::{PacketMetadata, FrameType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapAnalysisResult {
    pub session_id: Uuid,
    pub file_path: String,
    pub total_packets: u64,
    pub processed_packets: u64,
    pub malformed_packets: u64,
    pub management_frames: u64,
    pub control_frames: u64,
    pub data_frames: u64,
    pub unique_bssids: Vec<String>,
    pub unique_ssids: Vec<String>,
    pub link_type: u32,
    pub has_radiotap: bool,
    pub first_timestamp: Option<DateTime<Utc>>,
    pub last_timestamp: Option<DateTime<Utc>>,
    pub duration_secs: f64,
    pub packets: Vec<PacketMetadata>,
}

pub struct PcapAnalyzer;

impl PcapAnalyzer {
    /// Analyze a PCAP file asynchronously.
    ///
    /// Large files are processed on a blocking thread to avoid stalling the async runtime.
    /// Returns a full analysis result.
    pub async fn analyze(path: impl AsRef<Path>) -> Result<PcapAnalysisResult> {
        let path = path.as_ref().to_path_buf();

        tokio::task::spawn_blocking(move || {
            Self::analyze_blocking(&path)
        })
        .await
        .map_err(|e| Error::Other(format!("PCAP analysis task failed: {}", e)))?
    }

    fn analyze_blocking(path: &Path) -> Result<PcapAnalysisResult> {
        info!("Starting PCAP analysis: {}", path.display());

        let mut reader = PcapReader::open(path)?;
        let session_id = Uuid::new_v4();
        let has_radiotap = reader.has_radiotap();
        let link_type = reader.link_type;

        let mut result = PcapAnalysisResult {
            session_id,
            file_path: path.display().to_string(),
            total_packets: 0,
            processed_packets: 0,
            malformed_packets: 0,
            management_frames: 0,
            control_frames: 0,
            data_frames: 0,
            unique_bssids: vec![],
            unique_ssids: vec![],
            link_type,
            has_radiotap,
            first_timestamp: None,
            last_timestamp: None,
            duration_secs: 0.0,
            packets: vec![],
        };

        let mut bssids = std::collections::HashSet::new();
        let mut ssids = std::collections::HashSet::new();

        // Limit packet storage to prevent OOM on large files.
        const MAX_STORED_PACKETS: usize = 10_000;

        loop {
            let record = match reader.next_record() {
                Ok(Some(r)) => r,
                Ok(None) => break, // EOF
                Err(Error::PcapMalformed { reason }) => {
                    warn!("Malformed record: {}. Stopping analysis.", reason);
                    result.malformed_packets += 1;
                    break;
                }
                Err(e) => return Err(e),
            };

            result.total_packets += 1;

            // Convert timestamp.
            let ts = Utc
                .timestamp_opt(record.timestamp_sec as i64, record.timestamp_frac * 1000)
                .single()
                .unwrap_or_else(Utc::now);

            if result.first_timestamp.is_none() { result.first_timestamp = Some(ts); }
            result.last_timestamp = Some(ts);

            // Parse frame.
            let (frame_data, radiotap_channel, radiotap_signal, data_rate) =
                if has_radiotap && record.data.len() >= 8 {
                    match RadiotapHeader::parse(&record.data) {
                        Ok((rt, offset)) => {
                            let frame_data = &record.data[offset.min(record.data.len())..];
                            (frame_data, rt.frequency_mhz().and_then(freq_to_channel), rt.signal_dbm(), rt.rate_mbps())
                        }
                        Err(_) => {
                            result.malformed_packets += 1;
                            continue;
                        }
                    }
                } else {
                    (&record.data[..], None, None, None)
                };

            let pkt = match parse_dot11_frame(
                frame_data,
                session_id,
                ts,
                radiotap_channel,
                radiotap_signal,
                data_rate,
                has_radiotap,
            ) {
                Some(p) => p,
                None => { result.malformed_packets += 1; continue; }
            };

            result.processed_packets += 1;

            match pkt.frame_type {
                FrameType::Management => result.management_frames += 1,
                FrameType::Control => result.control_frames += 1,
                FrameType::Data => result.data_frames += 1,
                _ => {}
            }

            if let Some(bssid) = &pkt.bssid {
                bssids.insert(bssid.to_string());
            }
            if let Some(ref mgmt) = pkt.management_info {
                if let Some(ssid) = &mgmt.ssid {
                    ssids.insert(ssid.clone());
                }
            }

            if result.packets.len() < MAX_STORED_PACKETS {
                result.packets.push(pkt);
            }
        }

        result.unique_bssids = bssids.into_iter().collect();
        result.unique_bssids.sort();
        result.unique_ssids = ssids.into_iter().collect();
        result.unique_ssids.sort();

        if let (Some(first), Some(last)) = (result.first_timestamp, result.last_timestamp) {
            result.duration_secs = (last - first).num_milliseconds() as f64 / 1000.0;
        }

        info!(
            "PCAP analysis complete: {} packets ({} processed, {} malformed)",
            result.total_packets, result.processed_packets, result.malformed_packets
        );

        Ok(result)
    }
}

fn freq_to_channel(freq_mhz: u16) -> Option<u8> {
    if freq_mhz >= 2412 && freq_mhz <= 2472 {
        Some(((freq_mhz - 2407) / 5) as u8)
    } else if freq_mhz == 2484 {
        Some(14)
    } else if freq_mhz >= 5160 && freq_mhz <= 5885 {
        Some(((freq_mhz - 5000) / 5) as u8)
    } else {
        None
    }
}
