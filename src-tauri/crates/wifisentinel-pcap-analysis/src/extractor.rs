// wifisentinel-pcap-analysis/src/extractor.rs
// Extracts AP and client information from a PCAP analysis result.

use wifisentinel_core::models::{FrameSubtype, FrameType};
use super::indexer::PcapAnalysisResult;

pub struct PcapExtractor;

impl PcapExtractor {
    /// Returns a summary of APs extracted from a PCAP analysis.
    pub fn extract_ap_summary(result: &PcapAnalysisResult) -> Vec<PcapApSummary> {
        use std::collections::HashMap;
        let mut by_bssid: HashMap<String, PcapApSummary> = HashMap::new();

        for pkt in &result.packets {
            if !matches!(pkt.frame_type, FrameType::Management) { continue; }

            let bssid = match &pkt.bssid {
                Some(b) => b.to_string(),
                None => continue,
            };

            let entry = by_bssid.entry(bssid.clone()).or_insert_with(|| PcapApSummary {
                bssid: bssid.clone(),
                ssid: None,
                beacon_count: 0,
                probe_response_count: 0,
                channel: None,
                signal_dbm: None,
            });

            match pkt.frame_subtype {
                FrameSubtype::Beacon => {
                    entry.beacon_count += 1;
                    if entry.channel.is_none() { entry.channel = pkt.channel; }
                    if entry.signal_dbm.is_none() { entry.signal_dbm = pkt.rssi_dbm; }
                    if entry.ssid.is_none() {
                        entry.ssid = pkt.management_info.as_ref().and_then(|m| m.ssid.clone());
                    }
                }
                FrameSubtype::ProbeResponse => {
                    entry.probe_response_count += 1;
                    if entry.ssid.is_none() {
                        entry.ssid = pkt.management_info.as_ref().and_then(|m| m.ssid.clone());
                    }
                }
                _ => {}
            }
        }

        let mut summaries: Vec<PcapApSummary> = by_bssid.into_values().collect();
        summaries.sort_by(|a, b| b.beacon_count.cmp(&a.beacon_count));
        summaries
    }
}

#[derive(Debug, serde::Serialize)]
pub struct PcapApSummary {
    pub bssid: String,
    pub ssid: Option<String>,
    pub beacon_count: u64,
    pub probe_response_count: u64,
    pub channel: Option<u8>,
    pub signal_dbm: Option<i16>,
}
