// wifisentinel-analysis/src/statistics.rs
// Statistical summary of the scanned wireless environment.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use wifisentinel_core::models::{AccessPoint, AuthMode};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub total_aps: usize,
    pub active_aps: usize,
    pub hidden_aps: usize,
    pub by_band: HashMap<String, usize>,
    pub by_auth: HashMap<String, usize>,
    pub by_phy: HashMap<String, usize>,
    pub by_channel: HashMap<u8, usize>,
    pub avg_signal_dbm: f32,
    pub strongest_signal_dbm: i16,
    pub weakest_signal_dbm: i16,
    pub open_networks: usize,
    pub wpa3_networks: usize,
    pub pmf_networks: usize,
}

impl ScanStatistics {
    pub fn compute(aps: &[AccessPoint]) -> Self {
        let total = aps.len();
        let active = aps.iter().filter(|a| a.is_active).count();
        let hidden = aps.iter().filter(|a| a.is_hidden()).count();

        let mut by_band = HashMap::new();
        let mut by_auth = HashMap::new();
        let mut by_phy = HashMap::new();
        let mut by_channel = HashMap::new();
        let mut signal_sum: f32 = 0.0;
        let mut strongest = i16::MIN;
        let mut weakest = i16::MAX;
        let mut open_count = 0;
        let mut wpa3_count = 0;
        let mut pmf_count = 0;

        for ap in aps {
            *by_band.entry(ap.band.display_name().to_string()).or_insert(0usize) += 1;
            *by_auth.entry(ap.auth_mode.display_name()).or_insert(0usize) += 1;
            if let Some(phy) = &ap.phy {
                *by_phy.entry(phy.display_name().to_string()).or_insert(0usize) += 1;
            }
            *by_channel.entry(ap.channel).or_insert(0usize) += 1;
            signal_sum += ap.rssi_dbm as f32;
            if ap.rssi_dbm > strongest { strongest = ap.rssi_dbm; }
            if ap.rssi_dbm < weakest { weakest = ap.rssi_dbm; }
            if matches!(ap.auth_mode, AuthMode::Open) { open_count += 1; }
            if matches!(ap.auth_mode, AuthMode::Wpa3Personal | AuthMode::Wpa3Enterprise) { wpa3_count += 1; }
            if ap.pmf.is_some() { pmf_count += 1; }
        }

        Self {
            total_aps: total,
            active_aps: active,
            hidden_aps: hidden,
            by_band,
            by_auth,
            by_phy,
            by_channel,
            avg_signal_dbm: if total > 0 { signal_sum / total as f32 } else { 0.0 },
            strongest_signal_dbm: if total > 0 { strongest } else { 0 },
            weakest_signal_dbm: if total > 0 { weakest } else { 0 },
            open_networks: open_count,
            wpa3_networks: wpa3_count,
            pmf_networks: pmf_count,
        }
    }
}
