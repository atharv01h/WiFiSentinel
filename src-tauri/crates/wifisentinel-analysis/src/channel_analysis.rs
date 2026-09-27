// wifisentinel-analysis/src/channel_analysis.rs
// Channel utilization analysis.
//
// IMPORTANT: This measures AP density per channel, NOT actual RF utilization.
// We explicitly document this distinction in the output.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use wifisentinel_core::models::AccessPoint;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelAnalysis {
    /// AP count per channel. This is NOT RF utilization.
    pub ap_density: HashMap<u8, ChannelDensity>,
    /// Channels with highest AP count (top 3).
    pub most_congested: Vec<u8>,
    /// Channels with only 1 AP.
    pub least_congested: Vec<u8>,
    /// Data source description.
    pub data_source_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelDensity {
    pub channel: u8,
    pub band: String,
    pub ap_count: usize,
    pub ssids: Vec<String>,
    /// Estimated interference from overlapping channels (2.4 GHz only).
    pub overlap_factor: Option<f32>,
}

impl ChannelAnalysis {
    pub fn compute(aps: &[AccessPoint]) -> Self {
        let mut by_channel: HashMap<u8, ChannelDensity> = HashMap::new();

        for ap in aps {
            let entry = by_channel.entry(ap.channel).or_insert_with(|| ChannelDensity {
                channel: ap.channel,
                band: ap.band.display_name().to_string(),
                ap_count: 0,
                ssids: vec![],
                overlap_factor: None,
            });
            entry.ap_count += 1;
            if let Some(ssid) = &ap.ssid {
                if !entry.ssids.contains(ssid) {
                    entry.ssids.push(ssid.clone());
                }
            }
        }

        // Compute 2.4 GHz overlap factors.
        // Channels overlap within ±4 channels in 2.4 GHz.
        // Pre-compute all values before mutating to satisfy the borrow checker.
        let overlap_values: Vec<(u8, f32)> = (1u8..=14)
            .filter(|ch| by_channel.contains_key(ch))
            .map(|ch| {
                let overlapping: usize = by_channel.iter()
                    .filter(|(&other_ch, _)| other_ch != ch && other_ch <= 14)
                    .filter(|(&other_ch, _)| (other_ch as i32 - ch as i32).abs() <= 4)
                    .map(|(_, d)| d.ap_count)
                    .sum();
                (ch, overlapping as f32)
            })
            .collect();

        for (ch, factor) in overlap_values {
            if let Some(entry) = by_channel.get_mut(&ch) {
                entry.overlap_factor = Some(factor);
            }
        }

        let mut sorted: Vec<u8> = by_channel.keys().copied().collect();
        sorted.sort_by(|a, b| by_channel[b].ap_count.cmp(&by_channel[a].ap_count));

        let most_congested = sorted.iter().take(3).copied().collect();
        let least_congested = sorted.iter().filter(|&&ch| by_channel[&ch].ap_count == 1).copied().collect();

        Self {
            ap_density: by_channel,
            most_congested,
            least_congested,
            data_source_note: "AP density per channel based on observed BSSIDs. \
                This represents the count of access points per channel, NOT measured RF utilization. \
                Actual channel utilization requires specialized RF hardware.".into(),
        }
    }
}
