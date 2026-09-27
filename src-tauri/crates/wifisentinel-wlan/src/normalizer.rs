// wifisentinel-wlan/src/normalizer.rs
// Normalizes raw scan results:
// - Deduplicates by BSSID
// - Associates APs with WirelessNetwork entities
// - Detects security/channel changes
// - Updates signal history

use std::collections::HashMap;
use chrono::Utc;
use macaddr::MacAddr6;
use uuid::Uuid;

use wifisentinel_core::models::{
    AccessPoint, WirelessNetwork, SecurityProfile, TimelineEvent, EventType,
    SecuritySample, SignalSample, ChannelSample,
};

pub struct ScanNormalizer {
    /// Known APs indexed by BSSID.
    pub known_aps: HashMap<MacAddr6, AccessPoint>,
    /// Known networks indexed by SSID.
    pub known_networks: HashMap<String, WirelessNetwork>,
    /// Timeline events generated during this normalization pass.
    pub timeline_events: Vec<TimelineEvent>,
}

impl ScanNormalizer {
    pub fn new() -> Self {
        Self {
            known_aps: HashMap::new(),
            known_networks: HashMap::new(),
            timeline_events: Vec::new(),
        }
    }

    /// Load existing state from database.
    pub fn load_known_aps(&mut self, aps: impl IntoIterator<Item = AccessPoint>) {
        for ap in aps {
            self.known_aps.insert(ap.bssid, ap);
        }
    }

    pub fn load_known_networks(&mut self, nets: impl IntoIterator<Item = WirelessNetwork>) {
        for net in nets {
            self.known_networks.insert(net.ssid.clone(), net);
        }
    }

    /// Process a batch of APs from a scan result.
    /// Returns (new_aps, updated_aps, new_networks, updated_networks).
    pub fn process(&mut self, mut scanned: Vec<AccessPoint>) -> NormalizationResult {
        let mut new_aps = Vec::new();
        let mut updated_aps = Vec::new();
        let mut new_networks = Vec::new();
        let mut updated_networks = Vec::new();

        for ap in &mut scanned {
            // ── AP deduplication ──────────────────────────────────────
            if let Some(existing) = self.known_aps.get_mut(&ap.bssid) {
                // Update existing AP.
                let now = Utc::now();

                // Detect channel change.
                if existing.channel != ap.channel {
                    self.timeline_events.push(TimelineEvent::ap_event(
                        EventType::ApChannelChanged,
                        format!(
                            "Channel changed: {} → {} for {} ({})",
                            existing.channel, ap.channel,
                            ap.ssid.as_deref().unwrap_or("Hidden"),
                            ap.bssid
                        ),
                        existing.id,
                        ap.bssid.to_string(),
                        ap.ssid.clone(),
                    ));
                    existing.channel_history.push(ChannelSample {
                        timestamp: now,
                        channel: ap.channel,
                        band: ap.band,
                    });
                    // Trim history.
                    if existing.channel_history.len() > 50 {
                        existing.channel_history.remove(0);
                    }
                }

                // Detect security change.
                if existing.auth_mode != ap.auth_mode || existing.cipher != ap.cipher {
                    self.timeline_events.push(TimelineEvent::ap_event(
                        EventType::ApSecurityChanged,
                        format!(
                            "Security changed for {} ({}): {} → {}",
                            ap.ssid.as_deref().unwrap_or("Hidden"),
                            ap.bssid,
                            existing.auth_mode.display_name(),
                            ap.auth_mode.display_name(),
                        ),
                        existing.id,
                        ap.bssid.to_string(),
                        ap.ssid.clone(),
                    ));
                    existing.security_history.push(SecuritySample {
                        timestamp: now,
                        auth_mode: ap.auth_mode.clone(),
                        cipher: ap.cipher.clone(),
                    });
                }

                // Update signal.
                existing.signal_history.push(SignalSample {
                    timestamp: now,
                    rssi_dbm: ap.rssi_dbm,
                });
                if existing.signal_history.len() > 200 {
                    existing.signal_history.remove(0);
                }

                existing.rssi_dbm = ap.rssi_dbm;
                existing.signal_percent = ap.signal_percent;
                existing.channel = ap.channel;
                existing.band = ap.band;
                existing.auth_mode = ap.auth_mode.clone();
                existing.cipher = ap.cipher.clone();
                existing.last_seen = now;
                existing.is_active = true;
                existing.observation_count += 1;
                ap.id = existing.id; // propagate stable ID

                updated_aps.push(existing.clone());
            } else {
                // New AP.
                self.timeline_events.push(TimelineEvent::ap_event(
                    EventType::ApDiscovered,
                    format!(
                        "New AP discovered: {} ({}) on channel {} {}",
                        ap.ssid.as_deref().unwrap_or("Hidden"),
                        ap.bssid,
                        ap.channel,
                        ap.band.display_name(),
                    ),
                    ap.id,
                    ap.bssid.to_string(),
                    ap.ssid.clone(),
                ));

                self.known_aps.insert(ap.bssid, ap.clone());
                new_aps.push(ap.clone());
            }

            // ── Network association ───────────────────────────────────
            if let Some(ssid) = &ap.ssid {
                if let Some(net) = self.known_networks.get_mut(ssid) {
                    let ap_id = ap.id;
                    if !net.ap_ids.contains(&ap_id) {
                        net.ap_ids.push(ap_id);
                        net.last_seen = Utc::now();
                        updated_networks.push(net.clone());
                    }
                } else {
                    let net = WirelessNetwork {
                        id: Uuid::new_v4(),
                        ssid: ssid.clone(),
                        ap_ids: vec![ap.id],
                        security_profile: SecurityProfile {
                            auth_mode: ap.auth_mode.clone(),
                            cipher: ap.cipher.clone(),
                            pmf: ap.pmf,
                            has_inconsistent_aps: false,
                        },
                        first_seen: ap.first_seen,
                        last_seen: ap.last_seen,
                        is_trusted: false,
                        anomaly_flags: vec![],
                    };
                    self.known_networks.insert(ssid.clone(), net.clone());
                    new_networks.push(net);
                }
            }
        }

        // Mark APs not in this scan as inactive.
        let scanned_bssids: std::collections::HashSet<MacAddr6> =
            scanned.iter().map(|ap| ap.bssid).collect();

        for (bssid, ap) in &mut self.known_aps {
            if !scanned_bssids.contains(bssid) && ap.is_active {
                let cutoff = Utc::now() - chrono::Duration::minutes(5);
                if ap.last_seen < cutoff {
                    ap.is_active = false;
                    self.timeline_events.push(TimelineEvent::ap_event(
                        EventType::ApDisappeared,
                        format!(
                            "AP no longer visible: {} ({})",
                            ap.ssid.as_deref().unwrap_or("Hidden"),
                            ap.bssid
                        ),
                        ap.id,
                        ap.bssid.to_string(),
                        ap.ssid.clone(),
                    ));
                }
            }
        }

        NormalizationResult {
            new_aps,
            updated_aps,
            new_networks,
            updated_networks,
        }
    }
}

pub struct NormalizationResult {
    pub new_aps: Vec<AccessPoint>,
    pub updated_aps: Vec<AccessPoint>,
    pub new_networks: Vec<WirelessNetwork>,
    pub updated_networks: Vec<WirelessNetwork>,
}

impl Default for ScanNormalizer {
    fn default() -> Self {
        Self::new()
    }
}
