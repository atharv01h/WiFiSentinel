// wifisentinel-wlan/src/scan.rs
// BSS scanner using WlanGetNetworkBssList.

use std::slice;
use chrono::Utc;
use macaddr::MacAddr6;
use tracing::{debug, info, warn};
use uuid::Uuid;
use windows::{
    core::GUID,
    Win32::NetworkManagement::WiFi::{
        WlanCloseHandle, WlanFreeMemory, WlanGetNetworkBssList, WlanOpenHandle, WlanScan,
        WLAN_BSS_ENTRY, WLAN_BSS_LIST, dot11_BSS_type_infrastructure,
    },
    Win32::Foundation::HANDLE,
};

use wifisentinel_core::{
    models::{
        AccessPoint, AuthMode, Band, CipherSuite, Phy, SignalSample, ChannelSample,
        SecuritySample, PmfMode,
    },
    Result, Error,
};

/// Scans for nearby BSSIDs using the Windows WLAN API.
pub struct BssScanner;

impl BssScanner {
    /// Trigger an active scan and retrieve all visible BSSIDs.
    ///
    /// This calls WlanScan (which returns immediately) and then
    /// WlanGetNetworkBssList (which returns cached results).
    /// The WLAN service updates the BSS list in the background after WlanScan.
    pub async fn scan(adapter_id: Uuid, interface_guid: &str) -> Result<Vec<AccessPoint>> {
        // Run blocking WLAN API calls on a dedicated thread.
        let guid_str = interface_guid.to_string();
        let result = tokio::task::spawn_blocking(move || {
            Self::scan_blocking(adapter_id, &guid_str)
        })
        .await
        .map_err(|e| Error::Other(format!("Scan task panicked: {}", e)))?;

        result
    }

    fn scan_blocking(adapter_id: Uuid, interface_guid: &str) -> Result<Vec<AccessPoint>> {
        unsafe {
            let mut client_handle = HANDLE::default();
            let mut negotiated_version: u32 = 0;

            let err = WlanOpenHandle(2, None, &mut negotiated_version, &mut client_handle);
            if err != 0 {
                return Err(Error::WlanApi {
                    message: "WlanOpenHandle failed during scan".into(),
                    code: err,
                });
            }

            let _guard = HandleGuard(client_handle);

            let guid = parse_guid(interface_guid)?;

            // Trigger an active scan request (best effort; may be rate-limited by driver).
            let scan_result = WlanScan(client_handle, &guid, None, None, None);
            if scan_result != 0 {
                debug!("WlanScan returned {}: proceeding with cached BSS list", scan_result);
            }

            // Small pause to allow the scan to partially complete.
            // The BSS list is populated asynchronously by the WLAN service.
            std::thread::sleep(std::time::Duration::from_millis(100));

            // Retrieve BSS list.
            let mut bss_list_ptr: *mut WLAN_BSS_LIST = std::ptr::null_mut();
            let err = WlanGetNetworkBssList(
                client_handle,
                &guid,
                None,
                dot11_BSS_type_infrastructure,
                false,
                None,
                &mut bss_list_ptr,
            );

            if err != 0 {
                return Err(Error::WlanApi {
                    message: "WlanGetNetworkBssList failed".into(),
                    code: err,
                });
            }

            if bss_list_ptr.is_null() {
                return Ok(vec![]);
            }

            let bss_list = &*bss_list_ptr;
            let count = bss_list.dwNumberOfItems as usize;
            info!("BSS scan returned {} entries", count);

            let entries_ptr = &bss_list.wlanBssEntries[0] as *const WLAN_BSS_ENTRY;
            let entries = slice::from_raw_parts(entries_ptr, count);

            let mut access_points = Vec::with_capacity(count);
            for entry in entries {
                match Self::bss_entry_to_ap(adapter_id, entry) {
                    Ok(ap) => access_points.push(ap),
                    Err(e) => warn!("Failed to parse BSS entry: {}", e),
                }
            }

            WlanFreeMemory(bss_list_ptr as _);

            Ok(access_points)
        }
    }

    unsafe fn bss_entry_to_ap(adapter_id: Uuid, entry: &WLAN_BSS_ENTRY) -> Result<AccessPoint> {
        // Decode SSID.
        let ssid_len = entry.dot11Ssid.uSSIDLength as usize;
        let ssid_bytes = &entry.dot11Ssid.ucSSID[..ssid_len.min(32)];
        let ssid = if ssid_len == 0 {
            None
        } else {
            let s = String::from_utf8_lossy(ssid_bytes).trim_matches('\0').to_string();
            if s.is_empty() { None } else { Some(s) }
        };

        // Parse BSSID.
        let bssid_bytes = entry.dot11Bssid;
        let bssid = MacAddr6::from([
            bssid_bytes[0], bssid_bytes[1], bssid_bytes[2],
            bssid_bytes[3], bssid_bytes[4], bssid_bytes[5],
        ]);

        // Signal.
        let rssi_dbm = entry.lRssi as i16;
        let signal_percent = AccessPoint::signal_pct_from_dbm(rssi_dbm);

        // Channel from center frequency (kHz).
        let channel = frequency_khz_to_channel(entry.ulChCenterFrequency)
            .unwrap_or(0);
        let band = Band::from_channel(channel);

        // PHY from Windows PHY type enum.
        let phy = map_phy(entry.dot11BssPhyType.0 as u32);

        // Parse information elements (IEs) to get security info.
        let (auth_mode, cipher, pmf, beacon_interval) = if entry.ulIeSize > 0 {
            let ie_data_ptr = (entry as *const WLAN_BSS_ENTRY as *const u8)
                .add(entry.ulIeOffset as usize);
            let ie_slice = slice::from_raw_parts(ie_data_ptr, entry.ulIeSize as usize);
            parse_ies(ie_slice)
        } else {
            (AuthMode::Unknown("no-ie".into()), CipherSuite::Unknown("no-ie".into()), None, None)
        };

        // Vendor lookup (OUI-based).
        let vendor = lookup_vendor(&bssid_bytes);

        let now = Utc::now();

        Ok(AccessPoint {
            id: Uuid::new_v4(),
            bssid,
            ssid,
            vendor,
            band,
            channel,
            channel_width: None, // Not available from BSS entry without IEs
            rssi_dbm,
            signal_percent,
            phy,
            auth_mode,
            cipher,
            pmf,
            beacon_interval_tu: beacon_interval,
            capability_flags: Some(entry.usCapabilityInformation),
            is_active: true,
            is_trusted: false,
            observed_by_adapter: adapter_id,
            network_id: None,
            first_seen: now,
            last_seen: now,
            observation_count: 1,
            signal_history: vec![SignalSample { timestamp: now, rssi_dbm }],
            channel_history: vec![ChannelSample { timestamp: now, channel, band }],
            security_history: vec![SecuritySample {
                timestamp: now,
                auth_mode: AuthMode::Unknown("pending-parse".into()),
                cipher: CipherSuite::Unknown("pending-parse".into()),
            }],
        })
    }
}

/// Parse 802.11 Information Elements from BSS entry.
/// Returns (auth_mode, cipher, pmf, beacon_interval).
fn parse_ies(ies: &[u8]) -> (AuthMode, CipherSuite, Option<PmfMode>, Option<u16>) {
    let mut auth = AuthMode::Open;
    let mut cipher = CipherSuite::None;
    let mut pmf = None;
    let beacon_interval: Option<u16> = None;

    let mut i = 0;
    while i + 2 <= ies.len() {
        let id = ies[i];
        let len = ies[i + 1] as usize;
        i += 2;

        if i + len > ies.len() {
            break;
        }

        let data = &ies[i..i + len];

        match id {
            // RSN IE (WPA2/WPA3)
            48 => {
                if let Some((a, c, p)) = parse_rsn_ie(data) {
                    auth = a;
                    cipher = c;
                    pmf = Some(p);
                }
            }
            // Vendor-specific IE (WPA)
            221 if len >= 4 && data[0] == 0x00 && data[1] == 0x50 && data[2] == 0xf2 && data[3] == 0x01 => {
                if auth == AuthMode::Open {
                    // WPA IE present — WPA-Personal if PSK AKM
                    auth = AuthMode::WpaPersonal;
                    cipher = CipherSuite::Tkip;
                }
            }
            _ => {}
        }

        i += len;
    }

    (auth, cipher, pmf, beacon_interval)
}

/// Parse RSN (WPA2/WPA3) Information Element.
fn parse_rsn_ie(data: &[u8]) -> Option<(AuthMode, CipherSuite, PmfMode)> {
    if data.len() < 4 {
        return None;
    }

    let version = u16::from_le_bytes([data[0], data[1]]);
    if version != 1 {
        return None;
    }

    let mut pos = 2;

    // Group cipher suite (4 bytes: OUI + type).
    if pos + 4 > data.len() { return None; }
    let group_type = data[pos + 3];
    pos += 4;

    let _group_cipher = rsn_cipher_from_type(group_type);

    // Pairwise cipher count.
    if pos + 2 > data.len() { return None; }
    let pairwise_count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let mut pairwise_cipher = CipherSuite::Ccmp; // default
    for _ in 0..pairwise_count {
        if pos + 4 > data.len() { return None; }
        let cipher_type = data[pos + 3];
        pairwise_cipher = rsn_cipher_from_type(cipher_type);
        pos += 4;
    }

    // AKM suite count.
    if pos + 2 > data.len() { return None; }
    let akm_count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let mut auth_mode = AuthMode::Wpa2Personal;
    for _ in 0..akm_count {
        if pos + 4 > data.len() { return None; }
        let akm_type = data[pos + 3];
        auth_mode = match akm_type {
            1 => AuthMode::Wpa2Enterprise,
            2 => AuthMode::Wpa2Personal,
            8 => AuthMode::Wpa3Personal,    // SAE
            12 => AuthMode::Wpa3Enterprise, // EAP-SUITES
            18 => AuthMode::Owe,
            _ => AuthMode::Wpa2Personal,
        };
        pos += 4;
    }

    // RSN Capabilities (2 bytes).
    let pmf = if pos + 2 <= data.len() {
        let caps = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let mfpc = (caps >> 7) & 1 == 1; // Management Frame Protection Capable
        let mfpr = (caps >> 6) & 1 == 1; // Management Frame Protection Required
        if mfpr {
            PmfMode::Required
        } else if mfpc {
            PmfMode::Optional
        } else {
            PmfMode::Disabled
        }
    } else {
        PmfMode::Unknown
    };

    Some((auth_mode, pairwise_cipher, pmf))
}

fn rsn_cipher_from_type(t: u8) -> CipherSuite {
    match t {
        0 => CipherSuite::None,
        1 => CipherSuite::Wep40,
        2 => CipherSuite::Tkip,
        4 => CipherSuite::Ccmp,
        5 => CipherSuite::Wep104,
        8 => CipherSuite::Gcmp128,
        9 => CipherSuite::Gcmp256,
        _ => CipherSuite::Unknown(format!("type-{}", t)),
    }
}

/// Map Windows DOT11_PHY_TYPE to our Phy enum.
fn map_phy(phy_type: u32) -> Option<Phy> {
    // DOT11_PHY_TYPE values from Windows SDK:
    // 1=any, 2=fhss, 3=dsss, 4=irbaseband, 5=ofdm(802.11a),
    // 6=hrdsss(802.11b), 7=erp(802.11g), 8=ht(802.11n),
    // 9=vht(802.11ac), 10=dmg, 11=he(802.11ax), 12=eht(802.11be)
    match phy_type {
        5 => Some(Phy::A),
        6 => Some(Phy::B),
        7 => Some(Phy::G),
        8 => Some(Phy::N),
        9 => Some(Phy::Ac),
        11 => Some(Phy::Ax),
        12 => Some(Phy::Be),
        _ => None,
    }
}

fn frequency_khz_to_channel(freq_khz: u32) -> Option<u8> {
    if freq_khz == 0 { return None; }
    let freq_mhz = freq_khz / 1000;
    if freq_mhz >= 2412 && freq_mhz <= 2472 {
        Some(((freq_mhz - 2407) / 5) as u8)
    } else if freq_mhz == 2484 {
        Some(14)
    } else if freq_mhz >= 5160 && freq_mhz <= 5885 {
        Some(((freq_mhz - 5000) / 5) as u8)
    } else if freq_mhz >= 5955 {
        Some(((freq_mhz - 5950) / 5) as u8)
    } else {
        None
    }
}

/// Lightweight OUI vendor lookup using the first 3 octets of the BSSID.
fn lookup_vendor(bssid: &[u8; 6]) -> Option<String> {
    // Known OUI prefixes (first 3 bytes). This is a minimal set;
    // production builds can use the full OUI database.
    let oui = (bssid[0] as u32) << 16 | (bssid[1] as u32) << 8 | bssid[2] as u32;
    match oui {
        0x001A2B => Some("Cisco".into()),
        0x00259C => Some("Cisco".into()),
        0x0023EB => Some("Cisco".into()),
        0xF80272 => Some("Apple".into()),
        0xF4F5E8 => Some("Apple".into()),
        0x706655 => Some("Samsung".into()),
        0xBC1454 => Some("Samsung".into()),
        0x806C1B => Some("Google".into()),
        0x3C5AB4 => Some("Google".into()),
        0xF889D2 => Some("Realtek".into()),
        0x001CAE => Some("TP-Link".into()),
        0xC46E1F => Some("TP-Link".into()),
        0x0010DB => Some("TP-Link".into()),
        0x001018 => Some("Netgear".into()),
        0xA0040B => Some("Netgear".into()),
        0x10DA43 => Some("ASUS".into()),
        0x04D9F5 => Some("ASUS".into()),
        0x6C72E7 => Some("Intel".into()),
        0x001B21 => Some("Intel".into()),
        0x606BBD => Some("Alfa Networks".into()),
        _ => None,
    }
}

fn parse_guid(guid_str: &str) -> Result<GUID> {
    // Parse "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" format.
    let clean = guid_str.trim_matches(|c| c == '{' || c == '}');
    let parts: Vec<&str> = clean.split('-').collect();
    if parts.len() != 5 {
        return Err(Error::Other(format!("Invalid GUID format: {}", guid_str)));
    }

    let data1 = u32::from_str_radix(parts[0], 16)
        .map_err(|_| Error::Other("GUID parse error data1".into()))?;
    let data2 = u16::from_str_radix(parts[1], 16)
        .map_err(|_| Error::Other("GUID parse error data2".into()))?;
    let data3 = u16::from_str_radix(parts[2], 16)
        .map_err(|_| Error::Other("GUID parse error data3".into()))?;

    let combined = format!("{}{}", parts[3], parts[4]);
    let mut data4 = [0u8; 8];
    for i in 0..8 {
        data4[i] = u8::from_str_radix(&combined[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error::Other("GUID parse error data4".into()))?;
    }

    Ok(GUID { data1, data2, data3, data4 })
}

struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_invalid() {
                WlanCloseHandle(self.0, None);
            }
        }
    }
}
