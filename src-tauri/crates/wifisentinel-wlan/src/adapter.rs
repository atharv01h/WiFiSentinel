use std::os::windows::process::CommandExt;
const CREATE_NO_WINDOW: u32 = 0x08000000;
// wifisentinel-wlan/src/adapter.rs
// Adapter enumeration using Windows WLAN API + supplemental netsh data.

use std::collections::HashMap;
use chrono::Utc;
use tracing::{debug, info, warn};
use uuid::Uuid;
use windows::{
    Win32::NetworkManagement::WiFi::{
        WlanCloseHandle, WlanEnumInterfaces, WlanFreeMemory,
        WlanOpenHandle, WLAN_INTERFACE_INFO, WLAN_INTERFACE_INFO_LIST,
        WlanQueryInterface, WLAN_CONNECTION_ATTRIBUTES,
        wlan_intf_opcode_current_connection,
    },
    Win32::Foundation::HANDLE,
};

use wifisentinel_core::{
    models::{
        WirelessAdapter, AuthCipherPair, Band, Phy, Capability, AdapterState,
    },
    Result, Error,
};

use crate::netsh::NetshAdapter;

/// Enumerates wireless adapters using Windows WLAN API and enriches with
/// information from netsh and driver registry data.
pub struct AdapterEnumerator;

impl AdapterEnumerator {
    /// Returns a list of all wireless adapters detected on the system.
    /// Never panics; individual adapter errors are logged and skipped.
    pub fn enumerate() -> Vec<WirelessAdapter> {
        match Self::try_enumerate() {
            Ok(adapters) => adapters,
            Err(e) => {
                warn!("Adapter enumeration failed: {}", e);
                vec![]
            }
        }
    }

    fn try_enumerate() -> Result<Vec<WirelessAdapter>> {
        // Collect supplemental data from netsh (doesn't require WLAN handle).
        let netsh_data = crate::netsh::query_interfaces()
            .unwrap_or_default();
        let netsh_by_name: HashMap<String, NetshAdapter> = netsh_data
            .into_iter()
            .map(|a| (a.name.clone(), a))
            .collect();

        let netsh_drivers = crate::netsh::query_drivers()
            .unwrap_or_default();
        let drivers_by_name: HashMap<String, crate::netsh::NetshDriver> = netsh_drivers
            .into_iter()
            .map(|d| (d.interface_name.clone(), d))
            .collect();

        unsafe {
            let mut client_handle = HANDLE::default();
            let mut negotiated_version: u32 = 0;

            let err = WlanOpenHandle(2, None, &mut negotiated_version, &mut client_handle);
            if err != 0 {
                return Err(Error::WlanApi {
                    message: "WlanOpenHandle failed".into(),
                    code: err,
                });
            }

            let _guard = HandleGuard(client_handle);

            let mut iface_list_ptr: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
            let err = WlanEnumInterfaces(client_handle, None, &mut iface_list_ptr);
            if err != 0 {
                return Err(Error::WlanApi {
                    message: "WlanEnumInterfaces failed".into(),
                    code: err,
                });
            }

            let iface_list = &*iface_list_ptr;
            let iface_count = iface_list.dwNumberOfItems as usize;

            info!("Detected {} WLAN interface(s)", iface_count);

            let items_ptr = &iface_list.InterfaceInfo[0] as *const WLAN_INTERFACE_INFO;
            let interfaces = std::slice::from_raw_parts(items_ptr, iface_count);

            let mut adapters = Vec::with_capacity(iface_count);

            for iface in interfaces {
                match Self::build_adapter(client_handle, iface, &netsh_by_name, &drivers_by_name) {
                    Ok(adapter) => {
                        debug!("Enumerated adapter: {} ({})", adapter.name, adapter.guid);
                        adapters.push(adapter);
                    }
                    Err(e) => {
                        warn!("Failed to build adapter info: {}", e);
                    }
                }
            }

            WlanFreeMemory(iface_list_ptr as _);

            Ok(adapters)
        }
    }

    unsafe fn build_adapter(
        client_handle: HANDLE,
        iface: &WLAN_INTERFACE_INFO,
        netsh_by_name: &HashMap<String, NetshAdapter>,
        drivers_by_name: &HashMap<String, crate::netsh::NetshDriver>,
    ) -> Result<WirelessAdapter> {
        // Convert WLAN interface GUID to string.
        let guid_str = format!(
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            iface.InterfaceGuid.data1,
            iface.InterfaceGuid.data2,
            iface.InterfaceGuid.data3,
            iface.InterfaceGuid.data4[0],
            iface.InterfaceGuid.data4[1],
            iface.InterfaceGuid.data4[2],
            iface.InterfaceGuid.data4[3],
            iface.InterfaceGuid.data4[4],
            iface.InterfaceGuid.data4[5],
            iface.InterfaceGuid.data4[6],
            iface.InterfaceGuid.data4[7],
        );

        // Decode interface description (UTF-16).
        let desc_end = iface.strInterfaceDescription
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(iface.strInterfaceDescription.len());
        let description = String::from_utf16_lossy(&iface.strInterfaceDescription[..desc_end]);

        let state = map_interface_state(iface.isState.0);

        // Look up matching netsh interface info by description (best-effort).
        let iface_name = netsh_by_name.keys()
            .find(|k| description.contains(k.as_str()) || k.contains(&description[..]))
            .cloned()
            .unwrap_or_else(|| "Wi-Fi".to_string());

        let netsh = netsh_by_name.get(&iface_name);
        let driver = drivers_by_name.get(&iface_name);

        // Build supported PHYs list from netsh driver data.
        let supported_phys: Vec<Phy> = driver
            .map(|d| d.radio_types.iter().map(|r| Phy::from_wlan_str(r)).collect())
            .unwrap_or_default();

        // Build supported bands from supported PHYs.
        let mut supported_bands = vec![Band::Band2_4Ghz]; // assume 2.4 if unknown
        if supported_phys.iter().any(|p| matches!(p, Phy::A | Phy::N | Phy::Ac | Phy::Ax | Phy::Be)) {
            supported_bands.push(Band::Band5Ghz);
        }
        if supported_phys.iter().any(|p| matches!(p, Phy::Ax | Phy::Be)) {
            // 6 GHz requires explicit indication; Ax alone doesn't guarantee it.
            // We note it as unknown rather than claiming 6 GHz support.
        }
        supported_bands.dedup();

        let fips_supported = driver.and_then(|d| d.fips_supported);
        let pmf_supported = driver.and_then(|d| d.pmf_supported);
        let hosted_network = driver.and_then(|d| d.hosted_network_supported);

        // Capture and monitor mode detection.
        // Consumer Realtek/Intel drivers typically don't support monitor mode.
        // We probe Npcap presence and mark accordingly.
        let (capture_cap, monitor_cap) = detect_capture_capabilities(&description, &guid_str);

        let (compat_score, compat_notes) = WirelessAdapter::compute_compatibility_score(
            &capture_cap,
            &monitor_cap,
            fips_supported,
            pmf_supported,
            &supported_bands,
        );

        // Auth/cipher pairs from netsh.
        let auth_ciphers: Vec<AuthCipherPair> = driver
            .map(|d| {
                d.auth_cipher_pairs
                    .iter()
                    .map(|(a, c)| AuthCipherPair {
                        auth: a.clone(),
                        cipher: c.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Current connection info.
        let connection = query_current_connection(client_handle, iface);

        let mac_address = netsh.and_then(|n| {
            n.physical_address.as_deref().and_then(|mac| {
                mac.replace('-', ":").parse().ok()
            })
        });

        let now = Utc::now();

        Ok(WirelessAdapter {
            id: Uuid::new_v4(),
            name: iface_name.clone(),
            description: description.clone(),
            guid: guid_str,
            mac_address,
            manufacturer: driver.map(|d| d.vendor.clone()),
            driver_version: driver.map(|d| d.version.clone()),
            driver_date: driver.map(|d| d.date.clone()),
            inf_file: driver.map(|d| d.inf_file.clone()),
            driver_type: driver.map(|d| d.driver_type.clone()),
            state: state.clone(),
            connected_ssid: connection.as_ref().and_then(|c| c.ssid.clone()),
            connected_bssid: connection.as_ref().and_then(|c| c.bssid.clone()),
            active_band: connection.as_ref().and_then(|c| c.band.clone()),
            active_channel: connection.as_ref().and_then(|c| c.channel),
            active_phy: connection.as_ref().and_then(|c| c.phy.clone()),
            signal_dbm: netsh.and_then(|n| n.rssi),
            signal_percent: netsh.and_then(|n| n.signal_percent),
            rx_rate_mbps: netsh.and_then(|n| n.rx_rate_mbps),
            tx_rate_mbps: netsh.and_then(|n| n.tx_rate_mbps),
            supported_bands,
            supported_phys,
            fips_supported,
            pmf_supported,
            hosted_network_supported: hosted_network,
            capture_capability: capture_cap,
            monitor_mode_capability: monitor_cap,
            compatibility_score: compat_score,
            compatibility_notes: compat_notes,
            supported_auth_ciphers: auth_ciphers,
            first_seen: now,
            last_seen: now,
        })
    }
}

/// Current connection attributes from WlanQueryInterface.
struct ConnectionInfo {
    ssid: Option<String>,
    bssid: Option<String>,
    band: Option<Band>,
    channel: Option<u8>,
    phy: Option<Phy>,
}

unsafe fn query_current_connection(handle: HANDLE, iface: &WLAN_INTERFACE_INFO) -> Option<ConnectionInfo> {
    // This is safe to call and returns None on failure.
    let mut data_size: u32 = 0;
    let mut data_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut opcode_value_type = windows::Win32::NetworkManagement::WiFi::WLAN_OPCODE_VALUE_TYPE(0);

    let result = WlanQueryInterface(
        handle,
        &iface.InterfaceGuid,
        wlan_intf_opcode_current_connection,
        None,
        &mut data_size,
        &mut data_ptr,
        Some(&mut opcode_value_type),
    );

    if result != 0 || data_ptr.is_null() {
        return None;
    }

    let conn = &*(data_ptr as *const WLAN_CONNECTION_ATTRIBUTES);

    let ssid_len = conn.wlanAssociationAttributes.dot11Ssid.uSSIDLength as usize;
    let ssid_bytes = &conn.wlanAssociationAttributes.dot11Ssid.ucSSID[..ssid_len.min(32)];
    let ssid = String::from_utf8_lossy(ssid_bytes).trim_matches('\0').to_string();
    let ssid = if ssid.is_empty() { None } else { Some(ssid) };

    let bssid_bytes = conn.wlanAssociationAttributes.dot11Bssid;
    let bssid = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bssid_bytes[0], bssid_bytes[1], bssid_bytes[2],
        bssid_bytes[3], bssid_bytes[4], bssid_bytes[5]
    );
    let bssid = if bssid == "00:00:00:00:00:00" { None } else { Some(bssid) };

    // Channel: derive from PHY type + wlanSignalQuality (no direct channel field in WLAN_ASSOCIATION_ATTRIBUTES).
    // We leave channel as None here; it will be filled by BSS scan data.
    let channel: Option<u8> = None;
    let band: Option<Band> = None;

    WlanFreeMemory(data_ptr);

    Some(ConnectionInfo { ssid, bssid, band, channel, phy: None })
}

/// Probe Npcap presence and determine capture/monitor capabilities.
fn detect_capture_capabilities(description: &str, _guid: &str) -> (Capability, Capability) {
    // Check Npcap service.
    let npcap_present = is_npcap_installed();

    if !npcap_present {
        return (
            Capability::DriverDependent,
            Capability::Unknown,
        );
    }

    // Npcap is present. Monitor mode availability is driver-specific.
    // Known monitor-mode capable consumer adapters: Alfa AWUS series, some Panda adapters.
    // Realtek 8822CE / Intel AX series: typically managed mode only with consumer drivers.
    let desc_lower = description.to_lowercase();
    let likely_monitor = desc_lower.contains("alfa")
        || desc_lower.contains("awus")
        || desc_lower.contains("panda")
        || desc_lower.contains("ralink")
        || desc_lower.contains("mediatek");

    let capture_cap = Capability::Supported; // Npcap supports managed-mode capture
    let monitor_cap = if likely_monitor {
        Capability::DriverDependent
    } else {
        Capability::Unknown
    };

    (capture_cap, monitor_cap)
}

/// Check whether Npcap is installed by looking for the service.
pub fn is_npcap_installed() -> bool {
    // Check registry: HKLM\SYSTEM\CurrentControlSet\Services\npcap
    use std::process::Command;
    let output = Command::new("sc").creation_flags(CREATE_NO_WINDOW)
        .args(["query", "npcap"])
        .output();

    match output {
        Ok(out) => out.status.success() || String::from_utf8_lossy(&out.stdout).contains("RUNNING"),
        Err(_) => false,
    }
}

/// Convert frequency (kHz) to channel number.
#[allow(dead_code)]
fn frequency_to_channel(freq_khz: u32) -> Option<u8> {
    if freq_khz == 0 {
        return None;
    }
    let freq_mhz = freq_khz / 1000;
    if freq_mhz >= 2412 && freq_mhz <= 2484 {
        // 2.4 GHz
        if freq_mhz == 2484 {
            Some(14)
        } else {
            Some(((freq_mhz - 2407) / 5) as u8)
        }
    } else if freq_mhz >= 5160 && freq_mhz <= 5885 {
        Some(((freq_mhz - 5000) / 5) as u8)
    } else if freq_mhz >= 5955 && freq_mhz <= 7115 {
        // 6 GHz
        Some(((freq_mhz - 5950) / 5) as u8)
    } else {
        None
    }
}

/// Map Windows WLAN interface state to our AdapterState.
fn map_interface_state(state: i32) -> AdapterState {
    // wlan_interface_state values:
    // 0 = not_ready, 1 = connected, 2 = ad_hoc_network_formed,
    // 3 = disconnecting, 4 = disconnected, 5 = associating,
    // 6 = discovering, 7 = authenticating
    match state {
        0 => AdapterState::Unavailable,
        1 => AdapterState::Connected,
        3 => AdapterState::Connecting,
        4 => AdapterState::Disconnected,
        5 => AdapterState::Connecting,
        7 => AdapterState::Authenticating,
        _ => AdapterState::Unknown,
    }
}

/// RAII guard that closes the WLAN handle on drop.
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

