use std::os::windows::process::CommandExt;
const CREATE_NO_WINDOW: u32 = 0x08000000;
// wifisentinel-wlan/src/netsh.rs
// Supplemental adapter information via netsh output parsing.
//
// Windows WLAN API does not expose some fields (driver version, RSSI on
// interfaces page, supported radio types) directly. netsh provides these.
// This module parses netsh output into structured types.

use std::process::Command;
use tracing::debug;

/// Information from `netsh wlan show interfaces`.
#[derive(Debug, Clone, Default)]
pub struct NetshAdapter {
    pub name: String,
    pub description: String,
    pub guid: Option<String>,
    pub physical_address: Option<String>,
    pub interface_type: Option<String>,
    pub state: Option<String>,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub network_type: Option<String>,
    pub radio_type: Option<String>,
    pub authentication: Option<String>,
    pub cipher: Option<String>,
    pub connection_mode: Option<String>,
    pub channel: Option<u8>,
    pub receive_rate: Option<f64>,
    pub transmit_rate: Option<f64>,
    pub signal_percent: Option<u8>,
    pub rssi: Option<i16>,
    pub rx_rate_mbps: Option<f64>,
    pub tx_rate_mbps: Option<f64>,
}

/// Information from `netsh wlan show drivers`.
#[derive(Debug, Clone, Default)]
pub struct NetshDriver {
    pub interface_name: String,
    pub driver: String,
    pub vendor: String,
    pub provider: String,
    pub date: String,
    pub version: String,
    pub inf_file: String,
    pub driver_type: String,
    pub radio_types: Vec<String>,
    pub fips_supported: Option<bool>,
    pub pmf_supported: Option<bool>,
    pub hosted_network_supported: Option<bool>,
    pub auth_cipher_pairs: Vec<(String, String)>,
}

/// Run `netsh wlan show interfaces` and parse output.
pub fn query_interfaces() -> Result<Vec<NetshAdapter>, String> {
    let output = Command::new("netsh").creation_flags(CREATE_NO_WINDOW)
        .args(["wlan", "show", "interfaces"])
        .output()
        .map_err(|e| format!("Failed to run netsh: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "netsh exited with code {:?}",
            output.status.code()
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    debug!("netsh interfaces output: {} bytes", text.len());

    parse_interfaces(&text)
}

/// Run `netsh wlan show drivers` and parse output.
pub fn query_drivers() -> Result<Vec<NetshDriver>, String> {
    let output = Command::new("netsh").creation_flags(CREATE_NO_WINDOW)
        .args(["wlan", "show", "drivers"])
        .output()
        .map_err(|e| format!("Failed to run netsh: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "netsh exited with code {:?}",
            output.status.code()
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    debug!("netsh drivers output: {} bytes", text.len());

    parse_drivers(&text)
}

fn parse_interfaces(text: &str) -> Result<Vec<NetshAdapter>, String> {
    let mut adapters = Vec::new();
    let mut current: Option<NetshAdapter> = None;

    for line in text.lines() {
        let trimmed = line.trim();

        // New adapter block starts with "Name"
        if trimmed.starts_with("Name") && trimmed.contains(':') {
            if let Some(adapter) = current.take() {
                adapters.push(adapter);
            }
            let mut a = NetshAdapter::default();
            a.name = extract_value(trimmed).trim().to_string();
            current = Some(a);
            continue;
        }

        if let Some(ref mut adapter) = current {
            if let Some(val) = try_extract(trimmed, "Description") {
                adapter.description = val;
            } else if let Some(val) = try_extract(trimmed, "GUID") {
                adapter.guid = Some(val);
            } else if let Some(val) = try_extract(trimmed, "Physical address") {
                adapter.physical_address = Some(val);
            } else if let Some(val) = try_extract(trimmed, "Interface type") {
                adapter.interface_type = Some(val);
            } else if let Some(val) = try_extract(trimmed, "State") {
                adapter.state = Some(val);
            } else if let Some(val) = try_extract(trimmed, "SSID") {
                adapter.ssid = Some(val);
            } else if let Some(val) = try_extract(trimmed, "AP BSSID") {
                adapter.bssid = Some(val);
            } else if let Some(val) = try_extract(trimmed, "Network type") {
                adapter.network_type = Some(val);
            } else if let Some(val) = try_extract(trimmed, "Radio type") {
                adapter.radio_type = Some(val);
            } else if let Some(val) = try_extract(trimmed, "Authentication") {
                adapter.authentication = Some(val);
            } else if let Some(val) = try_extract(trimmed, "Cipher") {
                adapter.cipher = Some(val);
            } else if let Some(val) = try_extract(trimmed, "Connection mode") {
                adapter.connection_mode = Some(val);
            } else if let Some(val) = try_extract(trimmed, "Channel") {
                adapter.channel = val.parse().ok();
            } else if let Some(val) = try_extract(trimmed, "Receive rate (Mbps)") {
                adapter.rx_rate_mbps = val.parse().ok();
            } else if let Some(val) = try_extract(trimmed, "Transmit rate (Mbps)") {
                adapter.tx_rate_mbps = val.parse().ok();
            } else if let Some(val) = try_extract(trimmed, "Signal") {
                // "Signal : 100%"
                let pct = val.trim_end_matches('%').trim().parse::<u8>().ok();
                adapter.signal_percent = pct;
            } else if let Some(val) = try_extract(trimmed, "Rssi") {
                adapter.rssi = val.trim().parse().ok();
            }
        }
    }

    if let Some(adapter) = current {
        adapters.push(adapter);
    }

    Ok(adapters)
}

fn parse_drivers(text: &str) -> Result<Vec<NetshDriver>, String> {
    let mut drivers = Vec::new();
    let mut current: Option<NetshDriver> = None;
    let mut in_auth_cipher = false;

    for line in text.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("Interface name:") {
            if let Some(driver) = current.take() {
                drivers.push(driver);
            }
            let mut d = NetshDriver::default();
            d.interface_name = trimmed
                .trim_start_matches("Interface name:")
                .trim()
                .to_string();
            current = Some(d);
            in_auth_cipher = false;
            continue;
        }

        if let Some(ref mut driver) = current {
            if let Some(val) = try_extract(trimmed, "Driver") {
                driver.driver = val;
            } else if let Some(val) = try_extract(trimmed, "Vendor") {
                driver.vendor = val;
            } else if let Some(val) = try_extract(trimmed, "Provider") {
                driver.provider = val;
            } else if let Some(val) = try_extract(trimmed, "Date") {
                driver.date = val;
            } else if let Some(val) = try_extract(trimmed, "Version") {
                driver.version = val;
            } else if let Some(val) = try_extract(trimmed, "INF file") {
                driver.inf_file = val;
            } else if let Some(val) = try_extract(trimmed, "Type") {
                driver.driver_type = val;
            } else if let Some(val) = try_extract(trimmed, "Radio types supported") {
                driver.radio_types = val.split_whitespace()
                    .map(|s| s.to_string())
                    .collect();
            } else if let Some(val) = try_extract(trimmed, "FIPS 140 mode supported") {
                driver.fips_supported = Some(val.to_lowercase().contains("yes"));
            } else if let Some(val) = try_extract(trimmed, "802.11w Management Frame Protection supported") {
                driver.pmf_supported = Some(val.to_lowercase().contains("yes"));
            } else if let Some(val) = try_extract(trimmed, "Hosted network supported") {
                driver.hosted_network_supported = Some(val.to_lowercase().contains("yes"));
            } else if trimmed.contains("Authentication and cipher") {
                in_auth_cipher = true;
            } else if in_auth_cipher && !trimmed.is_empty() && !trimmed.starts_with("Number of") {
                // Lines like: "WPA2-Personal    CCMP"
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    driver.auth_cipher_pairs.push((parts[0].to_string(), parts[1].to_string()));
                } else if parts.len() == 1 && !parts[0].is_empty() {
                    // Sometimes each field is on its own line
                }
            } else if trimmed.starts_with("Number of") || trimmed.starts_with("Wireless Display") {
                in_auth_cipher = false;
            }
        }
    }

    if let Some(driver) = current {
        drivers.push(driver);
    }

    Ok(drivers)
}

fn try_extract(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{} :", key);
    if line.starts_with(&prefix) {
        Some(line[prefix.len()..].trim().to_string())
    } else if line.starts_with(&format!("{}:", key)) {
        Some(line[key.len() + 1..].trim().to_string())
    } else {
        None
    }
}

fn extract_value(line: &str) -> String {
    if let Some(pos) = line.find(':') {
        line[pos + 1..].trim().to_string()
    } else {
        String::new()
    }
}

