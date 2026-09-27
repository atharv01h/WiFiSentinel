// wifisentinel-core/src/models/network.rs
// Re-exports WirelessNetwork from access_point.rs.
// This module exists for organizational clarity — WirelessNetwork
// is defined alongside AccessPoint since they share type dependencies.

pub use super::access_point::{SecurityProfile, WirelessNetwork};
