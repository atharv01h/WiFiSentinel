// src/api/types.ts
// Domain types matching the Rust backend models exactly.

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type AuthMode = "open" | "wep" | "wpa_personal" | "wpa_enterprise"
  | "wpa2_personal" | "wpa2_enterprise" | "wpa3_personal" | "wpa3_enterprise"
  | "owe" | "unknown";
export type Band = "band2_4_ghz" | "band5_ghz" | "band6_ghz" | "unknown";
export type CaptureState = "initializing" | "running" | "stopped" | "unavailable" | "error";
export type AdapterState = "up" | "down" | "disconnected" | "connecting" | "connected" | "authenticating" | "unavailable" | "unknown";

export interface AccessPoint {
  id: string;
  bssid: string;
  ssid: string | null;
  vendor: string | null;
  band: Band;
  channel: number;
  rssi_dbm: number;
  signal_percent: number;
  auth_mode: AuthMode;
  cipher: string;
  pmf: string | null;
  beacon_interval_tu: number | null;
  is_active: boolean;
  is_trusted: boolean;
  first_seen: string;
  last_seen: string;
  observation_count: number;
}

export interface WirelessAdapter {
  id: string;
  name: string;
  description: string;
  guid: string;
  mac_address: string | null;
  driver_version: string | null;
  driver_date: string | null;
  state: AdapterState;
  connected_ssid: string | null;
  connected_bssid: string | null;
  active_channel: number | null;
  capture_capability: string;
  monitor_mode_capability: string;
  compatibility_score: number;
  compatibility_notes: string[];
}

export interface SecurityFinding {
  id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  confidence_score: number;
  is_active: number;
  affected_ap_id: string | null;
  created_at: string;
  recommendation: string;
  plain_explanation: string;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  event_type: string;
  description: string;
  severity: Severity;
  related_ap_bssid: string | null;
  related_ap_ssid: string | null;
  related_client_mac: string | null;
  related_finding_id: string | null;
  metadata: string;
}

export interface CaptureStatus {
  state: CaptureState;
  adapter_name: string;
  packet_count: number;
  dropped_count: number;
  packet_rate: number;
  file_size_bytes: number;
  duration_secs: number;
  npcap_available: boolean;
  error: string | null;
}

export interface ScanResult {
  access_points: AccessPoint[];
  new_count: number;
  total_count: number;
  findings_count: number;
}

export interface PostureIssue {
  message: string;
  severity: Severity;
}

export interface PostureReport {
  overall_score: number;
  overall_grade: string;
  issues: PostureIssue[];
  categories: Record<string, number>;
  generated_at: string;
}

export interface RsnInfo {
  version: number;
  group_cipher: string;
  pairwise_ciphers: string[];
  akm_suites: string[];
  pmf_capable: boolean;
  pmf_required: boolean;
}

export interface ManagementFrameInfo {
  ssid: string | null;
  supported_rates: number[];
  reason_code: number | null;
  status_code: number | null;
  beacon_interval: number | null;
  capability_info: number | null;
  ds_channel: number | null;
  rsn_info: RsnInfo | null;
}

export interface PacketMetadata {
  id: string;
  capture_session_id: string;
  timestamp: string;
  frame_type: string | Record<string, any>; // snake_case from rust enum
  frame_subtype: string | Record<string, any>;
  source_mac: string | null;
  destination_mac: string | null;
  bssid: string | null;
  channel: number | null;
  rssi_dbm: number | null;
  data_rate_mbps: number | null;
  has_radiotap: boolean;
  payload_bytes: number;
  is_encrypted: boolean;
  is_retry: boolean;
  sequence_number: number | null;
  management_info: ManagementFrameInfo | null;
}

export interface PcapAnalysisResult {
  session_id: string;
  file_path: string;
  total_packets: number;
  processed_packets: number;
  malformed_packets: number;
  management_frames: number;
  control_frames: number;
  data_frames: number;
  unique_bssids: string[];
  unique_ssids: string[];
  link_type: number;
  has_radiotap: boolean;
  first_timestamp: string | null;
  last_timestamp: string | null;
  duration_secs: number;
  packets: PacketMetadata[];
}

export interface SavedProfile {
  ssid: string;
  password: string | null;
}
