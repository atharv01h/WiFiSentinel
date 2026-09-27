// src/api/commands.ts
// Tauri IPC command wrappers with typed responses.

import { invoke } from "@tauri-apps/api/core";
import type {
  AccessPoint, WirelessAdapter, SecurityFinding,
  TimelineEvent, CaptureStatus, ScanResult,
  PostureReport, PcapAnalysisResult, SavedProfile
} from "./types";

// Helper to check for missing IPC context in browsers
function isIpcMissing(e: any): boolean {
  return String(e).includes("Cannot read properties of undefined") || (window as any).__TAURI_INTERNALS__ === undefined;
}

// ── Adapters ────────────────────────────────────────────────
export async function getAdapters(): Promise<WirelessAdapter[]> {
  try {
    const val = await invoke<unknown>("getadapters");
    return val as WirelessAdapter[];
  } catch (e) {
    if (isIpcMissing(e)) {
      console.warn("Tauri IPC missing. Returning empty adapters list.");
      return [];
    }
    throw e;
  }
}

// ── Scan ────────────────────────────────────────────────────
export async function scanNetworks(): Promise<ScanResult> {
  try {
    const val = await invoke<unknown>("scannetworks");
    return val as ScanResult;
  } catch (e) {
    if (isIpcMissing(e)) return null as any;
    throw e;
  }
}

export async function getAccessPoints(): Promise<AccessPoint[]> {
  try {
    const val = await invoke<unknown>("getaccesspoints");
    return val as AccessPoint[];
  } catch (e) {
    if (isIpcMissing(e)) return [];
    throw e;
  }
}

// ── Capture ─────────────────────────────────────────────────
export async function getCaptureStatus(): Promise<CaptureStatus> {
  try {
    const val = await invoke<unknown>("getcapturestatus");
    return val as CaptureStatus;
  } catch (e) {
    if (isIpcMissing(e)) return { 
      state: "idle", 
      adapter_name: "", 
      packet_count: 0, 
      dropped_count: 0, 
      packet_rate: 0, 
      file_size_bytes: 0, 
      duration_secs: 0, 
      npcap_available: false, 
      error: "IPC Missing" 
    } as any;
    throw e;
  }
}

export async function startCapture(
  adapterName: string,
  deviceName: string,
  outputPath?: string,
  filter?: string
): Promise<{ session_id: string }> {
  try {
    const val = await invoke<unknown>("startcapture", {
      adapterName,
      deviceName,
      outputPath: outputPath ?? null,
      filter: filter ?? null,
    });
    return val as { session_id: string };
  } catch (e) {
    if (isIpcMissing(e)) throw new Error("IPC Missing: Cannot start capture in browser.");
    throw e;
  }
}

export async function stopCapture(): Promise<void> {
  try {
    await invoke("stopcapture");
  } catch (e) {
    if (!isIpcMissing(e)) throw e;
  }
}

// ── Findings ────────────────────────────────────────────────
export async function getFindings(): Promise<SecurityFinding[]> {
  try {
    const val = await invoke<unknown>("getfindings");
    return val as SecurityFinding[];
  } catch (e) {
    if (isIpcMissing(e)) {
      console.warn("Tauri IPC missing. Returning mock findings.");
      return [];
    }
    throw e;
  }
}

// ── Timeline ────────────────────────────────────────────────
export async function getTimeline(opts?: {
  limit?: number;
  offset?: number;
  severity?: string;
  bssid?: string;
}): Promise<TimelineEvent[]> {
  try {
    const val = await invoke<unknown>("gettimeline", {
      limit: opts?.limit ?? 100,
      offset: opts?.offset ?? 0,
      severity: opts?.severity ?? null,
      bssid: opts?.bssid ?? null,
    });
    return val as TimelineEvent[];
  } catch (e) {
    if (isIpcMissing(e)) return [];
    throw e;
  }
}

// ── Analysis ────────────────────────────────────────────────
export async function getPosture(): Promise<PostureReport> {
  try {
    const val = await invoke<unknown>("getposture");
    return val as PostureReport;
  } catch (e) {
    if (isIpcMissing(e)) throw new Error("IPC Missing: Posture data unavailable in browser.");
    throw e;
  }
}

export async function getStatistics(): Promise<unknown> {
  try {
    return await invoke("getstatistics");
  } catch (e) {
    if (isIpcMissing(e)) return {};
    throw e;
  }
}

export async function getChannelAnalysis(): Promise<unknown> {
  try {
    return await invoke("getchannelanalysis");
  } catch (e) {
    if (isIpcMissing(e)) return {};
    throw e;
  }
}

// ── PCAP ────────────────────────────────────────────────────
export async function analyzePcap(filePath: string): Promise<PcapAnalysisResult> {
  try {
    const val = await invoke<unknown>("analyzepcap", { filePath });
    return val as PcapAnalysisResult;
  } catch (e) {
    if (isIpcMissing(e)) return null as any;
    throw e;
  }
}

// ── Report ──────────────────────────────────────────────────
export async function generateReport(
  format: "html" | "json",
  outputPath?: string
): Promise<{ path: string; size_bytes: number }> {
  try {
    const val = await invoke<unknown>("generatereport", {
      format,
      outputPath: outputPath ?? null,
    });
    return val as { path: string; size_bytes: number };
  } catch (e) {
    if (isIpcMissing(e)) throw new Error("IPC Missing: Cannot generate report in browser.");
    throw e;
  }
}

// ── Settings ────────────────────────────────────────────────
export async function markTrusted(
  entityType: "ssid" | "bssid",
  value: string,
  notes?: string
): Promise<void> {
  try {
    await invoke("marktrusted", { entityType, value, notes: notes ?? null });
  } catch (e) {
    if (!isIpcMissing(e)) throw e;
  }
}

export async function clearHistory(): Promise<void> {
  try {
    await invoke("clearhistory");
  } catch (e) {
    if (!isIpcMissing(e)) throw e;
  }
}

// ── Diagnostics ─────────────────────────────────────────────
export async function getDiagnostics(): Promise<unknown> {
  try {
    return await invoke("getdiagnostics");
  } catch (e) {
    if (isIpcMissing(e)) throw new Error("IPC Missing: Diagnostics unavailable.");
    throw e;
  }
}

// ── Profiles ────────────────────────────────────────────────
export async function getSavedProfiles(): Promise<SavedProfile[]> {
  try {
    const val = await invoke<unknown>("getsavedprofiles");
    return val as SavedProfile[];
  } catch (e) {
    if (isIpcMissing(e)) return [];
    throw e;
  }
}
