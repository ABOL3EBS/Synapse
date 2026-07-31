import { invoke } from "@tauri-apps/api/core";

// ---------------------------------------------------------------------------
// Shared types — must mirror the Rust structs in src-tauri/src/lib.rs
// ---------------------------------------------------------------------------

export interface ProtectionStatus {
  is_protected: boolean;
  blocks_week: number;
}

export interface ActivityItem {
  id: number;
  ts_ms: number;
  app_name: string;
  verdict: "Block" | "Alert" | "Allow";
  detector_ids: string[];
  a_ip_text: string;
  b_ip_text: string;
  country_code: string | null;
  dns_name: string | null;
}

export interface ThreatStats {
  blocks_today: number;
  blocks_week: number;
  blocked_addresses: number;
}

// ---------------------------------------------------------------------------
// Tauri context check
// ---------------------------------------------------------------------------

export const isTauri = (): boolean =>
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

// ---------------------------------------------------------------------------
// Tauri command wrappers
// ---------------------------------------------------------------------------

export function getProtectionStatus(): Promise<ProtectionStatus> {
  if (!isTauri()) return Promise.reject(new Error("not-tauri"));
  return invoke<ProtectionStatus>("get_protection_status");
}

export function getActivityFeed(limit = 50): Promise<ActivityItem[]> {
  if (!isTauri()) return Promise.reject(new Error("not-tauri"));
  return invoke<ActivityItem[]>("get_activity_feed", { limit });
}

export function getThreatStats(): Promise<ThreatStats> {
  if (!isTauri()) return Promise.reject(new Error("not-tauri"));
  return invoke<ThreatStats>("get_threat_stats");
}
