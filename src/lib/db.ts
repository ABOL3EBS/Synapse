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
  remote_ip_text: string;
  country_code: string | null;
  dns_name: string | null;
  /** evidence_json from the highest-scoring detector finding; null if none. */
  top_evidence: string | null;
}

export interface ThreatStats {
  blocks_today: number;
  blocks_week: number;
  blocked_addresses: number;
}

export interface ChartPoint {
  hour: number;
  count: number;
}

export interface DetectorStat {
  name: string;
  count: number;
  has_runs: boolean;
}

export interface TopApp {
  app_name: string;
  blocks: number;
  alerts: number;
}

export interface CountryStat {
  country_code: string;
  count: number;
}

export interface ActiveBlock {
  ip_text: string;
  remaining_ms: number;
  reason: string;
}

/** Three-state unblock result — mirrors UnblockResult in settings.rs */
export interface UnblockResult {
  queued: boolean;
  fast_path: boolean;
  message: string;
}

export interface AgentStatus {
  agent_ok: boolean;
  helper_ok: boolean;
  db_mtime_ms: number;
}

export interface ConfigValues {
  block_threshold: number;
  alert_threshold: number;
  cf_exclusions: string[];
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

export function getActivityChart(): Promise<ChartPoint[]> {
  if (!isTauri()) return Promise.reject(new Error("not-tauri"));
  return invoke<ChartPoint[]>("get_activity_chart");
}

export function getDetectorBreakdown(): Promise<DetectorStat[]> {
  if (!isTauri()) return Promise.reject(new Error("not-tauri"));
  return invoke<DetectorStat[]>("get_detector_breakdown");
}

export function getTopApps(): Promise<TopApp[]> {
  if (!isTauri()) return Promise.reject(new Error("not-tauri"));
  return invoke<TopApp[]>("get_top_apps");
}

export function getThreatCountries(): Promise<CountryStat[]> {
  if (!isTauri()) return Promise.reject(new Error("not-tauri"));
  return invoke<CountryStat[]>("get_threat_countries");
}

export function getActiveBlocks(): Promise<ActiveBlock[]> {
  if (!isTauri()) return Promise.reject(new Error("not-tauri"));
  return invoke<ActiveBlock[]>("get_active_blocks");
}

export function requestUnblock(ip_text: string): Promise<UnblockResult> {
  if (!isTauri()) return Promise.reject(new Error("not-tauri"));
  return invoke<UnblockResult>("request_unblock", { ip_text });
}

export function getAgentStatus(): Promise<AgentStatus> {
  if (!isTauri()) return Promise.reject(new Error("not-tauri"));
  return invoke<AgentStatus>("get_agent_status");
}

export function getConfigValues(): Promise<ConfigValues> {
  if (!isTauri()) return Promise.reject(new Error("not-tauri"));
  return invoke<ConfigValues>("get_config_values");
}
