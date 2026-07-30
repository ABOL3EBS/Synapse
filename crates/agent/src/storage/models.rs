// Intentionally unused until the Tauri UI IPC socket is wired up.
#![allow(dead_code)]

/// Row structs returned by StorageReader queries.
///
/// All structs derive serde::Serialize so they can be handed directly to
/// the Tauri IPC layer when the UI is wired up. They are intentionally
/// plain data — no logic, no rusqlite types exposed.
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct EnforcementRow {
    pub id: i64,
    pub ts_ms: i64,
    pub action: String,
    pub ip_text: String,
    pub ttl_ms: Option<i64>,
    pub reason: String,
    pub detector: Option<String>,
    pub score: Option<f64>,
    pub requested: bool,
    pub confirmed: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerdictRow {
    pub id: i64,
    pub ts_ms: i64,
    pub flow_id: i64,
    pub a_ip_text: String,
    pub b_ip_text: String,
    pub a_port: i64,
    pub b_port: i64,
    pub pid: Option<i64>,
    pub process_path: Option<String>,
    pub dns_name: Option<String>,
    pub country_code: Option<String>,
    pub verdict: String,
    pub composite_score: f64,
    pub flow_age_ms: i64,
}

#[derive(Debug, Serialize)]
pub struct FindingRow {
    pub detector_id: String,
    pub detector_version: String,
    pub score: f64,
    pub confidence: f64,
    pub severity: String,
    pub status: String,
    pub latency_us: i64,
    pub evidence_json: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DetectorHealthRow {
    pub detector_id: String,
    pub last_state: Option<String>,
    pub transition_count: i64,
    pub last_ts_ms: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct KpiSummary {
    pub blocks_24h: i64,
    pub alerts_24h: i64,
    pub unique_ips_blocked: i64,
    pub enforcement_failures: i64,
}
