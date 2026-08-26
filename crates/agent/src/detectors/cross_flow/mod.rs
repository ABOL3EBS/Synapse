mod detector;
mod scoring;
mod state;

#[cfg(test)]
mod tests;

pub use detector::CrossFlowDetector;
pub use state::CrossFlowState;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CrossFlowConfig {
    pub window_secs: u64,
    // Scan detection.
    pub scan_connection_threshold_high: u64,
    pub scan_connection_threshold_medium: u64,
    // DNS burst detection.
    pub dns_burst_threshold_high: u64,
    pub dns_burst_threshold_medium: u64,
    // Beaconing detection.
    pub beacon_min_connections_medium: usize, // ≥5 connections required
    pub beacon_min_connections_high: usize,   // ≥10 connections required
    pub beacon_cv_medium: f64,                // CV < 0.3 for medium tier
    pub beacon_cv_high: f64,                  // CV < 0.2 for high tier
    pub beacon_mean_min_secs: f64,            // lower bound on mean interval (2.0s)
    pub max_beacon_entries: usize,            // per-(ip,port,proto) cap (200)
    // Connection-diversity detection.
    pub max_pid_entries: usize,         // per-PID VecDeque cap (512)
    pub max_tracked_pids: usize,        // total PID map cap (1024)
    pub pid_diversity_window_secs: u64, // rolling window for diversity (10s)
    pub pid_diversity_threshold_medium: usize, // >20 distinct IPs → medium
    pub pid_diversity_threshold_high: usize, // >50 distinct IPs → high
}

impl Default for CrossFlowConfig {
    fn default() -> Self {
        Self {
            window_secs: 60,
            // 200/100: these thresholds apply per-(pid, remote_ip) — not the old
            // aggregate-all-PIDs counter. A single process making >200 connections
            // to one IP in 60s is genuinely anomalous; 20 browser tabs each making
            // 10 connections increments 20 separate (pid, ip) entries, none of
            // which crosses 200. Port scans operate in the thousands/min range.
            scan_connection_threshold_high: 200,
            scan_connection_threshold_medium: 100,
            dns_burst_threshold_high: 80,
            dns_burst_threshold_medium: 30,
            beacon_min_connections_medium: 5,
            beacon_min_connections_high: 10,
            beacon_cv_medium: 0.3,
            beacon_cv_high: 0.2,
            beacon_mean_min_secs: 2.0,
            max_beacon_entries: 200,
            max_pid_entries: 512,
            max_tracked_pids: 1024,
            pid_diversity_window_secs: 10,
            pid_diversity_threshold_medium: 20,
            pid_diversity_threshold_high: 50,
        }
    }
}
