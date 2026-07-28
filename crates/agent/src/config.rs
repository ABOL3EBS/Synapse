// crates/agent/src/config.rs
//
// TOML configuration for synapse-agent. All fields optional — missing values
// fall back to code defaults that match the current hardcoded constants.
//
// Load order:
//   1. SYNAPSE_CONFIG env var (explicit path)
//   2. ~/.synapse/synapse.toml (default path, only if exists)
//   3. All defaults (no config file)

use std::collections::HashMap;
use std::time::Duration;

use log::{info, warn};
use serde::Deserialize;

use crate::{detectors, flow};
use synapse_common::{DecisionConfig, Severity};

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    pub agent: AgentSection,
    pub flow: FlowSection,
    pub enrichment: EnrichmentSection,
    pub circuit_breaker: CircuitBreakerSection,
    pub decision: DecisionSection,
}

impl AgentConfig {
    /// Load config from TOML file. Checks SYNAPSE_CONFIG env var, then
    /// ~/.synapse/synapse.toml. Missing or malformed file → all defaults.
    pub fn load() -> Self {
        let path = Self::resolve_path();
        match path {
            Some(p) => match std::fs::read_to_string(&p) {
                Ok(content) => match toml::from_str::<AgentConfig>(&content) {
                    Ok(config) => {
                        info!("loaded config from {}", p.display());
                        config
                    }
                    Err(e) => {
                        warn!(
                            "failed to parse config {}: {e} — using defaults",
                            p.display()
                        );
                        Self::default()
                    }
                },
                Err(e) => {
                    info!("cannot read config {}: {e} — using defaults", p.display());
                    Self::default()
                }
            },
            None => {
                info!("no config file found — using defaults");
                Self::default()
            }
        }
    }

    fn resolve_path() -> Option<std::path::PathBuf> {
        if let Ok(path) = std::env::var("SYNAPSE_CONFIG") {
            if !path.is_empty() {
                return Some(std::path::PathBuf::from(path));
            }
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        let default = std::path::PathBuf::from(home)
            .join(".synapse")
            .join("synapse.toml");
        if default.exists() {
            Some(default)
        } else {
            None
        }
    }

    /// GeoIP database path. Env var GEOIP_DB_PATH overrides config.
    pub fn geoip_db_path(&self) -> Option<std::path::PathBuf> {
        if let Ok(path) = std::env::var("GEOIP_DB_PATH") {
            if !path.is_empty() {
                return Some(std::path::PathBuf::from(path));
            }
        }
        self.agent.geoip.db_path.as_ref().map(|p| expand_tilde(p))
    }

    /// Reputation feeds directory. Env var FEEDS_DIR overrides config.
    pub fn feeds_dir(&self) -> std::path::PathBuf {
        if let Ok(path) = std::env::var("FEEDS_DIR") {
            if !path.is_empty() {
                return std::path::PathBuf::from(path);
            }
        }
        self.agent
            .feeds
            .dir
            .as_ref()
            .map(|p| expand_tilde(p))
            .unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                std::path::PathBuf::from(home)
                    .join(".synapse")
                    .join("feeds")
            })
    }

    /// Storage database path. Env var SYNAPSE_DB_PATH overrides config.
    #[expect(dead_code, reason = "storage module deferred — see STATUS.md")]
    pub fn storage_db_path(&self) -> std::path::PathBuf {
        if let Ok(path) = std::env::var("SYNAPSE_DB_PATH") {
            if !path.is_empty() {
                return std::path::PathBuf::from(path);
            }
        }
        self.agent
            .storage
            .db_path
            .as_ref()
            .map(|p| expand_tilde(p))
            .unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                std::path::PathBuf::from(home)
                    .join(".synapse")
                    .join("synapse.db")
            })
    }

    /// Build a DecisionConfig from the TOML decision section.
    pub fn decision_config(&self) -> DecisionConfig {
        let ttl = &self.decision.ttl_by_severity;
        let mut ttl_by_severity = HashMap::new();
        ttl_by_severity.insert(Severity::Critical, Duration::from_secs(ttl.critical));
        ttl_by_severity.insert(Severity::High, Duration::from_secs(ttl.high));
        ttl_by_severity.insert(Severity::Medium, Duration::from_secs(ttl.medium));
        ttl_by_severity.insert(Severity::Low, Duration::from_secs(ttl.low));

        DecisionConfig {
            block_threshold: self.decision.block_threshold,
            alert_threshold: self.decision.alert_threshold,
            min_detectors_for_block: self.decision.min_detectors_for_block,
            ttl_by_severity,
            min_ttl: Duration::from_secs(self.decision.min_ttl_secs),
            max_ttl: Duration::from_secs(self.decision.max_ttl_secs),
            timed_out_weight: self.decision.timed_out_weight,
            errored_weight: self.decision.errored_weight,
        }
    }

    /// Detector timeout budget.
    pub fn detector_timeout(&self) -> Duration {
        Duration::from_millis(self.agent.detector_timeout_ms)
    }

    /// Poll timeout for BPF reads. Clamped to [0, i32::MAX] —
    /// `libc::poll` takes an i32, and negative means infinite wait.
    pub fn poll_timeout_ms(&self) -> i32 {
        self.agent.poll_timeout_ms.min(i32::MAX as u64) as i32
    }

    /// Local IP refresh interval.
    pub fn local_ip_refresh_secs(&self) -> u64 {
        self.agent.local_ip_refresh_secs
    }

    /// One-line summary for startup log.
    pub fn summary(&self) -> String {
        format!(
            "detector={}ms poll={}ms local_ip_refresh={}s flow_max={} enrich_workers={} cb_failures={} cb_cooldown={}s",
            self.agent.detector_timeout_ms,
            self.agent.poll_timeout_ms,
            self.agent.local_ip_refresh_secs,
            self.flow.max_flows,
            self.enrichment.worker_count,
            self.circuit_breaker.max_failures,
            self.circuit_breaker.cooldown_secs,
        )
    }

    /// Build a FlowConfig from the TOML flow section.
    pub fn flow_config(&self) -> flow::FlowConfig {
        flow::FlowConfig {
            max_flows: self.flow.max_flows,
            expiry_secs: self.flow.expiry_secs,
            evaluation_interval_secs: self.flow.evaluation_interval_secs,
            max_re_eval_per_tick: self.flow.max_re_eval_per_tick,
            batch_interval_ticks: self.flow.batch_interval_ticks,
        }
    }

    /// Build a CircuitBreakerConfig from the TOML circuit_breaker section.
    pub fn circuit_breaker_config(&self) -> detectors::CircuitBreakerConfig {
        detectors::CircuitBreakerConfig {
            max_failures: self.circuit_breaker.max_failures,
            cooldown: Duration::from_secs(self.circuit_breaker.cooldown_secs),
        }
    }
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AgentSection {
    pub detector_timeout_ms: u64,
    pub poll_timeout_ms: u64,
    pub local_ip_refresh_secs: u64,
    pub geoip: GeoIpSection,
    pub feeds: FeedsSection,
    pub storage: StorageSection,
}

impl Default for AgentSection {
    fn default() -> Self {
        Self {
            detector_timeout_ms: 100,
            poll_timeout_ms: 100,
            local_ip_refresh_secs: 5,
            geoip: GeoIpSection::default(),
            feeds: FeedsSection::default(),
            storage: StorageSection::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GeoIpSection {
    pub db_path: Option<String>,
}

impl Default for GeoIpSection {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        Self {
            db_path: Some(
                std::path::PathBuf::from(home)
                    .join(".synapse")
                    .join("GeoLite2-City.mmdb")
                    .to_string_lossy()
                    .into_owned(),
            ),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FeedsSection {
    pub dir: Option<String>,
}

impl Default for FeedsSection {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        Self {
            dir: Some(
                std::path::PathBuf::from(home)
                    .join(".synapse")
                    .join("feeds")
                    .to_string_lossy()
                    .into_owned(),
            ),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StorageSection {
    pub db_path: Option<String>,
}

impl Default for StorageSection {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        Self {
            db_path: Some(
                std::path::PathBuf::from(home)
                    .join(".synapse")
                    .join("synapse.db")
                    .to_string_lossy()
                    .into_owned(),
            ),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FlowSection {
    pub max_flows: usize,
    pub expiry_secs: u64,
    pub evaluation_interval_secs: u64,
    pub max_re_eval_per_tick: usize,
    pub batch_interval_ticks: u64,
}

impl Default for FlowSection {
    fn default() -> Self {
        Self {
            max_flows: 100_000,
            expiry_secs: 5,
            evaluation_interval_secs: 1,
            max_re_eval_per_tick: 100,
            batch_interval_ticks: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct EnrichmentSection {
    pub worker_count: usize,
}

impl Default for EnrichmentSection {
    fn default() -> Self {
        Self { worker_count: 4 }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CircuitBreakerSection {
    pub max_failures: u32,
    pub cooldown_secs: u64,
}

impl Default for CircuitBreakerSection {
    fn default() -> Self {
        Self {
            max_failures: 5,
            cooldown_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DecisionSection {
    pub block_threshold: f32,
    pub alert_threshold: f32,
    pub min_detectors_for_block: usize,
    pub timed_out_weight: f32,
    pub errored_weight: f32,
    pub min_ttl_secs: u64,
    pub max_ttl_secs: u64,
    pub ttl_by_severity: TtlBySeverity,
}

impl Default for DecisionSection {
    fn default() -> Self {
        Self {
            block_threshold: 0.7,
            alert_threshold: 0.3,
            min_detectors_for_block: 2,
            timed_out_weight: 0.1,
            errored_weight: 0.0,
            min_ttl_secs: 30,
            max_ttl_secs: 86_400,
            ttl_by_severity: TtlBySeverity::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TtlBySeverity {
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
}

impl Default for TtlBySeverity {
    fn default() -> Self {
        Self {
            critical: 3600,
            high: 900,
            medium: 300,
            low: 60,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn expand_tilde(path: &str) -> std::path::PathBuf {
    if path.starts_with('~') {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        std::path::PathBuf::from(path.replacen('~', &home, 1))
    } else {
        std::path::PathBuf::from(path)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_matches_hardcoded_values() {
        let config = AgentConfig::default();
        assert_eq!(config.agent.detector_timeout_ms, 100);
        assert_eq!(config.agent.poll_timeout_ms, 100);
        assert_eq!(config.agent.local_ip_refresh_secs, 5);
        assert_eq!(config.flow.max_flows, 100_000);
        assert_eq!(config.flow.expiry_secs, 5);
        assert_eq!(config.flow.evaluation_interval_secs, 1);
        assert_eq!(config.flow.max_re_eval_per_tick, 100);
        assert_eq!(config.flow.batch_interval_ticks, 10);
        assert_eq!(config.enrichment.worker_count, 4);
        assert_eq!(config.circuit_breaker.max_failures, 5);
        assert_eq!(config.circuit_breaker.cooldown_secs, 30);
        assert_eq!(config.decision.block_threshold, 0.7);
        assert_eq!(config.decision.alert_threshold, 0.3);
        assert_eq!(config.decision.min_detectors_for_block, 2);
        assert_eq!(config.decision.timed_out_weight, 0.1);
        assert_eq!(config.decision.errored_weight, 0.0);
        assert_eq!(config.decision.min_ttl_secs, 30);
        assert_eq!(config.decision.max_ttl_secs, 86_400);
        assert_eq!(config.decision.ttl_by_severity.critical, 3600);
        assert_eq!(config.decision.ttl_by_severity.high, 900);
        assert_eq!(config.decision.ttl_by_severity.medium, 300);
        assert_eq!(config.decision.ttl_by_severity.low, 60);
    }

    #[test]
    fn test_decision_config_conversion() {
        let config = AgentConfig::default();
        let dc = config.decision_config();
        assert_eq!(dc.block_threshold, 0.7);
        assert_eq!(dc.alert_threshold, 0.3);
        assert_eq!(dc.min_detectors_for_block, 2);
        assert_eq!(dc.min_ttl, Duration::from_secs(30));
        assert_eq!(
            dc.ttl_by_severity[&Severity::Critical],
            Duration::from_secs(3600)
        );
        assert_eq!(dc.ttl_by_severity[&Severity::Low], Duration::from_secs(60));
    }

    #[test]
    fn test_partial_toml_overrides_only_specified() {
        let toml_str = r#"
[decision]
block_threshold = 0.8

[flow]
max_flows = 50000
"#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        // Overridden
        assert_eq!(config.decision.block_threshold, 0.8);
        assert_eq!(config.flow.max_flows, 50_000);
        // Defaulted
        assert_eq!(config.decision.alert_threshold, 0.3);
        assert_eq!(config.decision.min_detectors_for_block, 2);
        assert_eq!(config.enrichment.worker_count, 4);
        assert_eq!(config.flow.expiry_secs, 5);
    }

    #[test]
    fn test_empty_toml_all_defaults() {
        let config: AgentConfig = toml::from_str("").unwrap();
        let default = AgentConfig::default();
        assert_eq!(
            config.agent.detector_timeout_ms,
            default.agent.detector_timeout_ms
        );
        assert_eq!(config.flow.max_flows, default.flow.max_flows);
        assert_eq!(
            config.enrichment.worker_count,
            default.enrichment.worker_count
        );
    }

    #[test]
    fn test_ttl_by_severity_override() {
        let toml_str = r#"
[decision.ttl_by_severity]
critical = 7200
high = 1800
"#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.decision.ttl_by_severity.critical, 7200);
        assert_eq!(config.decision.ttl_by_severity.high, 1800);
        // Untouched defaults
        assert_eq!(config.decision.ttl_by_severity.medium, 300);
        assert_eq!(config.decision.ttl_by_severity.low, 60);
    }

    #[test]
    fn test_expand_tilde() {
        let path = expand_tilde("~/foo/bar");
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        assert_eq!(path, std::path::PathBuf::from(home).join("foo/bar"));
    }

    #[test]
    fn test_expand_tilde_no_tilde() {
        let path = expand_tilde("/etc/foo");
        assert_eq!(path, std::path::PathBuf::from("/etc/foo"));
    }
}
