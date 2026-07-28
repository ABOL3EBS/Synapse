// crates/agent/src/detectors/process_correlator.rs
//
// Process-to-network behavioral correlation detector (Detector 2).
// Contextual behavioral scoring — NOT rigid process→port mappings.
// Analyzes WHERE a process runs, WHAT it connects to, and HOW it behaves.

use std::path::Path;
use std::time::Instant;

use synapse_common::{
    Detector, DetectorFinding, DetectorId, DetectorStatus, Evidence, FlowRecord, Severity,
};

/// Process-to-network behavioral correlation detector.
///
/// Evaluates four sub-detectors using contextual heuristics:
/// 1. Temp directory execution — processes running from /tmp or /var/tmp
/// 2. Shell/interpreter network activity — bash, python, perl with network connections
/// 3. Uncommon binary location — executables outside standard paths
/// 4. Unresolved process — PID attribution failed (unknown process + suspicious dest)
pub struct ProcessCorrelator;

impl ProcessCorrelator {
    /// Known-safe process basenames — browsers, OS services, common CLI tools.
    /// These are never scored by behavioral sub-detectors.
    const ALLOWLIST: &'static [&'static str] = &[
        "Brave Browser",
        "Brave Browser Helper",
        "Safari",
        "SafariHelper",
        "SafariCloudTabsAgent",
        "WebContent",
        "firefox",
        "Google Chrome",
        "Google Chrome Helper",
        "Chromium",
        "Microsoft Edge",
        "curl",
        "wget",
        "ssh",
        "git",
        "npm",
        "node",
        "cargo",
        "rustc",
        "Finder",
        "launchd",
        "cfprefsd",
        "nsurlsessiond",
        "SystemUIServer",
        "ControlCenter",
        "Spotlight",
        "mds",
        "mdworker",
        "WindowServer",
        "loginwindow",
    ];

    /// Paths where legitimate long-running processes are rare.
    const TEMP_DIRS: &'static [&'static str] = &["/tmp/", "/var/tmp/", "/private/tmp/"];

    /// Standard paths for system and user binaries.
    const STANDARD_PATHS: &'static [&'static str] = &[
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/libexec/",
        "/bin/",
        "/sbin/",
        "/System/",
        "/Applications/",
        "/Library/",
        "/opt/homebrew/bin/",
        "/opt/homebrew/sbin/",
        "/opt/homebrew/opt/",
        "/opt/local/bin/",
        "/usr/local/bin/",
        "/usr/local/sbin/",
        "/usr/local/opt/",
        "/Users/",
    ];

    /// Shell and interpreter basenames — suspicious when they have network activity.
    const SHELLS: &'static [&'static str] = &[
        "bash", "zsh", "sh", "csh", "tcsh", "ksh", "python", "python3", "perl", "ruby", "node",
        "php",
    ];

    fn score_temp_dir_execution(process_path: &str) -> f32 {
        for temp_dir in Self::TEMP_DIRS {
            if process_path.starts_with(temp_dir) {
                return 0.7;
            }
        }
        0.0
    }

    fn score_shell_network_activity(process_path: &str) -> f32 {
        let basename = Path::new(process_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        for shell in Self::SHELLS {
            if basename == *shell {
                return 0.6;
            }
        }
        0.0
    }

    fn score_uncommon_location(process_path: &str) -> f32 {
        // Empty path — no info, not suspicious on its own.
        if process_path.is_empty() {
            return 0.0;
        }

        // Standard paths (includes /usr/bin, /opt/homebrew, /usr/local, /Applications, /Users).
        for standard in Self::STANDARD_PATHS {
            if process_path.starts_with(standard) {
                // App bundle helper: /Applications/X.app/Contents/MacOS/X — legitimate.
                if process_path.contains(".app/Contents/") {
                    return 0.0;
                }
                return 0.0;
            }
        }

        // Unknown location outside all standard paths.
        0.4
    }

    fn score_unresolved_process(pid: Option<u32>, flow: &FlowRecord) -> f32 {
        // Unknown process + suspicious destination = higher score.
        if pid.is_some() {
            return 0.0;
        }

        // Check if destination is external (not RFC1918).
        let b_ip = flow.b_ip;
        let is_external = match b_ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                !(o[0] == 10
                    || (o[0] == 172 && (16..=31).contains(&o[1]))
                    || (o[0] == 192 && o[1] == 168))
            }
            std::net::IpAddr::V6(_) => true, // Treat IPv6 as external for v1.
        };

        if is_external {
            0.5
        } else {
            0.2
        }
    }

    /// Check if a process path basename matches the known-safe allowlist.
    fn is_known_safe(process_path: &str) -> bool {
        if process_path.is_empty() {
            return false;
        }
        let basename = Path::new(process_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        Self::ALLOWLIST.contains(&basename)
    }
}

impl Default for ProcessCorrelator {
    fn default() -> Self {
        Self
    }
}

impl Detector for ProcessCorrelator {
    fn id(&self) -> DetectorId {
        DetectorId::ProcessCorrelator
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn evaluate(&self, flow: &FlowRecord) -> DetectorFinding {
        let start = Instant::now();

        let process_path = flow.process_path.as_deref().unwrap_or("");

        // Known-safe process → skip behavioral scoring entirely.
        if Self::is_known_safe(process_path) {
            return DetectorFinding {
                detector_id: self.id(),
                detector_version: self.version().to_string(),
                score: 0.0,
                confidence: 1.0,
                severity: Severity::Low,
                evidence: vec![Evidence {
                    description: "Known safe process".to_string(),
                    detail: Some(process_path.to_string()),
                }],
                latency_us: start.elapsed().as_micros() as u64,
                status: DetectorStatus::Completed,
            };
        }

        // If no process info at all, check if unresolved process is suspicious.
        if process_path.is_empty() && flow.pid.is_none() {
            let e = Self::score_unresolved_process(flow.pid, flow);
            if e > 0.0 {
                let finding = DetectorFinding {
                    detector_id: self.id(),
                    detector_version: self.version().to_string(),
                    score: e,
                    confidence: 0.5,
                    severity: Severity::Medium,
                    evidence: vec![Evidence {
                        description: "Process attribution failed — unknown process".to_string(),
                        detail: None,
                    }],
                    latency_us: start.elapsed().as_micros() as u64,
                    status: DetectorStatus::Completed,
                };
                return finding;
            }
        }

        let mut evidence = Vec::new();
        let mut total_score = 0.0f32;
        let mut max_possible = 0.0f32;

        let e = Self::score_temp_dir_execution(process_path);
        if e > 0.0 {
            evidence.push(Evidence {
                description: "Process running from temp directory".to_string(),
                detail: Some(process_path.to_string()),
            });
        }
        total_score += e;
        max_possible += 1.0;

        let e = Self::score_shell_network_activity(process_path);
        if e > 0.0 {
            evidence.push(Evidence {
                description: "Shell/interpreter has network activity".to_string(),
                detail: Some(process_path.to_string()),
            });
        }
        total_score += e;
        max_possible += 1.0;

        let e = Self::score_uncommon_location(process_path);
        if e > 0.0 {
            evidence.push(Evidence {
                description: "Process at uncommon location".to_string(),
                detail: Some(process_path.to_string()),
            });
        }
        total_score += e;
        max_possible += 1.0;

        let e = Self::score_unresolved_process(flow.pid, flow);
        if e > 0.0 {
            evidence.push(Evidence {
                description: "Process attribution failed".to_string(),
                detail: None,
            });
        }
        total_score += e;
        max_possible += 1.0;

        let normalized = if max_possible > 0.0 {
            (total_score / max_possible).min(1.0)
        } else {
            0.0
        };

        let severity = if normalized > 0.6 {
            Severity::High
        } else if normalized > 0.3 {
            Severity::Medium
        } else {
            Severity::Low
        };

        let confidence = if evidence.len() >= 2 {
            0.7
        } else if !evidence.is_empty() {
            0.5
        } else {
            1.0
        };

        DetectorFinding {
            detector_id: self.id(),
            detector_version: self.version().to_string(),
            score: normalized,
            confidence,
            severity,
            evidence,
            latency_us: start.elapsed().as_micros() as u64,
            status: DetectorStatus::Completed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn make_flow_with_process(
        process_path: Option<String>,
        pid: Option<u32>,
        b_ip: IpAddr,
    ) -> FlowRecord {
        FlowRecord {
            flow_id: 1,
            a_ip: IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            b_ip,
            a_port: 50000,
            b_port: 443,
            protocol: 6,
            local_port: 50000,
            pid,
            packet_count: 10,
            byte_count: 5000,
            dns_name: None,
            process_path,
            process_start_time: Some(1700000000.0),
            country_code: None,
            asn: None,
            reputation_score: None,
            flow_age: std::time::Duration::from_secs(5),
        }
    }

    #[test]
    fn test_temp_dir_execution() {
        let detector = ProcessCorrelator;
        let flow = make_flow_with_process(
            Some("/tmp/malware.sh".to_string()),
            Some(1234),
            "8.8.8.8".parse().unwrap(),
        );
        let finding = detector.evaluate(&flow);
        assert!(finding.score > 0.0, "Temp dir execution should score > 0");
    }

    #[test]
    fn test_shell_network_activity() {
        let detector = ProcessCorrelator;
        let flow = make_flow_with_process(
            Some("/bin/bash".to_string()),
            Some(5678),
            "8.8.8.8".parse().unwrap(),
        );
        let finding = detector.evaluate(&flow);
        assert!(
            finding.score > 0.0,
            "Shell with network activity should score > 0"
        );
    }

    #[test]
    fn test_standard_path() {
        let detector = ProcessCorrelator;
        let flow = make_flow_with_process(
            Some("/usr/bin/curl".to_string()),
            Some(42),
            "8.8.8.8".parse().unwrap(),
        );
        let finding = detector.evaluate(&flow);
        assert_eq!(finding.score, 0.0, "Standard path process should score 0");
    }

    #[test]
    fn test_unresolved_process_external() {
        let detector = ProcessCorrelator;
        let flow = make_flow_with_process(None, None, "8.8.8.8".parse().unwrap());
        let finding = detector.evaluate(&flow);
        assert!(
            finding.score > 0.0,
            "Unresolved process + external dest should score > 0"
        );
    }

    #[test]
    fn test_unresolved_process_internal() {
        let detector = ProcessCorrelator;
        let flow = make_flow_with_process(None, None, "192.168.1.100".parse().unwrap());
        let finding = detector.evaluate(&flow);
        assert!(
            finding.score <= 0.3,
            "Unresolved process + internal dest should score low, got {}",
            finding.score
        );
    }

    #[test]
    fn test_python_network_activity() {
        let detector = ProcessCorrelator;
        let flow = make_flow_with_process(
            Some("/usr/local/bin/python3".to_string()),
            Some(9999),
            "10.0.0.50".parse().unwrap(),
        );
        let finding = detector.evaluate(&flow);
        assert!(
            finding.score > 0.0,
            "Python with network activity should score > 0"
        );
    }

    #[test]
    fn test_homebrew_path() {
        let detector = ProcessCorrelator;
        let flow = make_flow_with_process(
            Some("/opt/homebrew/bin/curl".to_string()),
            Some(42),
            "8.8.8.8".parse().unwrap(),
        );
        let finding = detector.evaluate(&flow);
        assert_eq!(finding.score, 0.0, "Homebrew path should score 0");
    }

    #[test]
    fn test_app_bundle_helper() {
        let detector = ProcessCorrelator;
        let flow = make_flow_with_process(
            Some("/Applications/Slack.app/Contents/MacOS/Slack".to_string()),
            Some(42),
            "8.8.8.8".parse().unwrap(),
        );
        let finding = detector.evaluate(&flow);
        assert_eq!(finding.score, 0.0, "App bundle helper should score 0");
    }

    #[test]
    fn test_unknown_location() {
        let detector = ProcessCorrelator;
        let flow = make_flow_with_process(
            Some("/var/data/sketchy.bin".to_string()),
            Some(42),
            "8.8.8.8".parse().unwrap(),
        );
        let finding = detector.evaluate(&flow);
        assert!(finding.score > 0.0, "Unknown location should score > 0");
    }

    #[test]
    fn test_known_safe_browser_scores_zero() {
        let detector = ProcessCorrelator;
        let flow = make_flow_with_process(
            Some("Brave Browser Helper".to_string()),
            Some(42),
            "172.217.14.99".parse().unwrap(),
        );
        let finding = detector.evaluate(&flow);
        assert_eq!(finding.score, 0.0, "Known safe browser should score 0");
        assert_eq!(finding.confidence, 1.0);
    }
}
