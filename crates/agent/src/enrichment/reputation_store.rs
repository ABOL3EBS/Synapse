// crates/agent/src/enrichment/reputation_store.rs
//
// Local file-backed reputation feed loader.
// Loads IP blocklists and CSV threat reputation feeds at startup,
// provides read-only lookup for enrichment workers.

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead};
use std::net::IpAddr;
use std::path::Path;

use ipnetwork::IpNetwork;
use log::{debug, info, warn};

/// In-memory reputation store loaded from local feed files.
/// Thread-safe for read-only access — shared via `Arc<ReputationStore>`.
pub struct ReputationStore {
    /// Exact IP matches from blocklist files (one IP per line).
    blocklist: HashMap<IpAddr, f32>,
    /// CIDR ranges from blocklist files (e.g., 192.0.2.0/24).
    cidr_ranges: Vec<(IpNetwork, f32)>,
    /// CSV threat reputation scores (ip → score).
    csv_scores: HashMap<IpAddr, f32>,
}

impl ReputationStore {
    /// Create an empty store (no feeds loaded).
    pub fn empty() -> Self {
        Self {
            blocklist: HashMap::new(),
            cidr_ranges: Vec::new(),
            csv_scores: HashMap::new(),
        }
    }

    /// Returns true if the store has no loaded data.
    pub fn is_empty(&self) -> bool {
        self.blocklist.is_empty() && self.cidr_ranges.is_empty() && self.csv_scores.is_empty()
    }

    /// Load reputation feeds from a directory.
    /// Processes `*.txt` (IP blocklists) and `*.csv` (threat reputation).
    /// Gracefully skips missing directory or unreadable files.
    pub fn load_from_dir(dir: &Path) -> Self {
        let mut store = Self::empty();

        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                info!(
                    "reputation feeds directory not found at {}: {}",
                    dir.display(),
                    e
                );
                return store;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };

            if name.starts_with('.') {
                continue; // skip hidden files
            }

            if name.ends_with(".txt") {
                if let Err(e) = store.load_blocklist_txt(&path) {
                    warn!("failed to load blocklist {}: {}", path.display(), e);
                }
            } else if name.ends_with(".csv") {
                if let Err(e) = store.load_threat_csv(&path) {
                    warn!("failed to load threat CSV {}: {}", path.display(), e);
                }
            }
        }

        info!(
            "reputation store loaded: {} blocklist IPs, {} CIDR ranges, {} CSV scores",
            store.blocklist.len(),
            store.cidr_ranges.len(),
            store.csv_scores.len(),
        );

        store
    }

    /// Load a plain-text blocklist (one IP or CIDR per line, # comments).
    fn load_blocklist_txt(&mut self, path: &Path) -> io::Result<()> {
        let file = fs::File::open(path)?;
        let reader = io::BufReader::new(file);
        let mut loaded = 0u32;

        for line in reader.lines().map_while(Result::ok) {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Try CIDR first (contains '/').
            if trimmed.contains('/') {
                match trimmed.parse::<IpNetwork>() {
                    Ok(cidr) => {
                        self.cidr_ranges.push((cidr, 1.0));
                        loaded += 1;
                    }
                    Err(e) => {
                        debug!("invalid CIDR in {}: {} ({})", path.display(), trimmed, e);
                    }
                }
            } else {
                match trimmed.parse::<IpAddr>() {
                    Ok(ip) => {
                        self.blocklist.insert(ip, 1.0);
                        loaded += 1;
                    }
                    Err(e) => {
                        debug!("invalid IP in {}: {} ({})", path.display(), trimmed, e);
                    }
                }
            }
        }

        info!("loaded blocklist {}: {} entries", path.display(), loaded);
        Ok(())
    }

    /// Load a CSV threat reputation feed (ip,score,category).
    fn load_threat_csv(&mut self, path: &Path) -> io::Result<()> {
        let file = fs::File::open(path)?;
        let reader = io::BufReader::new(file);
        let mut loaded = 0u32;

        for line in reader.lines().map_while(Result::ok) {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.splitn(3, ',').collect();
            if parts.len() < 2 {
                debug!("skipping short CSV line in {}: {}", path.display(), trimmed);
                continue;
            }

            let ip = match parts[0].trim().parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(e) => {
                    debug!("invalid IP in CSV {}: {} ({})", path.display(), parts[0], e);
                    continue;
                }
            };

            let score = match parts[1].trim().parse::<f32>() {
                Ok(s) => s.clamp(0.0, 1.0),
                Err(e) => {
                    debug!(
                        "invalid score in CSV {}: {} ({})",
                        path.display(),
                        parts[1],
                        e
                    );
                    continue;
                }
            };

            self.csv_scores.insert(ip, score);
            loaded += 1;
        }

        info!("loaded threat CSV {}: {} entries", path.display(), loaded);
        Ok(())
    }

    /// Look up reputation for an IP.
    /// Returns a score 0.0–1.0 (higher = more malicious).
    /// Returns None if the IP is unknown (not on any list).
    pub fn lookup(&self, ip: IpAddr) -> Option<f32> {
        // 1. Exact match in CSV scores (most specific, takes priority).
        if let Some(&score) = self.csv_scores.get(&ip) {
            debug!("reputation: {} → {score:.2} (CSV)", ip);
            return Some(score);
        }

        // 2. CIDR range match.
        for (network, score) in &self.cidr_ranges {
            if network.contains(ip) {
                debug!("reputation: {} → {score:.2} (CIDR {})", ip, network);
                return Some(*score);
            }
        }

        // 3. Exact blocklist match.
        if let Some(&score) = self.blocklist.get(&ip) {
            debug!("reputation: {} → {score:.2} (blocklist)", ip);
            return Some(score);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("synapse_reputation_test_{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_empty_store_returns_none() {
        let store = ReputationStore::empty();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(store.lookup(ip).is_none());
    }

    #[test]
    fn test_load_blocklist_txt() {
        let dir = temp_dir("blocklist");
        let file_path = dir.join("bad_ips.txt");
        let mut f = fs::File::create(&file_path).unwrap();
        writeln!(f, "# Known bad IPs").unwrap();
        writeln!(f, "103.224.182.251").unwrap();
        writeln!(f, "198.51.100.0/24").unwrap();
        writeln!(f).unwrap(); // blank line
        writeln!(f, "# Another comment").unwrap();
        writeln!(f, "203.0.113.50").unwrap();

        let store = ReputationStore::load_from_dir(&dir);
        assert_eq!(store.blocklist.len(), 2);
        assert_eq!(store.cidr_ranges.len(), 1);

        let ip1: IpAddr = "103.224.182.251".parse().unwrap();
        assert_eq!(store.lookup(ip1), Some(1.0));

        let ip2: IpAddr = "198.51.100.42".parse().unwrap(); // in 198.51.100.0/24
        assert_eq!(store.lookup(ip2), Some(1.0));

        let ip3: IpAddr = "8.8.8.8".parse().unwrap(); // not in list
        assert!(store.lookup(ip3).is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_threat_csv() {
        let dir = temp_dir("csv");
        let file_path = dir.join("threats.csv");
        let mut f = fs::File::create(&file_path).unwrap();
        writeln!(f, "ip,score,category").unwrap();
        writeln!(f, "1.2.3.4,0.95,malware").unwrap();
        writeln!(f, "5.6.7.8,0.70,phishing").unwrap();
        writeln!(f, "badline").unwrap(); // skip
        writeln!(f, "9.10.11.12,not_a_number,unknown").unwrap(); // skip

        let store = ReputationStore::load_from_dir(&dir);
        assert_eq!(store.csv_scores.len(), 2);

        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(store.lookup(ip1), Some(0.95));

        let ip2: IpAddr = "5.6.7.8".parse().unwrap();
        assert_eq!(store.lookup(ip2), Some(0.70));

        let ip3: IpAddr = "99.99.99.99".parse().unwrap();
        assert!(store.lookup(ip3).is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_csv_score_priority_over_blocklist() {
        let dir = temp_dir("priority");
        let txt = dir.join("blocklist.txt");
        let csv = dir.join("scores.csv");

        {
            let mut f = fs::File::create(&txt).unwrap();
            writeln!(f, "10.0.0.1").unwrap();
        }
        {
            let mut f = fs::File::create(&csv).unwrap();
            writeln!(f, "ip,score,category").unwrap();
            writeln!(f, "10.0.0.1,0.60,mixed").unwrap();
        }

        let store = ReputationStore::load_from_dir(&dir);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        // CSV score should take priority over blocklist
        assert_eq!(store.lookup(ip), Some(0.60));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_missing_directory_graceful() {
        let dir = std::path::PathBuf::from("/tmp/synapse_nonexistent_feed_dir_12345");
        let store = ReputationStore::load_from_dir(&dir);
        assert_eq!(store.blocklist.len(), 0);
        assert_eq!(store.cidr_ranges.len(), 0);
        assert_eq!(store.csv_scores.len(), 0);
    }

    #[test]
    fn test_private_ip_bypass() {
        let store = ReputationStore::empty();
        // Private IPs should return None (not in any list)
        let private: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(store.lookup(private).is_none());
    }

    #[test]
    fn test_hidden_files_skipped() {
        let dir = temp_dir("hidden");
        let hidden = dir.join(".hidden_blocklist.txt");
        let visible = dir.join("blocklist.txt");
        {
            let mut f = fs::File::create(&hidden).unwrap();
            writeln!(f, "1.1.1.1").unwrap();
        }
        {
            let mut f = fs::File::create(&visible).unwrap();
            writeln!(f, "2.2.2.2").unwrap();
        }

        let store = ReputationStore::load_from_dir(&dir);
        assert_eq!(store.blocklist.len(), 1); // only visible file loaded
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(store.lookup(ip).is_none()); // hidden file not loaded

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cidr_boundary_match() {
        let dir = temp_dir("cidr_boundary");
        let file_path = dir.join("ranges.txt");
        let mut f = fs::File::create(&file_path).unwrap();
        writeln!(f, "192.0.2.0/30").unwrap(); // covers .0, .1, .2, .3

        let store = ReputationStore::load_from_dir(&dir);

        let inside: IpAddr = "192.0.2.3".parse().unwrap();
        assert_eq!(store.lookup(inside), Some(1.0));

        let outside: IpAddr = "192.0.2.4".parse().unwrap();
        assert!(store.lookup(outside).is_none());

        let _ = fs::remove_dir_all(&dir);
    }
}
