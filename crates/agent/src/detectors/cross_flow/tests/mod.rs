use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
pub(crate) use synapse_common::{Detector, FlowRecord};

pub(crate) use super::{CrossFlowConfig, CrossFlowDetector, CrossFlowState};

mod beaconing;
mod diversity;
mod exclusions;
mod scan_dns;

pub(crate) fn live_excluded(
    ips: impl IntoIterator<Item = IpAddr>,
) -> Arc<ArcSwap<HashSet<IpAddr>>> {
    Arc::new(ArcSwap::from_pointee(ips.into_iter().collect()))
}

pub(crate) fn make_flow(a_ip: IpAddr, b_ip: IpAddr) -> FlowRecord {
    FlowRecord {
        flow_id: 1,
        a_ip,
        b_ip,
        a_port: 50000,
        b_port: 443,
        protocol: 6,
        local_port: 50000,
        // pid: None → evaluate() uses unwrap_or(0) sentinel, matching test
        // record_connection calls which also use pid=0.
        pid: None,
        packet_count: 10,
        byte_count: 5000,
        dns_name: None,
        process_path: Some("/usr/bin/curl".to_string()),
        process_start_time: Some(1700000000.0),
        country_code: None,
        asn: None,
        reputation_score: None,
        flow_age: std::time::Duration::from_secs(5),
        // a_port=50000=local_port → a_ip is local, b_ip is remote.
        resolved: Some(synapse_common::ResolvedFlow {
            local_ip: a_ip,
            local_port: 50000,
            remote_ip: b_ip,
            remote_port: 443,
        }),
    }
}

pub(crate) fn default_state() -> CrossFlowState {
    CrossFlowState::new(CrossFlowConfig::default(), live_excluded([]))
}

pub(crate) fn make_flow_with_pid(a_ip: IpAddr, b_ip: IpAddr, pid: u32) -> FlowRecord {
    FlowRecord {
        pid: Some(pid),
        ..make_flow(a_ip, b_ip)
    }
}
