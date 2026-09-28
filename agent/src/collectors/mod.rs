//! Collectors: the offline dataset collector and the live (read-only) endpoint collectors.

pub mod live;
pub mod offline;

use std::net::IpAddr;

/// Classify a socket's direction given the set of locally listening ports.
pub fn direction(state: &str, local_port: Option<u16>, remote: Option<IpAddr>, listening: &std::collections::HashSet<u16>) -> &'static str {
    if state == "LISTEN" {
        return "listen";
    }
    match remote {
        None => "bound",
        Some(ip) if ip.is_unspecified() => "bound",
        Some(_) => match local_port {
            Some(p) if listening.contains(&p) => "inbound",
            _ => "outbound",
        },
    }
}
