use crossnet::neigh;
use crossnet::neigh::get_neighbor_cache;
use crossnet::route::NetRouteAddr;
use crossnet::route::get_route_cache;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::datalink::interfaces;
use pnet::packet::ethernet::EtherTypes;
use regex::Regex;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;
use tracing::debug;
use tracing::warn;

use crate::PistolStream;
use crate::SendPacketParam;
use crate::error::PistolError;
use crate::layer::ipv6_multicast_mac;
use crate::scan::arp::build_arp_scan_buff;
use crate::scan::ndp_ns::build_ndp_ns_scan_packet;
use crate::scan::ndp_rs::build_ndp_ra_scan_packet;
use crate::scan::parse_mac_scan_response;
use crate::scan::arp_scan_raw;
use crate::scan::ndp_ns_scan_raw;

pub(crate) fn fake_interface() -> NetworkInterface {
    NetworkInterface {
        name: String::from("fake"),
        index: 0,
        mac: Some(MacAddr::zero()),
        ips: Vec::new(),
        flags: 0,
        description: String::new(),
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct NetInfo {
    pub inferred_dst_mac: MacAddr,
    pub inferred_src_mac: MacAddr,
    /// Inferred destination IP address.
    pub inferred_dst_addr: IpAddr,
    /// If user did not specify source IP address, we will use the IP address of the selected interface.
    pub inferred_src_addr: IpAddr,
    pub inferred_interface: NetworkInterface,
    /// Whether the network information is cached or inferred.
    pub cost: Duration,
    pub is_cached: bool,
    pub is_valid: bool,
    pub is_loopback: bool,
    /// Original user input destination IP address,
    /// which may be the same as infer_dst_addr if user input a valid IP address,
    /// or may be different if user input a hostname or an invalid IP address.
    pub origin_dst_addr: IpAddr,
    pub origin_src_addr: Option<IpAddr>,
}

impl NetInfo {
    pub(crate) fn invalid() -> Self {
        NetInfo {
            inferred_dst_mac: MacAddr::zero(),
            inferred_src_mac: MacAddr::zero(),
            inferred_dst_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            inferred_src_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            inferred_interface: fake_interface(),
            cost: Duration::ZERO,
            is_cached: true,
            is_valid: false,
            is_loopback: false,
            origin_dst_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            origin_src_addr: None,
        }
    }
}

impl fmt::Display for NetInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_valid {
            let output = format!(
                "dst_mac: {}, src_mac: {}, dst_addr: {}, src_addr: {}, interface: {}",
                self.inferred_dst_mac,
                self.inferred_src_mac,
                self.inferred_dst_addr,
                self.inferred_src_addr,
                self.inferred_interface
            );
            write!(f, "{}", output)
        } else {
            let output = format!(
                "dst_addr: {} is down or unreachable",
                self.inferred_dst_addr
            );
            write!(f, "{}", output)
        }
    }
}

pub fn infer_net_info(dst: IpAddr, src: Option<IpAddr>) -> Result<Option<NetInfo>, PistolError> {
    let neigh_cache = get_neighbor_cache()?;
    let route_cache = get_route_cache()?;
    match route_cache.search_route(dst) {
        Some(nr) => {
            match nr.gateway {
                Some(nra) => {
                    // If the route has a gateway,
                    // means the destination is not in the same subnet,
                    // we need to use the gateway's mac address as the destination mac address.
                    let c_inferred_dst_mac = match nra {
                        NetRouteAddr::IpPool(_p) => {
                            // The route addr can not be IpPool.
                            return Err(PistolError::RouteAddrTypeError);
                        }
                        NetRouteAddr::IpAddr(route_addr) => {
                            match neigh_cache.search_mac(&route_addr) {
                                Some(route_mac) => route_mac,
                                None => {
                                    // send arp(ipv4) or ndp(ipv6) to get the mac address of the gateway
                                    let timeout = Duration::from_secs_f32(1.0);
                                    match route_addr {
                                        IpAddr::V4(r4) => {
                                            arp_scan_raw(r4, timeout, 2)?;
                                        }
                                        IpAddr::V6(r6) => {

                                        }
                                    }
                                }
                            }
                        }
                        NetRouteAddr::MacAddr(route_mac) => {
                            // The route addr is a mac address, we can use it directly.
                            route_mac
                        }
                    };

                    let inferred_dst_mac_octects = c_inferred_dst_mac.octets();
                    if inferred_dst_mac_octects.len() < 6 {
                        return Err(PistolError::ParseMacAddrErr {
                            mac: c_inferred_dst_mac.to_string(),
                        });
                    }
                    let inferred_dst_mac = MacAddr::new(
                        inferred_dst_mac_octects[0],
                        inferred_dst_mac_octects[1],
                        inferred_dst_mac_octects[2],
                        inferred_dst_mac_octects[3],
                        inferred_dst_mac_octects[4],
                        inferred_dst_mac_octects[5],
                    );
                }
                None => {}
            }
        }
        None => {}
    }

    let mut nis = NeighborInfo::new()?;
    nis.infer_net_info(dst, src)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    #[test]
    fn test_infer_net_info() {
        let start = Instant::now();
        let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 78));
        let src = None;
        let mut nis = NeighborInfo::new().unwrap();
        if let Some(infer_result) = nis.infer_net_info(dst, src).unwrap() {
            println!(
                "infer result: {}, elapsed: {:?}",
                infer_result.inferred_interface.name,
                start.elapsed()
            );
        } else {
            println!("infer result: None, elapsed: {:?}", start.elapsed());
        }
    }
}
