use crossnet::iface::MacAddr as CrossNetMacAddr;
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
use crate::layer::ipv6_solicited_node_multicast_mac;
use crate::scan::arp::build_arp_scan_buff;
use crate::scan::arp_scan_raw;
use crate::scan::ndp_ns::build_ndp_ns_scan_packet;
use crate::scan::ndp_ns_scan_raw;
use crate::scan::ndp_ra::build_ndp_ra_scan_packet;
use crate::scan::ndp_ra_scan_raw;
use crate::scan::parse_mac_scan_response;

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
    pub(crate) fn fake() -> Self {
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

fn crossnet_mac_std(mac: CrossNetMacAddr) -> Result<MacAddr, PistolError> {
    let mac_octects = mac.octets();
    if mac_octects.len() < 6 {
        Err(PistolError::ParseMacAddrErr {
            mac: mac.to_string(),
        })
    } else {
        Ok(MacAddr::new(
            mac_octects[0],
            mac_octects[1],
            mac_octects[2],
            mac_octects[3],
            mac_octects[4],
            mac_octects[5],
        ))
    }
}

fn infer_ifname(dst: IpAddr, src: Option<IpAddr>) -> Result<Option<NetworkInterface>, PistolError> {
    let ifs = interfaces();
    match src {
        Some(s) => {
            for i in &ifs {
                for ip in &i.ips {
                    if ip.ip() == s {
                        return Ok(Some(i.clone()));
                    }
                }
            }
        }
        None => {
            let neighbor_cache = get_neighbor_cache()?;
            let route_cache = get_route_cache()?;

            let route = match route_cache.search_route(&dst) {
                Some(nr) => nr,
                None => {
                    // Return default route if no route found,
                    // but we need to check if the default route is valid.
                    match route_cache.get_default_route() {
                        Some(dr) => dr,
                        None => return Err(PistolError::CanNotFoundRoute { dst }),
                    }
                }
            };

            let dst2 = match route.gateway {
                Some(gateway) => match gateway {
                    NetRouteAddr::IpAddr(gateway_addr) => gateway_addr,
                    _ => dst,
                },
                None => dst,
            };

            // If the target needs to go through a gateway,
            // we need to find the interface name of the gateway.
            match neighbor_cache.search_ifname(&dst2)? {
                Some(n) => {
                    for i in &ifs {
                        if i.name == n {
                            return Ok(Some(i.clone()));
                        }
                    }
                }
                None => {
                    // Very rare case, if the neighbor cache
                    // does not have the interface name for
                    // the destination address.
                    for i in &ifs {
                        for ip in &i.ips {
                            if ip.contains(dst) {
                                return Ok(Some(i.clone()));
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(None)
}

pub fn infer_net_info(dst: IpAddr, src: Option<IpAddr>) -> Result<Option<NetInfo>, PistolError> {
    let neigh_cache = get_neighbor_cache()?;
    let route_cache = get_route_cache()?;
    let route = match route_cache.search_route(&dst) {
        Some(nr) => nr,
        None => {
            // Return default route if no route found,
            // but we need to check if the default route is valid.
            match route_cache.get_default_route() {
                Some(dr) => dr,
                None => return Err(PistolError::CanNotFoundRoute { dst }),
            }
        }
    };

    let inferred_dst_mac = match route.gateway {
        Some(nra) => {
            // If the route has a gateway,
            // means the destination is not in the same subnet,
            // we need to use the gateway's mac address as the destination mac address.
            match nra {
                NetRouteAddr::IpPool(_p) => {
                    // The route addr can not be IpPool.
                    return Err(PistolError::RouteAddrTypeError);
                }
                NetRouteAddr::IpAddr(route_addr) => {
                    match neigh_cache.search_mac(&route_addr) {
                        Some(route_mac) => crossnet_mac_std(route_mac)?,
                        None => {
                            // send arp(ipv4) or ndp(ipv6) to get the mac address of the gateway
                            let timeout = Duration::from_secs_f32(1.0);
                            match route_addr {
                                IpAddr::V4(d4) => {
                                    let (macs, _dur) = arp_scan_raw(d4, timeout, 2)?;
                                    if macs.len() > 0 {
                                        macs[0]
                                    } else {
                                        return Err(PistolError::CanNotFoundMac { dst });
                                    }
                                }
                                IpAddr::V6(d6) => {
                                    let (macs, _dur) = ndp_ra_scan_raw(d6, timeout, 2)?;
                                    if macs.len() > 0 {
                                        macs[0]
                                    } else {
                                        return Err(PistolError::CanNotFoundMac { dst });
                                    }
                                }
                            }
                        }
                    }
                }
                NetRouteAddr::MacAddr(route_mac) => {
                    // The route addr is a mac address, we can use it directly.
                    crossnet_mac_std(route_mac)?
                }
            }
        }
        None => {
            match neigh_cache.search_mac(&dst) {
                Some(mac) => crossnet_mac_std(mac)?,
                None => {
                    // send arp(ipv4) or ndp(ipv6) to get the mac address of the destination
                    let timeout = Duration::from_secs_f32(1.0);
                    match dst {
                        IpAddr::V4(d4) => {
                            let (macs, _dur) = arp_scan_raw(d4, timeout, 2)?;
                            if macs.len() > 0 {
                                macs[0]
                            } else {
                                return Err(PistolError::CanNotFoundMac { dst });
                            }
                        }
                        IpAddr::V6(d6) => {
                            let (macs, _dur) = ndp_ra_scan_raw(d6, timeout, 2)?;
                            if macs.len() > 0 {
                                macs[0]
                            } else {
                                return Err(PistolError::CanNotFoundMac { dst });
                            }
                        }
                    }
                }
            }
        }
    };

    let ni = NetInfo {
        inferred_dst_mac,
        inferred_src_mac,
        inferred_dst_addr,
        inferred_src_addr,
        inferred_interface,
        cost,
        is_cached,
        is_valid,
        is_loopback,
        origin_dst_addr,
        origin_src_addr,
    };

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
