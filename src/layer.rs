// use chrono::Local;
use pcapture::pcapng::EnhancedPacketBlock;
use pcapture::pcapng::GeneralBlock;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::ChannelType;
use pnet::datalink::Config;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::datalink::interfaces;
use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::EtherType;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::icmp::IcmpCode;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpType;
use pnet::packet::icmpv6;
use pnet::packet::icmpv6::Icmpv6Code;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmpv6::Icmpv6Type;
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::packet::icmpv6::ndp::MutableRouterSolicitPacket;
use pnet::packet::icmpv6::ndp::NdpOption;
use pnet::packet::icmpv6::ndp::NdpOptionTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::panic::Location;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::channel;
use std::time::Duration;
use std::time::Instant;
use tracing::debug;
use tracing::error;
use tracing::warn;
use uuid::Uuid;

use crate::DEFAULT_TIMEOUT;
use crate::PISTOL_PCAPNG;
use crate::PISTOL_PCAPNG_FLAG;
use crate::PISTOL_RUNNER_IS_RUNNING;
use crate::SYSTEM_NET_CACHE;
use crate::UNIFIED_RECV_MATCHS;

use crate::DST_CACHE;
use crate::PistolChannel;
use crate::error::PistolError;
use crate::route::DefaultRoute;
use crate::scan::arp::send_arp_scan_packet;
use crate::scan::ndp_ns::send_ndp_ns_scan_packet;
use crate::utils::arp_cache_update;

pub const ETHERNET_HEADER_SIZE: usize = 14;
pub const ARP_HEADER_SIZE: usize = 28;
pub const IPV4_HEADER_SIZE: usize = 20;
pub const IPV6_HEADER_SIZE: usize = 40;
pub const TCP_HEADER_SIZE: usize = 20;
pub const UDP_HEADER_SIZE: usize = 8;
pub const ICMP_HEADER_SIZE: usize = 8;
// big enough to store all data
pub const ETHERNET_BUFF_SIZE: usize = 4096;

pub const ICMPV6_NS_HEADER_SIZE: usize = 32;
pub const ICMPV6_RS_HEADER_SIZE: usize = 16;
// pub const ICMPV6_NA_HEADER_SIZE: usize = 32;
pub const ICMPV6_ER_HEADER_SIZE: usize = 8;
pub const ICMPV6_NI_HEADER_SIZE: usize = 32;

/// If the ICMP message is a Destination Unreachable,
/// Time Exceeded, Parameter Problem, or Source Quench,
/// the Internet header plus the first 64 bits of the original datagram's data are returned.
/// The remaining 32 bits of the ICMP message header are unused and must be zero.
/// --- From RFC 792 – Internet Control Message Protocol (ICMP) https://datatracker.ietf.org/doc/html/rfc792#page-6
fn get_icmp_payload(icmp_packet: &IcmpPacket) -> Vec<u8> {
    let icmp_type = icmp_packet.get_icmp_type();
    let icmp_payload = icmp_packet.payload().to_vec();
    if icmp_type == IcmpType(3) {
        // Destination Unreachable
        icmp_payload[4..].to_vec()
    } else if icmp_type == IcmpType(0) {
        // Source Quench - Deprecated
        icmp_payload[4..].to_vec()
    } else if icmp_type == IcmpType(11) {
        // Time Exceeded
        icmp_payload[4..].to_vec()
    } else {
        icmp_payload
    }
}

fn get_icmpv6_payload(icmpv6_packet: &Icmpv6Packet) -> Vec<u8> {
    let icmpv6_type = icmpv6_packet.get_icmpv6_type();
    let icmpv6_payload = icmpv6_packet.payload().to_vec();
    if icmpv6_type == Icmpv6Type(1) {
        // Destination Unreachable
        icmpv6_payload[4..].to_vec()
    } else if icmpv6_type == Icmpv6Type(3) {
        // Time Exceeded
        icmpv6_payload[4..].to_vec()
    } else if icmpv6_type == Icmpv6Type(4) {
        // Parameter Problem
        icmpv6_payload[4..].to_vec()
    } else if icmpv6_type == Icmpv6Type(128) || icmpv6_type == Icmpv6Type(129) {
        // Echo Request/Reply
        icmpv6_payload[4..].to_vec()
    } else {
        icmpv6_payload
    }
}

/// Use source IP address to find local interface
pub fn find_interface_by_src(src_addr: IpAddr) -> Option<NetworkInterface> {
    for interface in interfaces() {
        for ip in &interface.ips {
            let i = ip.ip();
            if src_addr == i {
                return Some(interface);
            }
        }
    }
    None
}

/// Use destination IP address to find local interface
pub fn find_interface_by_dst(dst_addr: IpAddr) -> Option<NetworkInterface> {
    for interface in interfaces() {
        for ip in &interface.ips {
            // ipn 0.0.0.0/0 contains all ip address
            if !ip.ip().is_unspecified() {
                if ip.contains(dst_addr) {
                    // debug!("ipn {} contains dst addr {}", ip, dst_addr);
                    return Some(interface);
                }
            }
        }
    }
    None
}

fn find_loopback_interface() -> Option<NetworkInterface> {
    for interface in interfaces() {
        if interface.is_loopback() {
            return Some(interface);
        }
    }
    None
}

fn get_default_route() -> Result<Option<DefaultRoute>, PistolError> {
    // release the lock when leaving the function
    let snc = match SYSTEM_NET_CACHE.lock() {
        Ok(snc) => snc,
        Err(e) => {
            return Err(PistolError::TryLockGlobalVarFailed {
                var_name: String::from("SYSTEM_NET_CACHE"),
                e: e.to_string(),
            });
        }
    };
    Ok(snc.default_route.clone())
}

/// Check if the target IP address is in the local.
fn dst_in_local(dst_addr: IpAddr) -> bool {
    for interface in interfaces() {
        for ipn in interface.ips {
            if ipn.contains(dst_addr) {
                return true;
            }
        }
    }
    // all data for other addresses are sent to the default route
    debug!("dst {} is not in local net", dst_addr);
    false
}

/// Check if the target IP address is one of the system IP address.
fn dst_in_host(dst_addr: IpAddr) -> bool {
    for interface in interfaces() {
        for ipn in interface.ips {
            if ipn.ip() == dst_addr {
                return true;
            }
        }
    }
    debug!("dst {} is not in host", dst_addr);
    false
}

/// Get the target mac address through arp table
fn search_mac_from_cache(dst_addr: IpAddr) -> Result<Option<MacAddr>, PistolError> {
    let snc = match SYSTEM_NET_CACHE.lock() {
        Ok(snc) => snc,
        Err(e) => {
            return Err(PistolError::TryLockGlobalVarFailed {
                var_name: String::from("SYSTEM_NET_CACHE"),
                e: e.to_string(),
            });
        }
    };
    Ok(snc.search_mac(dst_addr))
}

/// Get the send interface from the system route table
fn search_route_table(dst_addr: IpAddr) -> Result<Option<NetworkInterface>, PistolError> {
    let snc = match SYSTEM_NET_CACHE.lock() {
        Ok(snc) => snc,
        Err(e) => {
            return Err(PistolError::TryLockGlobalVarFailed {
                var_name: String::from("SYSTEM_NET_CACHE"),
                e: e.to_string(),
            });
        }
    };
    Ok(snc.search_route(dst_addr))
}

/// Destination mac address and interface cache
pub struct DstCache {
    pub dst_addr: IpAddr,
    pub src_addr: IpAddr,
    pub mac: MacAddr,
    pub interface: NetworkInterface,
}

// the same target address does not need to be searched again
fn update_dst_cache(
    dst_addr: IpAddr,
    src_addr: IpAddr,
    mac: MacAddr,
    interface: NetworkInterface,
) -> Result<(), PistolError> {
    match DST_CACHE.lock() {
        Ok(mut dst_cache) => {
            if !dst_cache.contains_key(&dst_addr) {
                let dc = DstCache {
                    dst_addr,
                    src_addr,
                    mac,
                    interface,
                };
                let _ = dst_cache.insert(dst_addr, dc);
            }
            Ok(())
        }
        Err(e) => Err(PistolError::TryLockGlobalVarFailed {
            var_name: String::from("DST_CACHE"),
            e: e.to_string(),
        }),
    }
}

fn get_dst_cache(dst_addr: IpAddr) -> Result<Option<(MacAddr, NetworkInterface)>, PistolError> {
    match DST_CACHE.lock() {
        Ok(dst_cache) => {
            let ret = dst_cache.get(&dst_addr);
            if let Some(dc) = ret {
                // debug!("dst {} found in cache", dst_addr);
                Ok(Some((dc.mac, dc.interface.clone())))
            } else {
                debug!("dst {} not found in cache", dst_addr);
                Ok(None)
            }
        }
        Err(e) => Err(PistolError::TryLockGlobalVarFailed {
            var_name: String::from("DST_CACHE"),
            e: e.to_string(),
        }),
    }
}

pub fn get_dst_mac_and_interface(
    dst_addr: IpAddr,
    src_addr: IpAddr,
    timeout: Option<Duration>,
) -> Result<(MacAddr, NetworkInterface), PistolError> {
    // search in the program cache
    if let Some((dst_mac, src_interface)) = get_dst_cache(dst_addr)? {
        return Ok((dst_mac, src_interface));
    }

    let src_interface = if src_addr == dst_addr {
        match find_loopback_interface() {
            Some(i) => i,
            None => return Err(PistolError::CanNotFoundInterface),
        }
    } else {
        match find_interface_by_dst(dst_addr) {
            Some(i) => i,
            None => match find_interface_by_src(src_addr) {
                Some(i) => i,
                None => match search_route_table(dst_addr)? {
                    Some(i) => i,
                    None => return Err(PistolError::CanNotFoundInterface),
                },
            },
        }
    };
    // println!("src inf: {}", src_interface.name);

    let dst_mac = match search_mac_from_cache(dst_addr)? {
        Some(m) => m,
        None => {
            if dst_addr.is_loopback() || dst_in_host(dst_addr) {
                // target is your own machine, such as when using localhost or 127.0.0.1 as the target
                let dst_mac = match src_interface.mac {
                    Some(m) => m,
                    None => return Err(PistolError::CanNotFoundMacAddress),
                };
                dst_mac
            } else if dst_in_local(dst_addr) {
                let src_mac = match src_interface.mac {
                    Some(m) => m,
                    None => return Err(PistolError::CanNotFoundMacAddress),
                };
                match dst_addr {
                    IpAddr::V4(dst_ipv4) => {
                        if let IpAddr::V4(src_ipv4) = src_addr {
                            let dst_mac = match send_arp_scan_packet(
                                dst_ipv4,
                                MacAddr::broadcast(),
                                src_ipv4,
                                src_mac,
                                src_interface.clone(),
                                timeout,
                            )? {
                                (Some(m), _rtt) => m,
                                (None, _rtt) => return Err(PistolError::CanNotFoundMacAddress),
                            };
                            arp_cache_update(dst_ipv4.into(), dst_mac)?;
                            dst_mac
                        } else {
                            return Err(PistolError::CanNotFoundMacAddress);
                        }
                    }
                    IpAddr::V6(dst_ipv6) => {
                        if let IpAddr::V6(src_ipv6) = src_addr {
                            let dst_mac = match send_ndp_ns_scan_packet(
                                dst_ipv6,
                                src_ipv6,
                                src_mac,
                                src_interface.clone(),
                                timeout,
                            )? {
                                (Some(m), _rtt) => m,
                                (None, _rtt) => return Err(PistolError::CanNotFoundMacAddress),
                            };
                            arp_cache_update(dst_ipv6.into(), dst_mac)?;
                            dst_mac
                        } else {
                            return Err(PistolError::CanNotFoundMacAddress);
                        }
                    }
                }
            } else {
                let default_route = match get_default_route()? {
                    Some(r) => r,
                    None => return Err(PistolError::CanNotFoundRouterAddress),
                };
                let dst_mac = match search_mac_from_cache(default_route.via)? {
                    Some(m) => m,
                    None => {
                        let dst_mac = MacAddr::broadcast();
                        let src_mac = match src_interface.mac {
                            Some(m) => m,
                            None => return Err(PistolError::CanNotFoundMacAddress),
                        };
                        match default_route.via {
                            IpAddr::V4(default_route_ipv4) => {
                                if let IpAddr::V4(src_ipv4) = src_addr {
                                    match send_arp_scan_packet(
                                        default_route_ipv4,
                                        dst_mac,
                                        src_ipv4,
                                        src_mac,
                                        src_interface.clone(),
                                        timeout,
                                    )? {
                                        (Some(m), _rtt) => {
                                            arp_cache_update(default_route_ipv4.into(), m)?;
                                            m
                                        }
                                        (None, _rtt) => {
                                            return Err(PistolError::CanNotFoundRouteMacAddress);
                                        }
                                    }
                                } else {
                                    return Err(PistolError::CanNotFoundRouteMacAddress);
                                }
                            }
                            IpAddr::V6(default_route_ipv6) => {
                                if let IpAddr::V6(src_ipv6) = src_addr {
                                    match ndp_rs(src_ipv6, timeout)? {
                                        (Some(m), _rtt) => {
                                            arp_cache_update(default_route_ipv6.into(), m)?;
                                            m
                                        }
                                        (None, _rtt) => {
                                            return Err(PistolError::CanNotFoundRouteMacAddress);
                                        }
                                    }
                                } else {
                                    return Err(PistolError::CanNotFoundRouteMacAddress);
                                }
                            }
                        }
                    }
                };
                dst_mac
            }
        }
    };
    update_dst_cache(dst_addr, src_addr, dst_mac, src_interface.clone())?;
    Ok((dst_mac, src_interface))
}

/// When the target is a loopback address,
/// we need to update not only the value of src addr,
/// but also the value of dst addr.
#[derive(Debug, Clone, Copy)]
pub struct InferAddr {
    pub dst_addr: IpAddr,
    pub src_addr: IpAddr,
}

impl InferAddr {
    /// Returns: (dst_addr, src_addr)
    pub fn ipv4_addr(&self) -> Result<(Ipv4Addr, Ipv4Addr), PistolError> {
        if let IpAddr::V4(dst_ipv4) = self.dst_addr {
            if let IpAddr::V4(src_ipv4) = self.src_addr {
                return Ok((dst_ipv4, src_ipv4));
            }
        }
        Err(PistolError::CanNotFoundSourceAddress)
    }
    /// Returns: (dst_addr, src_addr)
    pub fn ipv6_addr(&self) -> Result<(Ipv6Addr, Ipv6Addr), PistolError> {
        if let IpAddr::V6(dst_ipv6) = self.dst_addr {
            if let IpAddr::V6(src_ipv6) = self.src_addr {
                return Ok((dst_ipv6, src_ipv6));
            }
        }
        Err(PistolError::CanNotFoundSourceAddress)
    }
}

/// The source address is inferred from the target address.
/// When the target address is a loopback address,
/// it is mapped to an internal private address
/// because the loopback address only works at the transport layer
/// and cannot send data frames.
pub fn infer_addr(
    dst_addr: IpAddr,
    src_addr: Option<IpAddr>,
) -> Result<Option<InferAddr>, PistolError> {
    if dst_addr.is_loopback() {
        for interface in interfaces() {
            if !interface.is_loopback() {
                for ipn in interface.ips {
                    match ipn.ip() {
                        IpAddr::V4(src_ipv4) => {
                            if dst_addr.is_ipv4() && src_ipv4.is_private() {
                                let ia = InferAddr {
                                    dst_addr: src_ipv4.into(),
                                    src_addr: src_ipv4.into(),
                                };
                                return Ok(Some(ia));
                            }
                        }
                        IpAddr::V6(src_ipv6) => {
                            if dst_addr.is_ipv6()
                                && (src_ipv6.is_unicast_link_local() || src_ipv6.is_unique_local())
                            {
                                let ia = InferAddr {
                                    dst_addr: src_ipv6.into(),
                                    src_addr: src_ipv6.into(),
                                };
                                return Ok(Some(ia));
                            }
                        }
                    }
                }
            }
        }
    } else {
        match src_addr {
            Some(src_addr) => {
                let ia = InferAddr { dst_addr, src_addr };
                return Ok(Some(ia));
            }
            None => match search_route_table(dst_addr)? {
                // Try to get the interface for sending through the system routing table,
                // and then get the IP on it through the interface.
                Some(send_interface) => {
                    for ipn in send_interface.ips {
                        match ipn.ip() {
                            IpAddr::V4(src_ipv4) => {
                                if dst_addr.is_ipv4() && !src_ipv4.is_loopback() {
                                    let ia = InferAddr {
                                        dst_addr,
                                        src_addr: src_ipv4.into(),
                                    };
                                    return Ok(Some(ia));
                                }
                            }
                            IpAddr::V6(src_ipv6) => {
                                if dst_addr.is_ipv6() && !src_ipv6.is_loopback() {
                                    let ia = InferAddr {
                                        dst_addr,
                                        src_addr: src_ipv6.into(),
                                    };
                                    return Ok(Some(ia));
                                }
                            }
                        }
                    }
                }
                None => {
                    // When the above methods do not work,
                    // try to find an IP address in the same subnet as the target address
                    // in the local interface as the source address.
                    for interface in interfaces() {
                        for ipn in interface.ips {
                            if ipn.contains(dst_addr) {
                                let src_addr = ipn.ip();
                                let ia = InferAddr { dst_addr, src_addr };
                                return Ok(Some(ia));
                            }
                        }
                    }
                    // Finally, if we really can't find the source address,
                    // transform it to the address in the same network segment as the default route.
                    if let Some(default_route) = get_default_route()? {
                        for interface in interfaces() {
                            for ipn in interface.ips {
                                if ipn.contains(default_route.via) {
                                    let src_addr = ipn.ip();
                                    let ia = InferAddr { dst_addr, src_addr };
                                    return Ok(Some(ia));
                                }
                            }
                        }
                    }
                }
            },
        }
    }
    Ok(None)
}

#[derive(Debug, Clone, Copy)]
pub struct Layer2Match {
    pub name: &'static str,
    pub src_mac: Option<MacAddr>,         // response packet src mac
    pub dst_mac: Option<MacAddr>,         // response packet dst mac
    pub ethernet_type: Option<EtherType>, // reponse packet ethernet type
}

impl Layer2Match {
    pub fn do_match(&self, ethernet_packet: &[u8]) -> bool {
        let ethernet_packet = match EthernetPacket::new(&ethernet_packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => return false,
        };
        match self.src_mac {
            Some(src_mac) => {
                if ethernet_packet.get_source() != src_mac {
                    return false; // early stop
                }
            }
            None => (), // wild match
        };

        match self.dst_mac {
            Some(dst_mac) => {
                if ethernet_packet.get_destination() != dst_mac {
                    return false;
                }
            }
            None => (),
        };
        match self.ethernet_type {
            Some(ethernet_type) => {
                if ethernet_type != ethernet_packet.get_ethertype() {
                    return false;
                }
            }
            None => (),
        };
        true
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Layer3Match {
    pub name: &'static str,
    pub layer2: Option<Layer2Match>,
    pub src_addr: Option<IpAddr>, // response packet
    pub dst_addr: Option<IpAddr>, // response packet
}

impl Layer3Match {
    pub fn do_match(&self, ethernet_packet: &[u8]) -> bool {
        let m1 = match &self.layer2 {
            Some(layers) => layers.do_match(ethernet_packet),
            None => true,
        };
        if !m1 {
            // early stop
            return false;
        }
        let ethernet_packet = match EthernetPacket::new(&ethernet_packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => return false,
        };
        match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4_packet = match Ipv4Packet::new(ethernet_packet.payload()) {
                    Some(i) => i,
                    None => return false,
                };
                match self.src_addr {
                    Some(src_addr) => match src_addr {
                        IpAddr::V4(src_ipv4) => {
                            if ipv4_packet.get_source() != src_ipv4 {
                                return false;
                            }
                        }
                        _ => return false,
                    },
                    None => (),
                }
                match self.dst_addr {
                    Some(dst_addr) => match dst_addr {
                        IpAddr::V4(dst_ipv4) => {
                            if ipv4_packet.get_destination() != dst_ipv4 {
                                return false;
                            }
                        }
                        _ => return false,
                    },
                    None => (),
                }
                true
            }
            EtherTypes::Ipv6 => {
                let ipv6_packet = match Ipv6Packet::new(ethernet_packet.payload()) {
                    Some(i) => i,
                    None => return false,
                };
                match self.src_addr {
                    Some(src_addr) => match src_addr {
                        IpAddr::V6(src_ipv6) => {
                            if ipv6_packet.get_source() != src_ipv6 {
                                return false;
                            }
                        }
                        _ => return false,
                    },
                    None => (),
                }
                match self.dst_addr {
                    Some(dst_addr) => match dst_addr {
                        IpAddr::V6(dst_ipv6) => {
                            if ipv6_packet.get_destination() != dst_ipv6 {
                                return false;
                            }
                        }
                        _ => return false,
                    },
                    None => (),
                }
                true
            }
            EtherTypes::Arp => {
                // ARP is on layer 2.5, but here we consider it as layer 3.
                let arp_packet = match ArpPacket::new(ethernet_packet.payload()) {
                    Some(a) => a,
                    None => return false,
                };
                match self.src_addr {
                    Some(src_addr) => match src_addr {
                        IpAddr::V4(src_ipv4) => {
                            if arp_packet.get_sender_proto_addr() != src_ipv4 {
                                return false;
                            }
                        }
                        _ => return false,
                    },
                    None => (),
                }
                match self.dst_addr {
                    Some(dst_addr) => match dst_addr {
                        IpAddr::V4(dst_ipv4) => {
                            if arp_packet.get_target_proto_addr() != dst_ipv4 {
                                return false;
                            }
                        }
                        _ => return false,
                    },
                    None => (),
                };
                true
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Layer4MatchTcpUdp {
    pub name: &'static str,
    pub layer3: Option<Layer3Match>,
    pub src_port: Option<u16>, // response tcp or udp packet src port
    pub dst_port: Option<u16>, // response tcp or udp packet dst port
}

/// for debug use, return (src_ip, dst_ip)
#[allow(dead_code)]
fn get_ip(ethernet_packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    let ethernet_packet = match EthernetPacket::new(&ethernet_packet) {
        Some(ethernet_packet) => ethernet_packet,
        None => return None,
    };

    match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4_packet = match Ipv4Packet::new(ethernet_packet.payload()) {
                Some(i) => i,
                None => return None,
            };
            Some((
                ipv4_packet.get_source().into(),
                ipv4_packet.get_destination().into(),
            ))
        }
        EtherTypes::Ipv6 => {
            let ipv6_packet = match Ipv6Packet::new(ethernet_packet.payload()) {
                Some(i) => i,
                None => return None,
            };
            Some((
                ipv6_packet.get_source().into(),
                ipv6_packet.get_destination().into(),
            ))
        }
        _ => None,
    }
}

impl Layer4MatchTcpUdp {
    pub fn do_match(&self, ethernet_packet: &[u8]) -> bool {
        // let mut is_debug = false;
        // if let Some((src_ip, dst_ip)) = get_ip(ethernet_packet) {
        //     let src_ipv4 = Ipv4Addr::new(192, 168, 1, 3);
        //     let dst_ipv4 = Ipv4Addr::new(192, 168, 5, 3);
        //     if src_ip == src_ipv4 && dst_ip == dst_ipv4 {
        //         is_debug = true;
        //     }
        // }

        let m1 = match &self.layer3 {
            Some(layer3) => layer3.do_match(ethernet_packet),
            None => true,
        };
        // if is_debug {
        //     println!("m1: {}", m1);
        // }
        if !m1 {
            // early stop
            return false;
        }
        let ethernet_packet = match EthernetPacket::new(&ethernet_packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => return false,
        };
        let (r_src_port, r_dst_port) = match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4_packet = match Ipv4Packet::new(ethernet_packet.payload()) {
                    Some(i) => i,
                    None => return false,
                };
                match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp_packet = match TcpPacket::new(ipv4_packet.payload()) {
                            Some(t) => t,
                            None => return false,
                        };
                        (tcp_packet.get_source(), tcp_packet.get_destination())
                    }
                    IpNextHeaderProtocols::Udp => {
                        let udp_packet = match UdpPacket::new(ipv4_packet.payload()) {
                            Some(t) => t,
                            None => return false,
                        };
                        (udp_packet.get_source(), udp_packet.get_destination())
                    }
                    _ => (0, 0),
                }
            }
            EtherTypes::Ipv6 => {
                let ipv6_packet = match Ipv6Packet::new(ethernet_packet.payload()) {
                    Some(i) => i,
                    None => return false,
                };
                match ipv6_packet.get_next_header() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp_packet = match TcpPacket::new(ipv6_packet.payload()) {
                            Some(t) => t,
                            None => return false,
                        };
                        (tcp_packet.get_source(), tcp_packet.get_destination())
                    }
                    IpNextHeaderProtocols::Udp => {
                        let udp_packet = match UdpPacket::new(ipv6_packet.payload()) {
                            Some(t) => t,
                            None => return false,
                        };
                        (udp_packet.get_source(), udp_packet.get_destination())
                    }
                    _ => (0, 0),
                }
            }
            _ => (0, 0),
        };
        // if is_debug {
        //     println!("read to match src port");
        // }
        match self.src_port {
            Some(src_port) => {
                if src_port != r_src_port {
                    return false;
                }
            }
            None => (),
        };
        // if is_debug {
        //     println!("src port pass");
        //     println!(
        //         "next dst_port: {:?}, r_dst_port: {}",
        //         self.dst_port, r_dst_port
        //     );
        // }
        match self.dst_port {
            Some(dst_port) => {
                if dst_port != r_dst_port {
                    return false;
                }
            }
            None => (),
        };
        // if is_debug {
        //     println!("dst port pass");
        // }
        true
    }
}

/// Matches network layer data in icmp payload
#[derive(Debug, Clone, Copy)]
pub struct PayloadMatchIp {
    pub src_addr: Option<IpAddr>, // response packet
    pub dst_addr: Option<IpAddr>, // response packet
}

impl PayloadMatchIp {
    /// When the icmp payload contains ipv4 data
    pub fn do_match_ipv4(&self, icmp_payload: &[u8]) -> bool {
        let ipv4_packet = match Ipv4Packet::new(icmp_payload) {
            Some(i) => i,
            None => return false,
        };
        match self.src_addr {
            Some(src_addr) => match src_addr {
                IpAddr::V4(src_ipv4) => {
                    if ipv4_packet.get_source() != src_ipv4 {
                        return false;
                    }
                }
                _ => return false,
            },
            None => (),
        }
        match self.dst_addr {
            Some(dst_addr) => match dst_addr {
                IpAddr::V4(dst_ipv4) => {
                    if ipv4_packet.get_destination() != dst_ipv4 {
                        return false;
                    }
                }
                _ => return false,
            },
            None => (),
        }
        true
    }
    /// When the icmp payload contains ipv6 data, and generally, icmpv6 is used at this time
    pub fn do_match_ipv6(&self, icmpv6_payload: &[u8]) -> bool {
        let ipv6_packet = match Ipv6Packet::new(icmpv6_payload) {
            Some(i) => i,
            None => return false,
        };
        match self.src_addr {
            Some(src_addr) => match src_addr {
                IpAddr::V6(src_ipv6) => {
                    if ipv6_packet.get_source() != src_ipv6 {
                        return false;
                    }
                }
                _ => return false,
            },
            None => (),
        };
        match self.dst_addr {
            Some(dst_addr) => match dst_addr {
                IpAddr::V6(dst_ipv6) => {
                    if ipv6_packet.get_destination() != dst_ipv6 {
                        return false;
                    }
                }
                _ => return false,
            },
            None => (),
        }
        true
    }
}

/// Matches the transport layer data in icmp payload
#[derive(Debug, Clone, Copy)]
pub struct PayloadMatchTcpUdp {
    pub layer3: Option<PayloadMatchIp>,
    pub src_port: Option<u16>, // response tcp or udp packet src port
    pub dst_port: Option<u16>, // response tcp or udp packet dst port
}

impl PayloadMatchTcpUdp {
    pub fn do_match_ipv4(&self, icmp_payload: &[u8]) -> bool {
        let m1 = match self.layer3 {
            Some(layer3) => layer3.do_match_ipv4(icmp_payload),
            None => true,
        };
        if !m1 {
            // early stop
            return false;
        }
        let ipv4_packet = match Ipv4Packet::new(icmp_payload) {
            Some(i) => i,
            None => return false,
        };
        let (r_src_port, r_dst_port) = match ipv4_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                let tcp_packet = match TcpPacket::new(ipv4_packet.payload()) {
                    Some(t) => t,
                    None => return false,
                };
                (tcp_packet.get_source(), tcp_packet.get_destination())
            }
            IpNextHeaderProtocols::Udp => {
                let udp_packet = match UdpPacket::new(ipv4_packet.payload()) {
                    Some(t) => t,
                    None => return false,
                };
                (udp_packet.get_source(), udp_packet.get_destination())
            }
            _ => (0, 0),
        };
        match self.src_port {
            Some(src_port) => {
                if src_port != r_src_port {
                    return false;
                }
            }
            None => (),
        }
        match self.dst_port {
            Some(dst_port) => {
                if dst_port != r_dst_port {
                    return false;
                }
            }
            None => (),
        }
        true
    }
    pub fn do_match_ipv6(&self, icmpv6_payload: &[u8]) -> bool {
        let m1 = match self.layer3 {
            Some(layer3) => layer3.do_match_ipv6(icmpv6_payload),
            None => true,
        };
        if !m1 {
            // ealry stop
            return false;
        }
        let ipv6_packet = match Ipv6Packet::new(icmpv6_payload) {
            Some(i) => i,
            None => return false,
        };
        let (r_src_port, r_dst_port) = match ipv6_packet.get_next_header() {
            IpNextHeaderProtocols::Tcp => {
                let tcp_packet = match TcpPacket::new(ipv6_packet.payload()) {
                    Some(t) => t,
                    None => return false,
                };
                (tcp_packet.get_source(), tcp_packet.get_destination())
            }
            IpNextHeaderProtocols::Udp => {
                let udp_packet = match UdpPacket::new(ipv6_packet.payload()) {
                    Some(t) => t,
                    None => return false,
                };
                (udp_packet.get_source(), udp_packet.get_destination())
            }
            _ => (0, 0),
        };
        match self.src_port {
            Some(src_port) => {
                if src_port != r_src_port {
                    return false;
                }
            }
            None => (),
        }
        match self.dst_port {
            Some(dst_port) => {
                if dst_port != r_dst_port {
                    return false;
                }
            }
            None => (),
        }
        true
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PayloadMatchIcmp {
    pub layer3: Option<PayloadMatchIp>,
    pub icmp_type: Option<IcmpType>, // response icmp packet types
    pub icmp_code: Option<IcmpCode>, // response icmp packet codes
}

impl PayloadMatchIcmp {
    pub fn do_match(&self, icmp_payload: &[u8]) -> bool {
        let m1 = match self.layer3 {
            Some(layer3) => layer3.do_match_ipv4(icmp_payload),
            None => true,
        };
        if !m1 {
            // early stop
            return false;
        }
        let ipv4_packet = match Ipv4Packet::new(icmp_payload) {
            Some(i) => i,
            None => return false,
        };
        let (r_type, r_code) = match ipv4_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Icmp => match IcmpPacket::new(ipv4_packet.payload()) {
                Some(t) => (t.get_icmp_type(), t.get_icmp_code()),
                None => return false,
            },
            _ => return false,
        };
        match self.icmp_type {
            Some(t) => {
                if t != r_type {
                    return false;
                }
            }
            None => (),
        }
        match self.icmp_code {
            Some(c) => {
                if c != r_code {
                    return false;
                }
            }
            None => (),
        }
        true
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PayloadMatchIcmpv6 {
    pub layer3: Option<PayloadMatchIp>,
    pub icmpv6_type: Option<Icmpv6Type>, // response icmp packet types
    pub icmpv6_code: Option<Icmpv6Code>, // response icmp packet codes
}

impl PayloadMatchIcmpv6 {
    pub fn do_match(&self, icmpv6_payload: &[u8]) -> bool {
        let m1 = match self.layer3 {
            Some(layer3) => layer3.do_match_ipv6(icmpv6_payload),
            None => true,
        };
        if !m1 {
            // early stop
            return false;
        }
        let ipv6_packet = match Ipv6Packet::new(icmpv6_payload) {
            Some(i) => i,
            None => return false,
        };
        let (r_types, r_codes) = match ipv6_packet.get_next_header() {
            IpNextHeaderProtocols::Icmpv6 => match Icmpv6Packet::new(ipv6_packet.payload()) {
                Some(t) => (t.get_icmpv6_type(), t.get_icmpv6_code()),
                None => return false,
            },
            _ => return false,
        };
        match self.icmpv6_type {
            Some(types) => {
                if types != r_types {
                    return false;
                }
            }
            None => (),
        }
        match self.icmpv6_code {
            Some(codes) => {
                if codes != r_codes {
                    return false;
                }
            }
            None => (),
        }
        true
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PayloadMatch {
    PayloadMatchIp(PayloadMatchIp),
    PayloadMatchTcpUdp(PayloadMatchTcpUdp),
    PayloadMatchIcmp(PayloadMatchIcmp),
    PayloadMatchIcmpv6(PayloadMatchIcmpv6),
}

/// Because when icmp returns raw data as icmp packet payload,
/// there is no indication whether it is ipv4 data or ipv6 data.
/// But generally speaking, if ipv4 data is sent, ipv4 will be returned,
/// and the same is true for ipv6, so users need to choose two different functions.
impl PayloadMatch {
    pub fn do_match_ipv4(&self, icmp_payload: &[u8]) -> bool {
        match self {
            PayloadMatch::PayloadMatchIp(ip) => ip.do_match_ipv4(icmp_payload),
            PayloadMatch::PayloadMatchTcpUdp(tcp_udp) => tcp_udp.do_match_ipv4(icmp_payload),
            PayloadMatch::PayloadMatchIcmp(icmp) => icmp.do_match(icmp_payload),
            PayloadMatch::PayloadMatchIcmpv6(_) => false,
        }
    }
    pub fn do_match_ipv6(&self, icmpv6_payload: &[u8]) -> bool {
        match self {
            PayloadMatch::PayloadMatchIp(ip) => ip.do_match_ipv6(icmpv6_payload),
            PayloadMatch::PayloadMatchTcpUdp(tcp_udp) => tcp_udp.do_match_ipv4(icmpv6_payload),
            PayloadMatch::PayloadMatchIcmpv6(icmpv6) => icmpv6.do_match(icmpv6_payload),
            PayloadMatch::PayloadMatchIcmp(_) => false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Layer4MatchIcmp {
    pub name: &'static str,
    pub layer3: Option<Layer3Match>,
    pub icmp_type: Option<IcmpType>,   // response icmp packet types
    pub icmp_code: Option<IcmpCode>,   // response icmp packet codes
    pub payload: Option<PayloadMatch>, // used to confirm which port the data packet is from
}

impl Layer4MatchIcmp {
    pub fn do_match(&self, ethernet_packet: &[u8]) -> bool {
        let m1 = match &self.layer3 {
            Some(layer3) => layer3.do_match(ethernet_packet),
            None => true,
        };
        if !m1 {
            // early stop
            return false;
        }
        let ethernet_packet = match EthernetPacket::new(&ethernet_packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => return false,
        };
        let (r_type, r_code, icmp_payload) = match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4_packet = match Ipv4Packet::new(ethernet_packet.payload()) {
                    Some(i) => i,
                    None => return false,
                };
                match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Icmp => match IcmpPacket::new(ipv4_packet.payload()) {
                        Some(icmp_packet) => (
                            icmp_packet.get_icmp_type(),
                            icmp_packet.get_icmp_code(),
                            get_icmp_payload(&icmp_packet),
                        ),
                        None => return false,
                    },
                    _ => return false,
                }
            }
            _ => return false,
        };
        match self.icmp_type {
            Some(t) => {
                if t != r_type {
                    return false;
                }
            }
            None => (),
        }
        match self.icmp_code {
            Some(c) => {
                if c != r_code {
                    return false;
                }
            }
            None => (),
        }
        match self.payload {
            Some(payload) => payload.do_match_ipv4(&icmp_payload),
            None => true,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Layer4MatchIcmpv6 {
    pub name: &'static str,
    pub layer3: Option<Layer3Match>,
    pub icmpv6_type: Option<Icmpv6Type>, // response icmp packet types
    pub icmpv6_code: Option<Icmpv6Code>, // response icmp packet codes
    pub payload: Option<PayloadMatch>,
}

impl Layer4MatchIcmpv6 {
    pub fn do_match(&self, ethernet_packet: &[u8]) -> bool {
        let m1 = match &self.layer3 {
            Some(layer3) => layer3.do_match(ethernet_packet),
            None => true,
        };
        if !m1 {
            // early stop
            return false;
        }

        let ethernet_packet = match EthernetPacket::new(&ethernet_packet) {
            Some(ethernet_packet) => ethernet_packet,
            None => return false,
        };
        let (r_type, r_code, icmpv6_payload) = match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv6 => {
                let ipv6_packet = match Ipv6Packet::new(ethernet_packet.payload()) {
                    Some(i) => i,
                    None => return false,
                };
                match ipv6_packet.get_next_header() {
                    IpNextHeaderProtocols::Icmpv6 => {
                        match Icmpv6Packet::new(ipv6_packet.payload()) {
                            Some(icmpv6_packet) => (
                                icmpv6_packet.get_icmpv6_type(),
                                icmpv6_packet.get_icmpv6_code(),
                                get_icmpv6_payload(&icmpv6_packet),
                            ),
                            None => return false,
                        }
                    }
                    _ => return false,
                }
            }
            _ => return false,
        };
        match self.icmpv6_type {
            Some(t) => {
                if t != r_type {
                    return false;
                }
            }
            None => (),
        }
        match self.icmpv6_code {
            Some(c) => {
                if c != r_code {
                    return false;
                }
            }
            None => (),
        };
        match self.payload {
            Some(payload) => payload.do_match_ipv6(&icmpv6_payload),
            None => true,
        }
    }
}

/// or rules
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum LayerMatch {
    Layer2Match(Layer2Match),
    Layer3Match(Layer3Match),
    Layer4MatchTcpUdp(Layer4MatchTcpUdp),
    Layer4MatchIcmp(Layer4MatchIcmp),
    Layer4MatchIcmpv6(Layer4MatchIcmpv6),
}

impl LayerMatch {
    pub fn do_match(&self, ethernet_packet: &[u8]) -> bool {
        if ethernet_packet.len() > 0 {
            match self {
                LayerMatch::Layer2Match(l2) => l2.do_match(ethernet_packet),
                LayerMatch::Layer3Match(l3) => l3.do_match(ethernet_packet),
                LayerMatch::Layer4MatchTcpUdp(tcp_udp) => tcp_udp.do_match(ethernet_packet),
                LayerMatch::Layer4MatchIcmp(icmp) => icmp.do_match(ethernet_packet),
                LayerMatch::Layer4MatchIcmpv6(icmpv6) => icmpv6.do_match(ethernet_packet),
            }
        } else {
            false
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            LayerMatch::Layer2Match(l2) => l2.name,
            LayerMatch::Layer3Match(l3) => l3.name,
            LayerMatch::Layer4MatchTcpUdp(tcp_udp) => tcp_udp.name,
            LayerMatch::Layer4MatchIcmp(icmp) => icmp.name,
            LayerMatch::Layer4MatchIcmpv6(icmpv6) => icmpv6.name,
        }
    }
}

/// Capture the traffic and save into file.
pub fn layer2_capture(packet: &[u8]) -> Result<(), PistolError> {
    let ppf = match PISTOL_PCAPNG_FLAG.lock() {
        Ok(ppf) => *ppf,
        Err(e) => {
            return Err(PistolError::TryLockGlobalVarFailed {
                var_name: String::from("PISTOL_PCAPNG_FLAG"),
                e: e.to_string(),
            });
        }
    };

    if ppf {
        match PISTOL_PCAPNG.lock() {
            Ok(mut pp) => {
                // interface_id = 0 means we use the first interface we builed in fake pcapng headers
                const INTERFACE_ID: u32 = 0;
                // this is the default value of pcapture
                const SNAPLEN: usize = 65535;
                match EnhancedPacketBlock::new(INTERFACE_ID, packet, SNAPLEN) {
                    Ok(block) => {
                        let gb = GeneralBlock::EnhancedPacketBlock(block);
                        pp.append(gb);
                    }
                    Err(e) => {
                        error!("build EnhancedPacketBlock in layer2_send() failed: {}", e)
                    }
                }
            }
            Err(e) => {
                return Err(PistolError::TryLockGlobalVarFailed {
                    var_name: String::from("PISTOL_PCAPNG"),
                    e: e.to_string(),
                });
            }
        }
    }
    Ok(())
}

/// This function only recvs data.
fn layer2_set_matchs(
    layer_matchs: Vec<LayerMatch>,
) -> Result<(Receiver<Vec<u8>>, PistolChannel), PistolError> {
    // let (tx: Sender<Vec<u8>>, rx: Receiver<Vec<PistolChannel>>) = channel();
    let (tx, rx) = channel();
    let pc = PistolChannel {
        uuid: Uuid::new_v4(),
        channel: tx,
        layer_matchs,
    };

    match UNIFIED_RECV_MATCHS.lock() {
        Ok(mut urm) => urm.push(pc.clone()),
        Err(e) => {
            return Err(PistolError::TryLockGlobalVarFailed {
                var_name: String::from("UNIFIED_RECV_MATCHS"),
                e: e.to_string(),
            });
        }
    }
    Ok((rx, pc))
}

fn layer2_rm_matchs(uuid: &Uuid) -> Result<bool, PistolError> {
    match UNIFIED_RECV_MATCHS.lock() {
        Ok(mut urm) => {
            let mut urm_clone = urm.clone();
            if let Some(index) = urm_clone.iter().position(|pc| pc.uuid == *uuid) {
                urm_clone.remove(index);
                *urm = urm_clone;
                Ok(true)
            } else {
                Ok(false)
            }
        }
        Err(e) => Err(PistolError::TryLockGlobalVarFailed {
            var_name: String::from("UNIFIED_RECV_MATCHS"),
            e: e.to_string(),
        }),
    }
}

fn layer2_recv(rx: Receiver<Vec<u8>>, timeout: Option<Duration>) -> Result<Vec<u8>, PistolError> {
    let timeout = match timeout {
        Some(t) => t,
        None => Duration::from_secs_f64(DEFAULT_TIMEOUT),
    };

    // only 1 packet will be recv from match threads
    let iter = rx.recv_timeout(timeout).into_iter().take(1);
    for ethernet_packet in iter {
        return Ok(ethernet_packet);
    }
    Ok(Vec::new())
}

/// This function only sends data.
fn layer2_send(
    dst_mac: MacAddr,
    interface: NetworkInterface,
    payload: &[u8],
    payload_len: usize,
    ethernet_type: EtherType,
    timeout: Option<Duration>,
) -> Result<(), PistolError> {
    let config = Config {
        write_buffer_size: ETHERNET_BUFF_SIZE,
        read_buffer_size: ETHERNET_BUFF_SIZE,
        read_timeout: timeout,
        write_timeout: timeout,
        channel_type: ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
        socket_fd: None,
    };

    let (mut sender, _) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(PistolError::CreateDatalinkChannelFailed),
        Err(e) => return Err(e.into()),
    };

    let src_mac = if dst_mac == MacAddr::zero() {
        MacAddr::zero()
    } else {
        match interface.mac {
            Some(m) => m,
            None => return Err(PistolError::CanNotFoundMacAddress),
        }
    };

    let ethernet_buff_len = ETHERNET_HEADER_SIZE + payload_len;
    // According to the document, the minimum length of an Ethernet data packet is 64 bytes
    // (14 bytes of header and at least 46 bytes of data and 4 bytes of FCS),
    // but I found through packet capture that nmap did not follow this convention,
    // so this padding is also cancelled here.
    // let ethernet_buff_len = if ethernet_buff_len < 60 {
    //     // padding before FCS
    //     60
    // } else {
    //     ethernet_buff_len
    // };
    let mut buff = vec![0u8; ethernet_buff_len];
    let mut ethernet_packet = match MutableEthernetPacket::new(&mut buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ethernet_packet.set_destination(dst_mac);
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(ethernet_type);
    ethernet_packet.set_payload(payload);
    layer2_capture(&buff)?;

    match sender.send_to(&buff, Some(interface)) {
        Some(r) => match r {
            Err(e) => return Err(e.into()),
            _ => Ok(()),
        },
        None => Ok(()),
    }
}

/// In order to prevent other threads from reading and discarding data packets
/// that do not belong to them during the multi-threaded multi-packet sending process,
/// and to improve the stability of the scan, I decided to put the reception of
/// all data packets into one thread.
pub fn layer2_work(
    dst_mac: MacAddr,
    interface: NetworkInterface,
    payload: &[u8],
    payload_len: usize,
    ethernet_type: EtherType,
    layer_matchs: Vec<LayerMatch>,
    timeout: Option<Duration>,
    need_return: bool,
) -> Result<(Vec<u8>, Duration), PistolError> {
    let running = match PISTOL_RUNNER_IS_RUNNING.lock() {
        Ok(r) => *r,
        Err(e) => {
            return Err(PistolError::TryLockGlobalVarFailed {
                var_name: String::from("PISTOL_RUNNER_IS_RUNNING"),
                e: e.to_string(),
            });
        }
    };

    if running {
        let start = Instant::now();
        if need_return {
            // set the matchs
            let (rx, pc) = layer2_set_matchs(layer_matchs)?;
            layer2_send(
                dst_mac,
                interface,
                payload,
                payload_len,
                ethernet_type,
                timeout,
            )?;
            let data = layer2_recv(rx, timeout)?;
            let rtt = start.elapsed();
            // we done here and remove the matchs
            if !layer2_rm_matchs(&pc.uuid)? {
                warn!("can not found and remove recv matchs");
            }
            Ok((data, rtt))
        } else {
            layer2_send(
                dst_mac,
                interface,
                payload,
                payload_len,
                ethernet_type,
                timeout,
            )?;
            let rtt = start.elapsed();

            Ok((Vec::new(), rtt))
        }
    } else {
        Err(PistolError::PistolRunnerIsNotRunning)
    }
}

pub fn layer3_ipv4_send(
    dst_ipv4: Ipv4Addr,
    src_ipv4: Ipv4Addr,
    ethernet_payload: &[u8],
    layer_matchs: Vec<LayerMatch>,
    timeout: Option<Duration>,
    need_return: bool,
) -> Result<(Vec<u8>, Duration), PistolError> {
    let (dst_mac, interface) =
        get_dst_mac_and_interface(dst_ipv4.into(), src_ipv4.into(), timeout)?;
    debug!(
        "dst: {}, src: {}, sending interface: {}, {:?}",
        dst_ipv4, src_ipv4, interface.name, interface.ips
    );
    let ethernet_type = EtherTypes::Ipv4;
    let payload_len = ethernet_payload.len();
    let (layer2_buff, rtt) = layer2_work(
        dst_mac,
        interface,
        ethernet_payload,
        payload_len,
        ethernet_type,
        layer_matchs,
        timeout,
        need_return,
    )?;
    Ok((layer2_payload(&layer2_buff), rtt))
}

pub fn multicast_mac(ip: Ipv6Addr) -> MacAddr {
    let ip = ip.octets();
    // 33:33:FF:xx:xx:xx
    MacAddr::new(0x33, 0x33, 0xFF, ip[13], ip[14], ip[15])
}

fn get_mac_from_ndp_rs(buff: &[u8]) -> Option<MacAddr> {
    // return mac address from ndp
    match EthernetPacket::new(buff) {
        Some(ethernet_packet) => {
            let mac = ethernet_packet.get_source();
            Some(mac)
        }
        None => None,
    }
}

fn ndp_rs(
    src_ipv6: Ipv6Addr,
    timeout: Option<Duration>,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    // router solicitation
    let route_addr_2 = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x0002);
    // let route_addr_1 = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x0001);
    let interface = match find_interface_by_src(src_ipv6.into()) {
        Some(i) => i,
        None => return Err(PistolError::CanNotFoundInterface),
    };
    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(PistolError::CanNotFoundMacAddress),
    };

    // ipv6
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + ICMPV6_RS_HEADER_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    ipv6_header.set_traffic_class(0);
    ipv6_header.set_flow_label(0);
    ipv6_header.set_payload_length(ICMPV6_RS_HEADER_SIZE as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Icmpv6);
    ipv6_header.set_hop_limit(255);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(route_addr_2);

    // icmpv6
    let mut icmpv6_header =
        match MutableRouterSolicitPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
            Some(p) => p,
            None => {
                return Err(PistolError::BuildPacketError {
                    location: format!("{}", Location::caller()),
                });
            }
        };
    // Neighbor Solicitation
    icmpv6_header.set_icmpv6_type(Icmpv6Type(133));
    icmpv6_header.set_icmpv6_code(Icmpv6Code(0));
    icmpv6_header.set_reserved(0);
    let ndp_option = NdpOption {
        option_type: NdpOptionTypes::SourceLLAddr,
        length: 1,
        data: src_mac.octets().to_vec(),
    };
    icmpv6_header.set_options(&vec![ndp_option]);

    let mut icmpv6_header = match MutableIcmpv6Packet::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    let checksum = icmpv6::checksum(&icmpv6_header.to_immutable(), &src_ipv6, &route_addr_2);
    icmpv6_header.set_checksum(checksum);

    // let layer3 = Layer3Match {
    //     layer2: None,
    //     src_addr: None,
    //     dst_addr: Some(route_addr_1.into()),
    // };
    let layer3 = Layer3Match {
        name: "ndp_ns layer3",
        layer2: None,
        src_addr: None,
        dst_addr: None,
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: None,
        dst_addr: None,
    };
    let payload_icmpv6 = PayloadMatchIcmpv6 {
        layer3: Some(payload_ip),
        icmpv6_type: Some(Icmpv6Types::RouterSolicit),
        icmpv6_code: None,
    };
    let payload = PayloadMatch::PayloadMatchIcmpv6(payload_icmpv6);
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        name: "ndp_ns icmpv6",
        layer3: Some(layer3),
        icmpv6_type: Some(Icmpv6Types::RouterAdvert), // Type: Router Advertisement (134)
        icmpv6_code: None,
        payload: Some(payload),
    };
    let layer_match = LayerMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    let dst_mac = MacAddr(33, 33, 00, 00, 00, 02);
    let ethernet_type = EtherTypes::Ipv6;
    let (r, rtt) = layer2_work(
        dst_mac,
        interface.clone(),
        &ipv6_buff,
        IPV6_HEADER_SIZE + ICMPV6_RS_HEADER_SIZE,
        ethernet_type,
        vec![layer_match],
        timeout,
        true,
    )?;

    let mac = get_mac_from_ndp_rs(&r);
    Ok((mac, rtt))
}

fn layer2_payload(buff: &[u8]) -> Vec<u8> {
    match EthernetPacket::new(buff) {
        Some(ethernet_packet) => ethernet_packet.payload().to_vec(),
        None => Vec::new(),
    }
}

pub fn layer3_ipv6_send(
    dst_ipv6: Ipv6Addr,
    src_ipv6: Ipv6Addr,
    payload: &[u8],
    layer_matchs: Vec<LayerMatch>,
    timeout: Option<Duration>,
    need_return: bool,
) -> Result<(Vec<u8>, Duration), PistolError> {
    let dst_ipv6 = if dst_ipv6.is_loopback() {
        src_ipv6
    } else {
        dst_ipv6
    };
    let (dst_mac, interface) =
        get_dst_mac_and_interface(dst_ipv6.into(), src_ipv6.into(), timeout)?;

    let ethernet_type = EtherTypes::Ipv6;
    let payload_len = payload.len();
    let (layer2_buff, rtt) = layer2_work(
        dst_mac,
        interface,
        payload,
        payload_len,
        ethernet_type,
        layer_matchs,
        timeout,
        need_return,
    )?;
    Ok((layer2_payload(&layer2_buff), rtt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PistolLogger;
    use crate::PistolRunner;
    use pnet::packet::icmp::IcmpTypes;
    use std::str::FromStr;
    #[test]
    fn test_infer_addr() {
        let _pr = PistolRunner::init(
            PistolLogger::Debug,
            None,
            None, // use default value
        )
        .unwrap();
        let dst_ipv4 = Ipv4Addr::new(192, 168, 5, 129);
        let ia = infer_addr(dst_ipv4.into(), None).unwrap();
        if let Some(ia) = ia {
            let timeout = Some(Duration::from_secs_f64(1.0));
            let (_mac, interface) =
                get_dst_mac_and_interface(ia.dst_addr, ia.src_addr, timeout).unwrap();
            println!("{}", interface.name);
        }
        println!("{:?}", ia);
    }
    #[test]
    fn test_layer_match() {
        let data: Vec<u8> = vec![
            0x0, 0xc, 0x29, 0x5b, 0xbd, 0x5c, 0x0, 0xc, 0x29, 0x2c, 0x9, 0xe4, 0x8, 0x0, 0x45,
            0xc0, 0x0, 0x38, 0x1, 0xcd, 0x0, 0x0, 0x40, 0x1, 0xec, 0xdf, 0xc0, 0xa8, 0x5, 0x5,
            0xc0, 0xa8, 0x5, 0x3, 0x3, 0x3, 0x88, 0x6f, 0x0, 0x0, 0x0, 0x0, 0x45, 0x0, 0x0, 0x1c,
            0x81, 0x56, 0x40, 0x0, 0x40, 0x11, 0x2e, 0x22, 0xc0, 0xa8, 0x5, 0x3, 0xc0, 0xa8, 0x5,
            0x5, 0x73, 0xa, 0x1f, 0x90, 0x0, 0x8, 0xe1, 0xea,
        ];
        let dst_ipv4 = Ipv4Addr::new(192, 168, 5, 5);
        let src_ipv4 = Ipv4Addr::new(192, 168, 5, 3);
        let dst_port = 8080;
        let src_port = 29450;
        let layer3 = Layer3Match {
            name: "test layer3",
            layer2: None,
            src_addr: Some(dst_ipv4.into()),
            dst_addr: Some(src_ipv4.into()),
        };
        let payload_ip = PayloadMatchIp {
            src_addr: Some(src_ipv4.into()),
            dst_addr: Some(dst_ipv4.into()),
        };
        let payload_tcp_udp = PayloadMatchTcpUdp {
            layer3: Some(payload_ip),
            src_port: Some(src_port),
            dst_port: Some(dst_port),
        };
        let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcp_udp);
        let layer4_icmp = Layer4MatchIcmp {
            name: "test icmp",
            layer3: Some(layer3),
            icmp_type: None,
            icmp_code: None,
            payload: Some(payload),
        };
        let layer_match = LayerMatch::Layer4MatchIcmp(layer4_icmp);
        let x = layer_match.do_match(&data);
        println!("match ret: {}", x);
    }
    #[test]
    fn test_layer_match2() {
        let data = vec![
            0x0, 0xc, 0x29, 0x5b, 0xbd, 0x5c, 0x0, 0xc, 0x29, 0x2c, 0x9, 0xe4, 0x86, 0xdd, 0x60,
            0x0, 0x0, 0x0, 0x0, 0x20, 0x3a, 0xff, 0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2,
            0xc, 0x29, 0xff, 0xfe, 0x2c, 0x9, 0xe4, 0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2,
            0xc, 0x29, 0xff, 0xfe, 0x5b, 0xbd, 0x5c, 0x88, 0x0, 0x97, 0x8, 0x60, 0x0, 0x0, 0x0,
            0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xc, 0x29, 0xff, 0xfe, 0x2c, 0x9, 0xe4,
            0x2, 0x1, 0x0, 0xc, 0x29, 0x2c, 0x9, 0xe4,
        ];
        let dst_ipv6 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e4").unwrap();
        let src_ipv6 = Ipv6Addr::from_str("fe80::20c:29ff:fe5b:bd5c").unwrap();
        let layer3 = Layer3Match {
            name: "test layer3",
            layer2: None,
            src_addr: Some(dst_ipv6.into()),
            dst_addr: Some(src_ipv6.into()),
        };
        let layer4_icmpv6 = Layer4MatchIcmpv6 {
            name: "test icmpv6",
            layer3: Some(layer3),
            icmpv6_type: Some(Icmpv6Types::NeighborAdvert),
            icmpv6_code: None,
            payload: None,
        };
        let layer_match = LayerMatch::Layer4MatchIcmpv6(layer4_icmpv6);
        let x = layer_match.do_match(&data);
        println!("match ret: {}", x);
    }
    #[test]
    fn test_layer_match3() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 5, 3);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 3);
        let src_port = 45982;
        let dst_port = 33434;
        let layer3 = Layer3Match {
            name: "test layer3",
            layer2: None,
            src_addr: None,
            dst_addr: Some(src_ipv4.into()),
        };
        // set the icmp payload matchs
        let payload_ip = PayloadMatchIp {
            src_addr: Some(src_ipv4.into()),
            dst_addr: Some(dst_ipv4.into()),
        };
        let payload_tcp_udp = PayloadMatchTcpUdp {
            layer3: Some(payload_ip),
            src_port: Some(src_port),
            dst_port: Some(dst_port),
        };
        let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcp_udp);
        let layer4_icmp = Layer4MatchIcmp {
            name: "test icmp",
            layer3: Some(layer3),
            icmp_type: Some(IcmpTypes::TimeExceeded),
            icmp_code: None,
            payload: Some(payload),
        };
        let layer_match_icmp_time_exceeded = LayerMatch::Layer4MatchIcmp(layer4_icmp);

        let data = vec![
            0x0, 0xc, 0x29, 0x5b, 0xbd, 0x5c, 0x0, 0x50, 0x56, 0xff, 0xa6, 0x97, 0x8, 0x0, 0x45,
            0x0, 0x0, 0x58, 0xe, 0x7f, 0x0, 0x0, 0x80, 0x1, 0xa0, 0xd0, 0xc0, 0xa8, 0x5, 0x2, 0xc0,
            0xa8, 0x5, 0x3, 0xb, 0x0, 0x7c, 0x90, 0x0, 0x0, 0x0, 0x0, 0x45, 0x0, 0x0, 0x3c, 0x9b,
            0x2f, 0x40, 0x0, 0x1, 0x11, 0x57, 0x2b, 0xc0, 0xa8, 0x5, 0x3, 0xc0, 0xa8, 0x1, 0x3,
            0xb3, 0x9e, 0x82, 0x9a, 0x0, 0x28, 0x4d, 0x9, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
            0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
            0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        ];

        let ret = layer_match_icmp_time_exceeded.do_match(&data);
        println!("{}", ret);
    }
    #[test]
    fn test_layer_match4() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 5, 3);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 3);
        let src_port = 59470;
        let dst_port = 80;

        let layer3 = Layer3Match {
            name: "test layer3",
            layer2: None,
            src_addr: None, // usually this is the address of the router, not the address of the target machine.
            dst_addr: Some(src_ipv4.into()),
        };
        let payload_ip = PayloadMatchIp {
            src_addr: Some(src_ipv4.into()),
            dst_addr: Some(dst_ipv4.into()),
        };
        let payload_tcp_udp = PayloadMatchTcpUdp {
            layer3: Some(payload_ip),
            src_port: Some(src_port),
            dst_port: Some(dst_port),
        };
        let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcp_udp);
        let layer4_icmp = Layer4MatchIcmp {
            name: "test icmp",
            layer3: Some(layer3),
            icmp_type: Some(IcmpTypes::TimeExceeded),
            icmp_code: None,
            payload: Some(payload),
        };
        let layer_match_icmp_time_exceeded = LayerMatch::Layer4MatchIcmp(layer4_icmp);

        let data = vec![
            0x0, 0xc, 0x29, 0x5b, 0xbd, 0x5c, 0x0, 0x50, 0x56, 0xff, 0xa6, 0x97, 0x8, 0x0, 0x45,
            0x0, 0x0, 0x58, 0x7, 0x5e, 0x0, 0x0, 0x80, 0x1, 0xa7, 0xf1, 0xc0, 0xa8, 0x5, 0x2, 0xc0,
            0xa8, 0x5, 0x3, 0xb, 0x0, 0x7c, 0x85, 0x0, 0x0, 0x0, 0x0, 0x45, 0x0, 0x0, 0x3c, 0x8a,
            0x1f, 0x40, 0x0, 0x1, 0x6, 0x68, 0x46, 0xc0, 0xa8, 0x5, 0x3, 0xc0, 0xa8, 0x1, 0x3,
            0xe8, 0x4e, 0x0, 0x50, 0xb9, 0xc5, 0x70, 0x4a, 0x0, 0x0, 0x0, 0x0, 0xa0, 0x2, 0x16,
            0xd0, 0xf2, 0x92, 0x0, 0x0, 0x2, 0x4, 0x5, 0xb4, 0x4, 0x2, 0x8, 0xa, 0x78, 0x46, 0x2c,
            0x56, 0x0, 0x0, 0x0, 0x0, 0x1, 0x3, 0x3, 0x2,
        ];

        let ret = layer_match_icmp_time_exceeded.do_match(&data);
        println!("{}", ret);
    }
    #[test]
    fn test_layer_match5() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 5, 3);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 3);
        let src_port = 26845;
        let dst_port = 80;

        let layer3 = Layer3Match {
            name: "test layer3",
            layer2: None,
            src_addr: Some(dst_ipv4.into()),
            dst_addr: Some(src_ipv4.into()),
        };
        let layer4_tcp_udp = Layer4MatchTcpUdp {
            name: "test tcp_udp",
            layer3: Some(layer3),
            src_port: Some(dst_port),
            dst_port: Some(src_port),
        };
        let layer_match_tcp = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);

        let data = [
            0x0, 0xc, 0x29, 0x5b, 0xbd, 0x5c, 0x0, 0x50, 0x56, 0xff, 0xa6, 0x97, 0x8, 0x0, 0x45,
            0x0, 0x0, 0x28, 0xd, 0x83, 0x0, 0x0, 0x80, 0x6, 0xa5, 0xf6, 0xc0, 0xa8, 0x1, 0x3, 0xc0,
            0xa8, 0x5, 0x3, 0x0, 0x50, 0x68, 0xdd, 0x48, 0xc4, 0x1, 0xc5, 0xbf, 0x34, 0xcb, 0x88,
            0x50, 0x14, 0xfa, 0xf0, 0xef, 0x14, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];

        let ret = layer_match_tcp.do_match(&data);
        println!("{}", ret);
    }
    #[test]
    fn test_layer2_send() {
        let config = Config {
            write_buffer_size: ETHERNET_BUFF_SIZE,
            read_buffer_size: ETHERNET_BUFF_SIZE,
            read_timeout: Some(Duration::new(1, 0)),
            write_timeout: Some(Duration::new(1, 0)),
            channel_type: ChannelType::Layer2,
            bpf_fd_attempts: 1000,
            linux_fanout: None,
            promiscuous: false,
            socket_fd: None,
        };

        // let dst_ipv4 = Ipv4Addr::new(192, 168, 5, 5);
        let src_ipv4 = Ipv4Addr::new(192, 168, 5, 3);
        let interface = find_interface_by_src(src_ipv4.into()).unwrap();

        let (mut sender, _) = match datalink::channel(&interface, config) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            _ => panic!("create datalink channel failed"),
        };

        // let data: Vec<u8> = vec![
        //     0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x0, 0x45, 0x0, 0x0,
        //     0x3c, 0x84, 0x7c, 0x40, 0x0, 0x40, 0x6, 0xb8, 0x3d, 0x7f, 0x0, 0x0, 0x1, 0x7f, 0x0,
        //     0x0, 0x1, 0xbb, 0xee, 0x0, 0x50, 0xe4, 0xdf, 0xeb, 0x16, 0x0, 0x0, 0x0, 0x0, 0xa0, 0x2,
        //     0xff, 0xd7, 0xfe, 0x30, 0x0, 0x0, 0x2, 0x4, 0xff, 0xd7, 0x4, 0x2, 0x8, 0xa, 0xd4, 0xb8,
        //     0xfd, 0x6, 0x0, 0x0, 0x0, 0x0, 0x1, 0x3, 0x3, 0x7,
        // ];
        let data: Vec<u8> = vec![
            0x0, 0xc, 0x29, 0x2c, 0x9, 0xe4, 0x0, 0xc, 0x29, 0x5b, 0xbd, 0x5c, 0x8, 0x0, 0x45, 0x0,
            0x0, 0x28, 0x40, 0xaa, 0x0, 0x0, 0x3a, 0x6, 0xb4, 0xcd, 0xc0, 0xa8, 0x5, 0x3, 0xc0,
            0xa8, 0x5, 0x5, 0xc7, 0xec, 0x0, 0x50, 0x0, 0x0, 0x0, 0x0, 0x99, 0xb7, 0x60, 0xf6,
            0x50, 0x10, 0x4, 0x0, 0x5d, 0x91, 0x0, 0x0,
        ];
        let _ = sender.send_to(&data, Some(interface)).unwrap();
    }
}
