use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::datalink::interfaces;
use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::EtherType;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmp::IcmpCode;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpType;
use pnet::packet::icmpv6::Icmpv6Code;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmpv6::Icmpv6Type;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::net::IpAddr;
use std::net::Ipv6Addr;

pub(crate) const ETHERNET_HEADER_SIZE: usize = 14;
pub(crate) const ARP_HEADER_SIZE: usize = 28;
pub(crate) const IPV4_HEADER_SIZE: usize = 20;
pub(crate) const IPV6_HEADER_SIZE: usize = 40;
pub(crate) const TCP_HEADER_SIZE: usize = 20;
pub(crate) const UDP_HEADER_SIZE: usize = 8;
pub(crate) const ICMP_HEADER_SIZE: usize = 8;
// big enough to store all data
pub(crate) const ETHERNET_BUFF_SIZE: usize = 4096;

pub(crate) const ICMPV6_NS_HEADER_SIZE: usize = 32;
pub(crate) const ICMPV6_RS_HEADER_SIZE: usize = 16;
// pub(crate) const ICMPV6_NA_HEADER_SIZE: usize = 32;
pub(crate) const ICMPV6_ER_HEADER_SIZE: usize = 8;
pub(crate) const ICMPV6_NI_HEADER_SIZE: usize = 32;

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

pub(crate) fn find_interface_by_index(if_index: u32) -> Option<NetworkInterface> {
    for interface in interfaces() {
        if if_index == interface.index {
            return Some(interface);
        }
    }
    None
}

/// Use source IP address to find local interface
pub(crate) fn find_interface_by_src_ip(src_addr: IpAddr) -> Option<NetworkInterface> {
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

pub(crate) fn find_interface_by_dst_ip(dst_addr: IpAddr) -> Option<NetworkInterface> {
    for interface in interfaces() {
        for ip in &interface.ips {
            // check if dst_addr is in the same subnet as i
            if ip.contains(dst_addr) {
                return Some(interface);
            }
        }
    }
    None
}

pub(crate) fn find_interface_by_name(name: &str) -> Option<NetworkInterface> {
    for interface in interfaces() {
        if name == interface.name {
            return Some(interface);
        }
    }
    None
}

#[derive(Debug, Clone)]
pub(crate) struct Layer2Filter {
    pub(crate) name: String,
    pub(crate) src_mac: Option<MacAddr>, // response packet src mac
    pub(crate) dst_mac: Option<MacAddr>, // response packet dst mac
    pub(crate) ether_type: Option<EtherType>, // reponse packet ethernet type
}

impl Layer2Filter {
    pub(crate) fn check(&self, ethernet_packet: &[u8]) -> bool {
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
        match self.ether_type {
            Some(ether_type) => {
                if ether_type != ethernet_packet.get_ethertype() {
                    return false;
                }
            }
            None => (),
        };
        true
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Layer3Filter {
    pub name: String,
    pub layer2: Option<Layer2Filter>,
    pub src_addr: Option<IpAddr>, // response packet
    pub dst_addr: Option<IpAddr>, // response packet
}

impl Layer3Filter {
    pub(crate) fn check(&self, ethernet_packet: &[u8]) -> bool {
        let m1 = match &self.layer2 {
            Some(layers) => layers.check(ethernet_packet),
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

#[derive(Debug, Clone)]
pub(crate) struct Layer4FilterTcpUdp {
    pub(crate) name: String,
    pub(crate) layer3: Option<Layer3Filter>,
    pub(crate) src_port: Option<u16>, // response tcp or udp packet src port
    pub(crate) dst_port: Option<u16>, // response tcp or udp packet dst port
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

impl Layer4FilterTcpUdp {
    pub(crate) fn check(&self, ethernet_packet: &[u8]) -> bool {
        // let mut is_debug = false;
        // if let Some((src_ip, dst_ip)) = get_ip(ethernet_packet) {
        //     let src_ipv4 = Ipv4Addr::new(192, 168, 1, 3);
        //     let dst_ipv4 = Ipv4Addr::new(192, 168, 5, 3);
        //     if src_ip == src_ipv4 && dst_ip == dst_ipv4 {
        //         is_debug = true;
        //     }
        // }

        let m1 = match &self.layer3 {
            Some(layer3) => layer3.check(ethernet_packet),
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
pub(crate) struct PayloadMatchIp {
    pub(crate) src_addr: Option<IpAddr>, // response packet
    pub(crate) dst_addr: Option<IpAddr>, // response packet
}

impl PayloadMatchIp {
    /// When the icmp payload contains ipv4 data
    pub(crate) fn do_match_ipv4(&self, icmp_payload: &[u8]) -> bool {
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
    pub(crate) fn do_match_ipv6(&self, icmpv6_payload: &[u8]) -> bool {
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
pub(crate) struct PayloadMatchTcpUdp {
    pub(crate) layer3: Option<PayloadMatchIp>,
    pub(crate) src_port: Option<u16>, // response tcp or udp packet src port
    pub(crate) dst_port: Option<u16>, // response tcp or udp packet dst port
}

impl PayloadMatchTcpUdp {
    pub(crate) fn do_match_ipv4(&self, icmp_payload: &[u8]) -> bool {
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
    pub(crate) fn do_match_ipv6(&self, icmpv6_payload: &[u8]) -> bool {
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
pub(crate) struct PayloadMatchIcmp {
    pub(crate) layer3: Option<PayloadMatchIp>,
    pub(crate) icmp_type: Option<IcmpType>, // response icmp packet types
    pub(crate) icmp_code: Option<IcmpCode>, // response icmp packet codes
}

impl PayloadMatchIcmp {
    pub(crate) fn do_match(&self, icmp_payload: &[u8]) -> bool {
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
pub(crate) struct PayloadMatchIcmpv6 {
    pub(crate) layer3: Option<PayloadMatchIp>,
    pub(crate) icmpv6_type: Option<Icmpv6Type>, // response icmp packet types
    pub(crate) icmpv6_code: Option<Icmpv6Code>, // response icmp packet codes
}

impl PayloadMatchIcmpv6 {
    pub(crate) fn do_match(&self, icmpv6_payload: &[u8]) -> bool {
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
pub(crate) enum PayloadMatch {
    // PayloadMatchIp(PayloadMatchIp),
    PayloadMatchTcpUdp(PayloadMatchTcpUdp),
    PayloadMatchIcmp(PayloadMatchIcmp),
    PayloadMatchIcmpv6(PayloadMatchIcmpv6),
}

/// Because when icmp returns raw data as icmp packet payload,
/// there is no indication whether it is ipv4 data or ipv6 data.
/// But generally speaking, if ipv4 data is sent, ipv4 will be returned,
/// and the same is true for ipv6, so users need to choose two different functions.
impl PayloadMatch {
    pub(crate) fn do_match_ipv4(&self, icmp_payload: &[u8]) -> bool {
        match self {
            // PayloadMatch::PayloadMatchIp(ip) => ip.do_match_ipv4(icmp_payload),
            PayloadMatch::PayloadMatchTcpUdp(tcp_udp) => tcp_udp.do_match_ipv4(icmp_payload),
            PayloadMatch::PayloadMatchIcmp(icmp) => icmp.do_match(icmp_payload),
            PayloadMatch::PayloadMatchIcmpv6(_) => false,
        }
    }
    pub(crate) fn do_match_ipv6(&self, icmpv6_payload: &[u8]) -> bool {
        match self {
            // PayloadMatch::PayloadMatchIp(ip) => ip.do_match_ipv6(icmpv6_payload),
            PayloadMatch::PayloadMatchTcpUdp(tcp_udp) => tcp_udp.do_match_ipv6(icmpv6_payload),
            PayloadMatch::PayloadMatchIcmpv6(icmpv6) => icmpv6.do_match(icmpv6_payload),
            PayloadMatch::PayloadMatchIcmp(_) => false,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Layer4FilterIcmp {
    pub(crate) name: String,
    pub(crate) layer3: Option<Layer3Filter>,
    pub(crate) icmp_type: Option<IcmpType>, // response icmp packet types
    pub(crate) icmp_code: Option<IcmpCode>, // response icmp packet codes
    pub(crate) payload: Option<PayloadMatch>, // used to confirm which port the data packet is from
}

impl Layer4FilterIcmp {
    pub(crate) fn check(&self, ethernet_packet: &[u8]) -> bool {
        let m1 = match &self.layer3 {
            Some(layer3) => layer3.check(ethernet_packet),
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

#[derive(Debug, Clone)]
pub(crate) struct Layer4FilterIcmpv6 {
    pub(crate) name: String,
    pub(crate) layer3: Option<Layer3Filter>,
    pub(crate) icmpv6_type: Option<Icmpv6Type>, // response icmp packet types
    pub(crate) icmpv6_code: Option<Icmpv6Code>, // response icmp packet codes
    pub(crate) payload: Option<PayloadMatch>,
}

impl Layer4FilterIcmpv6 {
    pub(crate) fn check(&self, ethernet_packet: &[u8]) -> bool {
        let m1 = match &self.layer3 {
            Some(layer3) => layer3.check(ethernet_packet),
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
#[derive(Debug, Clone)]
pub(crate) enum PacketFilter {
    Layer2Filter(Layer2Filter),
    Layer3Filter(Layer3Filter),
    Layer4FilterTcpUdp(Layer4FilterTcpUdp),
    Layer4FilterIcmp(Layer4FilterIcmp),
    Layer4FilterIcmpv6(Layer4FilterIcmpv6),
}

impl PacketFilter {
    pub(crate) fn check(&self, ethernet_packet: &[u8]) -> bool {
        if ethernet_packet.len() > 0 {
            match self {
                PacketFilter::Layer2Filter(l2) => l2.check(ethernet_packet),
                PacketFilter::Layer3Filter(l3) => l3.check(ethernet_packet),
                PacketFilter::Layer4FilterTcpUdp(tcp_udp) => tcp_udp.check(ethernet_packet),
                PacketFilter::Layer4FilterIcmp(icmp) => icmp.check(ethernet_packet),
                PacketFilter::Layer4FilterIcmpv6(icmpv6) => icmpv6.check(ethernet_packet),
            }
        } else {
            false
        }
    }
    pub(crate) fn name(&self) -> String {
        match self {
            PacketFilter::Layer2Filter(l2) => l2.name.clone(),
            PacketFilter::Layer3Filter(l3) => l3.name.clone(),
            PacketFilter::Layer4FilterTcpUdp(tcp_udp) => tcp_udp.name.clone(),
            PacketFilter::Layer4FilterIcmp(icmp) => icmp.name.clone(),
            PacketFilter::Layer4FilterIcmpv6(icmpv6) => icmpv6.name.clone(),
        }
    }
}

pub(crate) fn multicast_mac(ip: Ipv6Addr) -> MacAddr {
    let ip = ip.octets();
    // 33:33:FF:xx:xx:xx
    MacAddr::new(0x33, 0x33, 0xFF, ip[13], ip[14], ip[15])
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::datalink;
    use pnet::packet::icmp::IcmpTypes;
    use pnet::packet::icmpv6::Icmpv6Types;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::time::Duration;
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
        let layer3 = Layer3Filter {
            name: "test layer3".to_string().to_string(),
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
        let layer4_icmp = Layer4FilterIcmp {
            name: "test icmp".to_string().to_string(),
            layer3: Some(layer3),
            icmp_type: None,
            icmp_code: None,
            payload: Some(payload),
        };
        let layer_match = PacketFilter::Layer4FilterIcmp(layer4_icmp);
        let x = layer_match.check(&data);
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
        let layer3 = Layer3Filter {
            name: "test layer3".to_string().to_string(),
            layer2: None,
            src_addr: Some(dst_ipv6.into()),
            dst_addr: Some(src_ipv6.into()),
        };
        let layer4_icmpv6 = Layer4FilterIcmpv6 {
            name: "test icmpv6".to_string().to_string(),
            layer3: Some(layer3),
            icmpv6_type: Some(Icmpv6Types::NeighborAdvert),
            icmpv6_code: None,
            payload: None,
        };
        let layer_match = PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6);
        let x = layer_match.check(&data);
        println!("match ret: {}", x);
    }
    #[test]
    fn test_layer_match3() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 5, 3);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 3);
        let src_port = 45982;
        let dst_port = 33434;
        let layer3 = Layer3Filter {
            name: "test layer3".to_string().to_string(),
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
        let layer4_icmp = Layer4FilterIcmp {
            name: "test icmp".to_string().to_string(),
            layer3: Some(layer3),
            icmp_type: Some(IcmpTypes::TimeExceeded),
            icmp_code: None,
            payload: Some(payload),
        };
        let layer_match_icmp_time_exceeded = PacketFilter::Layer4FilterIcmp(layer4_icmp);

        let data = vec![
            0x0, 0xc, 0x29, 0x5b, 0xbd, 0x5c, 0x0, 0x50, 0x56, 0xff, 0xa6, 0x97, 0x8, 0x0, 0x45,
            0x0, 0x0, 0x58, 0xe, 0x7f, 0x0, 0x0, 0x80, 0x1, 0xa0, 0xd0, 0xc0, 0xa8, 0x5, 0x2, 0xc0,
            0xa8, 0x5, 0x3, 0xb, 0x0, 0x7c, 0x90, 0x0, 0x0, 0x0, 0x0, 0x45, 0x0, 0x0, 0x3c, 0x9b,
            0x2f, 0x40, 0x0, 0x1, 0x11, 0x57, 0x2b, 0xc0, 0xa8, 0x5, 0x3, 0xc0, 0xa8, 0x1, 0x3,
            0xb3, 0x9e, 0x82, 0x9a, 0x0, 0x28, 0x4d, 0x9, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
            0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
            0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        ];

        let ret = layer_match_icmp_time_exceeded.check(&data);
        println!("{}", ret);
    }
    #[test]
    fn test_layer_match4() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 5, 3);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 3);
        let src_port = 59470;
        let dst_port = 80;

        let layer3 = Layer3Filter {
            name: "test layer3".to_string().to_string(),
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
        let layer4_icmp = Layer4FilterIcmp {
            name: "test icmp".to_string().to_string(),
            layer3: Some(layer3),
            icmp_type: Some(IcmpTypes::TimeExceeded),
            icmp_code: None,
            payload: Some(payload),
        };
        let layer_match_icmp_time_exceeded = PacketFilter::Layer4FilterIcmp(layer4_icmp);

        let data = vec![
            0x0, 0xc, 0x29, 0x5b, 0xbd, 0x5c, 0x0, 0x50, 0x56, 0xff, 0xa6, 0x97, 0x8, 0x0, 0x45,
            0x0, 0x0, 0x58, 0x7, 0x5e, 0x0, 0x0, 0x80, 0x1, 0xa7, 0xf1, 0xc0, 0xa8, 0x5, 0x2, 0xc0,
            0xa8, 0x5, 0x3, 0xb, 0x0, 0x7c, 0x85, 0x0, 0x0, 0x0, 0x0, 0x45, 0x0, 0x0, 0x3c, 0x8a,
            0x1f, 0x40, 0x0, 0x1, 0x6, 0x68, 0x46, 0xc0, 0xa8, 0x5, 0x3, 0xc0, 0xa8, 0x1, 0x3,
            0xe8, 0x4e, 0x0, 0x50, 0xb9, 0xc5, 0x70, 0x4a, 0x0, 0x0, 0x0, 0x0, 0xa0, 0x2, 0x16,
            0xd0, 0xf2, 0x92, 0x0, 0x0, 0x2, 0x4, 0x5, 0xb4, 0x4, 0x2, 0x8, 0xa, 0x78, 0x46, 0x2c,
            0x56, 0x0, 0x0, 0x0, 0x0, 0x1, 0x3, 0x3, 0x2,
        ];

        let ret = layer_match_icmp_time_exceeded.check(&data);
        println!("{}", ret);
    }
    #[test]
    fn test_layer_match5() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 5, 3);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 3);
        let src_port = 26845;
        let dst_port = 80;

        let layer3 = Layer3Filter {
            name: "test layer3".to_string().to_string(),
            layer2: None,
            src_addr: Some(dst_ipv4.into()),
            dst_addr: Some(src_ipv4.into()),
        };
        let layer4_tcp_udp = Layer4FilterTcpUdp {
            name: "test tcp_udp".to_string().to_string(),
            layer3: Some(layer3),
            src_port: Some(dst_port),
            dst_port: Some(src_port),
        };
        let layer_match_tcp = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);

        let data = [
            0x0, 0xc, 0x29, 0x5b, 0xbd, 0x5c, 0x0, 0x50, 0x56, 0xff, 0xa6, 0x97, 0x8, 0x0, 0x45,
            0x0, 0x0, 0x28, 0xd, 0x83, 0x0, 0x0, 0x80, 0x6, 0xa5, 0xf6, 0xc0, 0xa8, 0x1, 0x3, 0xc0,
            0xa8, 0x5, 0x3, 0x0, 0x50, 0x68, 0xdd, 0x48, 0xc4, 0x1, 0xc5, 0xbf, 0x34, 0xcb, 0x88,
            0x50, 0x14, 0xfa, 0xf0, 0xef, 0x14, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];

        let ret = layer_match_tcp.check(&data);
        println!("{}", ret);
    }
    #[test]
    fn test_layer2_send() {
        let config = datalink::Config {
            write_buffer_size: ETHERNET_BUFF_SIZE,
            read_buffer_size: ETHERNET_BUFF_SIZE,
            read_timeout: Some(Duration::new(1, 0)),
            write_timeout: Some(Duration::new(1, 0)),
            channel_type: datalink::ChannelType::Layer2,
            bpf_fd_attempts: 1000,
            linux_fanout: None,
            promiscuous: false,
            socket_fd: None,
        };

        // let dst_ipv4 = Ipv4Addr::new(192, 168, 5, 5);
        let src_ipv4 = Ipv4Addr::new(192, 168, 5, 3);
        let interface = find_interface_by_src_ip(src_ipv4.into()).unwrap();

        let (mut sender, _) = match datalink::channel(&interface, config) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
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
        let _ = sender.send_to(&data, None).unwrap();
    }
}
