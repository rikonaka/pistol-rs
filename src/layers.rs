// use chrono::Local;
use dns_lookup::lookup_host;
use log::debug;
use log::error;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::DataLinkReceiver;
use pnet::datalink::DataLinkSender;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::packet::arp::ArpHardwareTypes;
use pnet::packet::arp::ArpOperations;
use pnet::packet::arp::ArpPacket;
use pnet::packet::arp::MutableArpPacket;
use pnet::packet::ethernet::EtherType;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::icmp::IcmpCode;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpType;
use pnet::packet::icmpv6;
use pnet::packet::icmpv6::ndp::MutableNeighborSolicitPacket;
use pnet::packet::icmpv6::ndp::MutableRouterSolicitPacket;
use pnet::packet::icmpv6::ndp::NdpOption;
use pnet::packet::icmpv6::ndp::NdpOptionTypes;
use pnet::packet::icmpv6::ndp::NeighborAdvertPacket;
use pnet::packet::icmpv6::Icmpv6Code;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmpv6::Icmpv6Type;
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::time::Duration;
use std::time::Instant;
use subnetwork::Ipv6;

use crate::error::PistolError;
// use crate::route::SystemNetCache;
use crate::utils::dst_ipv4_in_local;
use crate::utils::dst_ipv6_in_local;
use crate::utils::find_interface_by_ip;
use crate::utils::system_cache_default_route;
use crate::utils::system_cache_default_route6;
use crate::utils::system_cache_search_mac;
use crate::utils::system_cache_search_route;
use crate::utils::system_cache_update;

pub const ETHERNET_HEADER_SIZE: usize = 14;
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Layer2Match {
    pub src_mac: Option<MacAddr>,         // response packet src mac
    pub dst_mac: Option<MacAddr>,         // response packet dst mac
    pub ethernet_type: Option<EtherType>, // reponse packet ethernet type
}

impl Layer2Match {
    pub fn do_match(&self, ethernet_buff: &[u8]) -> bool {
        let ethernet_packet = match EthernetPacket::new(&ethernet_buff) {
            Some(ethernet_packet) => ethernet_packet,
            None => {
                return false;
            }
        };
        let m1 = match self.src_mac {
            Some(src_mac) => {
                if ethernet_packet.get_source() == src_mac {
                    true
                } else {
                    false
                }
            }
            None => true, // wild match
        };
        let m2 = match self.dst_mac {
            Some(dst_mac) => {
                if ethernet_packet.get_destination() == dst_mac {
                    true
                } else {
                    false
                }
            }
            None => true, // wild match
        };
        let m3 = match self.ethernet_type {
            Some(ethernet_type) => {
                if ethernet_type == ethernet_packet.get_ethertype() {
                    true
                } else {
                    false
                }
            }
            None => true, // wild match
        };
        m1 & m2 & m3
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Layer3Match {
    pub layer2: Option<Layer2Match>,
    pub src_addr: Option<IpAddr>, // response packet
    pub dst_addr: Option<IpAddr>, // response packet
}

impl Layer3Match {
    pub fn do_match(&self, ethernet_buff: &[u8]) -> bool {
        let m1 = match self.layer2 {
            Some(layers) => layers.do_match(ethernet_buff),
            None => true,
        };
        // early stop
        if m1 {
            let ethernet_packet = match EthernetPacket::new(&ethernet_buff) {
                Some(ethernet_packet) => ethernet_packet,
                None => {
                    return false;
                }
            };
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    let ipv4_packet = match Ipv4Packet::new(ethernet_packet.payload()) {
                        Some(i) => i,
                        None => return false,
                    };
                    let m2 = match self.src_addr {
                        Some(src_addr) => match src_addr {
                            IpAddr::V4(src_ipv4) => {
                                if ipv4_packet.get_source() == src_ipv4 {
                                    true
                                } else {
                                    false
                                }
                            }
                            _ => false,
                        },
                        None => true,
                    };
                    if m2 {
                        let m3 = match self.dst_addr {
                            Some(dst_addr) => match dst_addr {
                                IpAddr::V4(dst_ipv4) => {
                                    if ipv4_packet.get_destination() == dst_ipv4 {
                                        true
                                    } else {
                                        false
                                    }
                                }
                                _ => false,
                            },
                            None => true,
                        };
                        m3
                    } else {
                        false
                    }
                }
                EtherTypes::Ipv6 => {
                    let ipv6_packet = match Ipv6Packet::new(ethernet_packet.payload()) {
                        Some(i) => i,
                        None => return false,
                    };
                    let m2 = match self.src_addr {
                        Some(src_addr) => match src_addr {
                            IpAddr::V6(src_ipv6) => {
                                if ipv6_packet.get_source() == src_ipv6 {
                                    true
                                } else {
                                    false
                                }
                            }
                            _ => false,
                        },
                        None => true,
                    };
                    if m2 {
                        let m3 = match self.dst_addr {
                            Some(dst_addr) => match dst_addr {
                                IpAddr::V6(dst_ipv6) => {
                                    if ipv6_packet.get_destination() == dst_ipv6 {
                                        true
                                    } else {
                                        false
                                    }
                                }
                                _ => false,
                            },
                            None => true,
                        };
                        m3
                    } else {
                        false
                    }
                }
                EtherTypes::Arp => {
                    // ARP is layer 2.5, but here we consider it as layer 3.
                    let arp_packet = match ArpPacket::new(ethernet_packet.payload()) {
                        Some(a) => a,
                        None => return false,
                    };
                    let m2 = match self.src_addr {
                        Some(src_addr) => match src_addr {
                            IpAddr::V4(src_ipv4) => {
                                if arp_packet.get_sender_proto_addr() == src_ipv4 {
                                    true
                                } else {
                                    false
                                }
                            }
                            _ => false,
                        },
                        None => true,
                    };
                    if m2 {
                        let m3 = match self.dst_addr {
                            Some(dst_addr) => match dst_addr {
                                IpAddr::V4(dst_ipv4) => {
                                    if arp_packet.get_target_proto_addr() == dst_ipv4 {
                                        true
                                    } else {
                                        false
                                    }
                                }
                                _ => false,
                            },
                            None => true,
                        };
                        m2 & m3
                    } else {
                        false
                    }
                }
                _ => false,
            }
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Layer4MatchTcpUdp {
    pub layer3: Option<Layer3Match>,
    pub src_port: Option<u16>, // response tcp or udp packet src port
    pub dst_port: Option<u16>, // response tcp or udp packet dst port
}

impl Layer4MatchTcpUdp {
    pub fn do_match(&self, ethernet_buff: &[u8]) -> bool {
        let m1 = match self.layer3 {
            Some(layer3) => layer3.do_match(ethernet_buff),
            None => true,
        };
        if m1 {
            let ethernet_packet = match EthernetPacket::new(&ethernet_buff) {
                Some(ethernet_packet) => ethernet_packet,
                None => {
                    return false;
                }
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
            let m2 = match self.src_port {
                Some(src_port) => {
                    if src_port == r_src_port {
                        true
                    } else {
                        false
                    }
                }
                None => true,
            };
            if m2 {
                let m3 = match self.dst_port {
                    Some(dst_port) => {
                        if dst_port == r_dst_port {
                            true
                        } else {
                            false
                        }
                    }
                    None => true,
                };
                m3
            } else {
                false
            }
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Layer4MatchIcmp {
    pub layer3: Option<Layer3Match>,
    pub types: Option<IcmpType>, // response icmp packet types
    pub codes: Option<IcmpCode>, // response icmp packet codes
}

impl Layer4MatchIcmp {
    pub fn do_match(&self, ethernet_buff: &[u8]) -> bool {
        let m1 = match self.layer3 {
            Some(layer3) => layer3.do_match(ethernet_buff),
            None => true,
        };
        if m1 {
            let ethernet_packet = match EthernetPacket::new(&ethernet_buff) {
                Some(ethernet_packet) => ethernet_packet,
                None => {
                    return false;
                }
            };
            let mut m_icmp = false;
            let (r_types, r_codes) = match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    let ipv4_packet = match Ipv4Packet::new(ethernet_packet.payload()) {
                        Some(i) => i,
                        None => return false,
                    };
                    match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Icmp => {
                            m_icmp = true;
                            let icmp_packet = match IcmpPacket::new(ipv4_packet.payload()) {
                                Some(t) => t,
                                None => return false,
                            };
                            (icmp_packet.get_icmp_type(), icmp_packet.get_icmp_code())
                        }
                        _ => (IcmpType(0), IcmpCode(0)),
                    }
                }
                _ => (IcmpType(0), IcmpCode(0)),
            };
            if m_icmp {
                let m2 = match self.types {
                    Some(types) => {
                        if types == r_types {
                            true
                        } else {
                            false
                        }
                    }
                    None => true,
                };
                if m2 {
                    let m3 = match self.codes {
                        Some(codes) => {
                            if codes == r_codes {
                                true
                            } else {
                                false
                            }
                        }
                        None => true,
                    };
                    m3
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Layer4MatchIcmpv6 {
    pub layer3: Option<Layer3Match>,
    pub icmpv6_type: Option<Icmpv6Type>, // response icmp packet types
    pub icmpv6_code: Option<Icmpv6Code>, // response icmp packet codes
}

impl Layer4MatchIcmpv6 {
    pub fn do_match(&self, ethernet_buff: &[u8]) -> bool {
        let m1 = match self.layer3 {
            Some(layer3) => layer3.do_match(ethernet_buff),
            None => true,
        };
        if m1 {
            let ethernet_packet = match EthernetPacket::new(&ethernet_buff) {
                Some(ethernet_packet) => ethernet_packet,
                None => {
                    return false;
                }
            };
            let mut m_icmpv6 = false;
            let (r_types, r_codes) = match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv6 => {
                    let ipv6_packet = match Ipv6Packet::new(ethernet_packet.payload()) {
                        Some(i) => i,
                        None => return false,
                    };
                    match ipv6_packet.get_next_header() {
                        IpNextHeaderProtocols::Icmpv6 => {
                            m_icmpv6 = true;
                            let icmpv6_packet = match Icmpv6Packet::new(ipv6_packet.payload()) {
                                Some(t) => t,
                                None => return false,
                            };
                            (
                                icmpv6_packet.get_icmpv6_type(),
                                icmpv6_packet.get_icmpv6_code(),
                            )
                        }
                        _ => (Icmpv6Type(0), Icmpv6Code(0)),
                    }
                }
                _ => (Icmpv6Type(0), Icmpv6Code(0)),
            };
            if m_icmpv6 {
                // println!("types: {:?}, codes: {:?}", r_types, r_codes);
                let m2 = match self.icmpv6_type {
                    Some(types) => {
                        if types == r_types {
                            true
                        } else {
                            false
                        }
                    }
                    None => true,
                };
                if m2 {
                    let m3 = match self.icmpv6_code {
                        Some(codes) => {
                            if codes == r_codes {
                                true
                            } else {
                                false
                            }
                        }
                        None => true,
                    };
                    m3
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LayersMatch {
    Layer2Match(Layer2Match),
    Layer3Match(Layer3Match),
    Layer4MatchTcpUdp(Layer4MatchTcpUdp),
    Layer4MatchIcmp(Layer4MatchIcmp),
    Layer4MatchIcmpv6(Layer4MatchIcmpv6),
}

impl LayersMatch {
    pub fn do_match(&self, ethernet_buff: &[u8]) -> bool {
        match self {
            LayersMatch::Layer2Match(l2) => l2.do_match(ethernet_buff),
            LayersMatch::Layer3Match(l3) => l3.do_match(ethernet_buff),
            LayersMatch::Layer4MatchTcpUdp(l4tcpudp) => l4tcpudp.do_match(ethernet_buff),
            LayersMatch::Layer4MatchIcmp(l4icmp) => l4icmp.do_match(ethernet_buff),
            LayersMatch::Layer4MatchIcmpv6(l4icmpv6) => l4icmpv6.do_match(ethernet_buff),
        }
    }
}

fn datalink_channel(
    interface: &NetworkInterface,
) -> Result<Option<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)>, PistolError> {
    let cfg = pnet::datalink::Config::default();
    match datalink::channel(&interface, cfg) {
        Ok(Ethernet(tx, rx)) => Ok(Some((tx, rx))),
        Ok(_) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn _print_packet_as_wireshark_format(buff: &[u8]) {
    let mut i = 0;
    for b in buff {
        if i % 16 == 0 {
            print!("\n");
        }
        let mut x = format!("{:X}", b);
        // println!("{}", x.len());
        if x.len() == 1 {
            x = format!("0{x} ");
        } else {
            x = format!("{x} ");
        }
        print!("{x}");
        i += 1;
    }
    println!("");
}

pub fn layer2_send(
    dst_mac: MacAddr,
    interface: NetworkInterface,
    send_buff: &[u8],
    ethernet_type: EtherType,
    layers_match: Vec<LayersMatch>,
    timeout: Duration,
) -> Result<(Vec<u8>, Duration), PistolError> {
    let (mut sender, mut receiver) = match datalink_channel(&interface)? {
        Some((s, r)) => (s, r),
        None => return Err(PistolError::CreateDatalinkChannelFailed),
    };
    let src_mac = if dst_mac == MacAddr::zero() {
        MacAddr::zero()
    } else {
        match interface.mac {
            Some(m) => m,
            None => return Err(PistolError::CanNotFoundMacAddress),
        }
    };

    let mut ethernet_buff = [0u8; ETHERNET_BUFF_SIZE];
    // let mut ethernet_buff = [0u8; ETHERNET_HEADER_SIZE + send_buff.len()];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buff).unwrap();
    ethernet_packet.set_destination(dst_mac);
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(ethernet_type);
    ethernet_packet.set_payload(send_buff);

    let final_buff = ethernet_buff[..(ETHERNET_HEADER_SIZE + send_buff.len())].to_vec();
    // _print_packet_as_wireshark_format(&final_buff);
    let send_time = Instant::now();
    match sender.send_to(&final_buff, Some(interface)) {
        Some(r) => match r {
            Err(e) => return Err(e.into()),
            _ => (),
        },
        None => (),
    }

    let start_time = Instant::now();
    if timeout != Duration::new(0, 0) {
        loop {
            if start_time.elapsed() > timeout {
                break;
            }
            let buff = match receiver.next() {
                Ok(b) => b,
                Err(e) => {
                    error!("layer2 send failed: {}", e);
                    &[]
                }
            };
            for m in &layers_match {
                match m.do_match(buff) {
                    true => {
                        debug!("match found: {:?}", m);
                        let rtt = send_time.elapsed();
                        return Ok((buff.to_vec(), rtt));
                    }
                    false => (),
                }
            }
        }
        Ok((vec![], start_time.elapsed()))
    } else {
        // not recv any response for flood attack enffience
        Ok((vec![], Duration::new(0, 0)))
    }
}

pub fn get_mac_from_arp(ethernet_buff: &[u8]) -> Option<MacAddr> {
    match EthernetPacket::new(ethernet_buff) {
        Some(re) => match re.get_ethertype() {
            EtherTypes::Arp => {
                let arp = ArpPacket::new(re.payload()).unwrap();
                Some(arp.get_sender_hw_addr())
            }
            _ => None,
        },
        None => None,
    }
}

fn arp(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    timeout: Duration,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    let interface = match find_interface_by_ip(src_ipv4.into()) {
        Some(i) => i,
        None => return Err(PistolError::CanNotFoundInterface),
    };

    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(PistolError::CanNotFoundMacAddress),
    };

    let mut arp_buff = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buff).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(src_mac);
    arp_packet.set_sender_proto_addr(src_ipv4);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(dst_ipv4);

    let ethernet_type = EtherTypes::Arp;
    let layer2 = Layer2Match {
        src_mac: None,
        dst_mac: None,
        ethernet_type: Some(ethernet_type),
    };
    let layer3 = Layer3Match {
        layer2: Some(layer2),
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layers_match = LayersMatch::Layer3Match(layer3);

    let (ret, rtt) = layer2_send(
        MacAddr::broadcast(),
        interface,
        &arp_buff,
        ethernet_type,
        vec![layers_match],
        timeout,
    )?;
    Ok((get_mac_from_arp(&ret), rtt))
}

pub fn system_route(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    timeout: Duration,
) -> Result<(MacAddr, NetworkInterface), PistolError> {
    let interface = match find_interface_by_ip(src_ipv4.into()) {
        Some(i) => i,
        None => {
            let interface = match system_cache_search_route(dst_ipv4.into()) {
                Some(i) => i,
                None => {
                    // The system route table not contain this ipaddr,
                    // so send it to the default route.
                    let default_route = match system_cache_default_route() {
                        Some(d) => d,
                        None => return Err(PistolError::CanNotFoundRouterAddress),
                    };
                    default_route.dev
                }
            };
            interface
        }
    };

    let dst_mac = match system_cache_search_mac(dst_ipv4.into()) {
        Some(m) => m,
        None => {
            if dst_ipv4_in_local(dst_ipv4) {
                let dst_mac = match arp(src_ipv4, dst_ipv4, timeout)? {
                    (Some(m), _rtt) => m,
                    (_, _) => return Err(PistolError::CanNotFoundMacAddress),
                };
                system_cache_update(dst_ipv4.into(), dst_mac);
                dst_mac
            } else {
                let default_route = match system_cache_default_route() {
                    Some(r) => r,
                    None => return Err(PistolError::CanNotFoundRouterAddress),
                };
                let dst_mac = match default_route.via {
                    IpAddr::V4(default_route_ipv4) => {
                        let dst_mac = match system_cache_search_mac(default_route_ipv4.into()) {
                            Some(m) => m,
                            None => match arp(src_ipv4, default_route_ipv4, timeout)? {
                                (Some(m), _rtt) => {
                                    system_cache_update(default_route_ipv4.into(), m);
                                    m
                                }
                                (_, _) => return Err(PistolError::CanNotFoundRouteMacAddress),
                            },
                        };
                        dst_mac
                    }
                    _ => return Err(PistolError::CanNotFoundRouterAddress),
                };
                dst_mac
            }
        }
    };
    Ok((dst_mac, interface))
}

pub fn layer3_ipv4_send(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    payload: &[u8],
    layers_match: Vec<LayersMatch>,
    timeout: Duration,
) -> Result<(Vec<u8>, Duration), PistolError> {
    // use chrono::Local;
    // let system_time = Local::now();
    // println!(
    //     "layer3 {}, start: {}",
    //     dst_ipv4,
    //     system_time.timestamp_millis()
    // );
    let (dst_mac, interface) = system_route(src_ipv4, dst_ipv4, timeout)?;
    // let ret = system_route(src_ipv4, dst_ipv4, timeout);
    // let system_time2 = Local::now();
    // println!(
    //     "layer3 {}, end: {}",
    //     dst_ipv4,
    //     system_time2.timestamp_millis()
    // );
    // let (dst_mac, interface) = ret?;

    debug!("convert dst ipv4: {} to mac: {}", dst_ipv4, dst_mac);
    debug!("use this interface to send data: {}", interface.name);
    let ethernet_type = EtherTypes::Ipv4;

    let (layer2_buff, rtt) = layer2_send(
        dst_mac,
        interface,
        payload,
        ethernet_type,
        layers_match,
        timeout,
    )?;
    Ok((layer2_payload(&layer2_buff), rtt))
}

pub fn multicast_mac(ip: Ipv6Addr) -> MacAddr {
    let ip = ip.octets();
    // 33:33:FF:xx:xx:xx
    MacAddr::new(0x33, 0x33, 0xFF, ip[13], ip[14], ip[15])
}

fn get_mac_from_ndp_ns(buff: &[u8]) -> Option<MacAddr> {
    // return mac address from ndp
    let ethernet_packet = EthernetPacket::new(buff).unwrap();
    let ipv6_packet = Ipv6Packet::new(ethernet_packet.payload()).unwrap();
    let icmpv6_packet = NeighborAdvertPacket::new(ipv6_packet.payload()).unwrap();
    for o in icmpv6_packet.get_options() {
        let mac = MacAddr::new(
            o.data[0], o.data[1], o.data[2], o.data[3], o.data[4], o.data[5],
        );
        // println!("{:?}", mac);
        return Some(mac);
    }
    None
}

fn ndp_ns(
    src_ipv6: Ipv6Addr,
    dst_ipv6: Ipv6Addr,
    timeout: Duration,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    // same as arp in ipv4
    let interface = match find_interface_by_ip(src_ipv6.into()) {
        Some(i) => i,
        None => return Err(PistolError::CanNotFoundInterface),
    };
    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(PistolError::CanNotFoundMacAddress),
    };

    // ipv6
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + ICMPV6_NS_HEADER_SIZE];
    let mut ipv6_header = MutableIpv6Packet::new(&mut ipv6_buff).unwrap();
    ipv6_header.set_version(6);
    ipv6_header.set_traffic_class(0);
    ipv6_header.set_flow_label(0);
    ipv6_header.set_payload_length(ICMPV6_NS_HEADER_SIZE as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Icmpv6);
    ipv6_header.set_hop_limit(255);
    ipv6_header.set_source(src_ipv6);
    let dst_multicast = Ipv6::new(dst_ipv6).link_multicast();
    ipv6_header.set_destination(dst_multicast);

    // icmpv6
    let mut icmpv6_header =
        MutableNeighborSolicitPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]).unwrap();
    // Neighbor Solicitation
    icmpv6_header.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
    icmpv6_header.set_icmpv6_code(Icmpv6Code(0));
    icmpv6_header.set_reserved(0);
    icmpv6_header.set_target_addr(dst_ipv6);
    let ndp_option = NdpOption {
        option_type: NdpOptionTypes::SourceLLAddr,
        length: 1,
        data: src_mac.octets().to_vec(),
    };
    icmpv6_header.set_options(&vec![ndp_option]);

    let mut icmpv6_header = MutableIcmpv6Packet::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]).unwrap();
    let checksum = icmpv6::checksum(&icmpv6_header.to_immutable(), &src_ipv6, &dst_multicast);
    icmpv6_header.set_checksum(checksum);

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        layer3: Some(layer3),
        icmpv6_type: Some(Icmpv6Type(136)),
        icmpv6_code: Some(Icmpv6Code(0)),
    };
    let layers_match = LayersMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    let ethernet_type = EtherTypes::Ipv6;
    let (r, rtt) = layer2_send(
        multicast_mac(dst_ipv6),
        interface.clone(),
        &ipv6_buff,
        ethernet_type,
        vec![layers_match],
        timeout,
    )?;
    let mac = match layer4_icmpv6.do_match(&r) {
        true => get_mac_from_ndp_ns(&r),
        false => None,
    };
    Ok((mac, rtt))
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
    timeout: Duration,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    // router solicitation
    let route_addr_2 = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x0002);
    // let route_addr_1 = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x0001);
    let interface = match find_interface_by_ip(src_ipv6.into()) {
        Some(i) => i,
        None => return Err(PistolError::CanNotFoundInterface),
    };
    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(PistolError::CanNotFoundMacAddress),
    };

    // ipv6
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + ICMPV6_RS_HEADER_SIZE];
    let mut ipv6_header = MutableIpv6Packet::new(&mut ipv6_buff).unwrap();
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
        MutableRouterSolicitPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]).unwrap();
    // Neighbor Solicitation
    icmpv6_header.set_icmpv6_type(Icmpv6Types::RouterSolicit);
    icmpv6_header.set_icmpv6_code(Icmpv6Code(0));
    icmpv6_header.set_reserved(0);
    let ndp_option = NdpOption {
        option_type: NdpOptionTypes::SourceLLAddr,
        length: 1,
        data: src_mac.octets().to_vec(),
    };
    icmpv6_header.set_options(&vec![ndp_option]);

    let mut icmpv6_header = MutableIcmpv6Packet::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]).unwrap();
    let checksum = icmpv6::checksum(&icmpv6_header.to_immutable(), &src_ipv6, &route_addr_2);
    icmpv6_header.set_checksum(checksum);

    // let layer3 = Layer3Match {
    //     layer2: None,
    //     src_addr: None,
    //     dst_addr: Some(route_addr_1.into()),
    // };
    let layer3 = Layer3Match {
        layer2: None,
        src_addr: None,
        dst_addr: None,
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        layer3: Some(layer3),
        icmpv6_type: Some(Icmpv6Type(134)), // Type: Router Advertisement (134)
        icmpv6_code: Some(Icmpv6Code(0)),
    };
    let layers_match = LayersMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    let dst_mac = MacAddr(33, 33, 00, 00, 00, 02);
    let ethernet_type = EtherTypes::Ipv6;
    let (r, rtt) = layer2_send(
        dst_mac,
        interface.clone(),
        &ipv6_buff,
        ethernet_type,
        vec![layers_match],
        timeout,
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

pub fn system_route6(
    src_ipv6: Ipv6Addr,
    dst_ipv6: Ipv6Addr,
    timeout: Duration,
) -> Result<(MacAddr, NetworkInterface), PistolError> {
    let interface = match find_interface_by_ip(src_ipv6.into()) {
        Some(i) => i,
        None => {
            let interface = match system_cache_search_route(dst_ipv6.into()) {
                Some(i) => i,
                None => {
                    // The system route table not contain this ipaddr,
                    // so send it to the default route.
                    let default_route = match system_cache_default_route6() {
                        Some(d) => d,
                        None => return Err(PistolError::CanNotFoundRouterAddress),
                    };
                    default_route.dev
                }
            };
            interface
        }
    };

    let dst_mac = match system_cache_search_mac(dst_ipv6.into()) {
        Some(m) => m,
        None => {
            if dst_ipv6_in_local(dst_ipv6) {
                let dst_mac = match ndp_ns(src_ipv6, dst_ipv6, timeout)? {
                    (Some(m), _rtt) => m,
                    (_, _) => return Err(PistolError::CanNotFoundMacAddress),
                };
                system_cache_update(dst_ipv6.into(), dst_mac);
                dst_mac
            } else {
                let default_route = match system_cache_default_route6() {
                    Some(r) => r,
                    None => return Err(PistolError::CanNotFoundRouterAddress),
                };
                let dst_mac = match default_route.via {
                    IpAddr::V6(default_route_ipv6) => {
                        let dst_mac = match system_cache_search_mac(default_route_ipv6.into()) {
                            Some(m) => m,
                            None => match ndp_rs(src_ipv6, timeout)? {
                                (Some(m), _rtt) => {
                                    system_cache_update(default_route_ipv6.into(), m);
                                    m
                                }
                                (_, _) => return Err(PistolError::CanNotFoundRouteMacAddress),
                            },
                        };
                        dst_mac
                    }
                    _ => return Err(PistolError::CanNotFoundRouterAddress),
                };
                dst_mac
            }
        }
    };
    Ok((dst_mac, interface))
}

pub fn layer3_ipv6_send(
    src_ipv6: Ipv6Addr,
    dst_ipv6: Ipv6Addr,
    payload: &[u8],
    layers_match: Vec<LayersMatch>,
    timeout: Duration,
) -> Result<(Vec<u8>, Duration), PistolError> {
    let (dst_mac, interface) = system_route6(src_ipv6, dst_ipv6, timeout)?;
    debug!("convert dst ipv6: {} to mac: {}", dst_ipv6, dst_mac);
    debug!("use this interface to send data: {}", interface.name);
    let ethernet_type = EtherTypes::Ipv6;
    let (layer2_buff, rtt) = layer2_send(
        dst_mac,
        interface,
        payload,
        ethernet_type,
        layers_match,
        timeout,
    )?;
    Ok((layer2_payload(&layer2_buff), rtt))
}

/// Queries the IP address of a domain name and returns.
pub fn dns_query(hostname: &str) -> Result<Vec<IpAddr>, PistolError> {
    let ips: Vec<IpAddr> = lookup_host(hostname)?;
    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_dns_query() {
        let hostname = "ipv6.sjtu.edu.cn";
        let ret = dns_query(hostname).unwrap();
        println!("{:?}", ret);
    }
}
