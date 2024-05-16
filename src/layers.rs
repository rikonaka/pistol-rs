use anyhow::Result;
use dns_lookup::lookup_host;
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
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::process::Command;
use std::sync::mpsc::channel;
use std::time::Duration;
use std::time::Instant;
use subnetwork::Ipv6;

use crate::errors::CanNotFoundInterface;
use crate::errors::CanNotFoundMacAddress;
use crate::errors::CanNotFoundRouterAddress;
use crate::errors::CreateDatalinkChannelFailed;
use crate::utils::find_interface_by_ipv4;
use crate::utils::find_interface_by_ipv6;
use crate::utils::find_interface_valid_mac_ipv4;
use crate::utils::find_interface_valid_mac_ipv6;
use crate::utils::get_threads_pool;
use crate::Ipv4CheckMethods;
use crate::Ipv6CheckMethods;
use crate::DEFAULT_MAXLOOP;

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

const NEIGNBOUR_MAX_TRY: usize = 3;

#[derive(Debug, Clone, Copy)]
pub struct Layer2Match {
    pub src_mac: Option<MacAddr>,         // response packet src mac
    pub dst_mac: Option<MacAddr>,         // response packet src mac
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

#[derive(Debug, Clone, Copy)]
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
                m1 & m2 & m3
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
                m1 & m2 & m3
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
                m1 & m2 & m3
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
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
        m1 & m2 & m3
    }
}

#[derive(Debug, Clone, Copy)]
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
        m1 & m_icmp & m2 & m3
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Layer4MatchIcmpv6 {
    pub layer3: Option<Layer3Match>,
    pub types: Option<Icmpv6Type>, // response icmp packet types
    pub codes: Option<Icmpv6Code>, // response icmp packet codes
}

impl Layer4MatchIcmpv6 {
    pub fn do_match(&self, ethernet_buff: &[u8]) -> bool {
        let m1 = match self.layer3 {
            Some(layer3) => layer3.do_match(ethernet_buff),
            None => true,
        };
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
        m1 & m_icmpv6 & m2 & m3
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
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
) -> Result<Option<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)>> {
    match datalink::channel(&interface, Default::default()) {
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
) -> Result<(Option<Vec<u8>>, Option<Duration>)> {
    let (mut sender, mut receiver) = match datalink_channel(&interface)? {
        Some((s, r)) => (s, r),
        None => return Err(CreateDatalinkChannelFailed::new().into()),
    };
    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(CanNotFoundMacAddress::new().into()),
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

    if timeout != Duration::new(0, 0) {
        let pool = get_threads_pool(1);
        let (tx, rx) = channel();

        pool.execute(move || {
            for _ in 0..DEFAULT_MAXLOOP {
                let buff = match receiver.next() {
                    Ok(b) => b,
                    Err(_) => &[],
                };
                for m in &layers_match {
                    match m.do_match(buff) {
                        true => {
                            match tx.send(buff.to_vec()) {
                                _ => (),
                            }
                            break;
                        }
                        false => (),
                    }
                }
            }
        });

        let (buff, rtt) = match rx.recv_timeout(timeout) {
            Ok(b) => {
                let rtt = send_time.elapsed();
                (b, Some(rtt))
            }
            Err(_) => {
                (vec![], None) // read timeout
            }
        };
        if buff.len() > 0 {
            Ok((Some(buff), rtt))
        } else {
            Ok((None, rtt))
        }
    } else {
        // not recv any response for flood attack enffience
        Ok((None, None))
    }
}

pub fn system_route() -> Result<Ipv4Addr> {
    if cfg!(target_os = "linux") {
        // ip route (default)
        let c = Command::new("bash").args(["-c", "ip route"]).output()?;
        // default via 192.168.72.2 dev ens33
        // 192.168.72.0/24 dev ens33 proto kernel scope link src 192.168.72.128
        let output = String::from_utf8_lossy(&c.stdout);
        let lines: Vec<&str> = output.split("\n").filter(|v| v.len() > 0).collect();
        for line in lines {
            if line.contains("default") {
                let l_split: Vec<&str> = line.split(" ").filter(|v| v.len() > 0).collect();
                let route_ipv4: Ipv4Addr = l_split[2].parse()?;
                return Ok(route_ipv4);
            }
        }
    } else if cfg!(target_os = "windows") {
        // route print
        let c = Command::new("powershell")
            .args(["route", "print"])
            .output()?;
        // 0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.30    281
        let output = String::from_utf8_lossy(&c.stdout);
        let lines: Vec<&str> = output.split("\n").filter(|v| v.len() > 0).collect();
        for line in lines {
            if line.contains("0.0.0.0") {
                let l_split: Vec<&str> = line.split(" ").filter(|v| v.len() > 0).collect();
                let route_ipv4: Ipv4Addr = l_split[2].parse()?;
                return Ok(route_ipv4);
            }
        }
    }
    Err(CanNotFoundRouterAddress::new().into())
}

pub fn system_route6() -> Result<Ipv6Addr> {
    if cfg!(target_os = "linux") {
        // ip route (default)
        let c = Command::new("bash").args(["-c", "ip -6 route"]).output()?;
        // 240e:34c:85:e4d0::/64 dev ens36 proto kernel metric 256 expires 86372sec pref medium
        // fe80::/64 dev ens33 proto kernel metric 256 pref medium
        // fe80::/64 dev ens36 proto kernel metric 256 pref medium
        // default via fe80::4a5f:8ff:fee0:1394 dev ens36 proto ra metric 1024 expires 1772sec hoplimit 64 pref medium
        let output = String::from_utf8_lossy(&c.stdout);
        let lines: Vec<&str> = output.split("\n").filter(|v| v.len() > 0).collect();
        for line in lines {
            if line.contains("default") {
                let l_split: Vec<&str> = line.split(" ").filter(|v| v.len() > 0).collect();
                let route_ipv6: Ipv6Addr = l_split[2].parse()?;
                return Ok(route_ipv6);
            }
        }
    } else if cfg!(target_os = "windows") {
        // route print
        let c = Command::new("powershell")
            .args(["route", "print"])
            .output()?;
        // 16    281 ::/0                     fe80::4a5f:8ff:fee0:1394
        let output = String::from_utf8_lossy(&c.stdout);
        let lines: Vec<&str> = output.split("\r\n").filter(|v| v.len() > 0).collect();
        for line in lines {
            if line.contains("::/0") {
                let l_split: Vec<&str> = line.split(" ").filter(|v| v.len() > 0).collect();
                let route_ipv6: Ipv6Addr = l_split[3].parse()?;
                return Ok(route_ipv6);
            }
        }
    }
    Err(CanNotFoundRouterAddress::new().into())
}

pub fn system_neighbour_cache() -> Result<Option<HashMap<IpAddr, MacAddr>>> {
    if cfg!(target_os = "linux") {
        // ip neighbour
        let c = Command::new("bash").args(["-c", "ip neighbour"]).output()?;
        // 192.168.72.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE
        // 192.168.72.254 dev ens33 lladdr 00:50:56:fa:d4:85 STALE
        // 192.168.72.2 dev ens33 lladdr 00:50:56:ff:8c:06 STALE
        let output = String::from_utf8_lossy(&c.stdout);
        let lines: Vec<&str> = output.split("\n").filter(|v| v.len() > 0).collect();
        let mut ret: HashMap<IpAddr, MacAddr> = HashMap::new();
        for line in lines {
            let l_split: Vec<&str> = line.split(" ").filter(|v| v.len() > 0).collect();
            if l_split.len() >= 6 {
                let ip_str = l_split[0];
                // let device = l_split[2];
                let mac_str = l_split[4];
                let ip: IpAddr = ip_str.parse()?;
                let mac: MacAddr = mac_str.parse()?;
                ret.insert(ip, mac);
            }
        }
        return Ok(Some(ret));
    } else if cfg!(target_os = "windows") {
        // Get-NetNeighbor
        let c = Command::new("powershell")
            .args(["Get-NetNeighbor"])
            .output()?;
        // ifIndex IPAddress                                          LinkLayerAddress      State       PolicyStore
        // ------- ---------                                          ----------------      -----       -----------
        // 17      ff15::efc0:988f                                    33-33-EF-C0-98-8F     Permanent   ActiveStore
        // 17      ff02::1:ffd0:8c47                                  33-33-FF-D0-8C-47     Permanent   ActiveStore
        let output = String::from_utf8_lossy(&c.stdout);
        let lines: Vec<&str> = output.split("\r\n").filter(|v| v.len() > 0).collect();
        let mut ret: HashMap<IpAddr, MacAddr> = HashMap::new();
        for line in lines[2..].to_vec() {
            let l_split: Vec<&str> = line.split(" ").filter(|v| v.len() > 0).collect();
            if l_split.len() >= 5 {
                let ip_str = l_split[1];
                let mac_str = l_split[2].replace("-", ":");
                let ip: IpAddr = ip_str.parse()?;
                let mac: MacAddr = mac_str.parse()?;
                ret.insert(ip, mac);
            }
        }
        return Ok(Some(ret));
    }
    Ok(None)
}

pub fn system_neighbour_cache6() -> Result<Option<HashMap<IpAddr, MacAddr>>> {
    if cfg!(target_os = "linux") {
        // ip neighbour
        let c = Command::new("bash")
            .args(["-c", "ip -6 neighbour"])
            .output()?;
        // fe80::4a5f:8ff:fee0:1394 dev ens33 FAILED
        // fe80::4a5f:8ff:fee0:1394 dev ens36 lladdr 48:5f:08:e0:13:94 router STALE
        let output = String::from_utf8_lossy(&c.stdout);
        let lines: Vec<&str> = output.split("\n").filter(|v| v.len() > 0).collect();
        let mut ret: HashMap<IpAddr, MacAddr> = HashMap::new();
        for line in lines {
            let l_split: Vec<&str> = line.split(" ").filter(|v| v.len() > 0).collect();
            if l_split.len() >= 6 {
                let ip_str = l_split[0];
                // let device = l_split[2];
                let mac_str = l_split[4];
                let ip: IpAddr = ip_str.parse()?;
                let mac: MacAddr = mac_str.parse()?;
                ret.insert(ip, mac);
            }
        }
        return Ok(Some(ret));
    } else if cfg!(target_os = "windows") {
        // Get-NetNeighbor
        let c = Command::new("powershell")
            .args(["Get-NetNeighbor"])
            .output()?;
        // ifIndex IPAddress                                          LinkLayerAddress      State       PolicyStore
        // ------- ---------                                          ----------------      -----       -----------
        // 17      ff15::efc0:988f                                    33-33-EF-C0-98-8F     Permanent   ActiveStore
        // 17      ff02::1:ffd0:8c47                                  33-33-FF-D0-8C-47     Permanent   ActiveStore
        let output = String::from_utf8_lossy(&c.stdout);
        let lines: Vec<&str> = output.split("\n").filter(|v| v.len() > 0).collect();
        let mut ret: HashMap<IpAddr, MacAddr> = HashMap::new();
        for line in lines[2..].to_vec() {
            let l_split: Vec<&str> = line.split(" ").filter(|v| v.len() > 0).collect();
            if l_split.len() >= 5 {
                let ip_str = l_split[1];
                let mac_str = l_split[2].replace("-", ":");
                let ip: IpAddr = ip_str.parse()?;
                let mac: MacAddr = mac_str.parse()?;
                ret.insert(ip, mac);
            }
        }
        return Ok(Some(ret));
    }
    Ok(None)
}

pub fn search_system_neighbour_cache(ip: IpAddr) -> Result<Option<MacAddr>> {
    let ret = system_neighbour_cache()?;
    // println!("{:?}", ret);
    match ret {
        Some(r) => {
            for (i, m) in r {
                if i == ip {
                    return Ok(Some(m));
                }
            }
            Ok(None)
        }
        None => Ok(None),
    }
}

pub fn search_system_neighbour_cache6(ip: IpAddr) -> Result<Option<MacAddr>> {
    let ret = system_neighbour_cache6()?;
    match ret {
        Some(r) => {
            for (i, m) in r {
                if i == ip {
                    return Ok(Some(m));
                }
            }
            Ok(None)
        }
        None => Ok(None),
    }
}

pub fn get_mac_from_arp(ethernet_buff: &[u8]) -> Option<MacAddr> {
    let re = EthernetPacket::new(ethernet_buff).unwrap();
    match re.get_ethertype() {
        EtherTypes::Arp => {
            let arp = ArpPacket::new(re.payload()).unwrap();
            Some(arp.get_sender_hw_addr())
        }
        _ => None,
    }
}

fn arp(src_ipv4: Ipv4Addr, dst_ipv4: Ipv4Addr) -> Result<(Option<MacAddr>, Option<Duration>)> {
    let interface = match find_interface_by_ipv4(src_ipv4) {
        Some(i) => i,
        None => return Err(CanNotFoundInterface::new().into()),
    };

    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(CanNotFoundMacAddress::new().into()),
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

    let timeout = Duration::new(3, 0);
    let (ret, rtt) = layer2_send(
        MacAddr::broadcast(),
        interface,
        &arp_buff,
        ethernet_type,
        vec![layers_match],
        timeout,
    )?;
    match ret {
        Some(r) => Ok((get_mac_from_arp(&r), rtt)),
        None => Ok((None, None)),
    }
}

pub fn layer3_ipv4_send(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    payload: &[u8],
    layers_match: Vec<LayersMatch>,
    timeout: Duration,
) -> Result<(Option<Vec<u8>>, Option<Duration>)> {
    let dst_mac = match search_system_neighbour_cache(dst_ipv4.into())? {
        Some(m) => m,
        None => {
            if dst_ipv4 == src_ipv4 {
                let interface = find_interface_by_ipv4(dst_ipv4).unwrap();
                let mac = interface.mac.unwrap();
                mac
            } else if dst_ipv4.is_loopback() {
                let mac = find_interface_valid_mac_ipv4();
                mac.unwrap()
            } else if dst_ipv4.is_global_x() {
                // Not local net, then try to send this packet to router.
                let route_ip = system_route()?;
                // let route_ip = Ipv4Addr::new(0, 0, 0, 0); // default route address
                match search_system_neighbour_cache(route_ip.into())? {
                    Some(m) => m,
                    None => {
                        let mut mac: Option<MacAddr> = None;
                        for _ in 0..NEIGNBOUR_MAX_TRY {
                            match arp(src_ipv4, route_ip)? {
                                (Some(m), Some(_rtt)) => {
                                    mac = Some(m);
                                    break;
                                }
                                (_, _) => (),
                            }
                        }
                        match mac {
                            Some(m) => m,
                            None => return Err(CanNotFoundMacAddress::new().into()),
                        }
                    }
                }
            } else {
                // Try to get mac througn arp.
                let mut mac: Option<MacAddr> = None;
                for _ in 0..NEIGNBOUR_MAX_TRY {
                    match arp(src_ipv4, dst_ipv4)? {
                        (Some(m), Some(_rtt)) => {
                            mac = Some(m);
                            break;
                        }
                        (_, _) => (),
                    }
                }
                match mac {
                    Some(m) => m,
                    None => return Err(CanNotFoundMacAddress::new().into()),
                }
            }
        }
    };
    let interface = match find_interface_by_ipv4(src_ipv4) {
        Some(i) => i,
        None => return Err(CanNotFoundInterface::new().into()),
    };

    let ethernet_type = EtherTypes::Ipv4;
    let (layer2_buff, rtt) = layer2_send(
        dst_mac,
        interface,
        payload,
        ethernet_type,
        layers_match,
        timeout,
    )?;
    match layer2_buff {
        Some(layer2_packet) => Ok((Some(layer2_payload(&layer2_packet)), rtt)),
        None => Ok((None, None)),
    }
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

fn ndp_ns(src_ipv6: Ipv6Addr, dst_ipv6: Ipv6Addr) -> Result<Option<MacAddr>> {
    // same as arp in ipv4
    let interface = match find_interface_by_ipv6(src_ipv6) {
        Some(i) => i,
        None => return Err(CanNotFoundInterface::new().into()),
    };
    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(CanNotFoundMacAddress::new().into()),
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
        types: None,
        codes: None,
    };
    let layers_match = LayersMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    let ethernet_type = EtherTypes::Ipv6;
    let timeout = Duration::new(3, 0);
    let (r, _rtt) = layer2_send(
        multicast_mac(dst_ipv6),
        interface.clone(),
        &ipv6_buff,
        ethernet_type,
        vec![layers_match],
        timeout,
    )?;
    let mac = match r {
        Some(r) => match layer4_icmpv6.do_match(&r) {
            true => get_mac_from_ndp_ns(&r),
            false => None,
        },
        None => None,
    };
    match mac {
        Some(mac) => Ok(Some(mac)),
        None => Ok(None),
    }
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

fn ndp_rs(src_ipv6: Ipv6Addr) -> Result<Option<MacAddr>> {
    // router solicitation
    let dst_ipv6_all_router = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 2);
    let interface = match find_interface_by_ipv6(src_ipv6) {
        Some(i) => i,
        None => return Err(CanNotFoundInterface::new().into()),
    };
    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(CanNotFoundMacAddress::new().into()),
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
    ipv6_header.set_destination(dst_ipv6_all_router);

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
    let checksum = icmpv6::checksum(
        &icmpv6_header.to_immutable(),
        &src_ipv6,
        &dst_ipv6_all_router,
    );
    icmpv6_header.set_checksum(checksum);

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: None,
        dst_addr: Some(dst_ipv6_all_router.into()),
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        layer3: Some(layer3),
        types: None,
        codes: None,
    };
    let layers_match = LayersMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    let timeout = Duration::new(3, 0);
    let dst_mac = MacAddr(33, 33, 00, 00, 00, 02);
    let ethernet_type = EtherTypes::Ipv6;
    let (r, _rtt) = layer2_send(
        dst_mac,
        interface.clone(),
        &ipv6_buff,
        ethernet_type,
        vec![layers_match],
        timeout,
    )?;
    let mac = match r {
        Some(r) => get_mac_from_ndp_rs(&r),
        None => None,
    };
    match mac {
        Some(mac) => Ok(Some(mac)),
        None => Ok(None),
    }
}

fn layer2_payload(buff: &[u8]) -> Vec<u8> {
    let ethernet_packet = EthernetPacket::new(buff).unwrap();
    ethernet_packet.payload().to_vec()
}

pub fn layer3_ipv6_send(
    src_ipv6: Ipv6Addr,
    dst_ipv6: Ipv6Addr,
    payload: &[u8],
    layers_match: Vec<LayersMatch>,
    timeout: Duration,
) -> Result<(Option<Vec<u8>>, Option<Duration>)> {
    let dst_mac = match search_system_neighbour_cache(dst_ipv6.into())? {
        Some(m) => m,
        None => {
            if dst_ipv6 == src_ipv6 {
                let interface = find_interface_by_ipv6(dst_ipv6).unwrap();
                let mac = interface.mac.unwrap();
                mac
            } else if dst_ipv6.is_loopback() {
                let mac = find_interface_valid_mac_ipv6();
                mac.unwrap()
            } else if dst_ipv6.is_global_x() {
                // Not local net, then try to send this packet to router.
                let route_ip = system_route6()?;
                // let route_ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0); // default route address
                match search_system_neighbour_cache6(route_ip.into())? {
                    Some(m) => m,
                    None => {
                        let mut mac: Option<MacAddr> = None;
                        for _ in 0..NEIGNBOUR_MAX_TRY {
                            match ndp_rs(src_ipv6)? {
                                Some(m) => {
                                    mac = Some(m);
                                    break;
                                }
                                None => (),
                            }
                        }
                        match mac {
                            Some(m) => m,
                            None => return Err(CanNotFoundMacAddress::new().into()),
                        }
                    }
                }
            } else {
                // Try to get mac through ndp.
                let mut mac: Option<MacAddr> = None;
                for _ in 0..NEIGNBOUR_MAX_TRY {
                    match ndp_ns(src_ipv6, dst_ipv6)? {
                        Some(m) => {
                            mac = Some(m);
                            break;
                        }
                        None => (),
                    }
                }
                match mac {
                    Some(m) => m,
                    None => return Err(CanNotFoundMacAddress::new().into()),
                }
            }
        }
    };
    let interface = match find_interface_by_ipv6(src_ipv6) {
        Some(i) => i,
        None => return Err(CanNotFoundInterface::new().into()),
    };

    let ethernet_type = EtherTypes::Ipv6;
    let (layer2_buff, rtt) = layer2_send(
        dst_mac,
        interface,
        payload,
        ethernet_type,
        layers_match,
        timeout,
    )?;
    match layer2_buff {
        Some(layer2_packet) => Ok((Some(layer2_payload(&layer2_packet)), rtt)),
        None => Ok((None, None)),
    }
}

pub fn dns_query(hostname: &str) -> Result<Vec<IpAddr>> {
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
    #[test]
    fn test_send_arp_packet() {
        let src_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 33);
        let dst_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 51);
        match arp(src_ipv4, dst_ipv4).unwrap() {
            (Some(m), rtt) => {
                println!("{} => rtt: {}", m, rtt.unwrap().as_secs_f32());
            }
            (_, _) => println!("None"),
        }
    }
    #[test]
    fn test_send_ndp_ns_packet() {
        let src_ipv6: Ipv6Addr = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        // let dst_ipv6 = "fe80::47c:7f4a:10a8:7f4a".parse().unwrap();
        match ndp_ns(src_ipv6, dst_ipv6).unwrap() {
            Some(mac) => println!("{}", mac),
            _ => println!("None"),
        }
    }
    #[test]
    fn test_send_ndp_rs_packet() {
        let src_ipv6: Ipv6Addr = "240e:34c:85:e4d0:20c:29ff:fe43:9c8c".parse().unwrap();
        match ndp_rs(src_ipv6).unwrap() {
            Some(mac) => println!("{}", mac),
            _ => println!("None"),
        }
    }
    #[test]
    fn test_system_arp_cache() {
        let r = system_neighbour_cache().unwrap().unwrap();
        for (i, m) in r {
            println!("{} - {}", i, m);
        }
    }
    #[test]
    fn test_duration_ep() {
        let a = Duration::new(1, 0);
        let b = Duration::new(0, 0);

        if a == Duration::new(0, 0) {
            println!("a == 0")
        }
        if b == Duration::new(0, 0) {
            println!("b == 0")
        }
    }
    #[test]
    fn test_windows_command() {
        let c = Command::new("powershell")
            .args(["Get-NetNeighbor"])
            .output()
            .unwrap();
        let output = String::from_utf8_lossy(&c.stdout);
        println!("{}", output);
    }
    #[test]
    fn test_linux_command() {
        let c = Command::new("bash")
            .args(["-c", "ip neighbour"])
            .output()
            .unwrap();
        let output = String::from_utf8_lossy(&c.stdout);
        println!("{}", output);
    }
    #[test]
    fn test_windows_mac() -> Result<()> {
        let s = "33-33-EF-C0-98-8F";
        let s = s.replace("-", ":");
        let _: MacAddr = s.parse()?;
        Ok(())
    }
}
