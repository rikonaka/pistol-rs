use anyhow::Result;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::{IcmpCode, IcmpType};
use pnet::packet::icmpv6;
use pnet::packet::icmpv6::ndp::{MutableNeighborSolicitPacket, NeighborAdvertPacket};
use pnet::packet::icmpv6::ndp::{NdpOption, NdpOptionTypes};
use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Type};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use subnetwork::Ipv6;

use crate::errors::{CanNotFoundInterface, CanNotFoundMacAddress, CreateDatalinkChannelFailed};
use crate::utils::{find_interface_by_ipv4, find_interface_by_ipv6};

pub const ETHERNET_HEADER_SIZE: usize = 14;
pub const IPV4_HEADER_SIZE: usize = 20;
pub const IPV6_HEADER_SIZE: usize = 40;
pub const TCP_HEADER_SIZE: usize = 20;
pub const UDP_HEADER_SIZE: usize = 8;
pub const ICMP_HEADER_SIZE: usize = 8;
// big enough to store all data
pub const ETHERNET_BUFF_SIZE: usize = 1024;

pub const ICMPV6_NS_HEADER_SIZE: usize = 32;
// pub const ICMPV6_NA_HEADER_SIZE: usize = 32;
pub const ICMPV6_ER_HEADER_SIZE: usize = 8;
pub const ICMPV6_NI_HEADER_SIZE: usize = 32;

const NEIGNBOUR_MAX_TRY: usize = 3;

#[derive(Debug, Clone, Copy)]
pub enum Layers {
    Layer2,
    Layer3Ipv4,
    Layer3Ipv6,
    Layer4TcpUdp,
    Layer4IcmpSpecific,
    Layer4Icmpv6Specific,
    Layer4Icmp,
    Layer4Icmpv6,
}

#[derive(Debug, Clone, Copy)]
pub struct RespMatch {
    // (src, dst)
    pub layer2: Option<(MacAddr, MacAddr)>,
    pub layer3_ipv4: Option<(Ipv4Addr, Ipv4Addr)>,
    pub layer3_ipv6: Option<(Ipv6Addr, Ipv6Addr)>,
    pub layer4_tcp_udp: Option<(u16, u16)>,
    pub layer4_icmp: Option<(Ipv4Addr, Ipv4Addr)>,
    pub layer4_icmpv6: Option<(Ipv6Addr, Ipv6Addr)>,
    pub layer4_icmp_specific: Option<(IcmpType, IcmpCode)>,
    pub layer4_icmpv6_specific: Option<(Icmpv6Type, Icmpv6Code)>,
    pub layer: Layers,
    pub jump_layer2: bool,
}

#[allow(dead_code)]
impl RespMatch {
    pub fn new_layer2(src_mac: MacAddr, dst_mac: MacAddr) -> RespMatch {
        RespMatch {
            layer2: Some((src_mac, dst_mac)),
            layer3_ipv4: None,
            layer3_ipv6: None,
            layer4_tcp_udp: None,
            layer4_icmp: None,
            layer4_icmpv6: None,
            layer4_icmp_specific: None,
            layer4_icmpv6_specific: None,
            layer: Layers::Layer2,
            jump_layer2: false,
        }
    }
    pub fn new_layer3_ipv4(src_ipv4: Ipv4Addr, dst_ipv4: Ipv4Addr, jump_layer2: bool) -> RespMatch {
        RespMatch {
            layer2: None,
            layer3_ipv4: Some((src_ipv4, dst_ipv4)),
            layer3_ipv6: None,
            layer4_tcp_udp: None,
            layer4_icmp: None,
            layer4_icmpv6: None,
            layer4_icmp_specific: None,
            layer4_icmpv6_specific: None,
            layer: Layers::Layer3Ipv4,
            jump_layer2,
        }
    }
    pub fn new_layer3_ipv6(src_ipv6: Ipv6Addr, dst_ipv6: Ipv6Addr, jump_layer2: bool) -> RespMatch {
        RespMatch {
            layer2: None,
            layer3_ipv4: None,
            layer3_ipv6: Some((src_ipv6, dst_ipv6)),
            layer4_tcp_udp: None,
            layer4_icmp: None,
            layer4_icmpv6: None,
            layer4_icmp_specific: None,
            layer4_icmpv6_specific: None,
            layer: Layers::Layer3Ipv6,
            jump_layer2,
        }
    }
    pub fn new_layer4_tcp_udp(src_port: u16, dst_port: u16, jump_layer2: bool) -> RespMatch {
        RespMatch {
            layer2: None,
            layer3_ipv4: None,
            layer3_ipv6: None,
            layer4_tcp_udp: Some((src_port, dst_port)),
            layer4_icmp: None,
            layer4_icmpv6: None,
            layer4_icmp_specific: None,
            layer4_icmpv6_specific: None,
            layer: Layers::Layer4TcpUdp,
            jump_layer2,
        }
    }
    pub fn new_layer4_icmp_specific(
        icmp_type: IcmpType,
        icmp_code: IcmpCode,
        jump_layer2: bool,
    ) -> RespMatch {
        RespMatch {
            layer2: None,
            layer3_ipv4: None,
            layer3_ipv6: None,
            layer4_tcp_udp: None,
            layer4_icmp: None,
            layer4_icmpv6: None,
            layer4_icmp_specific: Some((icmp_type, icmp_code)),
            layer4_icmpv6_specific: None,
            layer: Layers::Layer4IcmpSpecific,
            jump_layer2,
        }
    }
    pub fn new_layer4_icmpv6_specific(
        icmpv6_type: Icmpv6Type,
        icmpv6_code: Icmpv6Code,
        jump_layer2: bool,
    ) -> RespMatch {
        RespMatch {
            layer2: None,
            layer3_ipv4: None,
            layer3_ipv6: None,
            layer4_tcp_udp: None,
            layer4_icmp: None,
            layer4_icmpv6: None,
            layer4_icmp_specific: None,
            layer4_icmpv6_specific: Some((icmpv6_type, icmpv6_code)),
            layer: Layers::Layer4Icmpv6Specific,
            jump_layer2,
        }
    }
    pub fn new_layer4_icmp(src_ipv4: Ipv4Addr, dst_ipv4: Ipv4Addr, jump_layer2: bool) -> RespMatch {
        RespMatch {
            layer2: None,
            layer3_ipv4: None,
            layer3_ipv6: None,
            layer4_tcp_udp: None,
            layer4_icmp: Some((src_ipv4, dst_ipv4)),
            layer4_icmpv6: None,
            layer4_icmp_specific: None,
            layer4_icmpv6_specific: None,
            layer: Layers::Layer4Icmp,
            jump_layer2,
        }
    }
    pub fn new_layer4_icmpv6(
        src_ipv6: Ipv6Addr,
        dst_ipv6: Ipv6Addr,
        jump_layer2: bool,
    ) -> RespMatch {
        RespMatch {
            layer2: None,
            layer3_ipv4: None,
            layer3_ipv6: None,
            layer4_tcp_udp: None,
            layer4_icmp: None,
            layer4_icmpv6: Some((src_ipv6, dst_ipv6)),
            layer4_icmp_specific: None,
            layer4_icmpv6_specific: None,
            layer: Layers::Layer4Icmpv6,
            jump_layer2,
        }
    }

    fn match_layer2(&self, ethernet_buff: &[u8]) -> bool {
        let (src_mac, dst_mac) = match self.layer2 {
            Some((src_mac, dst_mac)) => (src_mac, dst_mac),
            None => {
                return false;
            }
        };
        let ethernet_packet = match EthernetPacket::new(&ethernet_buff) {
            Some(ethernet_packet) => ethernet_packet,
            None => {
                return false;
            }
        };
        if ethernet_packet.get_destination() == src_mac && ethernet_packet.get_source() == dst_mac {
            true
        } else {
            false
        }
    }
    fn match_layer3_ipv4(&self, ethernet_buff: &[u8]) -> bool {
        if self.match_layer2(ethernet_buff) || self.jump_layer2 {
            let (src_ipv4, dst_ipv4) = match self.layer3_ipv4 {
                Some((src_ipv4, dst_ipv4)) => (src_ipv4, dst_ipv4),
                None => {
                    return false;
                }
            };
            let ethernet_packet = match EthernetPacket::new(&ethernet_buff) {
                Some(ethernet_packet) => ethernet_packet,
                None => {
                    return false;
                }
            };
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => match Ipv4Packet::new(ethernet_packet.payload()) {
                    Some(ipv4_packet) => {
                        if ipv4_packet.get_destination() == src_ipv4
                            && ipv4_packet.get_source() == dst_ipv4
                        {
                            return true;
                        }
                    }
                    None => (),
                },
                _ => (),
            }
        }
        false
    }
    fn match_layer3_ipv6(&self, ethernet_buff: &[u8]) -> bool {
        if self.match_layer2(ethernet_buff) || self.jump_layer2 {
            let (src_ipv6, dst_ipv6) = match self.layer3_ipv6 {
                Some((src_ipv6, dst_ipv6)) => (src_ipv6, dst_ipv6),
                None => {
                    return false;
                }
            };
            let ethernet_packet = match EthernetPacket::new(&ethernet_buff) {
                Some(ethernet_packet) => ethernet_packet,
                None => {
                    return false;
                }
            };
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv6 => match Ipv6Packet::new(ethernet_packet.payload()) {
                    Some(ipv6_packet) => {
                        if ipv6_packet.get_destination() == src_ipv6
                            && ipv6_packet.get_source() == dst_ipv6
                        {
                            return true;
                        }
                    }
                    None => (),
                },
                _ => (),
            }
        }
        false
    }
    fn _match_tcp(src: u16, dst: u16, tcp_buff: &[u8]) -> bool {
        match TcpPacket::new(tcp_buff) {
            Some(tcp_packet) => {
                if tcp_packet.get_destination() == src && tcp_packet.get_source() == dst {
                    return true;
                }
            }
            None => (),
        }
        false
    }
    fn _match_udp(src: u16, dst: u16, udp_buff: &[u8]) -> bool {
        match UdpPacket::new(udp_buff) {
            Some(udp_packet) => {
                if udp_packet.get_destination() == src && udp_packet.get_source() == dst {
                    return true;
                }
            }
            None => (),
        }
        false
    }
    fn match_layer4_tcp_udp(&self, ethernet_buff: &[u8]) -> bool {
        if self.match_layer2(ethernet_buff) || self.jump_layer2 {
            let (src_port, dst_port) = match self.layer4_tcp_udp {
                Some((src_port, dst_port)) => (src_port, dst_port),
                None => {
                    return false;
                }
            };
            let ethernet_packet = match EthernetPacket::new(&ethernet_buff) {
                Some(ethernet_packet) => ethernet_packet,
                None => {
                    return false;
                }
            };
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => match Ipv4Packet::new(ethernet_packet.payload()) {
                    Some(ipv4_packet) => match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            return RespMatch::_match_tcp(
                                src_port,
                                dst_port,
                                ipv4_packet.payload(),
                            );
                        }
                        IpNextHeaderProtocols::Udp => {
                            return RespMatch::_match_udp(
                                src_port,
                                dst_port,
                                ipv4_packet.payload(),
                            );
                        }
                        _ => (),
                    },
                    None => (),
                },
                EtherTypes::Ipv6 => match Ipv6Packet::new(ethernet_packet.payload()) {
                    Some(ipv6_packet) => match ipv6_packet.get_next_header() {
                        IpNextHeaderProtocols::Tcp => {
                            return RespMatch::_match_tcp(
                                src_port,
                                dst_port,
                                ipv6_packet.payload(),
                            );
                        }
                        IpNextHeaderProtocols::Udp => {
                            return RespMatch::_match_udp(
                                src_port,
                                dst_port,
                                ipv6_packet.payload(),
                            );
                        }
                        _ => (),
                    },
                    None => (),
                },
                _ => (),
            }
        }
        false
    }
    fn _match_icmp(icmp_type: IcmpType, icmp_code: IcmpCode, icmp_buff: &[u8]) -> bool {
        match IcmpPacket::new(icmp_buff) {
            Some(icmp_packet) => {
                if icmp_packet.get_icmp_type() == icmp_type
                    && icmp_packet.get_icmp_code() == icmp_code
                {
                    return true;
                }
            }
            None => (),
        }
        false
    }
    fn _match_icmpv6(icmp_type: Icmpv6Type, icmp_code: Icmpv6Code, icmpv6_buff: &[u8]) -> bool {
        match Icmpv6Packet::new(icmpv6_buff) {
            Some(icmpv6_packet) => {
                if icmpv6_packet.get_icmpv6_type() == icmp_type
                    && icmpv6_packet.get_icmpv6_code() == icmp_code
                {
                    return true;
                }
            }
            None => (),
        }
        false
    }
    fn match_layer4_icmp(&self, ethernet_buff: &[u8]) -> bool {
        if self.match_layer2(ethernet_buff) || self.jump_layer2 {
            let (src_ipv4, dst_ipv4) = match self.layer4_icmp {
                Some((src_ipv4, dst_ipv4)) => (src_ipv4, dst_ipv4),
                None => {
                    return false;
                }
            };
            let ethernet_packet = match EthernetPacket::new(&ethernet_buff) {
                Some(ethernet_packet) => ethernet_packet,
                None => {
                    return false;
                }
            };
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => match Ipv4Packet::new(ethernet_packet.payload()) {
                    Some(ipv4_packet) => match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Icmp => {
                            if ipv4_packet.get_destination() == src_ipv4
                                && ipv4_packet.get_source() == dst_ipv4
                            {
                                return true;
                            }
                        }
                        _ => (),
                    },
                    None => (),
                },
                _ => (),
            }
        }
        false
    }
    fn match_layer4_icmpv6(&self, ethernet_buff: &[u8]) -> bool {
        if self.match_layer2(ethernet_buff) || self.jump_layer2 {
            let (src_ipv6, dst_ipv6) = match self.layer4_icmpv6 {
                Some((src_ipv6, dst_ipv6)) => (src_ipv6, dst_ipv6),

                None => {
                    return false;
                }
            };
            // println!("{} - {}", src_ipv6, dst_ipv6);
            let ethernet_packet = match EthernetPacket::new(&ethernet_buff) {
                Some(ethernet_packet) => ethernet_packet,
                None => {
                    return false;
                }
            };
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv6 => match Ipv6Packet::new(ethernet_packet.payload()) {
                    Some(ipv6_packet) => match ipv6_packet.get_next_header() {
                        IpNextHeaderProtocols::Icmpv6 => {
                            if ipv6_packet.get_destination() == src_ipv6
                                && ipv6_packet.get_source() == dst_ipv6
                            {
                                return true;
                            }
                        }
                        _ => (),
                    },
                    None => (),
                },
                _ => (),
            }
        }
        false
    }
    fn match_layer4_icmp_specific(&self, ethernet_buff: &[u8]) -> bool {
        if self.match_layer2(ethernet_buff) || self.jump_layer2 {
            let (icmp_type, icmp_code) = match self.layer4_icmp_specific {
                Some((icmp_type, icmp_code)) => (icmp_type, icmp_code),
                None => {
                    return false;
                }
            };
            let ethernet_packet = match EthernetPacket::new(&ethernet_buff) {
                Some(ethernet_packet) => ethernet_packet,
                None => {
                    return false;
                }
            };
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => match Ipv4Packet::new(ethernet_packet.payload()) {
                    Some(ipv4_packet) => match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Icmp => {
                            return RespMatch::_match_icmp(
                                icmp_type,
                                icmp_code,
                                ipv4_packet.payload(),
                            );
                        }
                        _ => (),
                    },
                    None => (),
                },
                _ => (),
            }
        }
        false
    }
    fn match_layer4_icmpv6_specific(&self, ethernet_buff: &[u8]) -> bool {
        if self.match_layer2(ethernet_buff) || self.jump_layer2 {
            let (icmpv6_type, icmpv6_code) = match self.layer4_icmpv6_specific {
                Some((icmpv6_type, icmpv6_code)) => (icmpv6_type, icmpv6_code),
                None => {
                    return false;
                }
            };
            let ethernet_packet = match EthernetPacket::new(&ethernet_buff) {
                Some(ethernet_packet) => ethernet_packet,
                None => {
                    return false;
                }
            };
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv6 => match Ipv6Packet::new(ethernet_packet.payload()) {
                    Some(ipv6_packet) => match ipv6_packet.get_next_header() {
                        IpNextHeaderProtocols::Icmpv6 => {
                            return RespMatch::_match_icmpv6(
                                icmpv6_type,
                                icmpv6_code,
                                ipv6_packet.payload(),
                            );
                        }
                        _ => (),
                    },
                    None => (),
                },
                _ => (),
            }
        }
        false
    }
    pub fn match_packet(&self, ethernet_buff: &[u8]) -> bool {
        match self.layer {
            Layers::Layer2 => self.match_layer2(ethernet_buff),
            Layers::Layer3Ipv4 => self.match_layer3_ipv4(ethernet_buff),
            Layers::Layer3Ipv6 => self.match_layer3_ipv6(ethernet_buff),
            Layers::Layer4TcpUdp => self.match_layer4_tcp_udp(ethernet_buff),
            Layers::Layer4IcmpSpecific => self.match_layer4_icmp_specific(ethernet_buff),
            Layers::Layer4Icmpv6Specific => self.match_layer4_icmpv6_specific(ethernet_buff),
            Layers::Layer4Icmp => self.match_layer4_icmp(ethernet_buff),
            Layers::Layer4Icmpv6 => self.match_layer4_icmpv6(ethernet_buff),
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

fn layer_2_ipv4_send(
    dst_mac: MacAddr,
    interface: NetworkInterface,
    send_buff: &[u8],
    mut match_objects: Vec<RespMatch>,
    max_loop: usize,
) -> Result<Option<Vec<u8>>> {
    let (mut sender, mut receiver) = match datalink_channel(&interface)? {
        Some((s, r)) => (s, r),
        None => return Err(CreateDatalinkChannelFailed::new().into()),
    };

    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(CanNotFoundMacAddress::new().into()),
    };

    for m in match_objects.iter_mut() {
        m.layer2 = Some((src_mac, dst_mac));
    }

    let mut ethernet_buff = [0u8; ETHERNET_BUFF_SIZE];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buff).unwrap();

    ethernet_packet.set_destination(dst_mac);
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);
    ethernet_packet.set_payload(send_buff);

    let final_buff = ethernet_buff[..ETHERNET_HEADER_SIZE + send_buff.len()].to_vec();
    // print_packet_as_wireshark(&final_buff);

    match sender.send_to(&final_buff, Some(interface)) {
        _ => (),
    }

    for _ in 0..max_loop {
        let buff = receiver.next()?;
        for m in &match_objects {
            match m.match_packet(buff) {
                true => return Ok(Some(buff.to_vec())),
                false => (),
            }
        }
    }
    Ok(None)
}

fn layer2_ipv6_send(
    dst_mac: MacAddr,
    interface: NetworkInterface,
    send_buff: &[u8],
    mut match_objects: Vec<RespMatch>,
    max_loop: usize,
) -> Result<Option<Vec<u8>>> {
    let (mut sender, mut receiver) = match datalink_channel(&interface)? {
        Some((s, r)) => (s, r),
        None => return Err(CreateDatalinkChannelFailed::new().into()),
    };

    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(CanNotFoundMacAddress::new().into()),
    };

    for m in match_objects.iter_mut() {
        m.layer2 = Some((src_mac, dst_mac));
    }

    let mut ethernet_buff = [0u8; ETHERNET_BUFF_SIZE];
    // let mut ethernet_buff = [0u8; ETHERNET_HEADER_SIZE + send_buff.len()];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buff).unwrap();

    ethernet_packet.set_destination(dst_mac);
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(EtherTypes::Ipv6);
    ethernet_packet.set_payload(send_buff);

    let final_buff = ethernet_buff[..ETHERNET_HEADER_SIZE + send_buff.len()].to_vec();
    // print_packet_as_wireshark(&final_buff);

    match sender.send_to(&final_buff, Some(interface)) {
        _ => (),
    }

    for _ in 0..max_loop {
        let buff = receiver.next()?;
        for m in &match_objects {
            match m.match_packet(buff) {
                true => return Ok(Some(buff.to_vec())),
                false => (),
            }
        }
    }
    Ok(None)
}

fn system_neighbour_cache() -> Result<Option<HashMap<IpAddr, MacAddr>>> {
    if cfg!(target_os = "linux") {
        // ip neighbour
        let c = Command::new("ip").arg("neighbour").output()?;
        // 192.168.72.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE
        // 192.168.72.254 dev ens33 lladdr 00:50:56:fa:d4:85 STALE
        // 192.168.72.2 dev ens33 lladdr 00:50:56:ff:8c:06 STALE
        // fe80::47c:7f4a:10a8:7f4a dev ens33 lladdr 00:50:56:c0:00:08 STALE
        let output = String::from_utf8_lossy(&c.stdout);
        let lines: Vec<&str> = output.split("\n").filter(|v| v.len() > 0).collect();
        let mut ret: HashMap<IpAddr, MacAddr> = HashMap::new();
        for line in lines {
            let l_split: Vec<&str> = line.split(" ").filter(|v| v.len() > 0).collect();
            if l_split.len() >= 6 {
                let ip_str = l_split[0];
                // let device = l_split[2];
                let mac_str = l_split[4];
                let ip: IpAddr = ip_str.parse().unwrap();
                let mac: MacAddr = mac_str.parse().unwrap();
                ret.insert(ip, mac);
            }
        }
        return Ok(Some(ret));
    } else if cfg!(target_os = "windows") {
        // Get-NetNeighbor
        let c = Command::new("Get-NetNeighbor").output()?;
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
                let mac_str = l_split[2];
                let ip: IpAddr = ip_str.parse().unwrap();
                let mac: MacAddr = mac_str.parse().unwrap();
                ret.insert(ip, mac);
            }
        }
        return Ok(Some(ret));
    }
    Ok(None)
}

fn search_system_neighbour_cache(ip: IpAddr) -> Result<Option<MacAddr>> {
    let ret = system_neighbour_cache()?;
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

fn arp(src_ipv4: Ipv4Addr, dst_ipv4: Ipv4Addr) -> Result<Option<MacAddr>> {
    let interface = match find_interface_by_ipv4(src_ipv4) {
        Some(i) => i,
        None => return Err(CanNotFoundInterface::new().into()),
    };

    let (mut sender, mut receiver) = match datalink_channel(&interface)? {
        Some((s, r)) => (s, r),
        None => return Err(CreateDatalinkChannelFailed::new().into()),
    };

    let mut ethernet_buff = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buff).unwrap();

    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(CanNotFoundMacAddress::new().into()),
    };

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(src_mac);
    arp_packet.set_sender_proto_addr(src_ipv4);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(dst_ipv4);

    ethernet_packet.set_payload(&arp_buffer);

    // ignore the send unexpect error
    match sender.send_to(ethernet_packet.packet(), None) {
        _ => (),
    }

    let max_loop = 16;
    for _ in 0..max_loop {
        let buf = receiver.next()?;
        let re = EthernetPacket::new(buf).unwrap();
        match re.get_ethertype() {
            EtherTypes::Arp => {
                let arp = ArpPacket::new(re.payload()).unwrap();
                if arp.get_sender_proto_addr() == dst_ipv4 && arp.get_target_hw_addr() == src_mac {
                    return Ok(Some(arp.get_sender_hw_addr()));
                }
            }
            _ => (),
        }
    }
    Ok(None)
}

pub fn layer3_ipv4_send(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    payload: &[u8],
    match_objects: Vec<RespMatch>,
    max_loop: usize,
) -> Result<Option<Vec<u8>>> {
    let dst_mac = match search_system_neighbour_cache(dst_ipv4.into())? {
        Some(m) => m,
        None => {
            let mut mac: Option<MacAddr> = None;
            for _ in 0..NEIGNBOUR_MAX_TRY {
                match arp(src_ipv4, dst_ipv4)? {
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
    };
    let interface = match find_interface_by_ipv4(src_ipv4) {
        Some(i) => i,
        None => return Err(CanNotFoundInterface::new().into()),
    };

    let layer2_buff = layer_2_ipv4_send(dst_mac, interface, payload, match_objects, max_loop)?;
    match layer2_buff {
        Some(layer2_packet) => Ok(Some(layer2_payload(&layer2_packet))),
        None => Ok(None),
    }
}

pub fn multicast_mac(ip: Ipv6Addr) -> MacAddr {
    let ip = ip.octets();
    // 33:33:FF:xx:xx:xx
    MacAddr::new(0x33, 0x33, 0xFF, ip[13], ip[14], ip[15])
}

fn get_mac_from_ndp_options(buff: &[u8]) -> Option<MacAddr> {
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

fn ndp(src_ipv6: Ipv6Addr, dst_ipv6: Ipv6Addr) -> Result<Option<MacAddr>> {
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

    // let match_ipv6 = MatchResp::new_layer3_ipv6(src_ipv6, dst_ipv6);
    let match_icmpv6 = RespMatch::new_layer4_icmpv6(src_ipv6, dst_ipv6, true);
    let max_loop = 32;

    let r = layer2_ipv6_send(
        multicast_mac(dst_ipv6),
        interface.clone(),
        &ipv6_buff,
        vec![match_icmpv6],
        max_loop,
    )?;
    let mac = match r {
        Some(r) => match match_icmpv6.match_packet(&r) {
            true => get_mac_from_ndp_options(&r),
            false => None,
        },
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
    match_objects: Vec<RespMatch>,
    max_loop: usize,
) -> Result<Option<Vec<u8>>> {
    let dst_mac = match search_system_neighbour_cache(dst_ipv6.into())? {
        Some(m) => m,
        None => {
            let mut mac: Option<MacAddr> = None;
            for _ in 0..NEIGNBOUR_MAX_TRY {
                match ndp(src_ipv6, dst_ipv6)? {
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
    };
    let interface = match find_interface_by_ipv6(src_ipv6) {
        Some(i) => i,
        None => return Err(CanNotFoundInterface::new().into()),
    };

    let layer2_buff = layer2_ipv6_send(dst_mac, interface, payload, match_objects, max_loop)?;
    match layer2_buff {
        Some(layer2_packet) => Ok(Some(layer2_payload(&layer2_packet))),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_send_arp_packet() {
        let src_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 72, 1);
        match arp(src_ipv4, dst_ipv4).unwrap() {
            Some(m) => {
                println!("{}", m);
            }
            None => println!("None"),
        }
    }
    #[test]
    fn test_send_ndp_packet() {
        let src_ipv6: Ipv6Addr = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        // let dst_ipv6 = "fe80::47c:7f4a:10a8:7f4a".parse().unwrap();
        match ndp(src_ipv6, dst_ipv6).unwrap() {
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
}
