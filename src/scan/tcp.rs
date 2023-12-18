use anyhow::Result;
use pnet::packet::icmp::{destination_unreachable, IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::{checksum, Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use rand::Rng;
use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::TcpStream;

use crate::layers::{layer3_ipv4_send, MatchResp};
use crate::layers::{IPV4_HEADER_SIZE, TCP_HEADER_SIZE};
use crate::IdleScanResults;
use crate::TargetScanStatus;

const TCP_DATA_SIZE: usize = 0;
const TTL: u8 = 64;

/* IdleScanAllZeroError */
#[derive(Debug, Clone)]
struct IdleScanAllZeroError {
    zombie_ipv4: Ipv4Addr,
    zombie_port: u16,
}

impl fmt::Display for IdleScanAllZeroError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "idle scan zombie {} port {} cannot be used because IP ID sequence class is: all zeros, try another proxy", self.zombie_ipv4, self.zombie_port)
    }
}

impl IdleScanAllZeroError {
    pub fn new(zombie_ipv4: Ipv4Addr, zombie_port: u16) -> IdleScanAllZeroError {
        IdleScanAllZeroError {
            zombie_ipv4,
            zombie_port,
        }
    }
}

impl Error for IdleScanAllZeroError {}

// const TCP_FLAGS_CWR_MASK: u8 = 0b10000000;
// const TCP_FLAGS_ECE_MASK: u8 = 0b01000000;
// const TCP_FLAGS_URG_MASK: u8 = 0b00100000;
// const TCP_FLAGS_ACK_MASK: u8 = 0b00010000;
// const TCP_FLAGS_PSH_MASK: u8 = 0b00001000;
const TCP_FLAGS_RST_MASK: u8 = 0b00000100;
// const TCP_FLAGS_SYN_MASK: u8 = 0b00000010;
// const TCP_FLAGS_FIN_MASK: u8 = 0b00000001;

pub fn send_syn_scan_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    max_loop: usize,
) -> Result<TargetScanStatus> {
    let mut rng = rand::thread_rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    let match_object_1 = MatchResp::new_layer4_tcp_udp(src_port, dst_port, false);
    let match_object_2 = MatchResp::new_layer4_icmp(src_ipv4, dst_ipv4, false);

    let ret = layer3_ipv4_send(
        src_ipv4,
        dst_ipv4,
        &ip_buff,
        vec![match_object_1, match_object_2],
        max_loop,
    )?;
    match ret {
        Some(r) => {
            match Ipv4Packet::new(&r) {
                Some(ipv4_packet) => {
                    match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            match TcpPacket::new(ipv4_packet.payload()) {
                                Some(tcp_packet) => {
                                    let tcp_flags = tcp_packet.get_flags();
                                    if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                                        // tcp syn/ack response
                                        return Ok(TargetScanStatus::Open);
                                    } else if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                        // tcp rst response
                                        return Ok(TargetScanStatus::Closed);
                                    }
                                }
                                None => (),
                            }
                        }
                        IpNextHeaderProtocols::Icmp => {
                            match IcmpPacket::new(ipv4_packet.payload()) {
                                Some(icmp_packet) => {
                                    let icmp_type = icmp_packet.get_icmp_type();
                                    let icmp_code = icmp_packet.get_icmp_code();
                                    let codes = vec![
                                        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
                                        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
                                        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
                                        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
                                        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
                                        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
                                    ];
                                    if icmp_type == IcmpTypes::DestinationUnreachable
                                        && codes.contains(&icmp_code)
                                    {
                                        // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                        return Ok(TargetScanStatus::Filtered);
                                    }
                                }
                                None => (),
                            }
                        }
                        _ => (),
                    }
                }
                None => (),
            }
        }
        None => (),
    }
    // no response received (even after retransmissions)
    Ok(TargetScanStatus::Filtered)
}

pub fn send_fin_scan_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    max_loop: usize,
) -> Result<TargetScanStatus> {
    let mut rng = rand::thread_rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_header = MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::FIN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    let match_object_1 = MatchResp::new_layer4_tcp_udp(src_port, dst_port, false);
    let match_object_2 = MatchResp::new_layer4_icmp(src_ipv4, dst_ipv4, false);

    let ret = layer3_ipv4_send(
        src_ipv4,
        dst_ipv4,
        &ip_buff,
        vec![match_object_1, match_object_2],
        max_loop,
    )?;
    match ret {
        Some(r) => {
            match Ipv4Packet::new(&r) {
                Some(ipv4_packet) => {
                    match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            match TcpPacket::new(ipv4_packet.payload()) {
                                Some(tcp_packet) => {
                                    let tcp_flags = tcp_packet.get_flags();
                                    if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                                        // tcp syn/ack response
                                        return Ok(TargetScanStatus::Open);
                                    } else if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                        // tcp rst packet
                                        return Ok(TargetScanStatus::Closed);
                                    }
                                }
                                None => (),
                            }
                        }
                        IpNextHeaderProtocols::Icmp => {
                            match IcmpPacket::new(ipv4_packet.payload()) {
                                Some(icmp_packet) => {
                                    let icmp_type = icmp_packet.get_icmp_type();
                                    let icmp_code = icmp_packet.get_icmp_code();
                                    let codes = vec![
                                        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
                                        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
                                        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
                                        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
                                        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
                                        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
                                    ];
                                    if icmp_type == IcmpTypes::DestinationUnreachable
                                        && codes.contains(&icmp_code)
                                    {
                                        // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                        return Ok(TargetScanStatus::Filtered);
                                    }
                                }
                                None => (),
                            }
                        }
                        _ => (),
                    }
                }
                None => (),
            }
        }
        None => (),
    }
    // no response received (even after retransmissions)
    Ok(TargetScanStatus::OpenOrFiltered)
}

pub fn send_ack_scan_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    max_loop: usize,
) -> Result<TargetScanStatus> {
    let mut rng = rand::thread_rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_header = MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    let match_object_1 = MatchResp::new_layer4_tcp_udp(src_port, dst_port, false);
    let match_object_2 = MatchResp::new_layer4_icmp(src_ipv4, dst_ipv4, false);

    let ret = layer3_ipv4_send(
        src_ipv4,
        dst_ipv4,
        &ip_buff,
        vec![match_object_1, match_object_2],
        max_loop,
    )?;
    match ret {
        Some(r) => {
            match Ipv4Packet::new(&r) {
                Some(ipv4_packet) => {
                    match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            match TcpPacket::new(ipv4_packet.payload()) {
                                Some(tcp_packet) => {
                                    let tcp_flags = tcp_packet.get_flags();
                                    if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                        // tcp rst response
                                        return Ok(TargetScanStatus::Unfiltered);
                                    }
                                }
                                None => (),
                            }
                        }
                        IpNextHeaderProtocols::Icmp => {
                            match IcmpPacket::new(ipv4_packet.payload()) {
                                Some(icmp_packet) => {
                                    let icmp_type = icmp_packet.get_icmp_type();
                                    let icmp_code = icmp_packet.get_icmp_code();
                                    let codes = vec![
                                        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
                                        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
                                        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
                                        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
                                        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
                                        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
                                    ];
                                    if icmp_type == IcmpTypes::DestinationUnreachable
                                        && codes.contains(&icmp_code)
                                    {
                                        // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                        return Ok(TargetScanStatus::Filtered);
                                    }
                                }
                                None => (),
                            }
                        }
                        _ => (),
                    }
                }
                None => (),
            }
        }
        None => (),
    }
    // no response received (even after retransmissions)
    Ok(TargetScanStatus::Filtered)
}

pub fn send_null_scan_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    max_loop: usize,
) -> Result<TargetScanStatus> {
    let mut rng = rand::thread_rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_header = MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(0);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    let match_object_1 = MatchResp::new_layer4_tcp_udp(src_port, dst_port, false);
    let match_object_2 = MatchResp::new_layer4_icmp(src_ipv4, dst_ipv4, false);

    let ret = layer3_ipv4_send(
        src_ipv4,
        dst_ipv4,
        &ip_buff,
        vec![match_object_1, match_object_2],
        max_loop,
    )?;
    match ret {
        Some(r) => {
            match Ipv4Packet::new(&r) {
                Some(ipv4_packet) => {
                    match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            match TcpPacket::new(ipv4_packet.payload()) {
                                Some(tcp_packet) => {
                                    let tcp_flags = tcp_packet.get_flags();
                                    if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                        // tcp rst response
                                        return Ok(TargetScanStatus::Closed);
                                    }
                                }
                                None => (),
                            }
                        }
                        IpNextHeaderProtocols::Icmp => {
                            match IcmpPacket::new(ipv4_packet.payload()) {
                                Some(icmp_packet) => {
                                    let icmp_type = icmp_packet.get_icmp_type();
                                    let icmp_code = icmp_packet.get_icmp_code();
                                    let codes = vec![
                                        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
                                        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
                                        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
                                        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
                                        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
                                        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
                                    ];
                                    if icmp_type == IcmpTypes::DestinationUnreachable
                                        && codes.contains(&icmp_code)
                                    {
                                        // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                        return Ok(TargetScanStatus::Filtered);
                                    }
                                }
                                None => (),
                            }
                        }
                        _ => (),
                    }
                }
                None => (),
            }
        }
        None => (),
    }
    // no response received (even after retransmissions)
    Ok(TargetScanStatus::OpenOrFiltered)
}

pub fn send_xmas_scan_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    max_loop: usize,
) -> Result<TargetScanStatus> {
    let mut rng = rand::thread_rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_header = MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    let match_object_1 = MatchResp::new_layer4_tcp_udp(src_port, dst_port, false);
    let match_object_2 = MatchResp::new_layer4_icmp(src_ipv4, dst_ipv4, false);

    let ret = layer3_ipv4_send(
        src_ipv4,
        dst_ipv4,
        &ip_buff,
        vec![match_object_1, match_object_2],
        max_loop,
    )?;
    match ret {
        Some(r) => {
            match Ipv4Packet::new(&r) {
                Some(ipv4_packet) => {
                    match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            match TcpPacket::new(ipv4_packet.payload()) {
                                Some(tcp_packet) => {
                                    let tcp_flags = tcp_packet.get_flags();
                                    if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                        // tcp rst response
                                        return Ok(TargetScanStatus::Closed);
                                    }
                                }
                                None => (),
                            }
                        }
                        IpNextHeaderProtocols::Icmp => {
                            match IcmpPacket::new(ipv4_packet.payload()) {
                                Some(icmp_packet) => {
                                    let icmp_type = icmp_packet.get_icmp_type();
                                    let icmp_code = icmp_packet.get_icmp_code();
                                    let codes = vec![
                                        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
                                        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
                                        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
                                        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
                                        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
                                        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
                                    ];
                                    if icmp_type == IcmpTypes::DestinationUnreachable
                                        && codes.contains(&icmp_code)
                                    {
                                        // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                        return Ok(TargetScanStatus::Filtered);
                                    }
                                }
                                None => (),
                            }
                        }
                        _ => (),
                    }
                }
                None => (),
            }
        }
        None => (),
    }
    // no response received (even after retransmissions)
    Ok(TargetScanStatus::OpenOrFiltered)
}

pub fn send_window_scan_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    max_loop: usize,
) -> Result<TargetScanStatus> {
    let mut rng = rand::thread_rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_header = MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    let match_object_1 = MatchResp::new_layer4_tcp_udp(src_port, dst_port, false);
    let match_object_2 = MatchResp::new_layer4_icmp(src_ipv4, dst_ipv4, false);

    let ret = layer3_ipv4_send(
        src_ipv4,
        dst_ipv4,
        &ip_buff,
        vec![match_object_1, match_object_2],
        max_loop,
    )?;
    match ret {
        Some(r) => {
            match Ipv4Packet::new(&r) {
                Some(ipv4_packet) => {
                    match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            match TcpPacket::new(ipv4_packet.payload()) {
                                Some(tcp_packet) => {
                                    let tcp_flags = tcp_packet.get_flags();
                                    if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                        if tcp_packet.get_window() > 0 {
                                            // tcp rst response with non-zero window field
                                            return Ok(TargetScanStatus::Open);
                                        } else {
                                            // tcp rst response with zero window field
                                            return Ok(TargetScanStatus::Closed);
                                        }
                                    }
                                }
                                None => (),
                            }
                        }
                        IpNextHeaderProtocols::Icmp => {
                            match IcmpPacket::new(ipv4_packet.payload()) {
                                Some(icmp_packet) => {
                                    let icmp_type = icmp_packet.get_icmp_type();
                                    let icmp_code = icmp_packet.get_icmp_code();
                                    let codes = vec![
                                        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
                                        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
                                        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
                                        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
                                        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
                                        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
                                    ];
                                    if icmp_type == IcmpTypes::DestinationUnreachable
                                        && codes.contains(&icmp_code)
                                    {
                                        // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                        return Ok(TargetScanStatus::Filtered);
                                    }
                                }
                                None => (),
                            }
                        }
                        _ => (),
                    }
                }
                None => (),
            }
        }
        None => (),
    }
    // no response received (even after retransmissions)
    Ok(TargetScanStatus::Filtered)
}

pub fn send_maimon_scan_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    max_loop: usize,
) -> Result<TargetScanStatus> {
    let mut rng = rand::thread_rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_header = MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::FIN | TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    let match_object_1 = MatchResp::new_layer4_tcp_udp(src_port, dst_port, false);
    let match_object_2 = MatchResp::new_layer4_icmp(src_ipv4, dst_ipv4, false);

    let ret = layer3_ipv4_send(
        src_ipv4,
        dst_ipv4,
        &ip_buff,
        vec![match_object_1, match_object_2],
        max_loop,
    )?;
    match ret {
        Some(r) => {
            match Ipv4Packet::new(&r) {
                Some(ipv4_packet) => {
                    match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            match TcpPacket::new(ipv4_packet.payload()) {
                                Some(tcp_packet) => {
                                    let tcp_flags = tcp_packet.get_flags();
                                    if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                        // tcp rst response
                                        return Ok(TargetScanStatus::Closed);
                                    }
                                }
                                None => (),
                            }
                        }
                        IpNextHeaderProtocols::Icmp => {
                            match IcmpPacket::new(ipv4_packet.payload()) {
                                Some(icmp_packet) => {
                                    let icmp_type = icmp_packet.get_icmp_type();
                                    let icmp_code = icmp_packet.get_icmp_code();
                                    let codes = vec![
                                        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
                                        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
                                        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
                                        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
                                        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
                                        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
                                    ];
                                    if icmp_type == IcmpTypes::DestinationUnreachable
                                        && codes.contains(&icmp_code)
                                    {
                                        // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                        return Ok(TargetScanStatus::Filtered);
                                    }
                                }
                                None => (),
                            }
                        }
                        _ => (),
                    }
                }
                None => (),
            }
        }
        None => (),
    }
    // no response received (even after retransmissions)
    Ok(TargetScanStatus::OpenOrFiltered)
}

pub fn send_idle_scan_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    zombie_ipv4: Ipv4Addr,
    zombie_port: u16,
    max_loop: usize,
) -> Result<(TargetScanStatus, Option<IdleScanResults>)> {
    fn _forge_syn_packet(
        src_ipv4: Ipv4Addr,
        dst_ipv4: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        // ip header
        let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
        let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_source(src_ipv4);
        ip_header.set_destination(dst_ipv4);
        ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
        let id = rng.gen();
        ip_header.set_identification(id);
        ip_header.set_flags(Ipv4Flags::DontFragment);
        ip_header.set_ttl(TTL);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        let c = checksum(&ip_header.to_immutable());
        ip_header.set_checksum(c);

        // tcp header
        let mut tcp_header = MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]).unwrap();
        tcp_header.set_source(src_port);
        tcp_header.set_destination(dst_port);
        tcp_header.set_sequence(rng.gen());
        tcp_header.set_acknowledgement(rng.gen());
        tcp_header.set_reserved(0);
        tcp_header.set_flags(TcpFlags::SYN);
        tcp_header.set_urgent_ptr(0);
        tcp_header.set_window(1024);
        tcp_header.set_data_offset(5);
        let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
        tcp_header.set_checksum(checksum);

        Ok(ip_buff.to_vec())
    }

    // 1. probe the zombie's ip id
    let match_tcp_zombie = MatchResp::new_layer4_tcp_udp(src_port, zombie_port, false);
    let match_icmp_zombie = MatchResp::new_layer4_icmp(src_ipv4, zombie_ipv4, false);
    let ip_buff = _forge_syn_packet(src_ipv4, zombie_ipv4, src_port, zombie_port)?;
    let ret = layer3_ipv4_send(
        src_ipv4,
        zombie_ipv4,
        &ip_buff,
        vec![match_tcp_zombie, match_icmp_zombie],
        max_loop,
    )?;

    let mut zombie_ip_id_1 = 0;
    match ret {
        Some(r) => {
            match Ipv4Packet::new(&r) {
                Some(ipv4_packet) => {
                    match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            match TcpPacket::new(ipv4_packet.payload()) {
                                Some(tcp_packet) => {
                                    // println!(">>> {}", tcp_packet.get_flags());
                                    let tcp_flags = tcp_packet.get_flags();
                                    if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                        // 2. zombie return rst packet, get this packet ip id
                                        zombie_ip_id_1 = ipv4_packet.get_identification();
                                    }
                                }
                                None => (),
                            }
                        }
                        IpNextHeaderProtocols::Icmp => {
                            match IcmpPacket::new(ipv4_packet.payload()) {
                                Some(icmp_packet) => {
                                    let icmp_type = icmp_packet.get_icmp_type();
                                    let icmp_code = icmp_packet.get_icmp_code();
                                    let codes = vec![
                                        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
                                        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
                                        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
                                        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
                                        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
                                        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
                                    ];
                                    if icmp_type == IcmpTypes::DestinationUnreachable
                                        && codes.contains(&icmp_code)
                                    {
                                        // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                        // dst is unreachable ignore this port
                                        return Ok((TargetScanStatus::Unreachable, None));
                                    }
                                }
                                None => (),
                            }
                        }
                        _ => (),
                    }
                }
                None => (),
            }
        }
        None => (),
    }

    // 3. forge a syn packet from the zombie to the target
    let ip_buff_2 = _forge_syn_packet(zombie_ipv4, dst_ipv4, zombie_port, dst_port)?;
    // ignore the response
    let _ret = layer3_ipv4_send(src_ipv4, dst_ipv4, &ip_buff_2, vec![], max_loop)?;

    // 4. probe the zombie's ip id again
    let ip_buff_3 = _forge_syn_packet(src_ipv4, zombie_ipv4, src_port, zombie_port)?;
    let match_tcp = MatchResp::new_layer4_tcp_udp(src_port, dst_port, false);
    let match_icmp = MatchResp::new_layer4_icmp(src_ipv4, dst_ipv4, false);
    let ret = layer3_ipv4_send(
        src_ipv4,
        dst_ipv4,
        &ip_buff_3,
        vec![match_tcp, match_icmp],
        max_loop,
    )?;

    let mut zombie_ip_id_2 = 0;
    match ret {
        Some(r) => {
            match Ipv4Packet::new(&r) {
                Some(ipv4_packet) => {
                    match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            match TcpPacket::new(ipv4_packet.payload()) {
                                Some(tcp_packet) => {
                                    // println!(">>> {}", tcp_packet.get_flags());
                                    let tcp_flags = tcp_packet.get_flags();
                                    if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                        // 5. zombie return rst packet again, get this packet ip id
                                        zombie_ip_id_2 = ipv4_packet.get_identification();
                                    }
                                }
                                None => (),
                            }
                        }
                        IpNextHeaderProtocols::Icmp => {
                            match IcmpPacket::new(ipv4_packet.payload()) {
                                Some(icmp_packet) => {
                                    let icmp_type = icmp_packet.get_icmp_type();
                                    let icmp_code = icmp_packet.get_icmp_code();
                                    let codes = vec![
                                        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
                                        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
                                        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
                                        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
                                        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
                                        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
                                    ];
                                    if icmp_type == IcmpTypes::DestinationUnreachable
                                        && codes.contains(&icmp_code)
                                    {
                                        // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                        // dst is unreachable ignore this port
                                        return Ok((TargetScanStatus::Unreachable, None));
                                    }
                                }
                                None => (),
                            }
                        }
                        _ => (),
                    }
                }
                None => (),
            }
        }
        None => (),
    }
    if zombie_ip_id_1 == 0 && zombie_ip_id_2 == 0 {
        return Err(IdleScanAllZeroError::new(zombie_ipv4, zombie_port).into());
    } else if zombie_ip_id_2 - zombie_ip_id_1 >= 2 {
        Ok((
            TargetScanStatus::Open,
            Some(IdleScanResults {
                zombie_ip_id_1,
                zombie_ip_id_2,
            }),
        ))
    } else {
        Ok((
            TargetScanStatus::ClosedOrFiltered,
            Some(IdleScanResults {
                zombie_ip_id_1,
                zombie_ip_id_2,
            }),
        ))
    }
}

pub fn send_connect_scan_packet(
    _: Ipv4Addr,
    _: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    _: usize,
) -> Result<TargetScanStatus> {
    let addr = SocketAddr::V4(SocketAddrV4::new(dst_ipv4, dst_port));
    match TcpStream::connect(&addr) {
        Ok(_) => Ok(TargetScanStatus::Open),
        Err(_) => Ok(TargetScanStatus::Closed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;
    #[test]
    fn test_send_syn_scan_packet() {
        // let src_ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        // let dst_ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 134);
        let src_port = utils::random_port();
        let dst_port = 99;
        // let dst_port = 80;
        let max_loop = 32;
        let ret = send_syn_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, max_loop).unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_fin_scan_packet() {
        // let src_ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        // let dst_ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 134);
        let src_port = utils::random_port();
        // let dst_port = 99;
        let dst_port = 80;
        let max_loop = 32;
        let ret = send_fin_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, max_loop);
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_ack_scan_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 134);
        let src_port = utils::random_port();
        // let dst_port = 99;
        let dst_port = 80;
        let max_loop = 32;
        let ret = send_ack_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, max_loop);
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_null_scan_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 134);
        let src_port = utils::random_port();
        // let dst_port = 99;
        let dst_port = 80;
        let max_loop = 32;
        let ret = send_null_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, max_loop);
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_window_scan_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 134);
        let src_port = utils::random_port();
        // let dst_port = 99;
        let dst_port = 80;
        let max_loop = 32;
        let ret = send_window_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, max_loop);
        println!("{:?}", ret);
    }
    #[test]
    #[should_panic]
    fn test_send_idle_scan_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 134);
        let zombie_ipv4 = Ipv4Addr::new(192, 168, 72, 135);

        let src_port = utils::random_port();
        let dst_port = 22;
        let zombie_port = utils::random_port();
        let max_loop = 32;
        let (ret, i) = send_idle_scan_packet(
            src_ipv4,
            src_port,
            dst_ipv4,
            dst_port,
            zombie_ipv4,
            zombie_port,
            max_loop,
        )
        .unwrap();
        println!("{:?}", ret);
        println!("{:?}", i.unwrap());
    }
    #[test]
    fn test_send_tcp_connect_scan_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 134);
        let max_loop = 64;
        let src_port = utils::random_port();
        let dst_port = 80;
        let ret =
            send_connect_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, max_loop).unwrap();
        println!("{:?}", ret);
    }
}
