use anyhow::Result;
use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::tcp::{ipv6_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use rand::Rng;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV6;
use std::net::TcpStream;

use crate::layers::layer3_ipv6_send;
use crate::layers::RespMatch;
use crate::layers::{IPV6_HEADER_SIZE, TCP_HEADER_SIZE};
use crate::TargetScanStatus;

// const TCP_FLAGS_CWR_MASK: u8 = 0b10000000;
// const TCP_FLAGS_ECE_MASK: u8 = 0b01000000;
// const TCP_FLAGS_URG_MASK: u8 = 0b00100000;
// const TCP_FLAGS_ACK_MASK: u8 = 0b00010000;
// const TCP_FLAGS_PSH_MASK: u8 = 0b00001000;
const TCP_FLAGS_RST_MASK: u8 = 0b00000100;
// const TCP_FLAGS_SYN_MASK: u8 = 0b00000010;
// const TCP_FLAGS_FIN_MASK: u8 = 0b00000001;

const TCP_DATA_SIZE: usize = 0;
const TTL: u8 = 255;

pub fn send_syn_scan_packet(
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    max_loop: usize,
) -> Result<TargetScanStatus> {
    let mut rng = rand::thread_rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = MutableIpv6Packet::new(&mut ipv6_buff).unwrap();
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    ipv6_header.set_hop_limit(TTL);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let match_object_1 = RespMatch::new_layer4_tcp_udp(src_port, dst_port, false);
    let match_object_2 = RespMatch::new_layer4_icmpv6(src_ipv6, dst_ipv6, false);

    let ret = layer3_ipv6_send(
        src_ipv6,
        dst_ipv6,
        &ipv6_buff,
        vec![match_object_1, match_object_2],
        max_loop,
    )?;

    match ret {
        Some(r) => {
            match Ipv6Packet::new(&r) {
                Some(ipv6_packet) => {
                    match ipv6_packet.get_next_header() {
                        IpNextHeaderProtocols::Tcp => {
                            match TcpPacket::new(ipv6_packet.payload()) {
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
                        IpNextHeaderProtocols::Icmpv6 => {
                            match Icmpv6Packet::new(ipv6_packet.payload()) {
                                Some(icmpv6_packet) => {
                                    let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                                    let icmpv6_code = icmpv6_packet.get_icmpv6_code();
                                    let codes = vec![
                                        Icmpv6Code(1), // communication with destination administratively prohibited
                                        Icmpv6Code(3), // address unreachable
                                        Icmpv6Code(4), // port unreachable
                                    ];
                                    if icmpv6_type == Icmpv6Types::DestinationUnreachable
                                        && codes.contains(&icmpv6_code)
                                    {
                                        // icmp unreachable error (type 3, code 1, 3, or 4)
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
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    max_loop: usize,
) -> Result<TargetScanStatus> {
    let mut rng = rand::thread_rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = MutableIpv6Packet::new(&mut ipv6_buff).unwrap();
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    ipv6_header.set_hop_limit(TTL);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::FIN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let match_object_1 = RespMatch::new_layer4_tcp_udp(src_port, dst_port, false);
    let match_object_2 = RespMatch::new_layer4_icmpv6(src_ipv6, dst_ipv6, false);

    let ret = layer3_ipv6_send(
        src_ipv6,
        dst_ipv6,
        &ipv6_buff,
        vec![match_object_1, match_object_2],
        max_loop,
    )?;

    match ret {
        Some(r) => {
            match Ipv6Packet::new(&r) {
                Some(ipv6_packet) => {
                    match ipv6_packet.get_next_header() {
                        IpNextHeaderProtocols::Tcp => {
                            match TcpPacket::new(ipv6_packet.payload()) {
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
                        IpNextHeaderProtocols::Icmpv6 => {
                            match Icmpv6Packet::new(ipv6_packet.payload()) {
                                Some(icmpv6_packet) => {
                                    let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                                    let icmpv6_code = icmpv6_packet.get_icmpv6_code();
                                    let codes = vec![
                                        Icmpv6Code(1), // communication with destination administratively prohibited
                                        Icmpv6Code(3), // address unreachable
                                        Icmpv6Code(4), // port unreachable
                                    ];
                                    if icmpv6_type == Icmpv6Types::DestinationUnreachable
                                        && codes.contains(&icmpv6_code)
                                    {
                                        // icmp unreachable error (type 3, code 1, 3, or 4)
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
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    max_loop: usize,
) -> Result<TargetScanStatus> {
    let mut rng = rand::thread_rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = MutableIpv6Packet::new(&mut ipv6_buff).unwrap();
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    ipv6_header.set_hop_limit(TTL);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let match_object_1 = RespMatch::new_layer4_tcp_udp(src_port, dst_port, false);
    let match_object_2 = RespMatch::new_layer4_icmpv6(src_ipv6, dst_ipv6, false);

    let ret = layer3_ipv6_send(
        src_ipv6,
        dst_ipv6,
        &ipv6_buff,
        vec![match_object_1, match_object_2],
        max_loop,
    )?;

    match ret {
        Some(r) => {
            match Ipv6Packet::new(&r) {
                Some(ipv6_packet) => {
                    match ipv6_packet.get_next_header() {
                        IpNextHeaderProtocols::Tcp => {
                            match TcpPacket::new(ipv6_packet.payload()) {
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
                        IpNextHeaderProtocols::Icmpv6 => {
                            match Icmpv6Packet::new(ipv6_packet.payload()) {
                                Some(icmpv6_packet) => {
                                    let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                                    let icmpv6_code = icmpv6_packet.get_icmpv6_code();
                                    let codes = vec![
                                        Icmpv6Code(1), // communication with destination administratively prohibited
                                        Icmpv6Code(3), // address unreachable
                                        Icmpv6Code(4), // port unreachable
                                    ];
                                    if icmpv6_type == Icmpv6Types::DestinationUnreachable
                                        && codes.contains(&icmpv6_code)
                                    {
                                        // icmp unreachable error (type 3, code 1, 3, or 4)
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
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    max_loop: usize,
) -> Result<TargetScanStatus> {
    let mut rng = rand::thread_rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = MutableIpv6Packet::new(&mut ipv6_buff).unwrap();
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    ipv6_header.set_hop_limit(TTL);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(0);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let match_object_1 = RespMatch::new_layer4_tcp_udp(src_port, dst_port, false);
    let match_object_2 = RespMatch::new_layer4_icmpv6(src_ipv6, dst_ipv6, false);

    let ret = layer3_ipv6_send(
        src_ipv6,
        dst_ipv6,
        &ipv6_buff,
        vec![match_object_1, match_object_2],
        max_loop,
    )?;

    match ret {
        Some(r) => {
            match Ipv6Packet::new(&r) {
                Some(ipv6_packet) => {
                    match ipv6_packet.get_next_header() {
                        IpNextHeaderProtocols::Tcp => {
                            match TcpPacket::new(ipv6_packet.payload()) {
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
                        IpNextHeaderProtocols::Icmpv6 => {
                            match Icmpv6Packet::new(ipv6_packet.payload()) {
                                Some(icmpv6_packet) => {
                                    let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                                    let icmpv6_code = icmpv6_packet.get_icmpv6_code();
                                    let codes = vec![
                                        Icmpv6Code(1), // communication with destination administratively prohibited
                                        Icmpv6Code(3), // address unreachable
                                        Icmpv6Code(4), // port unreachable
                                    ];
                                    if icmpv6_type == Icmpv6Types::DestinationUnreachable
                                        && codes.contains(&icmpv6_code)
                                    {
                                        // icmp unreachable error (type 3, code 1, 3, or 4)
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
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    max_loop: usize,
) -> Result<TargetScanStatus> {
    let mut rng = rand::thread_rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = MutableIpv6Packet::new(&mut ipv6_buff).unwrap();
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    ipv6_header.set_hop_limit(TTL);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let match_object_1 = RespMatch::new_layer4_tcp_udp(src_port, dst_port, false);
    let match_object_2 = RespMatch::new_layer4_icmpv6(src_ipv6, dst_ipv6, false);

    let ret = layer3_ipv6_send(
        src_ipv6,
        dst_ipv6,
        &ipv6_buff,
        vec![match_object_1, match_object_2],
        max_loop,
    )?;

    match ret {
        Some(r) => {
            match Ipv6Packet::new(&r) {
                Some(ipv6_packet) => {
                    match ipv6_packet.get_next_header() {
                        IpNextHeaderProtocols::Tcp => {
                            match TcpPacket::new(ipv6_packet.payload()) {
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
                        IpNextHeaderProtocols::Icmpv6 => {
                            match Icmpv6Packet::new(ipv6_packet.payload()) {
                                Some(icmpv6_packet) => {
                                    let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                                    let icmpv6_code = icmpv6_packet.get_icmpv6_code();
                                    let codes = vec![
                                        Icmpv6Code(1), // communication with destination administratively prohibited
                                        Icmpv6Code(3), // address unreachable
                                        Icmpv6Code(4), // port unreachable
                                    ];
                                    if icmpv6_type == Icmpv6Types::DestinationUnreachable
                                        && codes.contains(&icmpv6_code)
                                    {
                                        // icmp unreachable error (type 3, code 1, 3, or 4)
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
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    max_loop: usize,
) -> Result<TargetScanStatus> {
    let mut rng = rand::thread_rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = MutableIpv6Packet::new(&mut ipv6_buff).unwrap();
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    ipv6_header.set_hop_limit(TTL);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let match_object_1 = RespMatch::new_layer4_tcp_udp(src_port, dst_port, false);
    let match_object_2 = RespMatch::new_layer4_icmpv6(src_ipv6, dst_ipv6, false);

    let ret = layer3_ipv6_send(
        src_ipv6,
        dst_ipv6,
        &ipv6_buff,
        vec![match_object_1, match_object_2],
        max_loop,
    )?;

    match ret {
        Some(r) => {
            match Ipv6Packet::new(&r) {
                Some(ipv6_packet) => {
                    match ipv6_packet.get_next_header() {
                        IpNextHeaderProtocols::Tcp => {
                            match TcpPacket::new(ipv6_packet.payload()) {
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
                        IpNextHeaderProtocols::Icmpv6 => {
                            match Icmpv6Packet::new(ipv6_packet.payload()) {
                                Some(icmpv6_packet) => {
                                    let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                                    let icmpv6_code = icmpv6_packet.get_icmpv6_code();
                                    let codes = vec![
                                        Icmpv6Code(1), // communication with destination administratively prohibited
                                        Icmpv6Code(3), // address unreachable
                                        Icmpv6Code(4), // port unreachable
                                    ];
                                    if icmpv6_type == Icmpv6Types::DestinationUnreachable
                                        && codes.contains(&icmpv6_code)
                                    {
                                        // icmp unreachable error (type 3, code 1, 3, or 4)
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
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    max_loop: usize,
) -> Result<TargetScanStatus> {
    let mut rng = rand::thread_rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = MutableIpv6Packet::new(&mut ipv6_buff).unwrap();
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    ipv6_header.set_hop_limit(TTL);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::FIN | TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let match_object_1 = RespMatch::new_layer4_tcp_udp(src_port, dst_port, false);
    let match_object_2 = RespMatch::new_layer4_icmpv6(src_ipv6, dst_ipv6, false);

    let ret = layer3_ipv6_send(
        src_ipv6,
        dst_ipv6,
        &ipv6_buff,
        vec![match_object_1, match_object_2],
        max_loop,
    )?;

    match ret {
        Some(r) => {
            match Ipv6Packet::new(&r) {
                Some(ipv6_packet) => {
                    match ipv6_packet.get_next_header() {
                        IpNextHeaderProtocols::Tcp => {
                            match TcpPacket::new(ipv6_packet.payload()) {
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
                        IpNextHeaderProtocols::Icmpv6 => {
                            match Icmpv6Packet::new(ipv6_packet.payload()) {
                                Some(icmpv6_packet) => {
                                    let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                                    let icmpv6_code = icmpv6_packet.get_icmpv6_code();
                                    let codes = vec![
                                        Icmpv6Code(1), // communication with destination administratively prohibited
                                        Icmpv6Code(3), // address unreachable
                                        Icmpv6Code(4), // port unreachable
                                    ];
                                    if icmpv6_type == Icmpv6Types::DestinationUnreachable
                                        && codes.contains(&icmpv6_code)
                                    {
                                        // icmp unreachable error (type 3, code 1, 3, or 4)
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

pub fn send_connect_scan_packet(
    _: Ipv6Addr,
    _: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    _: usize,
) -> Result<TargetScanStatus> {
    let addr = SocketAddr::V6(SocketAddrV6::new(dst_ipv6, dst_port, 0, 0));
    match TcpStream::connect(&addr) {
        Ok(_) => Ok(TargetScanStatus::Open),
        Err(_) => Ok(TargetScanStatus::Closed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_send_syn_scan_packet_new() {
        let src_ipv6: Ipv6Addr = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let src_port = 32109;
        let dst_port = 80;
        let max_loop = 32;
        let ret = send_syn_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop).unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_fin_scan_packet() {
        let src_ipv6: Ipv6Addr = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let src_port = 32109;
        let dst_port = 80;
        let max_loop = 32;
        let ret = send_fin_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop);
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_ack_scan_packet() {
        let src_ipv6: Ipv6Addr = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let src_port = 32109;
        let dst_port = 80;
        let max_loop = 32;
        let ret = send_ack_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop);
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_null_scan_packet() {
        let src_ipv6: Ipv6Addr = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let src_port = 32109;
        let dst_port = 80;
        let max_loop = 32;
        let ret = send_null_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop);
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_window_scan_packet() {
        let src_ipv6: Ipv6Addr = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let src_port = 32109;
        let dst_port = 80;
        let max_loop = 32;
        let ret = send_window_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop);
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_tcp_connect_scan_packet() {
        let src_ipv6: Ipv6Addr = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let src_port = 32109;
        let dst_port = 81;
        let max_loop = 32;
        let ret =
            send_connect_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop).unwrap();
        println!("{:?}", ret);
    }
}
