use anyhow::Result;
use pnet::packet::icmp::{destination_unreachable, IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum, Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::{icmp_packet_iter, ipv4_packet_iter, tcp_packet_iter};
use rand::Rng;
use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::TcpStream;
use std::time::Duration;

use crate::utils::return_layer4_icmp_channel;
use crate::utils::return_layer4_tcp_channel;
use crate::utils::ICMP_BUFF_SIZE;
use crate::utils::IPV4_HEADER_LEN;
use crate::utils::IP_TTL;
use crate::utils::TCP_BUFF_SIZE;
use crate::utils::TCP_DATA_LEN;
use crate::utils::TCP_HEADER_LEN;
use crate::utils;
use crate::IdleScanResults;
use crate::TcpScanStatus;

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
    timeout: Duration,
    max_loop: usize,
) -> Result<TcpScanStatus> {
    let (mut tcp_tx, mut tcp_rx) = return_layer4_tcp_channel(TCP_BUFF_SIZE)?;
    let (_, mut icmp_rx) = return_layer4_icmp_channel(ICMP_BUFF_SIZE)?;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
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

    match tcp_tx.send_to(tcp_header, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut tcp_iter = tcp_packet_iter(&mut tcp_rx);
    let mut icmp_iter = icmp_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((tcp_packet, addr)) => {
                    if addr == dst_ipv4 {
                        if tcp_packet.get_source() == dst_port
                            && tcp_packet.get_destination() == src_port
                        {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                                // tcp syn/ack response
                                return Ok(TcpScanStatus::Open);
                            } else if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok(TcpScanStatus::Closed);
                            }
                        }
                    }
                }
                _ => (), // do nothing
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((icmp_packet, addr)) => {
                    if addr == dst_ipv4 {
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
                            return Ok(TcpScanStatus::Filtered);
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }
    // no response received (even after retransmissions)
    Ok(TcpScanStatus::Filtered)
}

pub fn send_fin_scan_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<TcpScanStatus> {
    let (mut tcp_tx, mut tcp_rx) = return_layer4_tcp_channel(TCP_BUFF_SIZE)?;
    let (_, mut icmp_rx) = return_layer4_icmp_channel(ICMP_BUFF_SIZE)?;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
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

    match tcp_tx.send_to(tcp_header, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut tcp_iter = tcp_packet_iter(&mut tcp_rx);
    let mut icmp_iter = icmp_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((tcp_packet, addr)) => {
                    if addr == dst_ipv4 {
                        if tcp_packet.get_source() == dst_port
                            && tcp_packet.get_destination() == src_port
                        {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                                // tcp syn/ack response
                                return Ok(TcpScanStatus::Open);
                            } else if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst packet
                                return Ok(TcpScanStatus::Closed);
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((icmp_packet, addr)) => {
                    if addr == dst_ipv4 {
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
                            return Ok(TcpScanStatus::Filtered);
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }
    // no response received (even after retransmissions)
    Ok(TcpScanStatus::OpenOrFiltered)
}

pub fn send_ack_scan_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<TcpScanStatus> {
    let (mut tcp_tx, mut tcp_rx) = return_layer4_tcp_channel(TCP_BUFF_SIZE)?;
    let (_, mut icmp_rx) = return_layer4_icmp_channel(ICMP_BUFF_SIZE)?;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
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

    match tcp_tx.send_to(tcp_header, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut tcp_iter = tcp_packet_iter(&mut tcp_rx);
    let mut icmp_iter = icmp_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((tcp_packet, addr)) => {
                    if addr == dst_ipv4 {
                        if tcp_packet.get_destination() == src_port
                            && tcp_packet.get_source() == dst_port
                        {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok(TcpScanStatus::Unfiltered);
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((icmp_packet, addr)) => {
                    if addr == dst_ipv4 {
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
                            return Ok(TcpScanStatus::Filtered);
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }
    // no response received (even after retransmissions)
    Ok(TcpScanStatus::Filtered)
}

pub fn send_null_scan_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<TcpScanStatus> {
    let (mut tcp_tx, mut tcp_rx) = return_layer4_tcp_channel(TCP_BUFF_SIZE)?;
    let (_, mut icmp_rx) = return_layer4_icmp_channel(ICMP_BUFF_SIZE)?;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
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

    match tcp_tx.send_to(tcp_header, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut tcp_iter = tcp_packet_iter(&mut tcp_rx);
    let mut icmp_iter = icmp_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((tcp_packet, addr)) => {
                    if addr == dst_ipv4 {
                        if tcp_packet.get_destination() == src_port
                            && tcp_packet.get_source() == dst_port
                        {
                            if tcp_packet.get_source() == dst_port
                                && tcp_packet.get_destination() == src_port
                            {
                                let tcp_flags = tcp_packet.get_flags();
                                if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                    // tcp rst response
                                    return Ok(TcpScanStatus::Closed);
                                }
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((icmp_packet, addr)) => {
                    if addr == dst_ipv4 {
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
                            return Ok(TcpScanStatus::Filtered);
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }
    // no response received (even after retransmissions)
    Ok(TcpScanStatus::OpenOrFiltered)
}

pub fn send_xmas_scan_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<TcpScanStatus> {
    let (mut tcp_tx, mut tcp_rx) = return_layer4_tcp_channel(TCP_BUFF_SIZE)?;
    let (_, mut icmp_rx) = return_layer4_icmp_channel(ICMP_BUFF_SIZE)?;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
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

    match tcp_tx.send_to(tcp_header, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut tcp_iter = tcp_packet_iter(&mut tcp_rx);
    let mut icmp_iter = icmp_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((tcp_packet, addr)) => {
                    if addr == dst_ipv4 {
                        if tcp_packet.get_destination() == src_port
                            && tcp_packet.get_source() == dst_port
                        {
                            if tcp_packet.get_source() == dst_port
                                && tcp_packet.get_destination() == src_port
                            {
                                let tcp_flags = tcp_packet.get_flags();
                                if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                    // tcp rst response
                                    return Ok(TcpScanStatus::Closed);
                                }
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((icmp_packet, addr)) => {
                    if addr == dst_ipv4 {
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
                            return Ok(TcpScanStatus::Filtered);
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }
    // no response received (even after retransmissions)
    Ok(TcpScanStatus::OpenOrFiltered)
}

pub fn send_window_scan_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<TcpScanStatus> {
    let (mut tcp_tx, mut tcp_rx) = return_layer4_tcp_channel(TCP_BUFF_SIZE)?;
    let (_, mut icmp_rx) = return_layer4_icmp_channel(ICMP_BUFF_SIZE)?;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
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

    match tcp_tx.send_to(tcp_header, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut tcp_iter = tcp_packet_iter(&mut tcp_rx);
    let mut icmp_iter = icmp_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((tcp_packet, addr)) => {
                    if addr == dst_ipv4 {
                        if tcp_packet.get_destination() == src_port
                            && tcp_packet.get_source() == dst_port
                        {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                if tcp_packet.get_window() > 0 {
                                    // tcp rst response with non-zero window field
                                    return Ok(TcpScanStatus::Open);
                                } else {
                                    // tcp rst response with zero window field
                                    return Ok(TcpScanStatus::Closed);
                                }
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((icmp_packet, addr)) => {
                    if addr == dst_ipv4 {
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
                            return Ok(TcpScanStatus::Filtered);
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }
    // no response received (even after retransmissions)
    Ok(TcpScanStatus::Filtered)
}

pub fn send_maimon_scan_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<TcpScanStatus> {
    let (mut tcp_tx, mut tcp_rx) = return_layer4_tcp_channel(TCP_BUFF_SIZE)?;
    let (_, mut icmp_rx) = return_layer4_icmp_channel(ICMP_BUFF_SIZE)?;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
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

    match tcp_tx.send_to(tcp_header, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut tcp_iter = tcp_packet_iter(&mut tcp_rx);
    let mut icmp_iter = icmp_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((tcp_packet, addr)) => {
                    if addr == dst_ipv4 {
                        if tcp_packet.get_destination() == src_port
                            && tcp_packet.get_source() == dst_port
                        {
                            if tcp_packet.get_source() == dst_port
                                && tcp_packet.get_destination() == src_port
                            {
                                let tcp_flags = tcp_packet.get_flags();
                                if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                    // tcp rst response
                                    return Ok(TcpScanStatus::Closed);
                                }
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((icmp_packet, addr)) => {
                    if addr == dst_ipv4 {
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
                            return Ok(TcpScanStatus::Filtered);
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }
    // no response received (even after retransmissions)
    Ok(TcpScanStatus::OpenOrFiltered)
}

pub fn send_idle_scan_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    zombie_ipv4: Ipv4Addr,
    zombie_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<(TcpScanStatus, Option<IdleScanResults>)> {
    fn _forge_syn_packet(
        src_ipv4: Ipv4Addr,
        dst_ipv4: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Result<Vec<u8>> {
        // ip header
        let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN];
        let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_total_length((IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN) as u16);
        let id = utils::random_u16();
        ip_header.set_identification(id);
        ip_header.set_flags(Ipv4Flags::DontFragment);
        ip_header.set_ttl(IP_TTL);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        let c = checksum(&ip_header.to_immutable());
        ip_header.set_checksum(c);
        ip_header.set_source(src_ipv4);
        ip_header.set_destination(dst_ipv4);

        // tcp header
        let mut rng = rand::thread_rng();
        let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
        let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
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

        // set tcp header as ip payload
        ip_header.set_payload(tcp_header.packet());

        Ok(ip_buff.to_vec())
    }

    let tcp_protocol = Layer3(IpNextHeaderProtocols::Tcp);
    let (mut tcp_tx, mut tcp_rx) = match transport_channel(TCP_BUFF_SIZE, tcp_protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(e.into()),
    };
    let icmp_protocol = Layer3(IpNextHeaderProtocols::Icmp);
    let (_, mut icmp_rx) = match transport_channel(ICMP_BUFF_SIZE, icmp_protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(e.into()),
    };
    let mut tcp_iter = ipv4_packet_iter(&mut tcp_rx);
    let mut icmp_iter = ipv4_packet_iter(&mut icmp_rx);

    // 1. probe the zombie's ip id
    let ip_buff = _forge_syn_packet(src_ipv4, zombie_ipv4, src_port, zombie_port)?;
    let ip_packet = Ipv4Packet::new(&ip_buff).unwrap();
    match tcp_tx.send_to(ip_packet, zombie_ipv4.into()) {
        Ok(n) => assert_eq!(n, IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut zombie_ip_id_1 = 0;
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((packet, addr)) => {
                    if addr == zombie_ipv4 {
                        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                            if packet.get_destination() == src_ipv4 {
                                let ipv4_payload = packet.payload();
                                let tcp_packet = TcpPacket::new(ipv4_payload).unwrap();
                                println!(">>> {}", tcp_packet.get_flags());
                                if tcp_packet.get_source() == zombie_port
                                    && tcp_packet.get_destination() == src_port
                                {
                                    let tcp_flags = tcp_packet.get_flags();
                                    if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                        // 2. zombie return rst packet, get this packet ip id
                                        zombie_ip_id_1 = packet.get_identification();
                                        if zombie_ip_id_1 == 0 {
                                            return Err(IdleScanAllZeroError::new(
                                                zombie_ipv4,
                                                zombie_port,
                                            )
                                            .into());
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((packet, addr)) => {
                    if addr == dst_ipv4 {
                        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                            let ipv4_payload = packet.payload();
                            let icmp_packet = IcmpPacket::new(ipv4_payload).unwrap();
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
                                // dst is unreachable ignore this port
                                return Ok((TcpScanStatus::Unreachable, None));
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }

    // 3. forge a syn packet from the zombie to the target
    let ip_buff_2 = _forge_syn_packet(zombie_ipv4, dst_ipv4, zombie_port, dst_port)?;
    let ip_packet_2 = Ipv4Packet::new(&ip_buff_2).unwrap();
    match tcp_tx.send_to(ip_packet_2, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    // 4. probe the zombie's ip id again
    let ip_buff_3 = _forge_syn_packet(src_ipv4, zombie_ipv4, src_port, zombie_port)?;
    let ip_packet_3 = Ipv4Packet::new(&ip_buff_3).unwrap();
    match tcp_tx.send_to(ip_packet_3, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }
    let mut zombie_ip_id_2 = 0;
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((packet, addr)) => {
                    if addr == zombie_ipv4 {
                        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                            if packet.get_destination() == src_ipv4
                                && packet.get_source() == zombie_ipv4
                            {
                                let ipv4_payload = packet.payload();
                                let tcp_packet = TcpPacket::new(ipv4_payload).unwrap();
                                if tcp_packet.get_source() == zombie_port {
                                    let tcp_flags = tcp_packet.get_flags();
                                    if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                        // 5. zombie return rst packet again, get this packet ip id
                                        zombie_ip_id_2 = packet.get_identification();
                                        if zombie_ip_id_2 == 0 {
                                            return Err(IdleScanAllZeroError::new(
                                                zombie_ipv4,
                                                zombie_port,
                                            )
                                            .into());
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((packet, addr)) => {
                    if addr == dst_ipv4 {
                        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                            let ipv4_payload = packet.payload();
                            let icmp_packet = IcmpPacket::new(ipv4_payload).unwrap();
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
                                // dst is unreachable ignore this port
                                return Ok((TcpScanStatus::Unreachable, None));
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }

    if zombie_ip_id_2 - zombie_ip_id_1 >= 2 {
        Ok((
            TcpScanStatus::Open,
            Some(IdleScanResults {
                zombie_ip_id_1,
                zombie_ip_id_2,
            }),
        ))
    } else {
        Ok((
            TcpScanStatus::ClosedOrFiltered,
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
    timeout: Duration,
    _: usize,
) -> Result<TcpScanStatus> {
    let addr = SocketAddr::V4(SocketAddrV4::new(dst_ipv4, dst_port));
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => Ok(TcpScanStatus::Open),
        Err(_) => Ok(TcpScanStatus::Closed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_send_syn_scan_packet_new() {
        // let src_ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        // let dst_ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 106);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 119);
        let src_port = 32109;
        let dst_port = 81;
        let timeout = Duration::from_secs(1);
        let max_loop = 4;
        let ret = send_syn_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout, max_loop)
            .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_fin_scan_packet() {
        // let src_ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        // let dst_ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 106);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 119);
        let timeout = Duration::from_secs(1);
        let max_loop = 8;
        let ret = send_fin_scan_packet(src_ipv4, 53511, dst_ipv4, 80, timeout, max_loop);
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_ack_scan_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 106);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 119);
        let timeout = Duration::from_secs(1);
        let max_loop = 8;
        let ret = send_ack_scan_packet(src_ipv4, 53511, dst_ipv4, 80, timeout, max_loop);
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_null_scan_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 106);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 119);
        let timeout = Duration::from_secs(1);
        let max_loop = 8;
        let ret = send_null_scan_packet(src_ipv4, 53511, dst_ipv4, 80, timeout, max_loop);
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_window_scan_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 106);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 119);
        let timeout = Duration::from_secs(1);
        let max_loop = 8;
        let ret = send_window_scan_packet(src_ipv4, 53511, dst_ipv4, 80, timeout, max_loop);
        println!("{:?}", ret);
    }
    #[test]
    #[should_panic]
    fn test_send_idle_scan_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 106);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 119);
        let zombie_ipv4 = Ipv4Addr::new(192, 168, 1, 33);

        let src_port = utils::random_port();
        let dst_port = 80;
        let zombie_port = utils::random_port();
        let timeout = Duration::from_secs(1);
        let max_loop = 8;
        let (ret, i) = send_idle_scan_packet(
            src_ipv4,
            src_port,
            dst_ipv4,
            dst_port,
            zombie_ipv4,
            zombie_port,
            timeout,
            max_loop,
        )
        .unwrap();
        println!("{:?}", ret);
        println!("{:?}", i.unwrap());
    }
    #[test]
    fn test_send_tcp_handshark() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 106);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 119);
        let timeout = Duration::from_secs(10);
        let max_loop = 64;
        let src_port = utils::random_port();
        let ret =
            send_connect_scan_packet(src_ipv4, src_port, dst_ipv4, 81, timeout, max_loop).unwrap();
        println!("{:?}", ret);
    }
}
