use anyhow::Result;
use pnet::packet::icmp::{destination_unreachable, IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum, Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer3;
// use pnet::transport::TransportChannelType::Layer4;
// use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{ipv4_packet_iter, transport_channel};
use rand::Rng;
use std::net::Ipv4Addr;
use std::thread::sleep;
use std::time::Duration;

use crate::utils;

const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const TCP_DATA_LEN: usize = 0;
const TCP_BUFF_SIZE: usize = 4096;
const ICMP_BUFF_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy)]
pub enum TcpScanStatus {
    Open,
    Closed,
    Filtered,
    OpenOrFiltered,
    Unfiltered,
}

struct TcpHandShake {
    syn: u32,
    ack: u32,
}

pub fn send_syn_scan_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<TcpScanStatus> {
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

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN) as u16);
    let id = utils::random_u16();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(52);
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

    match tcp_tx.send_to(ip_header, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut tcp_iter = ipv4_packet_iter(&mut tcp_rx);
    let mut icmp_iter = ipv4_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        println!(">>> 1");
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((packet, addr)) => {
                    if addr == dst_ipv4 {
                        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                            if packet.get_destination() == src_ipv4
                                && packet.get_source() == dst_ipv4
                            {
                                let ipv4_payload = packet.payload();
                                let tcp_buff = TcpPacket::new(ipv4_payload).unwrap();
                                let tcp_flags = tcp_buff.get_flags();
                                if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                                    // tcp syn/ack response
                                    return Ok(TcpScanStatus::Open);
                                } else if tcp_flags == (TcpFlags::RST | TcpFlags::ACK) {
                                    // tcp rst response
                                    return Ok(TcpScanStatus::Closed);
                                } else {
                                    // do nothing
                                }
                            }
                        }
                    }
                }
                _ => (), // do nothing
            },
            Err(e) => return Err(e.into()),
        }
        println!(">>> 2");
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
                                // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                return Ok(TcpScanStatus::Filtered);
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        println!(">>> 3");
    }
    // no response received (even after retransmissions)
    Ok(TcpScanStatus::Filtered)
}

pub fn send_fin_scan_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<TcpScanStatus> {
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

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN) as u16);
    let id = utils::random_u16();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(52);
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
    tcp_header.set_flags(TcpFlags::FIN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    // set tcp header as ip payload
    ip_header.set_payload(tcp_header.packet());

    match tcp_tx.send_to(ip_header, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut tcp_iter = ipv4_packet_iter(&mut tcp_rx);
    let mut icmp_iter = ipv4_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((packet, addr)) => {
                    if addr == dst_ipv4 {
                        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                            if packet.get_destination() == src_ipv4
                                && packet.get_source() == dst_ipv4
                            {
                                let ipv4_payload = packet.payload();
                                let tcp_buff = TcpPacket::new(ipv4_payload).unwrap();
                                let tcp_flags = tcp_buff.get_flags();
                                if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                                    // tcp syn/ack response
                                    return Ok(TcpScanStatus::Open);
                                } else if tcp_flags == (TcpFlags::RST | TcpFlags::ACK) {
                                    // tcp rst packet
                                    return Ok(TcpScanStatus::Closed);
                                } else {
                                    // do nothing
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
                                // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                return Ok(TcpScanStatus::Filtered);
                            }
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
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<TcpScanStatus> {
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

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN) as u16);
    let id = utils::random_u16();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(52);
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
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    // set tcp header as ip payload
    ip_header.set_payload(tcp_header.packet());

    match tcp_tx.send_to(ip_header, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut tcp_iter = ipv4_packet_iter(&mut tcp_rx);
    let mut icmp_iter = ipv4_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((packet, addr)) => {
                    if addr == dst_ipv4 {
                        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                            if packet.get_destination() == src_ipv4
                                && packet.get_source() == dst_ipv4
                            {
                                let ipv4_payload = packet.payload();
                                let tcp_buff = TcpPacket::new(ipv4_payload).unwrap();
                                let tcp_flags = tcp_buff.get_flags();
                                if tcp_flags == TcpFlags::RST {
                                    // tcp rst response
                                    return Ok(TcpScanStatus::Unfiltered);
                                } else {
                                    // do nothing
                                }
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
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
                            // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                            return Ok(TcpScanStatus::Filtered);
                        }
                    }
                }
            }
            _ => (),
        },
        Err(e) => return Err(e.into()),
    }
    // no response received (even after retransmissions)
    Ok(TcpScanStatus::Filtered)
}

fn tcp_handshake_step_1_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Option<Vec<u8>> {
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN) as u16);
    let id = utils::random_u16();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(52);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(0);
    tcp_header.set_acknowledgement(0);
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    // set tcp header as ip payload
    ip_header.set_payload(tcp_header.packet());

    // no response received (even after retransmissions)
    Some(ip_buff.to_vec())
}

fn tcp_handshake_step_2_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    sequence: u32,
    acknowledgement: u32,
) -> Option<Vec<u8>> {
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN) as u16);
    let id = utils::random_u16();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(52);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(sequence);
    tcp_header.set_acknowledgement(acknowledgement);
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    // set tcp header as ip payload
    ip_header.set_payload(tcp_header.packet());

    // no response received (even after retransmissions)
    Some(ip_buff.to_vec())
}

fn tcp_handshake_step_3_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    sequence: u32,
    acknowledgement: u32,
) -> Option<Vec<u8>> {
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN) as u16);
    let id = utils::random_u16();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(52);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(sequence);
    tcp_header.set_acknowledgement(acknowledgement);
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::FIN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    // set tcp header as ip payload
    ip_header.set_payload(tcp_header.packet());

    // no response received (even after retransmissions)
    Some(ip_buff.to_vec())
}

fn tcp_handshake_step_4_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    sequence: u32,
    acknowledgement: u32,
) -> Option<Vec<u8>> {
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN) as u16);
    let id = utils::random_u16();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(52);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(sequence);
    tcp_header.set_acknowledgement(acknowledgement);
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    // set tcp header as ip payload
    ip_header.set_payload(tcp_header.packet());

    // no response received (even after retransmissions)
    Some(ip_buff.to_vec())
}

pub fn tcp_handshake(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<TcpScanStatus> {
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

    let ip_buff = tcp_handshake_step_1_packet(src_ipv4, dst_ipv4, src_port, dst_port).unwrap();
    let ip_packet = Ipv4Packet::new(&ip_buff).unwrap();
    match tcp_tx.send_to(ip_packet, dst_ipv4.into()) {
        Ok(_) => (),
        Err(e) => return Err(e.into()),
    }
    println!("send 1 packet");
    sleep(Duration::from_secs(100));

    let mut tcp_iter = ipv4_packet_iter(&mut tcp_rx);
    let mut icmp_iter = ipv4_packet_iter(&mut icmp_rx);

    let mut seq = 0;
    let mut ack = 0;
    for _ in 0..max_loop {
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
                                // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                return Ok(TcpScanStatus::Closed);
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((packet, addr)) => {
                    if addr == dst_ipv4 {
                        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                            if packet.get_destination() == src_ipv4
                                && packet.get_source() == dst_ipv4
                            {
                                let ipv4_payload = packet.payload();
                                let tcp_packet = TcpPacket::new(ipv4_payload).unwrap();
                                let tcp_flags = tcp_packet.get_flags();
                                if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                                    // tcp syn/ack response
                                    seq = tcp_packet.get_sequence();
                                    ack = tcp_packet.get_acknowledgement();
                                    // println!(">>>>>> ");
                                    break;
                                } else if tcp_flags == (TcpFlags::RST | TcpFlags::ACK) {
                                    // tcp rst response
                                    return Ok(TcpScanStatus::Closed);
                                } else {
                                    // do nothing
                                }
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }

    let ip_buff =
        tcp_handshake_step_2_packet(src_ipv4, dst_ipv4, src_port, dst_port, ack, seq + 1).unwrap();
    let ip_packet = Ipv4Packet::new(&ip_buff).unwrap();
    // match tcp_tx.send_to(ip_packet, dst_ipv4.into()) {
    //     Ok(_) => (),
    //     Err(e) => return Err(e.into()),
    // }
    println!("send 2 packet");

    let ip_buff =
        tcp_handshake_step_3_packet(src_ipv4, dst_ipv4, src_port, dst_port, ack, seq + 1).unwrap();
    let ip_packet = Ipv4Packet::new(&ip_buff).unwrap();
    // match tcp_tx.send_to(ip_packet, dst_ipv4.into()) {
    //     Ok(_) => (),
    //     Err(e) => return Err(e.into()),
    // }
    println!("send 3 packet");

    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((packet, addr)) => {
                    if addr == dst_ipv4 {
                        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                            if packet.get_destination() == src_ipv4
                                && packet.get_source() == dst_ipv4
                            {
                                let ipv4_payload = packet.payload();
                                let tcp_buff = TcpPacket::new(ipv4_payload).unwrap();
                                let tcp_flags = tcp_buff.get_flags();
                                if tcp_flags == (TcpFlags::FIN | TcpFlags::ACK) {
                                    // tcp syn/ack response
                                    seq = tcp_buff.get_sequence();
                                    ack = tcp_buff.get_acknowledgement();
                                    break;
                                } else if tcp_flags == (TcpFlags::RST | TcpFlags::ACK) {
                                    // tcp rst response
                                    return Ok(TcpScanStatus::Closed);
                                } else {
                                    // do nothing
                                }
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }

    let ip_buff =
        tcp_handshake_step_4_packet(src_ipv4, dst_ipv4, src_port, dst_port, seq + 1, seq + 1)
            .unwrap();
    let ip_packet = Ipv4Packet::new(&ip_buff).unwrap();
    // match tcp_tx.send_to(ip_packet, dst_ipv4.into()) {
    //     Ok(_) => (),
    //     Err(e) => return Err(e.into()),
    // }
    println!("send 4 packet");

    Ok(TcpScanStatus::Open)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_send_syn_scan_packet() {
        // let src_ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        // let dst_ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 211);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let timeout = Duration::from_secs(1);
        let max_loop = 4;
        let ret = send_syn_scan_packet(src_ipv4, dst_ipv4, 53511, 80, timeout, max_loop).unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_fin_scan_packet() {
        // let src_ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        // let dst_ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 211);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let timeout = Duration::from_secs(1);
        let max_loop = 8;
        let ret = send_fin_scan_packet(src_ipv4, dst_ipv4, 49511, 81, timeout, max_loop);
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_ack_scan_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 211);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let timeout = Duration::from_secs(1);
        let max_loop = 8;
        let ret = send_ack_scan_packet(src_ipv4, dst_ipv4, 49511, 80, timeout, max_loop);
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_tcp_handshark() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 211);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let timeout = Duration::from_secs(10);
        let max_loop = 64;
        let src_port = utils::random_port();
        let ret = tcp_handshake(src_ipv4, dst_ipv4, src_port, 80, timeout, max_loop).unwrap();
        println!("{:?}", ret);
    }
}
