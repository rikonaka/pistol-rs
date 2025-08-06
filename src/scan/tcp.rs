use pnet::packet::Packet;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::icmp::destination_unreachable;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::Ipv4Flags;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv4::checksum;
use pnet::packet::tcp;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::tcp::ipv4_checksum;
use rand::Rng;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::net::TcpStream;
use std::panic::Location;
use std::time::Duration;
use std::time::Instant;

use crate::error::PistolError;
use crate::layer::IPV4_HEADER_SIZE;
use crate::layer::Layer3Match;
use crate::layer::Layer4MatchIcmp;
use crate::layer::Layer4MatchTcpUdp;
use crate::layer::LayerMatch;
use crate::layer::PayloadMatch;
use crate::layer::PayloadMatchIp;
use crate::layer::PayloadMatchTcpUdp;
use crate::layer::TCP_HEADER_SIZE;
use crate::layer::layer3_ipv4_send;
use crate::scan::DataRecvStatus;
use crate::scan::PortStatus;
use crate::scan::TcpIdleScans;
use crate::utils;

const TCP_DATA_SIZE: usize = 0;
const TTL: u8 = 64;

// const TCP_FLAGS_CWR_MASK: u8 = 0b10000000;
// const TCP_FLAGS_ECE_MASK: u8 = 0b01000000;
// const TCP_FLAGS_URG_MASK: u8 = 0b00100000;
// const TCP_FLAGS_ACK_MASK: u8 = 0b00010000;
// const TCP_FLAGS_PSH_MASK: u8 = 0b00001000;
const TCP_FLAGS_RST_MASK: u8 = 0b00000100;
// const TCP_FLAGS_SYN_MASK: u8 = 0b00000010;
// const TCP_FLAGS_FIN_MASK: u8 = 0b00000001;

pub fn send_syn_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    timeout: Option<Duration>,
) -> Result<(PortStatus, DataRecvStatus, Duration), PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = match MutableIpv4Packet::new(&mut ip_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.random());
    tcp_header.set_acknowledgement(rng.random());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
        ip_id: None,
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv4.into()),
        dst_addr: Some(dst_ipv4.into()),
    };
    let payload_tcpudp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcpudp);
    let layer4_icmp = Layer4MatchIcmp {
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let layer_match_1 = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);
    let layer_match_2 = LayerMatch::Layer4MatchIcmp(layer4_icmp);

    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    let (ret, rtt) = layer3_ipv4_send(
        dst_ipv4,
        src_ipv4,
        &ip_buff,
        vec![layer_match_1, layer_match_2],
        timeout,
        true,
    )?;
    match Ipv4Packet::new(&ret) {
        Some(ipv4_packet) => {
            match ipv4_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    match TcpPacket::new(ipv4_packet.payload()) {
                        Some(tcp_packet) => {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                                // tcp syn/ack response
                                return Ok((PortStatus::Open, DataRecvStatus::Yes, rtt));
                            } else if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok((PortStatus::Closed, DataRecvStatus::Yes, rtt));
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
                            if icmp_type == IcmpTypes::DestinationUnreachable {
                                if codes.contains(&icmp_code) {
                                    // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                    return Ok((PortStatus::Filtered, DataRecvStatus::Yes, rtt));
                                }
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
    // no response received (even after retransmissions)
    Ok((PortStatus::Filtered, DataRecvStatus::No, rtt))
}

pub fn send_fin_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    timeout: Option<Duration>,
) -> Result<(PortStatus, DataRecvStatus, Duration), PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = match MutableIpv4Packet::new(&mut ip_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.random());
    tcp_header.set_acknowledgement(rng.random());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::FIN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
        ip_id: None,
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv4.into()),
        dst_addr: Some(dst_ipv4.into()),
    };
    let payload_tcpudp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcpudp);
    let layer4_icmp = Layer4MatchIcmp {
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let layer_match_1 = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);
    let layer_match_2 = LayerMatch::Layer4MatchIcmp(layer4_icmp);

    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    let (ret, rtt) = layer3_ipv4_send(
        dst_ipv4,
        src_ipv4,
        &ip_buff,
        vec![layer_match_1, layer_match_2],
        timeout,
        true,
    )?;
    match Ipv4Packet::new(&ret) {
        Some(ipv4_packet) => {
            match ipv4_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    match TcpPacket::new(ipv4_packet.payload()) {
                        Some(tcp_packet) => {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                                // tcp syn/ack response
                                return Ok((PortStatus::Open, DataRecvStatus::Yes, rtt));
                            } else if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst packet
                                return Ok((PortStatus::Closed, DataRecvStatus::Yes, rtt));
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
                            if icmp_type == IcmpTypes::DestinationUnreachable {
                                if codes.contains(&icmp_code) {
                                    // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                    return Ok((PortStatus::Filtered, DataRecvStatus::Yes, rtt));
                                }
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
    // no response received (even after retransmissions)
    Ok((PortStatus::OpenOrFiltered, DataRecvStatus::No, rtt))
}

pub fn send_ack_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    timeout: Option<Duration>,
) -> Result<(PortStatus, DataRecvStatus, Duration), PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = match MutableIpv4Packet::new(&mut ip_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    // tcp_header.set_sequence(rng.random());
    tcp_header.set_sequence(0);
    tcp_header.set_acknowledgement(rng.random());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
        ip_id: None,
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv4.into()),
        dst_addr: Some(dst_ipv4.into()),
    };
    let payload_tcpudp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcpudp);
    let layer4_icmp = Layer4MatchIcmp {
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let layer_match_1 = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);
    let layer_match_2 = LayerMatch::Layer4MatchIcmp(layer4_icmp);

    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    let (ret, rtt) = layer3_ipv4_send(
        dst_ipv4,
        src_ipv4,
        &ip_buff,
        vec![layer_match_1, layer_match_2],
        timeout,
        true,
    )?;
    match Ipv4Packet::new(&ret) {
        Some(ipv4_packet) => {
            match ipv4_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    match TcpPacket::new(ipv4_packet.payload()) {
                        Some(tcp_packet) => {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok((PortStatus::Unfiltered, DataRecvStatus::Yes, rtt));
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
                            if icmp_type == IcmpTypes::DestinationUnreachable {
                                if codes.contains(&icmp_code) {
                                    // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                    return Ok((PortStatus::Filtered, DataRecvStatus::Yes, rtt));
                                }
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
    // no response received (even after retransmissions)
    Ok((PortStatus::Filtered, DataRecvStatus::No, rtt))
}

pub fn send_null_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    timeout: Option<Duration>,
) -> Result<(PortStatus, DataRecvStatus, Duration), PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = match MutableIpv4Packet::new(&mut ip_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.random());
    tcp_header.set_acknowledgement(rng.random());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(0);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
        ip_id: None,
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv4.into()),
        dst_addr: Some(dst_ipv4.into()),
    };
    let payload_tcpudp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcpudp);
    let layer4_icmp = Layer4MatchIcmp {
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let layer_match_1 = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);
    let layer_match_2 = LayerMatch::Layer4MatchIcmp(layer4_icmp);

    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    let (ret, rtt) = layer3_ipv4_send(
        dst_ipv4,
        src_ipv4,
        &ip_buff,
        vec![layer_match_1, layer_match_2],
        timeout,
        true,
    )?;
    match Ipv4Packet::new(&ret) {
        Some(ipv4_packet) => {
            match ipv4_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    match TcpPacket::new(ipv4_packet.payload()) {
                        Some(tcp_packet) => {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok((PortStatus::Closed, DataRecvStatus::Yes, rtt));
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
                            if icmp_type == IcmpTypes::DestinationUnreachable {
                                if codes.contains(&icmp_code) {
                                    // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                    return Ok((PortStatus::Filtered, DataRecvStatus::Yes, rtt));
                                }
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
    // no response received (even after retransmissions)
    Ok((PortStatus::OpenOrFiltered, DataRecvStatus::No, rtt))
}

pub fn send_xmas_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    timeout: Option<Duration>,
) -> Result<(PortStatus, DataRecvStatus, Duration), PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = match MutableIpv4Packet::new(&mut ip_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut rng = rand::rng();
    let mut tcp_header = match MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.random());
    tcp_header.set_acknowledgement(rng.random());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
        ip_id: None,
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv4.into()),
        dst_addr: Some(dst_ipv4.into()),
    };
    let payload_tcpudp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcpudp);
    let layer4_icmp = Layer4MatchIcmp {
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let layer_match_1 = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);
    let layer_match_2 = LayerMatch::Layer4MatchIcmp(layer4_icmp);

    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    let (ret, rtt) = layer3_ipv4_send(
        dst_ipv4,
        src_ipv4,
        &ip_buff,
        vec![layer_match_1, layer_match_2],
        timeout,
        true,
    )?;
    match Ipv4Packet::new(&ret) {
        Some(ipv4_packet) => {
            match ipv4_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    match TcpPacket::new(ipv4_packet.payload()) {
                        Some(tcp_packet) => {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok((PortStatus::Closed, DataRecvStatus::Yes, rtt));
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
                            if icmp_type == IcmpTypes::DestinationUnreachable {
                                if codes.contains(&icmp_code) {
                                    // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                    return Ok((PortStatus::Filtered, DataRecvStatus::Yes, rtt));
                                }
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
    // no response received (even after retransmissions)
    Ok((PortStatus::OpenOrFiltered, DataRecvStatus::No, rtt))
}

pub fn send_window_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    timeout: Option<Duration>,
) -> Result<(PortStatus, DataRecvStatus, Duration), PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = match MutableIpv4Packet::new(&mut ip_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.random());
    tcp_header.set_acknowledgement(rng.random());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
        ip_id: None,
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv4.into()),
        dst_addr: Some(dst_ipv4.into()),
    };
    let payload_tcpudp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcpudp);
    let layer4_icmp = Layer4MatchIcmp {
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let layer_match_1 = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);
    let layer_match_2 = LayerMatch::Layer4MatchIcmp(layer4_icmp);

    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    let (ret, rtt) = layer3_ipv4_send(
        dst_ipv4,
        src_ipv4,
        &ip_buff,
        vec![layer_match_1, layer_match_2],
        timeout,
        true,
    )?;
    match Ipv4Packet::new(&ret) {
        Some(ipv4_packet) => {
            match ipv4_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    match TcpPacket::new(ipv4_packet.payload()) {
                        Some(tcp_packet) => {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                if tcp_packet.get_window() > 0 {
                                    // tcp rst response with non-zero window field
                                    return Ok((PortStatus::Open, DataRecvStatus::Yes, rtt));
                                } else {
                                    // tcp rst response with zero window field
                                    return Ok((PortStatus::Closed, DataRecvStatus::Yes, rtt));
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
                            if icmp_type == IcmpTypes::DestinationUnreachable {
                                if codes.contains(&icmp_code) {
                                    // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                    return Ok((PortStatus::Filtered, DataRecvStatus::Yes, rtt));
                                }
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
    // no response received (even after retransmissions)
    Ok((PortStatus::Filtered, DataRecvStatus::No, rtt))
}

pub fn send_maimon_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    timeout: Option<Duration>,
) -> Result<(PortStatus, DataRecvStatus, Duration), PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = match MutableIpv4Packet::new(&mut ip_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.random());
    tcp_header.set_acknowledgement(rng.random());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::FIN | TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
        ip_id: None,
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv4.into()),
        dst_addr: Some(dst_ipv4.into()),
    };
    let payload_tcpudp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcpudp);
    let layer4_icmp = Layer4MatchIcmp {
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let layer_match_1 = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);
    let layer_match_2 = LayerMatch::Layer4MatchIcmp(layer4_icmp);

    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    let (ret, rtt) = layer3_ipv4_send(
        dst_ipv4,
        src_ipv4,
        &ip_buff,
        vec![layer_match_1, layer_match_2],
        timeout,
        true,
    )?;
    match Ipv4Packet::new(&ret) {
        Some(ipv4_packet) => {
            match ipv4_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    match TcpPacket::new(ipv4_packet.payload()) {
                        Some(tcp_packet) => {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok((PortStatus::Closed, DataRecvStatus::Yes, rtt));
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
                            if icmp_type == IcmpTypes::DestinationUnreachable {
                                if codes.contains(&icmp_code) {
                                    // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                    return Ok((PortStatus::Filtered, DataRecvStatus::Yes, rtt));
                                }
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
    // no response received (even after retransmissions)
    Ok((PortStatus::OpenOrFiltered, DataRecvStatus::No, rtt))
}

pub fn send_idle_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    zombie_ipv4: Ipv4Addr,
    zombie_port: u16,
    timeout: Option<Duration>,
) -> Result<(PortStatus, DataRecvStatus, Option<TcpIdleScans>, Duration), PistolError> {
    fn _forge_syn_packet(
        src_ipv4: Ipv4Addr,
        dst_ipv4: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Result<Vec<u8>, PistolError> {
        let mut rng = rand::rng();
        // ip header
        let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
        let mut ip_header = match MutableIpv4Packet::new(&mut ip_buff) {
            Some(p) => p,
            None => {
                return Err(PistolError::BuildPacketError {
                    location: format!("{}", Location::caller()),
                });
            }
        };
        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_source(src_ipv4);
        ip_header.set_destination(dst_ipv4);
        ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
        let id = rng.random();
        ip_header.set_identification(id);
        ip_header.set_flags(Ipv4Flags::DontFragment);
        ip_header.set_ttl(TTL);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        let c = checksum(&ip_header.to_immutable());
        ip_header.set_checksum(c);

        // tcp header
        let mut tcp_header = match MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
            Some(p) => p,
            None => {
                return Err(PistolError::BuildPacketError {
                    location: format!("{}", Location::caller()),
                });
            }
        };
        tcp_header.set_source(src_port);
        tcp_header.set_destination(dst_port);
        tcp_header.set_sequence(rng.random());
        tcp_header.set_acknowledgement(rng.random());
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
    let layer3_zombie = Layer3Match {
        layer2: None,
        src_addr: Some(zombie_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
        ip_id: None,
    };
    let layer4_tcp_udp_zombie = Layer4MatchTcpUdp {
        layer3: Some(layer3_zombie),
        src_port: Some(zombie_port),
        dst_port: Some(src_port),
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv4.into()),
        dst_addr: Some(dst_ipv4.into()),
    };
    let payload_tcpudp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(zombie_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcpudp);
    let layer4_icmp_zombie = Layer4MatchIcmp {
        layer3: Some(layer3_zombie),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };

    let layer_match_zombie_1 = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp_zombie);
    let layer_match_zombie_2 = LayerMatch::Layer4MatchIcmp(layer4_icmp_zombie);

    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    let ip_buff = _forge_syn_packet(src_ipv4, zombie_ipv4, src_port, zombie_port)?;
    let (ret, rtt_1) = layer3_ipv4_send(
        zombie_ipv4,
        src_ipv4,
        &ip_buff,
        vec![layer_match_zombie_1, layer_match_zombie_2],
        timeout,
        true,
    )?;

    let mut zombie_ip_id_1 = 0;
    match Ipv4Packet::new(&ret) {
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
                            if icmp_type == IcmpTypes::DestinationUnreachable {
                                if codes.contains(&icmp_code) {
                                    // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                    // dst is unreachable ignore this port
                                    return Ok((
                                        PortStatus::Unreachable,
                                        DataRecvStatus::Yes,
                                        None,
                                        rtt_1,
                                    ));
                                }
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

    // 3. forge a syn packet from the zombie to the target
    let ip_buff_2 = _forge_syn_packet(zombie_ipv4, dst_ipv4, zombie_port, dst_port)?;
    // ignore the response
    let _ret = layer3_ipv4_send(dst_ipv4, src_ipv4, &ip_buff_2, vec![], timeout, true)?;

    // 4. probe the zombie's ip id again
    let ip_buff_3 = _forge_syn_packet(src_ipv4, zombie_ipv4, src_port, zombie_port)?;
    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
        ip_id: None,
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv4.into()),
        dst_addr: Some(dst_ipv4.into()),
    };
    let payload_tcpudp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcpudp);
    let layer4_icmp = Layer4MatchIcmp {
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let layer_match_1 = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);
    let layer_match_2 = LayerMatch::Layer4MatchIcmp(layer4_icmp);

    let (ret, rtt_2) = layer3_ipv4_send(
        dst_ipv4,
        src_ipv4,
        &ip_buff_3,
        vec![layer_match_1, layer_match_2],
        timeout,
        true,
    )?;

    let mut zombie_ip_id_2 = 0;
    let rtt = (rtt_1 + rtt_2) / 2;
    match Ipv4Packet::new(&ret) {
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
                            if icmp_type == IcmpTypes::DestinationUnreachable {
                                if codes.contains(&icmp_code) {
                                    // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                    // dst is unreachable ignore this port
                                    return Ok((
                                        PortStatus::Unreachable,
                                        DataRecvStatus::Yes,
                                        None,
                                        rtt,
                                    ));
                                }
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
    if zombie_ip_id_1 == 0 && zombie_ip_id_2 == 0 {
        return Err(PistolError::IdleScanAllZeroError {
            zombie_ipv4,
            zombie_port,
        });
    } else if zombie_ip_id_2 - zombie_ip_id_1 >= 2 {
        Ok((
            PortStatus::Open,
            DataRecvStatus::Yes,
            Some(TcpIdleScans {
                zombie_ip_id_1,
                zombie_ip_id_2,
            }),
            rtt,
        ))
    } else {
        Ok((
            PortStatus::ClosedOrFiltered,
            DataRecvStatus::No,
            Some(TcpIdleScans {
                zombie_ip_id_1,
                zombie_ip_id_2,
            }),
            rtt,
        ))
    }
}

/// For both IPv4 and IPv6 target.
pub fn send_connect_scan_packet(
    dst_addr: IpAddr,
    dst_port: u16,
    timeout: Option<Duration>,
) -> Result<(PortStatus, DataRecvStatus, Duration), PistolError> {
    let start_time = Instant::now();
    match dst_addr {
        IpAddr::V4(dst_ipv4) => {
            let addr = SocketAddr::V4(SocketAddrV4::new(dst_ipv4, dst_port));
            let t = match timeout {
                Some(t) => t,
                None => utils::get_default_timeout(),
            };
            match TcpStream::connect_timeout(&addr, t) {
                Ok(_) => Ok((PortStatus::Open, DataRecvStatus::Yes, start_time.elapsed())),
                Err(_) => Ok((PortStatus::Closed, DataRecvStatus::No, start_time.elapsed())),
            }
        }
        IpAddr::V6(dst_ipv6) => {
            let addr = SocketAddr::V6(SocketAddrV6::new(dst_ipv6, dst_port, 0, 0));
            let t = match timeout {
                Some(t) => t,
                None => utils::get_default_timeout(),
            };
            match TcpStream::connect_timeout(&addr, t) {
                Ok(_) => Ok((PortStatus::Open, DataRecvStatus::Yes, start_time.elapsed())),
                Err(_) => Ok((PortStatus::Closed, DataRecvStatus::No, start_time.elapsed())),
            }
        }
    }
}
