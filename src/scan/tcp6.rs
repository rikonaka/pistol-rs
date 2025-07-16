use pnet::packet::Packet;
use pnet::packet::icmpv6::Icmpv6Code;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::tcp::ipv6_checksum;
use rand::Rng;
use std::net::Ipv6Addr;
use std::panic::Location;
use std::time::Duration;

use crate::error::PistolError;
use crate::layer::IPV6_HEADER_SIZE;
use crate::layer::Layer3Match;
use crate::layer::Layer4MatchIcmpv6;
use crate::layer::Layer4MatchTcpUdp;
use crate::layer::LayerMatch;
use crate::layer::TCP_HEADER_SIZE;
use crate::layer::layer3_ipv6_send;

use super::PortStatus;

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
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    let mut rng = rand::rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
            });
        }
    };
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
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
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
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
    };
    let layers_match_1 = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);
    let layers_match_2 = LayerMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    let (ret, rtt) = layer3_ipv6_send(
        dst_ipv6,
        src_ipv6,
        &ipv6_buff,
        vec![layers_match_1, layers_match_2],
        timeout,
        true,
    )?;

    match Ipv6Packet::new(&ret) {
        Some(ipv6_packet) => {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    match TcpPacket::new(ipv6_packet.payload()) {
                        Some(tcp_packet) => {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                                // tcp syn/ack response
                                return Ok((PortStatus::Open, rtt));
                            } else if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok((PortStatus::Closed, rtt));
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
                                return Ok((PortStatus::Filtered, rtt));
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
    Ok((PortStatus::Filtered, rtt))
}

pub fn send_fin_scan_packet(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    let mut rng = rand::rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
            });
        }
    };
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
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
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
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
    };
    let layers_match_1 = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);
    let layers_match_2 = LayerMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    let (ret, rtt) = layer3_ipv6_send(
        dst_ipv6,
        src_ipv6,
        &ipv6_buff,
        vec![layers_match_1, layers_match_2],
        timeout,
        true,
    )?;

    match Ipv6Packet::new(&ret) {
        Some(ipv6_packet) => {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    match TcpPacket::new(ipv6_packet.payload()) {
                        Some(tcp_packet) => {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                                // tcp syn/ack response
                                return Ok((PortStatus::Open, rtt));
                            } else if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst packet
                                return Ok((PortStatus::Closed, rtt));
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
                                return Ok((PortStatus::Filtered, rtt));
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
    Ok((PortStatus::OpenOrFiltered, rtt))
}

pub fn send_ack_scan_packet(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    let mut rng = rand::rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
            });
        }
    };
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
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
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
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
    };
    let layers_match_1 = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);
    let layers_match_2 = LayerMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    let (ret, rtt) = layer3_ipv6_send(
        dst_ipv6,
        src_ipv6,
        &ipv6_buff,
        vec![layers_match_1, layers_match_2],
        timeout,
        true,
    )?;

    match Ipv6Packet::new(&ret) {
        Some(ipv6_packet) => {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    match TcpPacket::new(ipv6_packet.payload()) {
                        Some(tcp_packet) => {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok((PortStatus::Unfiltered, rtt));
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
                                return Ok((PortStatus::Filtered, rtt));
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
    Ok((PortStatus::Filtered, rtt))
}

pub fn send_null_scan_packet(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    let mut rng = rand::rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
            });
        }
    };
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
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
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
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
    };
    let layers_match_1 = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);
    let layers_match_2 = LayerMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    let (ret, rtt) = layer3_ipv6_send(
        dst_ipv6,
        src_ipv6,
        &ipv6_buff,
        vec![layers_match_1, layers_match_2],
        timeout,
        true,
    )?;

    match Ipv6Packet::new(&ret) {
        Some(ipv6_packet) => {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    match TcpPacket::new(ipv6_packet.payload()) {
                        Some(tcp_packet) => {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok((PortStatus::Closed, rtt));
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
                                return Ok((PortStatus::Filtered, rtt));
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
    Ok((PortStatus::OpenOrFiltered, rtt))
}

pub fn send_xmas_scan_packet(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    let mut rng = rand::rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
            });
        }
    };
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
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
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
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
    };
    let layers_match_1 = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);
    let layers_match_2 = LayerMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    let (ret, rtt) = layer3_ipv6_send(
        dst_ipv6,
        src_ipv6,
        &ipv6_buff,
        vec![layers_match_1, layers_match_2],
        timeout,
        true,
    )?;

    match Ipv6Packet::new(&ret) {
        Some(ipv6_packet) => {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    match TcpPacket::new(ipv6_packet.payload()) {
                        Some(tcp_packet) => {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok((PortStatus::Closed, rtt));
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
                                return Ok((PortStatus::Filtered, rtt));
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
    Ok((PortStatus::OpenOrFiltered, rtt))
}

pub fn send_window_scan_packet(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    let mut rng = rand::rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
            });
        }
    };
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
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
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
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
    };
    let layers_match_1 = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);
    let layers_match_2 = LayerMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    let (ret, rtt) = layer3_ipv6_send(
        dst_ipv6,
        src_ipv6,
        &ipv6_buff,
        vec![layers_match_1, layers_match_2],
        timeout,
        true,
    )?;

    match Ipv6Packet::new(&ret) {
        Some(ipv6_packet) => {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    match TcpPacket::new(ipv6_packet.payload()) {
                        Some(tcp_packet) => {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                if tcp_packet.get_window() > 0 {
                                    // tcp rst response with non-zero window field
                                    return Ok((PortStatus::Open, rtt));
                                } else {
                                    // tcp rst response with zero window field
                                    return Ok((PortStatus::Closed, rtt));
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
                                return Ok((PortStatus::Filtered, rtt));
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
    Ok((PortStatus::Filtered, rtt))
}

pub fn send_maimon_scan_packet(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    let mut rng = rand::rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
            });
        }
    };
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
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
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
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
    };
    let layers_match_1 = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);
    let layers_match_2 = LayerMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    let (ret, rtt) = layer3_ipv6_send(
        dst_ipv6,
        src_ipv6,
        &ipv6_buff,
        vec![layers_match_1, layers_match_2],
        timeout,
        true,
    )?;

    match Ipv6Packet::new(&ret) {
        Some(ipv6_packet) => {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    match TcpPacket::new(ipv6_packet.payload()) {
                        Some(tcp_packet) => {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok((PortStatus::Closed, rtt));
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
                                return Ok((PortStatus::Filtered, rtt));
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
    Ok((PortStatus::OpenOrFiltered, rtt))
}
