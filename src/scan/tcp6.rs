use crossbeam::channel::Receiver;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
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
use rand::RngExt;
use std::net::Ipv6Addr;
use std::panic::Location;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use crate::ask_runner;
use crate::error::PistolError;
use crate::get_response;
use crate::layer::IPV6_HEADER_SIZE;
use crate::layer::Layer3Filter;
use crate::layer::Layer4FilterIcmpv6;
use crate::layer::Layer4FilterTcpUdp;
use crate::layer::PacketFilter;
use crate::layer::PayloadMatch;
use crate::layer::PayloadMatchIp;
use crate::layer::PayloadMatchTcpUdp;
use crate::layer::TCP_HEADER_SIZE;
use crate::scan::PortStatus;
use crate::scan::RecvResponse;

// const TCP_FLAGS_CWR_MASK: u8 = 0b10000000;
// const TCP_FLAGS_ECE_MASK: u8 = 0b01000000;
// const TCP_FLAGS_URG_MASK: u8 = 0b00100000;
// const TCP_FLAGS_ACK_MASK: u8 = 0b00010000;
// const TCP_FLAGS_PSH_MASK: u8 = 0b00001000;
const TCP_FLAGS_RST_MASK: u8 = 0b00000100;
// const TCP_FLAGS_SYN_MASK: u8 = 0b00000010;
// const TCP_FLAGS_FIN_MASK: u8 = 0b00000001;

const TCP_DATA_SIZE: usize = 0;
const HOP_LIMIT: u8 = 255;

pub(crate) fn send_syn_scan_packet(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
    let mut rng = rand::rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
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
    ipv6_header.set_hop_limit(HOP_LIMIT);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: String::from("tcp6 syn scan layer3"),
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp6 syn scan tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv6.into()),
        dst_addr: Some(dst_ipv6.into()),
    };
    let payload_tcp_udp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcp_udp);
    let layer4_icmpv6 = Layer4FilterIcmpv6 {
        name: String::from("tcp6 syn scan icmpv6"),
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv6;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ipv6_buff,
        ether_type,
        vec![filter_1, filter_2],
        timeout,
        0,
    )?;
    Ok(receiver)
}

pub(crate) fn recv_syn_scan_packet(
    start: Instant,
    timeout: Duration,
    receiver: Receiver<(Arc<[u8]>, Duration)>,
) -> Result<(PortStatus, RecvResponse, Duration), PistolError> {
    let (eth_response, rtt) = get_response(receiver, start, timeout);
    let codes = vec![
        Icmpv6Code(1), // communication with destination administratively prohibited
        Icmpv6Code(3), // address unreachable
        Icmpv6Code(4), // port unreachable
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ipv6_packet) = Ipv6Packet::new(eth_packet.payload()) {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
                        let tcp_flags = tcp_packet.get_flags();
                        if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                            // tcp syn/ack response
                            return Ok((PortStatus::Open, RecvResponse::Yes, rtt));
                        } else if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                            // tcp rst response
                            return Ok((PortStatus::Closed, RecvResponse::Yes, rtt));
                        }
                    }
                }
                IpNextHeaderProtocols::Icmpv6 => {
                    if let Some(icmpv6_packet) = Icmpv6Packet::new(ipv6_packet.payload()) {
                        let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                        let icmpv6_code = icmpv6_packet.get_icmpv6_code();
                        if icmpv6_type == Icmpv6Types::DestinationUnreachable {
                            if codes.contains(&icmpv6_code) {
                                // icmpv6 unreachable error (type 1, code 1, 3, or 4)
                                return Ok((PortStatus::Filtered, RecvResponse::Yes, rtt));
                            }
                        }
                    }
                }
                _ => (),
            }
        }
    }
    // no response received (even after retransmissions)
    Ok((PortStatus::Filtered, RecvResponse::No, rtt))
}

pub(crate) fn send_fin_scan_packet(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
    let mut rng = rand::rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
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
    ipv6_header.set_hop_limit(HOP_LIMIT);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: String::from("tcp6 fin scan layer3"),
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp6 fin scan tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv6.into()),
        dst_addr: Some(dst_ipv6.into()),
    };
    let payload_tcp_udp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcp_udp);
    let layer4_icmpv6 = Layer4FilterIcmpv6 {
        name: String::from("tcp6 fin scan icmpv6"),
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv6;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ipv6_buff,
        ether_type,
        vec![filter_1, filter_2],
        timeout,
        0,
    )?;

    Ok(receiver)
}

pub(crate) fn recv_fin_scan_packet(
    start: Instant,
    timeout: Duration,
    receiver: Receiver<(Arc<[u8]>, Duration)>,
) -> Result<(PortStatus, RecvResponse, Duration), PistolError> {
    let (eth_response, rtt) = get_response(receiver, start, timeout);
    let codes = vec![
        Icmpv6Code(1), // communication with destination administratively prohibited
        Icmpv6Code(3), // address unreachable
        Icmpv6Code(4), // port unreachable
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ipv6_packet) = Ipv6Packet::new(eth_packet.payload()) {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
                        let tcp_flags = tcp_packet.get_flags();
                        if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                            // tcp syn/ack response
                            return Ok((PortStatus::Open, RecvResponse::Yes, rtt));
                        } else if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                            // tcp rst packet
                            return Ok((PortStatus::Closed, RecvResponse::Yes, rtt));
                        }
                    }
                }
                IpNextHeaderProtocols::Icmpv6 => {
                    if let Some(icmpv6_packet) = Icmpv6Packet::new(ipv6_packet.payload()) {
                        let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                        let icmpv6_code = icmpv6_packet.get_icmpv6_code();
                        if icmpv6_type == Icmpv6Types::DestinationUnreachable {
                            if codes.contains(&icmpv6_code) {
                                // icmpv6 unreachable error (type 1, code 1, 3, or 4)
                                return Ok((PortStatus::Filtered, RecvResponse::Yes, rtt));
                            }
                        }
                    }
                }
                _ => (),
            }
        }
    }
    // no response received (even after retransmissions)
    Ok((PortStatus::OpenOrFiltered, RecvResponse::No, rtt))
}

pub(crate) fn send_ack_scan_packet(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
    let mut rng = rand::rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
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
    ipv6_header.set_hop_limit(HOP_LIMIT);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: String::from("tcp6 ack scan layer3"),
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp6 ack scan tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv6.into()),
        dst_addr: Some(dst_ipv6.into()),
    };
    let payload_tcp_udp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcp_udp);
    let layer4_icmpv6 = Layer4FilterIcmpv6 {
        name: String::from("tcp6 ack scan icmpv6"),
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv6;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ipv6_buff,
        ether_type,
        vec![filter_1, filter_2],
        timeout,
        0,
    )?;
    Ok(receiver)
}

pub(crate) fn recv_ack_scan_packet(
    start: Instant,
    timeout: Duration,
    receiver: Receiver<(Arc<[u8]>, Duration)>,
) -> Result<(PortStatus, RecvResponse, Duration), PistolError> {
    let (eth_response, rtt) = get_response(receiver, start, timeout);
    let codes = vec![
        Icmpv6Code(1), // communication with destination administratively prohibited
        Icmpv6Code(3), // address unreachable
        Icmpv6Code(4), // port unreachable
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ipv6_packet) = Ipv6Packet::new(eth_packet.payload()) {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
                        let tcp_flags = tcp_packet.get_flags();
                        if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                            // tcp rst response
                            return Ok((PortStatus::Unfiltered, RecvResponse::Yes, rtt));
                        }
                    }
                }
                IpNextHeaderProtocols::Icmpv6 => {
                    if let Some(icmpv6_packet) = Icmpv6Packet::new(ipv6_packet.payload()) {
                        let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                        let icmpv6_code = icmpv6_packet.get_icmpv6_code();
                        if icmpv6_type == Icmpv6Types::DestinationUnreachable {
                            if codes.contains(&icmpv6_code) {
                                // icmpv6 unreachable error (type 1, code 1, 3, or 4)
                                return Ok((PortStatus::Filtered, RecvResponse::Yes, rtt));
                            }
                        }
                    }
                }
                _ => (),
            }
        }
    }
    // no response received (even after retransmissions)
    Ok((PortStatus::Filtered, RecvResponse::No, rtt))
}

pub(crate) fn send_null_scan_packet(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
    let mut rng = rand::rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
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
    ipv6_header.set_hop_limit(HOP_LIMIT);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: String::from("tcp6 null scan layer3"),
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp6 null scan tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv6.into()),
        dst_addr: Some(dst_ipv6.into()),
    };
    let payload_tcp_udp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcp_udp);
    let layer4_icmpv6 = Layer4FilterIcmpv6 {
        name: String::from("tcp6 null scan icmpv6"),
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv6;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ipv6_buff,
        ether_type,
        vec![filter_1, filter_2],
        timeout,
        0,
    )?;
    Ok(receiver)
}

pub(crate) fn recv_null_scan_packet(
    start: Instant,
    timeout: Duration,
    receiver: Receiver<(Arc<[u8]>, Duration)>,
) -> Result<(PortStatus, RecvResponse, Duration), PistolError> {
    let (eth_response, rtt) = get_response(receiver, start, timeout);
    let codes = vec![
        Icmpv6Code(1), // communication with destination administratively prohibited
        Icmpv6Code(3), // address unreachable
        Icmpv6Code(4), // port unreachable
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ipv6_packet) = Ipv6Packet::new(eth_packet.payload()) {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
                        let tcp_flags = tcp_packet.get_flags();
                        if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                            // tcp rst response
                            return Ok((PortStatus::Closed, RecvResponse::Yes, rtt));
                        }
                    }
                }
                IpNextHeaderProtocols::Icmpv6 => {
                    if let Some(icmpv6_packet) = Icmpv6Packet::new(ipv6_packet.payload()) {
                        let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                        let icmpv6_code = icmpv6_packet.get_icmpv6_code();
                        if icmpv6_type == Icmpv6Types::DestinationUnreachable {
                            if codes.contains(&icmpv6_code) {
                                // icmpv6 unreachable error (type 1, code 1, 3, or 4)
                                return Ok((PortStatus::Filtered, RecvResponse::Yes, rtt));
                            }
                        }
                    }
                }
                _ => (),
            }
        }
    }
    // no response received (even after retransmissions)
    Ok((PortStatus::OpenOrFiltered, RecvResponse::No, rtt))
}

pub(crate) fn send_xmas_scan_packet(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
    let mut rng = rand::rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
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
    ipv6_header.set_hop_limit(HOP_LIMIT);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: String::from("tcp6 xmas scan layer3"),
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp6 xmas scan tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv6.into()),
        dst_addr: Some(dst_ipv6.into()),
    };
    let payload_tcp_udp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcp_udp);
    let layer4_icmpv6 = Layer4FilterIcmpv6 {
        name: String::from("tcp6 xmas scan icmpv6"),
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv6;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ipv6_buff,
        ether_type,
        vec![filter_1, filter_2],
        timeout,
        0,
    )?;
    Ok(receiver)
}

pub(crate) fn recv_xmas_scan_packet(
    start: Instant,
    timeout: Duration,
    receiver: Receiver<(Arc<[u8]>, Duration)>,
) -> Result<(PortStatus, RecvResponse, Duration), PistolError> {
    let (eth_response, rtt) = get_response(receiver, start, timeout);
    let codes = vec![
        Icmpv6Code(1), // communication with destination administratively prohibited
        Icmpv6Code(3), // address unreachable
        Icmpv6Code(4), // port unreachable
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ipv6_packet) = Ipv6Packet::new(eth_packet.payload()) {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
                        let tcp_flags = tcp_packet.get_flags();
                        if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                            // tcp rst response
                            return Ok((PortStatus::Closed, RecvResponse::Yes, rtt));
                        }
                    }
                }
                IpNextHeaderProtocols::Icmpv6 => {
                    if let Some(icmpv6_packet) = Icmpv6Packet::new(ipv6_packet.payload()) {
                        let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                        let icmpv6_code = icmpv6_packet.get_icmpv6_code();
                        if icmpv6_type == Icmpv6Types::DestinationUnreachable {
                            if codes.contains(&icmpv6_code) {
                                // icmpv6 unreachable error (type 1, code 1, 3, or 4)
                                return Ok((PortStatus::Filtered, RecvResponse::Yes, rtt));
                            }
                        }
                    }
                }
                _ => (),
            }
        }
    }
    // no response received (even after retransmissions)
    Ok((PortStatus::OpenOrFiltered, RecvResponse::No, rtt))
}

pub(crate) fn send_window_scan_packet(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
    let mut rng = rand::rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
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
    ipv6_header.set_hop_limit(HOP_LIMIT);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: String::from("tcp6 windows scan layer3"),
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp6 windows scan tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv6.into()),
        dst_addr: Some(dst_ipv6.into()),
    };
    let payload_tcp_udp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcp_udp);
    let layer4_icmpv6 = Layer4FilterIcmpv6 {
        name: String::from("tcp6 windows scan icmpv6"),
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv6;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ipv6_buff,
        ether_type,
        vec![filter_1, filter_2],
        timeout,
        0,
    )?;
    Ok(receiver)
}

pub(crate) fn recv_window_scan_packet(
    start: Instant,
    timeout: Duration,
    receiver: Receiver<(Arc<[u8]>, Duration)>,
) -> Result<(PortStatus, RecvResponse, Duration), PistolError> {
    let (eth_response, rtt) = get_response(receiver, start, timeout);
    let codes = vec![
        Icmpv6Code(1), // communication with destination administratively prohibited
        Icmpv6Code(3), // address unreachable
        Icmpv6Code(4), // port unreachable
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ipv6_packet) = Ipv6Packet::new(eth_packet.payload()) {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
                        let tcp_flags = tcp_packet.get_flags();
                        if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                            if tcp_packet.get_window() > 0 {
                                // tcp rst response with non-zero window field
                                return Ok((PortStatus::Open, RecvResponse::Yes, rtt));
                            } else {
                                // tcp rst response with zero window field
                                return Ok((PortStatus::Closed, RecvResponse::Yes, rtt));
                            }
                        }
                    }
                }
                IpNextHeaderProtocols::Icmpv6 => {
                    if let Some(icmpv6_packet) = Icmpv6Packet::new(ipv6_packet.payload()) {
                        let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                        let icmpv6_code = icmpv6_packet.get_icmpv6_code();
                        if icmpv6_type == Icmpv6Types::DestinationUnreachable {
                            if codes.contains(&icmpv6_code) {
                                // icmpv6 unreachable error (type 1, code 1, 3, or 4)
                                return Ok((PortStatus::Filtered, RecvResponse::Yes, rtt));
                            }
                        }
                    }
                }
                _ => (),
            }
        }
    }
    // no response received (even after retransmissions)
    Ok((PortStatus::Filtered, RecvResponse::No, rtt))
}

pub(crate) fn send_maimon_scan_packet(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
    let mut rng = rand::rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
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
    ipv6_header.set_hop_limit(HOP_LIMIT);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: String::from("tcp6 maimon scan layer3"),
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp6 maimon scan tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv6.into()),
        dst_addr: Some(dst_ipv6.into()),
    };
    let payload_tcp_udp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcp_udp);
    let layer4_icmpv6 = Layer4FilterIcmpv6 {
        name: String::from("tcp6 maimon scan icmpv6"),
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv6;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ipv6_buff,
        ether_type,
        vec![filter_1, filter_2],
        timeout,
        0,
    )?;
    Ok(receiver)
}

pub(crate) fn recv_maimon_scan_packet(
    start: Instant,
    timeout: Duration,
    receiver: Receiver<(Arc<[u8]>, Duration)>,
) -> Result<(PortStatus, RecvResponse, Duration), PistolError> {
    let (eth_response, rtt) = get_response(receiver, start, timeout);
    let codes = vec![
        Icmpv6Code(1), // communication with destination administratively prohibited
        Icmpv6Code(3), // address unreachable
        Icmpv6Code(4), // port unreachable
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ipv6_packet) = Ipv6Packet::new(eth_packet.payload()) {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
                        let tcp_flags = tcp_packet.get_flags();
                        if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                            // tcp rst response
                            return Ok((PortStatus::Closed, RecvResponse::Yes, rtt));
                        }
                    }
                }
                IpNextHeaderProtocols::Icmpv6 => {
                    if let Some(icmpv6_packet) = Icmpv6Packet::new(ipv6_packet.payload()) {
                        let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                        let icmpv6_code = icmpv6_packet.get_icmpv6_code();
                        if icmpv6_type == Icmpv6Types::DestinationUnreachable {
                            if codes.contains(&icmpv6_code) {
                                // icmpv6 unreachable error (type 1, code 1, 3, or 4)
                                return Ok((PortStatus::Filtered, RecvResponse::Yes, rtt));
                            }
                        }
                    }
                }
                _ => (),
            }
        }
    }
    // no response received (even after retransmissions)
    Ok((PortStatus::OpenOrFiltered, RecvResponse::No, rtt))
}
