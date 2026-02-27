use crossbeam::channel::Receiver;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
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
use rand::RngExt;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::net::TcpStream;
use std::panic::Location;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use crate::ask_runner;
use crate::error::PistolError;
use crate::get_response;
use crate::layer::IPV4_HEADER_SIZE;
use crate::layer::Layer3Filter;
use crate::layer::Layer4FilterIcmp;
use crate::layer::Layer4FilterTcpUdp;
use crate::layer::PacketFilter;
use crate::layer::PayloadMatch;
use crate::layer::PayloadMatchIp;
use crate::layer::PayloadMatchTcpUdp;
use crate::layer::TCP_HEADER_SIZE;
use crate::scan::PortStatus;
use crate::scan::RecvResponse;

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

pub(crate) fn send_syn_scan_packet(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
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

    let layer3 = Layer3Filter {
        name: String::from("tcp syn scan layer3"),
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp syn scan tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
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
    let layer4_icmp = Layer4FilterIcmp {
        name: String::from("tcp syn scan icmp"),
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ip_buff,
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
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
            match ip_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
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
                IpNextHeaderProtocols::Icmp => {
                    if let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) {
                        let icmp_type = icmp_packet.get_icmp_type();
                        let icmp_code = icmp_packet.get_icmp_code();
                        if icmp_type == IcmpTypes::DestinationUnreachable {
                            if codes.contains(&icmp_code) {
                                // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
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
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
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

    let layer3 = Layer3Filter {
        name: String::from("tcp fin scan layer3"),
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp fin scan tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
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
    let layer4_icmp = Layer4FilterIcmp {
        name: String::from("tcp fin scan icmp"),
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ip_buff,
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
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
            match ip_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
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
                IpNextHeaderProtocols::Icmp => {
                    if let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) {
                        let icmp_type = icmp_packet.get_icmp_type();
                        let icmp_code = icmp_packet.get_icmp_code();
                        if icmp_type == IcmpTypes::DestinationUnreachable {
                            if codes.contains(&icmp_code) {
                                // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
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
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
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

    let layer3 = Layer3Filter {
        name: String::from("tcp ack scan layer3"),
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp ack scan tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
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
    let layer4_icmp = Layer4FilterIcmp {
        name: String::from("tcp ack scan icmp"),
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ip_buff,
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
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
            match ip_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                        let tcp_flags = tcp_packet.get_flags();
                        if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                            // tcp rst response
                            return Ok((PortStatus::Unfiltered, RecvResponse::Yes, rtt));
                        }
                    }
                }
                IpNextHeaderProtocols::Icmp => {
                    if let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) {
                        let icmp_type = icmp_packet.get_icmp_type();
                        let icmp_code = icmp_packet.get_icmp_code();
                        if icmp_type == IcmpTypes::DestinationUnreachable {
                            if codes.contains(&icmp_code) {
                                // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
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
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
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

    let layer3 = Layer3Filter {
        name: String::from("tcp null scan layer3"),
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp null scan tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
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
    let layer4_icmp = Layer4FilterIcmp {
        name: String::from("tcp null scan icmp"),
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ip_buff,
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
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
            match ip_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                        let tcp_flags = tcp_packet.get_flags();
                        if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                            // tcp rst response
                            return Ok((PortStatus::Closed, RecvResponse::Yes, rtt));
                        }
                    }
                }
                IpNextHeaderProtocols::Icmp => {
                    if let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) {
                        let icmp_type = icmp_packet.get_icmp_type();
                        let icmp_code = icmp_packet.get_icmp_code();
                        if icmp_type == IcmpTypes::DestinationUnreachable {
                            if codes.contains(&icmp_code) {
                                // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
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
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
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

    let layer3 = Layer3Filter {
        name: String::from("tcp xmas scan icmp"),
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp xmas scan tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
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
    let layer4_icmp = Layer4FilterIcmp {
        name: String::from("tcp xmas scan icmp"),
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ip_buff,
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
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
            match ip_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                        let tcp_flags = tcp_packet.get_flags();
                        if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                            // tcp rst response
                            return Ok((PortStatus::Closed, RecvResponse::Yes, rtt));
                        }
                    }
                }
                IpNextHeaderProtocols::Icmp => {
                    if let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) {
                        let icmp_type = icmp_packet.get_icmp_type();
                        let icmp_code = icmp_packet.get_icmp_code();
                        if icmp_type == IcmpTypes::DestinationUnreachable {
                            if codes.contains(&icmp_code) {
                                // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
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
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
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

    let layer3 = Layer3Filter {
        name: String::from("tcp window scan layer3"),
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp window scan tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
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
    let layer4_icmp = Layer4FilterIcmp {
        name: String::from("tcp window scan icmp"),
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ip_buff,
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
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
            match ip_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
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
                IpNextHeaderProtocols::Icmp => {
                    if let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) {
                        let icmp_type = icmp_packet.get_icmp_type();
                        let icmp_code = icmp_packet.get_icmp_code();
                        if icmp_type == IcmpTypes::DestinationUnreachable {
                            if codes.contains(&icmp_code) {
                                // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
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
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
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

    let layer3 = Layer3Filter {
        name: String::from("tcp maimon scan layer3"),
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp maimon scan tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
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
    let layer4_icmp = Layer4FilterIcmp {
        name: String::from("tcp maimon scan icmp"),
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ip_buff,
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
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
            match ip_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                        let tcp_flags = tcp_packet.get_flags();
                        if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                            // tcp rst response
                            return Ok((PortStatus::Closed, RecvResponse::Yes, rtt));
                        }
                    }
                }
                IpNextHeaderProtocols::Icmp => {
                    if let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) {
                        let icmp_type = icmp_packet.get_icmp_type();
                        let icmp_code = icmp_packet.get_icmp_code();
                        if icmp_type == IcmpTypes::DestinationUnreachable {
                            if codes.contains(&icmp_code) {
                                // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
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

fn forge_syn_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<Arc<[u8]>, PistolError> {
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

    Ok(Arc::new(ip_buff))
}

/// Step 1: probe the zombie's ip id.
pub(crate) fn send_idle_scan_packet_1(
    _dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    _dst_port: u16,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    zombie_mac: MacAddr,
    zombie_ipv4: Ipv4Addr,
    zombie_port: u16,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
    // 1. probe the zombie's ip id
    let layer3_zombie = Layer3Filter {
        name: String::from("tcp zombie scan layer3 1"),
        layer2: None,
        src_addr: Some(zombie_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_tcp_udp_zombie = Layer4FilterTcpUdp {
        name: String::from("tcp zombie scan tcp_udp 1"),
        layer3: Some(layer3_zombie.clone()),
        src_port: Some(zombie_port),
        dst_port: Some(src_port),
        flag: None,
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
    let layer4_icmp_zombie = Layer4FilterIcmp {
        name: String::from("tcp zombie scan icmp 1"),
        layer3: Some(layer3_zombie.clone()),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };

    let filter_zombie_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp_zombie);
    let filter_zombie_2 = PacketFilter::Layer4FilterIcmp(layer4_icmp_zombie);

    let ip_buff_1 = forge_syn_packet(zombie_ipv4, zombie_port, src_ipv4, src_port)?;

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    let receiver = ask_runner(
        iface,
        zombie_mac,
        src_mac,
        &ip_buff_1,
        ether_type,
        vec![filter_zombie_1, filter_zombie_2],
        timeout,
        0,
    )?;
    Ok(receiver)
}

/// Step 2: forge a syn packet from the zombie to the target, and ignore the response.
pub(crate) fn send_idle_scan_packet_2(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_mac: MacAddr,
    _src_ipv4: Ipv4Addr,
    _src_port: u16,
    _zombie_mac: MacAddr,
    zombie_ipv4: Ipv4Addr,
    zombie_port: u16,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<(), PistolError> {
    // 2. forge a syn packet from the zombie to the target
    let ip_buff_2 = forge_syn_packet(dst_ipv4, dst_port, zombie_ipv4, zombie_port)?;
    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    // ignore the response
    let _receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ip_buff_2,
        ether_type,
        Vec::new(),
        timeout,
        0,
    )?;
    Ok(())
}

/// Step 3: probe the zombie's ip id again,
/// if the ip id increased by 2, the port is open,
/// if the ip id only increased by 1, the port is closed or filtered.
pub(crate) fn send_idle_scan_packet_3(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    _zombie_mac: MacAddr,
    zombie_ipv4: Ipv4Addr,
    zombie_port: u16,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
    // 4. probe the zombie's ip id again
    let layer3 = Layer3Filter {
        name: String::from("tcp zombie scan layer 2"),
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp zombie scan tcp_udp 2"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
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
    let layer4_icmp = Layer4FilterIcmp {
        name: String::from("tcp zombie scan icmp 2"),
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let ip_buff_3 = forge_syn_packet(zombie_ipv4, zombie_port, src_ipv4, src_port)?;

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ip_buff_3,
        ether_type,
        vec![filter_1, filter_2],
        timeout,
        0,
    )?;
    Ok(receiver)
}

pub(crate) fn recv_idle_scan_packet_1(
    start: Instant,
    timeout: Duration,
    receiver: Receiver<(Arc<[u8]>, Duration)>,
) -> Result<(PortStatus, RecvResponse, Duration, u16), PistolError> {
    let (eth_response, rtt_1) = get_response(receiver, start, timeout);
    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    let mut zombie_ip_id_1 = 0;
    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
            match ip_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                        let tcp_flags = tcp_packet.get_flags();
                        if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                            // 2. zombie return rst packet, get this packet ip id
                            zombie_ip_id_1 = ip_packet.get_identification();
                        }
                    }
                }
                IpNextHeaderProtocols::Icmp => {
                    if let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) {
                        let icmp_type = icmp_packet.get_icmp_type();
                        let icmp_code = icmp_packet.get_icmp_code();
                        if icmp_type == IcmpTypes::DestinationUnreachable {
                            if codes.contains(&icmp_code) {
                                // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                // dst is unreachable ignore this port
                                return Ok((
                                    PortStatus::Unreachable,
                                    RecvResponse::Yes,
                                    rtt_1,
                                    zombie_ip_id_1,
                                ));
                            }
                        }
                    }
                }
                _ => (),
            }
        }
    }
    Ok((PortStatus::Open, RecvResponse::Yes, rtt_1, zombie_ip_id_1))
}

pub(crate) fn recv_idle_scan_packet_2(
    zombie_ipv4: Ipv4Addr,
    zombie_port: u16,
    start: Instant,
    timeout: Duration,
    receiver: Receiver<(Arc<[u8]>, Duration)>,
    rtt_1: Duration,
    zombie_ip_id_1: u16,
) -> Result<(PortStatus, RecvResponse, Duration), PistolError> {
    let (eth_response, rtt_2) = get_response(receiver, start, timeout);
    // same as recv_idle_scan_packet_1
    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    let mut zombie_ip_id_2 = 0;
    let rtt = (rtt_1 + rtt_2) / 2;
    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
            match ip_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                        let tcp_flags = tcp_packet.get_flags();
                        if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                            // 5. zombie return rst packet again, get this packet ip id
                            zombie_ip_id_2 = ip_packet.get_identification();
                        }
                    }
                }
                IpNextHeaderProtocols::Icmp => {
                    if let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) {
                        let icmp_type = icmp_packet.get_icmp_type();
                        let icmp_code = icmp_packet.get_icmp_code();
                        if icmp_type == IcmpTypes::DestinationUnreachable {
                            if codes.contains(&icmp_code) {
                                // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                // dst is unreachable ignore this port
                                return Ok((PortStatus::Unreachable, RecvResponse::Yes, rtt));
                            }
                        }
                    }
                }
                _ => (),
            }
        }
    }

    if zombie_ip_id_1 == 0 && zombie_ip_id_2 == 0 {
        return Err(PistolError::IdleScanAllZeroError {
            zombie_ipv4,
            zombie_port,
        });
    } else if zombie_ip_id_2 - zombie_ip_id_1 >= 2 {
        Ok((PortStatus::Open, RecvResponse::Yes, rtt))
    } else {
        Ok((PortStatus::ClosedOrFiltered, RecvResponse::No, rtt))
    }
}

/// Tcp 3-way handshake scan (also known as TCP connect scan) implementation.
/// Step 1: send a syn packet to the target port, and wait for the syn-ack or rst response.
pub(crate) fn send_connect_scan_packet_1(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
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
    tcp_header.set_acknowledgement(0);
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: String::from("tcp connnect scan 1 layer3"),
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp connnect scan 1 tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
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
    let layer4_icmp = Layer4FilterIcmp {
        name: String::from("tcp syn scan icmp"),
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ip_buff,
        ether_type,
        vec![filter_1, filter_2],
        timeout,
        0,
    )?;
    Ok(receiver)
}

/// TCP 3-way handshake scan (also known as TCP connect scan) implementation.
/// Step 2: if receive syn-ack, send ack to finish the 3-way.
pub(crate) fn send_connect_scan_packet_2(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    last_server_sequence: u32,
    last_server_acknowledgement: u32,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
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
    tcp_header.set_sequence(last_server_acknowledgement);
    tcp_header.set_acknowledgement(last_server_sequence + 1);
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: String::from("tcp connnect scan 2 layer3"),
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp connnect scan 2 tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
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
    let layer4_icmp = Layer4FilterIcmp {
        name: String::from("tcp syn scan icmp"),
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ip_buff,
        ether_type,
        vec![filter_1, filter_2],
        timeout,
        0,
    )?;
    Ok(receiver)
}

/// TCP 4-way handshake scan (also known as TCP connect scan) implementation.
/// Step 3: send fin-ack to the target port, try to close the connection.
pub(crate) fn send_connect_scan_packet_3(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    last_client_sequence: u32,
    last_client_acknowledgement: u32,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
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
    tcp_header.set_sequence(last_client_sequence);
    tcp_header.set_acknowledgement(last_client_acknowledgement);
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::FIN | TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: String::from("tcp connnect scan 2 layer3"),
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp connnect scan 2 tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
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
    let layer4_icmp = Layer4FilterIcmp {
        name: String::from("tcp syn scan icmp"),
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ip_buff,
        ether_type,
        vec![filter_1, filter_2],
        timeout,
        0,
    )?;
    Ok(receiver)
}

/// TCP 4-way handshake scan (also known as TCP connect scan) implementation.
/// Step 4: if receive fin-ack, the connection is closed successfully.
/// We ignore the 2th handshake response, and just wait for the fin-ack response.
pub(crate) fn send_connect_scan_packet_4(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    last_server_sequence: u32,
    last_server_acknowledgement: u32,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
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
    tcp_header.set_sequence(last_server_acknowledgement);
    tcp_header.set_acknowledgement(last_server_sequence + 1);
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: String::from("tcp connnect scan 2 layer3"),
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("tcp connnect scan 2 tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: Some(TcpFlags::FIN | TcpFlags::ACK),
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
    let layer4_icmp = Layer4FilterIcmp {
        name: String::from("tcp syn scan icmp"),
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
    let filter_2 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ip_buff,
        ether_type,
        vec![filter_1, filter_2],
        timeout,
        0,
    )?;
    Ok(receiver)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum TcpConnStatus {
    Next,
    Stop,
    Retry,
}

/// Returns:
/// 1.continue to next step or not,
/// 2.sequence number of the last server response,
/// 3.acknowledgement number of the last server response,
/// 4.rtt.
pub(crate) fn recv_connect_scan_packet(
    start: Instant,
    timeout: Duration,
    receiver: Receiver<(Arc<[u8]>, Duration)>,
) -> Result<(TcpConnStatus, u32, u32, Duration), PistolError> {
    let (eth_response, rtt) = get_response(receiver, start, timeout);
    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
            match ip_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                        let tcp_flags = tcp_packet.get_flags();
                        if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                            // tcp rst response
                            return Ok((TcpConnStatus::Stop, 0, 0, rtt));
                        } else {
                            let seq = tcp_packet.get_sequence();
                            let ack = tcp_packet.get_acknowledgement();
                            return Ok((TcpConnStatus::Next, seq, ack, rtt));
                        }
                    }
                }
                IpNextHeaderProtocols::Icmp => {
                    if let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) {
                        let icmp_type = icmp_packet.get_icmp_type();
                        let icmp_code = icmp_packet.get_icmp_code();
                        if icmp_type == IcmpTypes::DestinationUnreachable {
                            if codes.contains(&icmp_code) {
                                // icmp unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
                                return Ok((TcpConnStatus::Stop, 0, 0, rtt));
                            }
                        }
                    }
                }
                _ => (),
            }
        }
    }
    // no response received (even after retransmissions)
    Ok((TcpConnStatus::Retry, 0, 0, rtt))
}

/// For both IPv4 and IPv6 target.
pub(crate) fn send_connect_scan_packet(
    dst_addr: IpAddr,
    dst_port: u16,
    timeout: Duration,
) -> Result<(PortStatus, RecvResponse, Duration), PistolError> {
    let start_time = Instant::now();
    match dst_addr {
        IpAddr::V4(dst_ipv4) => {
            let addr = SocketAddr::V4(SocketAddrV4::new(dst_ipv4, dst_port));
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(_) => Ok((PortStatus::Open, RecvResponse::Yes, start_time.elapsed())),
                Err(_) => Ok((PortStatus::Closed, RecvResponse::No, start_time.elapsed())),
            }
        }
        IpAddr::V6(dst_ipv6) => {
            let addr = SocketAddr::V6(SocketAddrV6::new(dst_ipv6, dst_port, 0, 0));
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(_) => Ok((PortStatus::Open, RecvResponse::Yes, start_time.elapsed())),
                Err(_) => Ok((PortStatus::Closed, RecvResponse::No, start_time.elapsed())),
            }
        }
    }
}
