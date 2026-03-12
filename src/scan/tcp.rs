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

use crate::error::PistolError;
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

pub(crate) fn build_syn_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<(Arc<[u8]>, Vec<Arc<PacketFilter>>), PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = match MutableIpv4Packet::new(&mut ip_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: Location::caller().to_string(),
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
                location: Location::caller().to_string(),
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
    let filter_1 = Arc::new(PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp));
    let filter_2 = Arc::new(PacketFilter::Layer4FilterIcmp(layer4_icmp));

    let ip_buff = Arc::new(ip_buff);
    Ok((ip_buff, vec![filter_1, filter_2]))
}

pub(crate) fn parse_syn_scan_response(eth_response: Arc<[u8]>) -> Result<PortStatus, PistolError> {
    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
            if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
                match ip_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                                // tcp syn/ack response
                                return Ok(PortStatus::Open);
                            } else if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok(PortStatus::Closed);
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
                                    return Ok(PortStatus::Filtered);
                                }
                            }
                        }
                    }
                    _ => (),
                }
            }
        }
    }
    // no response received (even after retransmissions)
    Ok(PortStatus::Filtered)
}

pub(crate) fn build_fin_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<(Arc<[u8]>, Vec<Arc<PacketFilter>>), PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = match MutableIpv4Packet::new(&mut ip_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: Location::caller().to_string(),
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
                location: Location::caller().to_string(),
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
    let filter_1 = Arc::new(PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp));
    let filter_2 = Arc::new(PacketFilter::Layer4FilterIcmp(layer4_icmp));

    let ip_buff = Arc::new(ip_buff);
    Ok((ip_buff, vec![filter_1, filter_2]))
}

pub(crate) fn parse_fin_scan_response(eth_response: Arc<[u8]>) -> Result<PortStatus, PistolError> {
    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
            if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
                match ip_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                                // tcp syn/ack response
                                return Ok(PortStatus::Open);
                            } else if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst packet
                                return Ok(PortStatus::Closed);
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
                                    return Ok(PortStatus::Filtered);
                                }
                            }
                        }
                    }
                    _ => (),
                }
            }
        }
    }
    // no response received (even after retransmissions)
    Ok(PortStatus::OpenOrFiltered)
}

pub(crate) fn build_ack_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<(Arc<[u8]>, Vec<Arc<PacketFilter>>), PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = match MutableIpv4Packet::new(&mut ip_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: Location::caller().to_string(),
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
                location: Location::caller().to_string(),
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
    let filter_1 = Arc::new(PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp));
    let filter_2 = Arc::new(PacketFilter::Layer4FilterIcmp(layer4_icmp));

    let ip_buff = Arc::new(ip_buff);
    Ok((ip_buff, vec![filter_1, filter_2]))
}

pub(crate) fn parse_ack_scan_response(eth_response: Arc<[u8]>) -> Result<PortStatus, PistolError> {
    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
            if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
                match ip_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok(PortStatus::Unfiltered);
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
                                    return Ok(PortStatus::Filtered);
                                }
                            }
                        }
                    }
                    _ => (),
                }
            }
        }
    }
    // no response received (even after retransmissions)
    Ok(PortStatus::Filtered)
}

pub(crate) fn build_null_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<(Arc<[u8]>, Vec<Arc<PacketFilter>>), PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = match MutableIpv4Packet::new(&mut ip_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: Location::caller().to_string(),
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
                location: Location::caller().to_string(),
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
    let filter_1 = Arc::new(PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp));
    let filter_2 = Arc::new(PacketFilter::Layer4FilterIcmp(layer4_icmp));

    let ip_buff = Arc::new(ip_buff);
    Ok((ip_buff, vec![filter_1, filter_2]))
}

pub(crate) fn parse_null_scan_response(eth_response: Arc<[u8]>) -> Result<PortStatus, PistolError> {
    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
            if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
                match ip_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok(PortStatus::Closed);
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
                                    return Ok(PortStatus::Filtered);
                                }
                            }
                        }
                    }
                    _ => (),
                }
            }
        }
    }
    // no response received (even after retransmissions)
    Ok(PortStatus::OpenOrFiltered)
}

pub(crate) fn build_xmas_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<(Arc<[u8]>, Vec<Arc<PacketFilter>>), PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = match MutableIpv4Packet::new(&mut ip_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: Location::caller().to_string(),
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
                location: Location::caller().to_string(),
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
    let filter_1 = Arc::new(PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp));
    let filter_2 = Arc::new(PacketFilter::Layer4FilterIcmp(layer4_icmp));

    let ip_buff = Arc::new(ip_buff);
    Ok((ip_buff, vec![filter_1, filter_2]))
}

pub(crate) fn parse_xmas_scan_response(eth_response: Arc<[u8]>) -> Result<PortStatus, PistolError> {
    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
            if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
                match ip_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok(PortStatus::Closed);
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
                                    return Ok(PortStatus::Filtered);
                                }
                            }
                        }
                    }
                    _ => (),
                }
            }
        }
    }
    // no response received (even after retransmissions)
    Ok(PortStatus::OpenOrFiltered)
}

pub(crate) fn build_window_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<(Arc<[u8]>, Vec<Arc<PacketFilter>>), PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = match MutableIpv4Packet::new(&mut ip_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: Location::caller().to_string(),
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
                location: Location::caller().to_string(),
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
    let filter_1 = Arc::new(PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp));
    let filter_2 = Arc::new(PacketFilter::Layer4FilterIcmp(layer4_icmp));

    let ip_buff = Arc::new(ip_buff);
    Ok((ip_buff, vec![filter_1, filter_2]))
}

pub(crate) fn parse_window_scan_response(
    eth_response: Arc<[u8]>,
) -> Result<PortStatus, PistolError> {
    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
            if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
                match ip_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                if tcp_packet.get_window() > 0 {
                                    // tcp rst response with non-zero window field
                                    return Ok(PortStatus::Open);
                                } else {
                                    // tcp rst response with zero window field
                                    return Ok(PortStatus::Closed);
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
                                    return Ok(PortStatus::Filtered);
                                }
                            }
                        }
                    }
                    _ => (),
                }
            }
        }
    }
    // no response received (even after retransmissions)
    Ok(PortStatus::Filtered)
}

pub(crate) fn build_maimon_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<(Arc<[u8]>, Vec<Arc<PacketFilter>>), PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = match MutableIpv4Packet::new(&mut ip_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: Location::caller().to_string(),
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
                location: Location::caller().to_string(),
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
    let filter_1 = Arc::new(PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp));
    let filter_2 = Arc::new(PacketFilter::Layer4FilterIcmp(layer4_icmp));

    let ip_buff = Arc::new(ip_buff);
    Ok((ip_buff, vec![filter_1, filter_2]))
}

pub(crate) fn parse_maimon_scan_response(
    eth_response: Arc<[u8]>,
) -> Result<PortStatus, PistolError> {
    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
            if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
                match ip_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok(PortStatus::Closed);
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
                                    return Ok(PortStatus::Filtered);
                                }
                            }
                        }
                    }
                    _ => (),
                }
            }
        }
    }
    // no response received (even after retransmissions)
    Ok(PortStatus::OpenOrFiltered)
}

/// For both IPv4 and IPv6 target.
pub(crate) fn send_connect_scan_packet(
    dst_addr: IpAddr,
    dst_port: u16,
    timeout: Duration,
) -> Result<(PortStatus, Duration), PistolError> {
    let start = Instant::now();
    let addr = match dst_addr {
        IpAddr::V4(dst_ipv4) => SocketAddr::V4(SocketAddrV4::new(dst_ipv4, dst_port)),
        IpAddr::V6(dst_ipv6) => SocketAddr::V6(SocketAddrV6::new(dst_ipv6, dst_port, 0, 0)),
    };
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => Ok((PortStatus::Open, start.elapsed())),
        Err(_) => Ok((PortStatus::Closed, start.elapsed())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_connect_scan_filter() {
        let packet: [u8; 60] = [
            0x0, 0xc, 0x29, 0xec, 0xd0, 0x37, 0x0, 0xc, 0x29, 0xc5, 0xf6, 0x99, 0x8, 0x0, 0x45,
            0x0, 0x0, 0x2c, 0x0, 0x0, 0x40, 0x0, 0x40, 0x6, 0xaf, 0x2b, 0xc0, 0xa8, 0x5, 0x4d,
            0xc0, 0xa8, 0x5, 0x3, 0x0, 0x16, 0x31, 0xe3, 0x1d, 0xd0, 0x4, 0x72, 0x51, 0xc3, 0x52,
            0xb0, 0x60, 0x12, 0xfa, 0xf0, 0x18, 0xd6, 0x0, 0x0, 0x2, 0x4, 0x5, 0xb4, 0x0, 0x0,
        ];

        let dst_ipv4 = Ipv4Addr::new(192, 168, 5, 78);
        let src_ipv4 = Ipv4Addr::new(192, 168, 5, 3);
        let dst_port = 22;
        let src_port = 12771;

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

        let filter = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp);
        println!("{}", filter.check(&packet));
    }
}
