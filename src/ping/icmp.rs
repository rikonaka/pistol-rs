use chrono::Utc;
use crossbeam::channel::Receiver;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmp;
use pnet::packet::icmp::IcmpCode;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::icmp::destination_unreachable;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::Ipv4Flags;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv4::MutableIpv4Packet;
use rand::RngExt;
use std::net::Ipv4Addr;
use std::panic::Location;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use crate::ask_runner;
use crate::error::PistolError;
use crate::get_response;
use crate::layer::ICMP_HEADER_SIZE;
use crate::layer::IPV4_HEADER_SIZE;
use crate::layer::Layer3Filter;
use crate::layer::Layer4FilterIcmp;
use crate::layer::PacketFilter;
use crate::ping::PingStatus;
use crate::scan::RecvResponse;

const ICMP_ECHO_DATA_SIZE: usize = 16;
const ICMP_TIMESTAMP_DATA_SIZE: usize = 12;
const ICMP_ADDRESS_DATA_SIZE: usize = 4;
const TTL: u8 = 64;

pub(crate) fn send_icmp_echo_packet(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_ECHO_DATA_SIZE];
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
    ip_header.set_total_length((IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_ECHO_DATA_SIZE) as u16);
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    let mut icmp_header = match MutableEchoRequestPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    icmp_header.set_icmp_type(IcmpTypes::EchoRequest); // echo
    icmp_header.set_icmp_code(IcmpCode(0));
    icmp_header.set_identifier(rng.random());
    icmp_header.set_sequence_number(1);
    let mut tv_sec = Utc::now().timestamp().to_be_bytes();
    tv_sec.reverse(); // Big-Endian
    let mut tv_usec = Utc::now().timestamp_subsec_millis().to_be_bytes();
    tv_usec.reverse(); // Big-Endian
    let mut timestamp = Vec::new();
    timestamp.extend(tv_sec);
    timestamp.extend(tv_usec);
    icmp_header.set_payload(&timestamp);

    let mut icmp_header = match MutableIcmpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    let checksum = icmp::checksum(&icmp_header.to_immutable());
    icmp_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: String::from("ping echo layer3"),
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    // match all icmp reply
    let layer4_icmp = Layer4FilterIcmp {
        name: String::from("ping echo icmp"),
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: None,
    };
    let filter_1 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ip_buff,
        ether_type,
        vec![filter_1],
        timeout,
        0,
    )?;
    Ok(receiver)
}

pub(crate) fn recv_icmp_echo_packet(
    start: Instant,
    timeout: Duration,
    receiver: Receiver<(Arc<[u8]>, Duration)>,
) -> Result<(PingStatus, RecvResponse, Duration), PistolError> {
    let (eth_response, rtt) = get_response(receiver, start, timeout);
    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationHostUnreachable,     // 1
        destination_unreachable::IcmpCodes::DestinationPortUnreachable,     // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
            match ip_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmpv6 => {
                    if let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) {
                        let icmp_type = icmp_packet.get_icmp_type();
                        let icmp_code = icmp_packet.get_icmp_code();
                        if icmp_type == IcmpTypes::DestinationUnreachable {
                            if codes.contains(&icmp_code) {
                                return Ok((PingStatus::Down, RecvResponse::Yes, rtt));
                            }
                        } else if icmp_type == IcmpTypes::EchoReply {
                            return Ok((PingStatus::Up, RecvResponse::Yes, rtt));
                        }
                    }
                }
                _ => (),
            }
        }
    }
    // no response received (even after retransmissions)
    Ok((PingStatus::Down, RecvResponse::No, rtt))
}

pub(crate) fn send_icmp_timestamp_packet(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_TIMESTAMP_DATA_SIZE];
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
    ip_header
        .set_total_length((IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_TIMESTAMP_DATA_SIZE) as u16);
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // the timestamp package and echo request package are similar, so the structure will not be changed.
    let mut icmp_header = match MutableEchoRequestPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    icmp_header.set_icmp_type(IcmpTypes::Timestamp); // timestamp
    icmp_header.set_icmp_code(IcmpCode(0));
    icmp_header.set_identifier(rng.random());
    icmp_header.set_sequence_number(0);
    let timestamp_payload = [0u8; ICMP_TIMESTAMP_DATA_SIZE];
    icmp_header.set_payload(&timestamp_payload);

    let mut icmp_header = match MutableIcmpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    let checksum = icmp::checksum(&icmp_header.to_immutable());
    icmp_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: String::from("ping timestamp layer3"),
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    // match all icmp reply
    let layer4_icmp = Layer4FilterIcmp {
        name: String::from("ping timestamp icmp"),
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: None,
    };
    let filter_1 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ip_buff,
        ether_type,
        vec![filter_1],
        timeout,
        0,
    )?;
    Ok(receiver)
}

pub(crate) fn recv_icmp_timestamp_packet(
    start: Instant,
    timeout: Duration,
    receiver: Receiver<(Arc<[u8]>, Duration)>,
) -> Result<(PingStatus, RecvResponse, Duration), PistolError> {
    let (eth_response, rtt) = get_response(receiver, start, timeout);

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
            match ip_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmpv6 => {
                    if let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) {
                        let icmp_type = icmp_packet.get_icmp_type();
                        if icmp_type == IcmpTypes::DestinationUnreachable {
                            return Ok((PingStatus::Down, RecvResponse::Yes, rtt));
                        } else if icmp_type == IcmpTypes::TimestampReply {
                            return Ok((PingStatus::Up, RecvResponse::Yes, rtt));
                        }
                    }
                }
                _ => (),
            }
        }
    }
    // no response received (even after retransmissions)
    Ok((PingStatus::Down, RecvResponse::No, rtt))
}

pub(crate) fn send_icmp_address_mask_packet(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_ADDRESS_DATA_SIZE];
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
    ip_header
        .set_total_length((IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_ADDRESS_DATA_SIZE) as u16);
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // the address mask package and echo request package are similar, so the structure will not be changed.
    let mut icmp_header = match MutableEchoRequestPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    icmp_header.set_icmp_type(IcmpTypes::AddressMaskRequest); // address mask
    icmp_header.set_icmp_code(IcmpCode(0));
    icmp_header.set_identifier(rng.random());
    icmp_header.set_sequence_number(0);
    let timestamp_payload = [0u8; ICMP_ADDRESS_DATA_SIZE];
    icmp_header.set_payload(&timestamp_payload);

    let mut icmp_header = match MutableIcmpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    let checksum = icmp::checksum(&icmp_header.to_immutable());
    icmp_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: String::from("ping address mask layer3"),
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    // match all icmp reply
    let layer4_icmp = Layer4FilterIcmp {
        name: String::from("ping address mask icmp"),
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: None,
    };
    let filter_1 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ip_buff,
        ether_type,
        vec![filter_1],
        timeout,
        0,
    )?;
    Ok(receiver)
}

pub(crate) fn recv_icmp_address_mask_packet(
    start: Instant,
    timeout: Duration,
    receiver: Receiver<(Arc<[u8]>, Duration)>,
) -> Result<(PingStatus, RecvResponse, Duration), PistolError> {
    let (eth_response, rtt) = get_response(receiver, start, timeout);
    let codes = vec![
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationHostUnreachable,     // 1
        destination_unreachable::IcmpCodes::DestinationPortUnreachable,     // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
            match ip_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmpv6 => {
                    if let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) {
                        let icmp_type = icmp_packet.get_icmp_type();
                        let icmp_code = icmp_packet.get_icmp_code();
                        if icmp_type == IcmpTypes::DestinationUnreachable {
                            if codes.contains(&icmp_code) {
                                // icmp protocol unreachable error (type 3, code 2)
                                return Ok((PingStatus::Down, RecvResponse::Yes, rtt));
                            }
                        } else if icmp_type == IcmpTypes::AddressMaskReply {
                            return Ok((PingStatus::Up, RecvResponse::Yes, rtt));
                        }
                    }
                }
                _ => (),
            }
        }
    }
    // no response received (even after retransmissions)
    Ok((PingStatus::Down, RecvResponse::No, rtt))
}
