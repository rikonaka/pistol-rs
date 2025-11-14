use chrono::Utc;
use pnet::packet::Packet;
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
use rand::Rng;
use std::panic::Location;

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::error::PistolError;
use crate::layer::ICMP_HEADER_SIZE;
use crate::layer::IPV4_HEADER_SIZE;
use crate::layer::Layer3Filter;
use crate::layer::Layer4FilterIcmp;
use crate::layer::PacketFilter;
use crate::layer::layer3_ipv4_send;
use crate::ping::PingStatus;
use crate::scan::DataRecvStatus;

const TTL: u8 = 64;

pub fn send_icmp_echo_packet(
    dst_ipv4: Ipv4Addr,
    src_ipv4: Ipv4Addr,
    timeout: Option<Duration>,
) -> Result<(PingStatus, DataRecvStatus, Duration), PistolError> {
    const ICMP_DATA_SIZE: usize = 16;
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE];
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
    ip_header.set_total_length((IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE) as u16);
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

    let codes_1 = vec![
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationHostUnreachable,     // 1
        destination_unreachable::IcmpCodes::DestinationPortUnreachable,     // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    let layer3 = Layer3Filter {
        name: "ping echo layer3",
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    // match all icmp reply
    let layer4_icmp = Layer4FilterIcmp {
        name: "ping echo icmp",
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: None,
    };
    let layer_match = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let (ret, rtt) = layer3_ipv4_send(
        dst_ipv4,
        src_ipv4,
        &ip_buff,
        vec![layer_match],
        timeout,
        true,
    )?;
    match Ipv4Packet::new(&ret) {
        Some(ipv4_packet) => match ipv4_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Icmp => match IcmpPacket::new(ipv4_packet.payload()) {
                Some(icmp_packet) => {
                    let icmp_type = icmp_packet.get_icmp_type();
                    let icmp_code = icmp_packet.get_icmp_code();
                    if icmp_type == IcmpTypes::DestinationUnreachable {
                        if codes_1.contains(&icmp_code) {
                            return Ok((PingStatus::Down, DataRecvStatus::Yes, rtt));
                        }
                    } else if icmp_type == IcmpTypes::EchoReply {
                        return Ok((PingStatus::Up, DataRecvStatus::Yes, rtt));
                    }
                }
                None => (),
            },
            _ => (),
        },
        None => (),
    }
    // no response received (even after retransmissions)
    Ok((PingStatus::Down, DataRecvStatus::No, rtt))
}

pub fn send_icmp_timestamp_packet(
    dst_ipv4: Ipv4Addr,
    src_ipv4: Ipv4Addr,
    timeout: Option<Duration>,
) -> Result<(PingStatus, DataRecvStatus, Duration), PistolError> {
    const ICMP_DATA_SIZE: usize = 12;
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE];
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
    ip_header.set_total_length((IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE) as u16);
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
    let timestamp_payload = [0u8; ICMP_DATA_SIZE];
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
        name: "ping timestamp layer3",
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    // match all icmp reply
    let layer4_icmp = Layer4FilterIcmp {
        name: "ping timestamp icmp",
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: None,
    };
    let layer_match = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let (ret, rtt) = layer3_ipv4_send(
        dst_ipv4,
        src_ipv4,
        &ip_buff,
        vec![layer_match],
        timeout,
        true,
    )?;
    match Ipv4Packet::new(&ret) {
        Some(ipv4_packet) => match ipv4_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Icmp => match IcmpPacket::new(ipv4_packet.payload()) {
                Some(icmp_packet) => {
                    let icmp_type = icmp_packet.get_icmp_type();
                    if icmp_type == IcmpTypes::DestinationUnreachable {
                        return Ok((PingStatus::Down, DataRecvStatus::Yes, rtt));
                    } else if icmp_type == IcmpTypes::TimestampReply {
                        return Ok((PingStatus::Up, DataRecvStatus::Yes, rtt));
                    }
                }
                None => (),
            },
            _ => (),
        },
        None => (),
    }
    // no response received (even after retransmissions)
    Ok((PingStatus::Down, DataRecvStatus::No, rtt))
}

pub fn send_icmp_address_mask_packet(
    dst_ipv4: Ipv4Addr,
    src_ipv4: Ipv4Addr,
    timeout: Option<Duration>,
) -> Result<(PingStatus, DataRecvStatus, Duration), PistolError> {
    const ICMP_DATA_SIZE: usize = 4;
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE];
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
    ip_header.set_total_length((IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE) as u16);
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
    let timestamp_payload = [0u8; ICMP_DATA_SIZE];
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

    let codes_1 = vec![
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::DestinationHostUnreachable,     // 1
        destination_unreachable::IcmpCodes::DestinationPortUnreachable,     // 3
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    let layer3 = Layer3Filter {
        name: "ping address mask layer3",
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    // match all icmp reply
    let layer4_icmp = Layer4FilterIcmp {
        name: "ping address mask icmp",
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: None,
    };
    let layer_match = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let (ret, rtt) = layer3_ipv4_send(
        dst_ipv4,
        src_ipv4,
        &ip_buff,
        vec![layer_match],
        timeout,
        true,
    )?;
    match Ipv4Packet::new(&ret) {
        Some(ipv4_packet) => {
            match ipv4_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmp => {
                    match IcmpPacket::new(ipv4_packet.payload()) {
                        Some(icmp_packet) => {
                            let icmp_type = icmp_packet.get_icmp_type();
                            let icmp_code = icmp_packet.get_icmp_code();
                            if icmp_type == IcmpTypes::DestinationUnreachable {
                                if codes_1.contains(&icmp_code) {
                                    // icmp protocol unreachable error (type 3, code 2)
                                    return Ok((PingStatus::Down, DataRecvStatus::Yes, rtt));
                                }
                            } else if icmp_type == IcmpTypes::AddressMaskReply {
                                return Ok((PingStatus::Up, DataRecvStatus::Yes, rtt));
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
    Ok((PingStatus::Down, DataRecvStatus::No, rtt))
}
