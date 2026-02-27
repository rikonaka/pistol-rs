use chrono::Utc;
use crossbeam::channel::Receiver;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmpv6;
use pnet::packet::icmpv6::Icmpv6Code;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use rand::RngExt;
use std::net::Ipv6Addr;
use std::panic::Location;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use crate::ask_runner;
use crate::error::PistolError;
use crate::get_response;
use crate::layer::ICMPV6_ER_HEADER_SIZE;
use crate::layer::IPV6_HEADER_SIZE;
use crate::layer::Layer3Filter;
use crate::layer::Layer4FilterIcmpv6;
use crate::layer::PacketFilter;
use crate::ping::PingStatus;
use crate::scan::RecvResponse;

const ICMPV6_DATA_SIZE: usize = 16;
const TTL: u8 = 255;

pub(crate) fn send_icmpv6_ping_packet(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
    let mut rng = rand::rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + ICMPV6_ER_HEADER_SIZE + ICMPV6_DATA_SIZE];
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
    let payload_length = ICMPV6_ER_HEADER_SIZE + ICMPV6_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Icmpv6);
    ipv6_header.set_hop_limit(TTL);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    let mut icmpv6_header = match MutableEchoRequestPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..])
    {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    icmpv6_header.set_icmpv6_type(Icmpv6Types::EchoRequest);
    icmpv6_header.set_icmpv6_code(Icmpv6Code(0));
    icmpv6_header.set_identifier(rng.random());
    icmpv6_header.set_sequence_number(1);
    let mut tv_sec = Utc::now().timestamp().to_be_bytes();
    tv_sec.reverse(); // Big-Endian
    let mut tv_usec = Utc::now().timestamp_subsec_millis().to_be_bytes();
    tv_usec.reverse(); // Big-Endian
    let mut timestamp = Vec::new();
    timestamp.extend(tv_sec);
    timestamp.extend(tv_usec);
    // println!("{:?}", timestamp);
    icmpv6_header.set_payload(&timestamp);

    let mut icmp_header = match MutableIcmpv6Packet::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    let checksum = icmpv6::checksum(&icmp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    icmp_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: String::from("ping6 layer3"),
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    // match all icmpv6 reply
    let layer4_icmpv6 = Layer4FilterIcmpv6 {
        name: String::from("ping6 icmpv6"),
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
        payload: None,
    };
    let filter_1 = PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv6;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ipv6_buff,
        ether_type,
        vec![filter_1],
        timeout,
        0,
    )?;
    Ok(receiver)
}

pub(crate) fn recv_icmpv6_ping_packet(
    start: Instant,
    timeout: Duration,
    receiver: Receiver<(Arc<[u8]>, Duration)>,
) -> Result<(PingStatus, RecvResponse, Duration), PistolError> {
    let (eth_response, rtt) = get_response(receiver, start, timeout);

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if let Some(ipv6_packet) = Ipv6Packet::new(eth_packet.payload()) {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Icmpv6 => {
                    if let Some(icmpv6_packet) = Icmpv6Packet::new(ipv6_packet.payload()) {
                        let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                        if icmpv6_type == Icmpv6Types::DestinationUnreachable {
                            return Ok((PingStatus::Down, RecvResponse::Yes, rtt));
                        } else if icmpv6_type == Icmpv6Types::EchoReply {
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
