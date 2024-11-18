use chrono::Utc;
use pnet::packet::icmpv6;
use pnet::packet::icmpv6::echo_reply;
use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmpv6::Icmpv6Code;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmpv6::Icmpv6Type;
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::Packet;
use rand::Rng;
use std::net::Ipv6Addr;
use std::time::Duration;

use crate::errors::PistolErrors;
use crate::layers::layer3_ipv6_send;
use crate::layers::Layer3Match;
use crate::layers::Layer4MatchIcmpv6;
use crate::layers::LayersMatch;
use crate::layers::ICMPV6_ER_HEADER_SIZE;
use crate::layers::IPV6_HEADER_SIZE;
use crate::ping::PingStatus;

const TTL: u8 = 255;

pub fn send_icmpv6_ping_packet(
    src_ipv6: Ipv6Addr,
    dst_ipv6: Ipv6Addr,
    timeout: Duration,
) -> Result<(PingStatus, Duration), PistolErrors> {
    const ICMPV6_DATA_SIZE: usize = 16;
    let mut rng = rand::thread_rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + ICMPV6_ER_HEADER_SIZE + ICMPV6_DATA_SIZE];
    let mut ipv6_header = MutableIpv6Packet::new(&mut ipv6_buff).unwrap();
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

    let mut icmpv6_header =
        MutableEchoRequestPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]).unwrap();
    icmpv6_header.set_icmpv6_type(Icmpv6Type(128));
    icmpv6_header.set_icmpv6_code(Icmpv6Code(0));
    icmpv6_header.set_sequence_number(1);
    icmpv6_header.set_identifier(rng.gen());
    let mut tv_sec = Utc::now().timestamp().to_be_bytes();
    tv_sec.reverse(); // Big-Endian
    let mut tv_usec = Utc::now().timestamp_subsec_millis().to_be_bytes();
    tv_usec.reverse(); // Big-Endian
    let mut timestamp = Vec::new();
    timestamp.extend(tv_sec);
    timestamp.extend(tv_usec);
    // println!("{:?}", timestamp);
    icmpv6_header.set_payload(&timestamp);

    let mut icmp_header = MutableIcmpv6Packet::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]).unwrap();
    let checksum = icmpv6::checksum(&icmp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    icmp_header.set_checksum(checksum);

    let codes_1 = vec![
        Icmpv6Code(1), // communication with destination administratively prohibited
        Icmpv6Code(3), // address unreachable
        Icmpv6Code(4), // port unreachable
    ];
    let codes_2 = vec![
        echo_reply::Icmpv6Codes::NoCode, // 0
    ];

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
    };
    let layers_match = LayersMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    let (ret, rtt) = layer3_ipv6_send(src_ipv6, dst_ipv6, &ipv6_buff, vec![layers_match], timeout)?;
    match Ipv6Packet::new(&ret) {
        Some(ipv6_packet) => {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Icmpv6 => {
                    match Icmpv6Packet::new(ipv6_packet.payload()) {
                        Some(icmpv6_packet) => {
                            let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                            let icmpv6_code = icmpv6_packet.get_icmpv6_code();

                            if icmpv6_type == Icmpv6Types::DestinationUnreachable {
                                if codes_1.contains(&icmpv6_code) {
                                    // icmp protocol unreachable error (type 3, code 2)
                                    return Ok((PingStatus::Down, rtt));
                                }
                            } else if icmpv6_type == Icmpv6Types::EchoReply {
                                if codes_2.contains(&icmpv6_code) {
                                    return Ok((PingStatus::Up, rtt));
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
    Ok((PingStatus::Down, rtt))
}
