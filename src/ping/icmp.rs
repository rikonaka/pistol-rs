use anyhow::Result;
use pnet::packet::icmp;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::{destination_unreachable, echo_reply};
use pnet::packet::icmp::{IcmpCode, IcmpType, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::Ipv4Flags;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::Packet;
use rand::Rng;

use std::net::Ipv4Addr;

use crate::layers::layer3_ipv4_send;
use crate::layers::MatchResp;
use crate::layers::{ICMP_HEADER_SIZE, IPV4_HEADER_SIZE};
use crate::ping::PingStatus;

const TTL: u8 = 64;

pub fn send_icmp_ping_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    max_loop: usize,
) -> Result<PingStatus> {
    let mut rng = rand::thread_rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + ICMP_HEADER_SIZE];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    ip_header.set_total_length((IPV4_HEADER_SIZE + ICMP_HEADER_SIZE) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    let mut icmp_header = MutableEchoRequestPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]).unwrap();
    icmp_header.set_icmp_type(IcmpType(8));
    icmp_header.set_icmp_code(IcmpCode(0));
    icmp_header.set_sequence_number(1);
    icmp_header.set_identifier(2);

    let mut icmp_header = MutableIcmpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]).unwrap();
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

    let match_icmp = MatchResp::new_layer4_icmp(src_ipv4, dst_ipv4, false);
    let ret = layer3_ipv4_send(src_ipv4, dst_ipv4, &ip_buff, vec![match_icmp], max_loop)?;
    match ret {
        Some(r) => {
            match Ipv4Packet::new(&r) {
                Some(ipv4_packet) => {
                    match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Icmp => {
                            match IcmpPacket::new(ipv4_packet.payload()) {
                                Some(icmp_packet) => {
                                    let icmp_type = icmp_packet.get_icmp_type();
                                    let icmp_code = icmp_packet.get_icmp_code();

                                    let codes_2 = vec![
                                        echo_reply::IcmpCodes::NoCode, // 0
                                    ];
                                    if icmp_type == IcmpTypes::DestinationUnreachable {
                                        if codes_1.contains(&icmp_code) {
                                            // icmp protocol unreachable error (type 3, code 2)
                                            return Ok(PingStatus::Down);
                                        }
                                    } else if icmp_type == IcmpTypes::EchoReply {
                                        if codes_2.contains(&icmp_code) {
                                            return Ok(PingStatus::Up);
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
        }
        None => (),
    }
    // no response received (even after retransmissions)
    Ok(PingStatus::Down)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_icmp_ping_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 133);
        let max_loop = 32;
        let ret = send_icmp_ping_packet(src_ipv4, dst_ipv4, max_loop).unwrap();
        println!("{:?}", ret);
    }
}
