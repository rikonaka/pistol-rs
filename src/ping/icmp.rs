use anyhow::Result;
use pnet::packet::icmp;
use pnet::packet::icmp::{destination_unreachable, echo_reply};
use pnet::packet::icmp::{IcmpCode, IcmpPacket, IcmpType, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::{ipv4_packet_iter, transport_channel};
use pnet_packet::icmp::echo_request::MutableEchoRequestPacket;

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::ping::PingStatus;
use crate::ping::ICMP_BUFF_SIZE;
use crate::ping::ICMP_DATA_LEN;
use crate::ping::ICMP_HEADER_LEN;
use crate::ping::IPV4_HEADER_LEN;
use crate::utils;

pub fn send_icmp_ping_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    timeout: Duration,
    max_loop: usize,
) -> Result<PingStatus> {
    let icmp_protocol = Layer3(IpNextHeaderProtocols::Icmp);
    let (mut icmp_tx, mut icmp_rx) = transport_channel(ICMP_BUFF_SIZE, icmp_protocol)?;

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_DATA_LEN) as u16);
    let id = utils::random_u16();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(64);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    let mut icmp_buff = [0u8; ICMP_HEADER_LEN + ICMP_DATA_LEN];
    let mut icmp_header = MutableEchoRequestPacket::new(&mut icmp_buff[..]).unwrap();
    icmp_header.set_icmp_code(IcmpCode(0));
    icmp_header.set_icmp_type(IcmpType(8));
    icmp_header.set_sequence_number(1);
    icmp_header.set_identifier(2);

    let mut icmp_header = MutableIcmpPacket::new(&mut icmp_buff).unwrap();
    let checksum = icmp::checksum(&icmp_header.to_immutable());
    icmp_header.set_checksum(checksum);

    ip_header.set_payload(&icmp_header.packet());
    match icmp_tx.send_to(ip_header, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut icmp_iter = ipv4_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((packet, addr)) => {
                    if addr == dst_ipv4 {
                        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                            let ipv4_payload = packet.payload();
                            let icmp_packet = IcmpPacket::new(ipv4_payload).unwrap();
                            let icmp_type = icmp_packet.get_icmp_type();
                            let icmp_code = icmp_packet.get_icmp_code();
                            let codes_1 = vec![
                                destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
                                destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
                                destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
                                destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
                                destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
                                destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
                            ];
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
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }
    // no response received (even after retransmissions)
    Ok(PingStatus::Down)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_icmp_ping_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168,213, 129);
        let dst_ipv4 = Ipv4Addr::new(192, 168,213, 128);
        let timeout = Duration::from_secs(1);
        let max_loop = 8;
        let ret = send_icmp_ping_packet(src_ipv4, dst_ipv4, timeout, max_loop).unwrap();
        println!("{:?}", ret);
    }
}
