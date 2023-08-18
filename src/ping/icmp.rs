use anyhow::Result;
use pnet::packet::icmp;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{destination_unreachable, echo_reply};
use pnet::packet::icmp::{IcmpCode, IcmpType, IcmpTypes, MutableIcmpPacket};
use pnet::transport::icmp_packet_iter;

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::ping::PingStatus;
use crate::utils::ICMP_BUFF_SIZE;
use crate::utils::ICMP_DATA_LEN;
use crate::utils::ICMP_HEADER_LEN;
use crate::utils::return_layer4_icmp_channel;

pub fn send_icmp_ping_packet(
    _: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    timeout: Duration,
    max_loop: usize,
) -> Result<PingStatus> {
    let (mut icmp_tx, mut icmp_rx) = return_layer4_icmp_channel(ICMP_BUFF_SIZE)?;

    let mut icmp_buff = [0u8; ICMP_HEADER_LEN + ICMP_DATA_LEN];
    let mut icmp_header = MutableEchoRequestPacket::new(&mut icmp_buff[..]).unwrap();
    icmp_header.set_icmp_type(IcmpType(8));
    icmp_header.set_icmp_code(IcmpCode(0));
    icmp_header.set_sequence_number(1);
    icmp_header.set_identifier(2);

    let mut icmp_header = MutableIcmpPacket::new(&mut icmp_buff).unwrap();
    let checksum = icmp::checksum(&icmp_header.to_immutable());
    icmp_header.set_checksum(checksum);

    match icmp_tx.send_to(icmp_header, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, ICMP_HEADER_LEN + ICMP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut icmp_iter = icmp_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((icmp_packet, addr)) => {
                    if addr == dst_ipv4 {
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
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 206);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 119);
        let timeout = Duration::from_secs(1);
        let max_loop = 8;
        let ret = send_icmp_ping_packet(src_ipv4, dst_ipv4, timeout, max_loop).unwrap();
        println!("{:?}", ret);
    }
}
