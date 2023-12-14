use anyhow::Result;
use pnet::packet::icmpv6;
use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmpv6::{echo_reply, MutableIcmpv6Packet};
use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Type, Icmpv6Types};
use pnet::transport::icmpv6_packet_iter;

use std::net::Ipv6Addr;
use std::time::Duration;

use crate::ping::PingStatus;
use crate::utils::return_layer4_icmp6_channel;
use crate::utils::ICMP_BUFF_SIZE;
use crate::utils::ICMP_DATA_LEN;
use crate::utils::ICMP_HEADER_LEN;

pub fn send_icmp_ping_packet(
    src_ipv6: Ipv6Addr,
    dst_ipv6: Ipv6Addr,
    timeout: Duration,
    max_loop: usize,
) -> Result<PingStatus> {
    let (mut icmp_tx, mut icmp_rx) = return_layer4_icmp6_channel(ICMP_BUFF_SIZE)?;

    let mut icmp_buff = [0u8; ICMP_HEADER_LEN + ICMP_DATA_LEN];
    let mut icmp_header = MutableEchoRequestPacket::new(&mut icmp_buff[..]).unwrap();
    icmp_header.set_icmpv6_type(Icmpv6Type(128));
    icmp_header.set_icmpv6_code(Icmpv6Code(0));
    icmp_header.set_sequence_number(1);
    icmp_header.set_identifier(2);

    let mut icmp_header = MutableIcmpv6Packet::new(&mut icmp_buff).unwrap();
    let checksum = icmpv6::checksum(&icmp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    icmp_header.set_checksum(checksum);

    match icmp_tx.send_to(icmp_header, dst_ipv6.into()) {
        Ok(n) => assert_eq!(n, ICMP_HEADER_LEN + ICMP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut icmp_iter = icmpv6_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((icmp_packet, addr)) => {
                    if addr == dst_ipv6 {
                        let icmp_type = icmp_packet.get_icmpv6_type();
                        let icmp_code = icmp_packet.get_icmpv6_code();
                        let codes_1 = vec![
                            Icmpv6Code(1), // communication with destination administratively prohibited
                            Icmpv6Code(3), // address unreachable
                            Icmpv6Code(4), // port unreachable
                        ];
                        let codes_2 = vec![
                            echo_reply::Icmpv6Codes::NoCode, // 0
                        ];
                        if icmp_type == Icmpv6Types::DestinationUnreachable {
                            if codes_1.contains(&icmp_code) {
                                // icmp protocol unreachable error (type 3, code 2)
                                return Ok(PingStatus::Down);
                            }
                        } else if icmp_type == Icmpv6Types::EchoReply {
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
        let src_ipv6 = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6 = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let timeout = Duration::from_secs(1);
        let max_loop = 8;
        let ret = send_icmp_ping_packet(src_ipv6, dst_ipv6, timeout, max_loop).unwrap();
        println!("{:?}", ret);
    }
}
