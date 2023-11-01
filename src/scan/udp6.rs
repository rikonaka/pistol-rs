use anyhow::Result;
use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Types};
use pnet::packet::udp::{ipv6_checksum, MutableUdpPacket};
use pnet::transport::{icmpv6_packet_iter, udp_packet_iter};
use std::net::Ipv6Addr;
use std::time::Duration;

use crate::utils::return_layer4_icmp6_channel;
use crate::utils::return_layer4_udp6_channel;
use crate::utils::ICMP_BUFF_SIZE;
use crate::utils::UDP_BUFF_SIZE;
use crate::utils::UDP_DATA_LEN;
use crate::utils::UDP_HEADER_LEN;
use crate::TargetScanStatus;

pub fn send_udp_scan_packet(
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<TargetScanStatus> {
    let (mut udp_tx, mut udp_rx) = return_layer4_udp6_channel(UDP_BUFF_SIZE)?;
    let (_, mut icmp_rx) = return_layer4_icmp6_channel(ICMP_BUFF_SIZE)?;

    // udp header
    let mut udp_buff = [0u8; UDP_HEADER_LEN + UDP_DATA_LEN];
    let mut udp_header = MutableUdpPacket::new(&mut udp_buff[..]).unwrap();
    udp_header.set_source(src_port);
    udp_header.set_destination(dst_port);
    udp_header.set_length((UDP_HEADER_LEN + UDP_DATA_LEN) as u16);
    let checksum = ipv6_checksum(&udp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    udp_header.set_checksum(checksum);

    match udp_tx.send_to(udp_header, dst_ipv6.into()) {
        Ok(n) => assert_eq!(n, UDP_HEADER_LEN + UDP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut udp_iter = udp_packet_iter(&mut udp_rx);
    let mut icmp_iter = icmpv6_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match udp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((udp_packet, addr)) => {
                    if addr == dst_ipv6 {
                        if udp_packet.get_destination() == src_port
                            && udp_packet.get_source() == dst_port
                        {
                            // any udp response from target port (unusual)
                            return Ok(TargetScanStatus::Open);
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((icmp_packet, addr)) => {
                    if addr == dst_ipv6 {
                        let icmp_type = icmp_packet.get_icmpv6_type();
                        let icmp_code = icmp_packet.get_icmpv6_code();
                        if icmp_type == Icmpv6Types::DestinationUnreachable {
                            let codes_1 = vec![
                                Icmpv6Code(4), // port unreachable
                            ];
                            let codes_2 = vec![
                                Icmpv6Code(1), // communication with destination administratively prohibited
                                Icmpv6Code(3), // address unreachable
                            ];
                            if codes_1.contains(&icmp_code) {
                                // icmp port unreachable error (type 3, code 4)
                                return Ok(TargetScanStatus::Closed);
                            } else if codes_2.contains(&icmp_code) {
                                // other icmp unreachable errors (type 3, code 1, or 3)
                                return Ok(TargetScanStatus::Filtered);
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
    Ok(TargetScanStatus::OpenOrFiltered)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_send_udp_scan_packet() {
        // 240e:34c:8b:25b0:17c1:ac6c:9baa:ade
        let src_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x17c1, 0xac6c, 0x9baa, 0xade);
        // 240e:34c:8b:25b0:20c:29ff:fe0c:237e
        let dst_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x20c, 0x29ff, 0xfe0c, 0x237e);
        let src_port = 54887;
        let dst_port = 53;
        let max_loop = 32;
        let timeout = Duration::from_secs(1);
        let ret = send_udp_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout, max_loop)
            .unwrap();
        println!("{:?}", ret);
    }
}
