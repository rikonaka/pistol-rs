use anyhow::Result;
use pnet::packet::icmp::{destination_unreachable, IcmpTypes};
use pnet::packet::udp::{ipv4_checksum, MutableUdpPacket};
use pnet::transport::{icmp_packet_iter, udp_packet_iter};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::utils::return_layer4_icmp_channel;
use crate::utils::return_layer4_udp_channel;
use crate::utils::ICMP_BUFF_SIZE;
use crate::utils::UDP_BUFF_SIZE;
use crate::utils::UDP_DATA_LEN;
use crate::utils::UDP_HEADER_LEN;
use crate::UdpScanStatus;

pub fn send_udp_scan_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<UdpScanStatus> {
    let (mut udp_tx, mut udp_rx) = return_layer4_udp_channel(UDP_BUFF_SIZE)?;
    let (_, mut icmp_rx) = return_layer4_icmp_channel(ICMP_BUFF_SIZE)?;

    // const UDP_DATA_LEN: usize = 10; // test

    // udp header
    let mut udp_buff = [0u8; UDP_HEADER_LEN + UDP_DATA_LEN];
    let mut udp_header = MutableUdpPacket::new(&mut udp_buff[..]).unwrap();
    udp_header.set_source(src_port);
    udp_header.set_destination(dst_port);
    udp_header.set_length((UDP_HEADER_LEN + UDP_DATA_LEN) as u16);
    // udp_header.set_payload(&vec![b'a'; 10]); // test
    let checksum = ipv4_checksum(&udp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    udp_header.set_checksum(checksum);

    match udp_tx.send_to(udp_header, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, UDP_HEADER_LEN + UDP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut udp_iter = udp_packet_iter(&mut udp_rx);
    let mut icmp_iter = icmp_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match udp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((udp_packet, addr)) => {
                    if addr == dst_ipv4 {
                        if udp_packet.get_destination() == src_port
                            && udp_packet.get_source() == dst_port
                        {
                            // any udp response from target port (unusual)
                            return Ok(UdpScanStatus::Open);
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
                    if addr == dst_ipv4 {
                        let icmp_type = icmp_packet.get_icmp_type();
                        let icmp_code = icmp_packet.get_icmp_code();
                        if icmp_type == IcmpTypes::DestinationUnreachable {
                            let codes_1 = vec![
                                destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
                            ];
                            let codes_2 = vec![
                                    destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
                                    destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
                                    destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
                                    destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
                                    destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
                                ];
                            if codes_1.contains(&icmp_code) {
                                // icmp port unreachable error (type 3, code 3)
                                return Ok(UdpScanStatus::Closed);
                            } else if codes_2.contains(&icmp_code) {
                                // other icmp unreachable errors (type 3, code 1, 2, 9, 10, or 13)
                                return Ok(UdpScanStatus::Filtered);
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
    Ok(UdpScanStatus::OpenOrFiltered)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_send_udp_scan_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 33);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 233);
        let src_port = 54338;
        // let dst_port = 53;
        let dst_port = 2233;
        let max_loop = 32;
        let timeout = Duration::from_secs(1);
        let ret = send_udp_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout, max_loop)
            .unwrap();
        println!("{:?}", ret);
    }
}
