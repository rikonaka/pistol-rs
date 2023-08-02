use anyhow::Result;
use pnet::packet::icmp::{destination_unreachable, IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::udp::{ipv4_checksum, MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::{ipv4_packet_iter, transport_channel};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::utils;

const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const UDP_DATA_LEN: usize = 0;
const UDP_BUFF_SIZE: usize = 4096;
const ICMP_BUFF_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy)]
pub enum UdpScanStatus {
    Open,
    OpenOrFiltered,
    Closed,
    Filtered,
}

pub fn send_udp_scan_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<UdpScanStatus> {
    let udp_protocol = Layer3(IpNextHeaderProtocols::Udp);
    let (mut udp_tx, mut udp_rx) = match transport_channel(UDP_BUFF_SIZE, udp_protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(e.into()),
    };
    let icmp_protocol = Layer3(IpNextHeaderProtocols::Icmp);
    let (_, mut icmp_rx) = match transport_channel(ICMP_BUFF_SIZE, icmp_protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(e.into()),
    };

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + UDP_HEADER_LEN + UDP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_LEN + UDP_HEADER_LEN + UDP_DATA_LEN) as u16);
    let id = utils::random_u16();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(52);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    let c = checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // udp header
    let mut udp_buff = [0u8; UDP_HEADER_LEN + UDP_DATA_LEN];
    let mut udp_header = MutableUdpPacket::new(&mut udp_buff[..]).unwrap();
    udp_header.set_source(src_port);
    udp_header.set_destination(dst_port);
    udp_header.set_length((UDP_HEADER_LEN + UDP_DATA_LEN) as u16);
    let checksum = ipv4_checksum(&udp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    udp_header.set_checksum(checksum);

    // set udp header as ip payload
    ip_header.set_payload(udp_header.packet());
    match udp_tx.send_to(ip_header, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, IPV4_HEADER_LEN + UDP_HEADER_LEN + UDP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut udp_iter = ipv4_packet_iter(&mut udp_rx);
    let mut icmp_iter = ipv4_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match udp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((packet, addr)) => {
                    if addr == dst_ipv4 && packet.get_destination() == src_ipv4 {
                        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                            let ipv4_payload = packet.payload();
                            let udp_packet = UdpPacket::new(ipv4_payload).unwrap();
                            if udp_packet.get_destination() == src_port
                                && udp_packet.get_source() == dst_port
                            {
                                // any udp response from target port (unusual)
                                return Ok(UdpScanStatus::Open);
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((packet, addr)) => {
                    if addr == dst_ipv4 {
                        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                            let ipv4_payload = packet.payload();
                            let icmp_packet = IcmpPacket::new(ipv4_payload).unwrap();
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
        let src_ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let dst_ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let max_loop = 32;
        let timeout = Duration::from_secs(1);
        let ret = send_udp_scan_packet(src_ipv4, dst_ipv4, 54422, 53, timeout, max_loop).unwrap();
        println!("{:?}", ret);
    }
}
