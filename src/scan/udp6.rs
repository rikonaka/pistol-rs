use anyhow::Result;
use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::udp::{ipv6_checksum, MutableUdpPacket};
use pnet::packet::Packet;
use std::net::Ipv6Addr;

use crate::layers::layer3_ipv6_send;
use crate::layers::MatchResp;
use crate::layers::{IPV6_HEADER_SIZE, UDP_HEADER_SIZE};
use crate::TargetScanStatus;

const UDP_DATA_SIZE: usize = 0;
const TTL: u8 = 255;

pub fn send_udp_scan_packet(
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    max_loop: usize,
) -> Result<TargetScanStatus> {
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE];
    let mut ipv6_header = MutableIpv6Packet::new(&mut ipv6_buff).unwrap();
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = UDP_HEADER_SIZE + UDP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Udp);
    ipv6_header.set_hop_limit(TTL);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // udp header
    let mut udp_header = MutableUdpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]).unwrap();
    udp_header.set_source(src_port);
    udp_header.set_destination(dst_port);
    udp_header.set_length((UDP_HEADER_SIZE + UDP_DATA_SIZE) as u16);
    let checksum = ipv6_checksum(&udp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    udp_header.set_checksum(checksum);

    let codes_1 = vec![
        Icmpv6Code(4), // port unreachable
    ];
    let codes_2 = vec![
        Icmpv6Code(1), // communication with destination administratively prohibited
        Icmpv6Code(3), // address unreachable
    ];

    let match_object_1 = MatchResp::new_layer4_tcp_udp(src_port, dst_port, false);
    let match_object_2 = MatchResp::new_layer4_icmpv6(src_ipv6, dst_ipv6, false);

    let ret = layer3_ipv6_send(
        src_ipv6,
        dst_ipv6,
        &ipv6_buff,
        vec![match_object_1, match_object_2],
        max_loop,
    )?;
    match ret {
        Some(r) => {
            match Ipv6Packet::new(&r) {
                Some(ipv6_packet) => {
                    match ipv6_packet.get_next_header() {
                        IpNextHeaderProtocols::Udp => {
                            // any udp response from target port (unusual)
                            return Ok(TargetScanStatus::Open);
                        }
                        IpNextHeaderProtocols::Icmpv6 => {
                            match Icmpv6Packet::new(ipv6_packet.payload()) {
                                Some(icmpv6_packet) => {
                                    // let icmp_type = icmp_packet.get_icmp_type();
                                    let icmpv6_code = icmpv6_packet.get_icmpv6_code();
                                    if codes_1.contains(&icmpv6_code) {
                                        // icmp port unreachable error (type 3, code 3)
                                        return Ok(TargetScanStatus::Closed);
                                    } else if codes_2.contains(&icmpv6_code) {
                                        // other icmp unreachable errors (type 3, code 1, 2, 9, 10, or 13)
                                        return Ok(TargetScanStatus::Filtered);
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
    Ok(TargetScanStatus::OpenOrFiltered)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_send_udp_scan_packet() {
        let src_ipv6: Ipv6Addr = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let src_port = 32109;
        let dst_port = 80;
        let max_loop = 32;
        let ret = send_udp_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop).unwrap();
        println!("{:?}", ret);
    }
}
