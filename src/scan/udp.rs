use anyhow::Result;
use pnet::packet::icmp::destination_unreachable;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::Ipv4Flags;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::{ipv4_checksum, MutableUdpPacket};
use pnet::packet::Packet;
use rand::Rng;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::layers::layer3_ipv4_send;
use crate::layers::{Layer3Match, Layer4MatchIcmp, Layer4MatchTcpUdp, LayersMatch};
use crate::layers::{IPV4_HEADER_SIZE, UDP_HEADER_SIZE};
use crate::TargetScanStatus;

const UDP_DATA_SIZE: usize = 0;
const TTL: u8 = 64;

pub fn send_udp_scan_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    timeout: Duration,
) -> Result<(TargetScanStatus, Option<Duration>)> {
    let mut rng = rand::thread_rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // udp header
    let mut udp_header = MutableUdpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]).unwrap();
    udp_header.set_source(src_port);
    udp_header.set_destination(dst_port);
    udp_header.set_length((UDP_HEADER_SIZE + UDP_DATA_SIZE) as u16);
    // udp_header.set_payload(&vec![b'a'; 10]); // test
    let checksum = ipv4_checksum(&udp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    udp_header.set_checksum(checksum);

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

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    let layer4_icmp = Layer4MatchIcmp {
        layer3: Some(layer3),
        types: None,
        codes: None,
    };
    let layers_match_1 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp);
    let layers_match_2 = LayersMatch::Layer4MatchIcmp(layer4_icmp);

    let (ret, rtt) = layer3_ipv4_send(
        src_ipv4,
        dst_ipv4,
        &ip_buff,
        vec![layers_match_1, layers_match_2],
        timeout,
    )?;
    match ret {
        Some(r) => {
            match Ipv4Packet::new(&r) {
                Some(ipv4_packet) => {
                    match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Udp => {
                            // any udp response from target port (unusual)
                            return Ok((TargetScanStatus::Open, rtt));
                        }
                        IpNextHeaderProtocols::Icmp => {
                            match IcmpPacket::new(ipv4_packet.payload()) {
                                Some(icmp_packet) => {
                                    // let icmp_type = icmp_packet.get_icmp_type();
                                    let icmp_code = icmp_packet.get_icmp_code();
                                    if codes_1.contains(&icmp_code) {
                                        // icmp port unreachable error (type 3, code 3)
                                        return Ok((TargetScanStatus::Closed, rtt));
                                    } else if codes_2.contains(&icmp_code) {
                                        // other icmp unreachable errors (type 3, code 1, 2, 9, 10, or 13)
                                        return Ok((TargetScanStatus::Filtered, rtt));
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
    Ok((TargetScanStatus::OpenOrFiltered, rtt))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_send_udp_scan_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 135);
        let src_port = 54338;
        // let dst_port = 53;
        let dst_port = 2233;
        let timeout = Duration::new(3, 0);
        let ret = send_udp_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout).unwrap();
        println!("{:?}", ret);
    }
}
