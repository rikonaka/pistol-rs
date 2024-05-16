use anyhow::Result;
use pnet::packet::icmp;
use pnet::packet::icmp::destination_unreachable;
use pnet::packet::icmp::IcmpCode;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpType;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::Ipv4Flags;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::udp;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::Packet;
use rand::Rng;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::layers::layer3_ipv4_send;
use crate::layers::Layer3Match;
use crate::layers::LayersMatch;
use crate::layers::ICMP_HEADER_SIZE;
use crate::layers::IPV4_HEADER_SIZE;
use crate::layers::TCP_HEADER_SIZE;
use crate::layers::UDP_HEADER_SIZE;

use super::TargetScanStatus;

const TTL: u8 = 64;

fn _build_tcp_packet(src_ipv4: Ipv4Addr, dst_ipv4: Ipv4Addr) -> Vec<u8> {
    const TCP_DATA_SIZE: usize = 0;
    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff).unwrap();
    tcp_header.set_source(rng.gen());
    tcp_header.set_destination(rng.gen());
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    tcp_buff.to_vec()
}

fn _build_udp_packet(src_ipv4: Ipv4Addr, dst_ipv4: Ipv4Addr) -> Vec<u8> {
    const UDP_DATA_SIZE: usize = 0;
    // udp header
    let mut rng = rand::thread_rng();
    let mut udp_buff = [0u8; UDP_HEADER_SIZE + UDP_DATA_SIZE];
    let mut udp_header = MutableUdpPacket::new(&mut udp_buff).unwrap();
    udp_header.set_source(rng.gen());
    udp_header.set_destination(rng.gen());
    udp_header.set_length((UDP_HEADER_SIZE + UDP_DATA_SIZE) as u16);
    let checksum = udp::ipv4_checksum(&udp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    udp_header.set_checksum(checksum);
    udp_buff.to_vec()
}

fn _build_icmp_packet() -> Vec<u8> {
    const ICMP_DATA_SIZE: usize = 0;
    let mut icmp_buff = [0u8; ICMP_HEADER_SIZE + ICMP_DATA_SIZE];
    let mut icmp_header = MutableIcmpPacket::new(&mut icmp_buff).unwrap();
    icmp_header.set_icmp_type(IcmpType(8));
    icmp_header.set_icmp_code(IcmpCode(0));
    let checksum = icmp::checksum(&icmp_header.to_immutable());
    icmp_header.set_checksum(checksum);
    icmp_buff.to_vec()
}

pub fn send_ip_procotol_scan_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    protocol: IpNextHeaderProtocol,
    timeout: Duration,
) -> Result<(TargetScanStatus, Option<Duration>)> {
    const TCP_DATA_SIZE: usize = 0;
    const UDP_DATA_SIZE: usize = 0;
    const ICMP_DATA_SIZE: usize = 0;
    let mut rng = rand::thread_rng();

    // an exception is made for certain popular protocols (including TCP, UDP, and ICMP)
    let buff_layer_2 = match protocol {
        IpNextHeaderProtocols::Tcp => {
            // ip header
            let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
            let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
            ip_header.set_version(4);
            ip_header.set_header_length(5);
            ip_header.set_source(src_ipv4);
            ip_header.set_destination(dst_ipv4);
            ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
            let id = rng.gen();
            ip_header.set_identification(id);
            ip_header.set_flags(Ipv4Flags::DontFragment);
            ip_header.set_ttl(TTL);
            ip_header.set_next_level_protocol(protocol);
            let c = ipv4::checksum(&ip_header.to_immutable());
            ip_header.set_checksum(c);

            let tcp_buff = _build_tcp_packet(src_ipv4, dst_ipv4);
            ip_header.set_payload(&tcp_buff);
            ip_buff.to_vec()
        }
        IpNextHeaderProtocols::Udp => {
            // ip header
            let mut ip_buff = [0u8; IPV4_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE];
            let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
            ip_header.set_version(4);
            ip_header.set_header_length(5);
            ip_header.set_source(src_ipv4);
            ip_header.set_destination(dst_ipv4);
            ip_header.set_total_length((IPV4_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE) as u16);
            let id = rng.gen();
            ip_header.set_identification(id);
            ip_header.set_flags(Ipv4Flags::DontFragment);
            ip_header.set_ttl(TTL);
            ip_header.set_next_level_protocol(protocol);
            let c = ipv4::checksum(&ip_header.to_immutable());
            ip_header.set_checksum(c);

            let tcp_buff = _build_udp_packet(src_ipv4, dst_ipv4);
            ip_header.set_payload(&tcp_buff);
            ip_buff.to_vec()
        }
        IpNextHeaderProtocols::Icmp => {
            // ip header
            let mut ip_buff = [0u8; IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE];
            let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
            ip_header.set_version(4);
            ip_header.set_header_length(5);
            ip_header.set_source(src_ipv4);
            ip_header.set_destination(dst_ipv4);
            ip_header
                .set_total_length((IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE) as u16);
            let id = rng.gen();
            ip_header.set_identification(id);
            ip_header.set_flags(Ipv4Flags::DontFragment);
            ip_header.set_ttl(TTL);
            ip_header.set_next_level_protocol(protocol);
            let c = ipv4::checksum(&ip_header.to_immutable());
            ip_header.set_checksum(c);

            let icmp_buff = _build_icmp_packet();
            ip_header.set_payload(&icmp_buff);
            ip_buff.to_vec()
        }
        _ => {
            // ip header
            let mut ip_buff = [0u8; IPV4_HEADER_SIZE];
            let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
            ip_header.set_version(4);
            ip_header.set_header_length(5);
            ip_header.set_source(src_ipv4);
            ip_header.set_destination(dst_ipv4);
            ip_header.set_total_length(IPV4_HEADER_SIZE as u16);
            let id = rng.gen();
            ip_header.set_identification(id);
            ip_header.set_flags(Ipv4Flags::DontFragment);
            ip_header.set_ttl(TTL);
            ip_header.set_next_level_protocol(protocol);
            let c = ipv4::checksum(&ip_header.to_immutable());
            ip_header.set_checksum(c);
            ip_buff.to_vec()
        }
    };

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layers_match = LayersMatch::Layer3Match(layer3);
    let (ret, rtt) = layer3_ipv4_send(
        src_ipv4,
        dst_ipv4,
        &buff_layer_2,
        vec![layers_match],
        timeout,
    )?;

    match ret {
        Some(r) => {
            let ipv4_packet = Ipv4Packet::new(&r).unwrap();
            match ipv4_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmp => {
                    let ipv4_payload = ipv4_packet.payload();
                    let icmp_packet = IcmpPacket::new(ipv4_payload).unwrap();
                    let icmp_type = icmp_packet.get_icmp_type();
                    let icmp_code = icmp_packet.get_icmp_code();
                    let codes_1 = vec![
                        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
                    ];
                    let codes_2 = vec![
                        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
                        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
                        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
                        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
                        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
                    ];
                    if icmp_type == IcmpTypes::DestinationUnreachable {
                        if codes_1.contains(&icmp_code) {
                            // icmp protocol unreachable error (type 3, code 2)
                            return Ok((TargetScanStatus::Closed, rtt));
                        } else if codes_2.contains(&icmp_code) {
                            // other icmp unreachable errors (type 3, code 1, 3, 9, 10, or 13)
                            return Ok((TargetScanStatus::Filtered, rtt));
                        }
                    }
                }
                _ => {
                    return Ok((TargetScanStatus::Open, rtt));
                }
            }
        }
        None => (),
    };
    // no response received (even after retransmissions)
    Ok((TargetScanStatus::OpenOrFiltered, rtt))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ip_scan_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 135);
        let timeout = Duration::new(3, 0);
        let protocol = IpNextHeaderProtocols::Tcp;
        // let protocol = IpNextHeaderProtocols::Udp;
        // let protocol = IpNextHeaderProtocols::Icmp;
        let ret = send_ip_procotol_scan_packet(src_ipv4, dst_ipv4, protocol, timeout);
        println!("{:?}", ret);
    }
}
