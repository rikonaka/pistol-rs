use anyhow::Result;
use pnet::packet::icmp::{self, destination_unreachable};
use pnet::packet::icmp::{IcmpCode, IcmpPacket, IcmpType, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{self, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags};
use pnet::packet::udp::{self, MutableUdpPacket};
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::{ipv4_packet_iter, transport_channel};
use rand::Rng;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::utils::return_layer3_icmp_channel;
use crate::utils::BUFF_SIZE;
use crate::utils::ICMP_BUFF_SIZE;
use crate::utils::ICMP_DATA_LEN;
use crate::utils::ICMP_HEADER_LEN;
use crate::utils::IPV4_HEADER_LEN;
use crate::utils::IP_TTL;
use crate::utils::TCP_DATA_LEN;
use crate::utils::TCP_HEADER_LEN;
use crate::utils::UDP_DATA_LEN;
use crate::utils::UDP_HEADER_LEN;
use crate::IpScanStatus;

fn _build_tcp_packet(src_ipv4: Ipv4Addr, dst_ipv4: Ipv4Addr) -> Vec<u8> {
    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
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
    // udp header
    let mut rng = rand::thread_rng();
    let mut udp_buff = [0u8; UDP_HEADER_LEN + UDP_DATA_LEN];
    let mut udp_header = MutableUdpPacket::new(&mut udp_buff[..]).unwrap();
    udp_header.set_source(rng.gen());
    udp_header.set_destination(rng.gen());
    udp_header.set_length((UDP_HEADER_LEN + UDP_DATA_LEN) as u16);
    let checksum = udp::ipv4_checksum(&udp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    udp_header.set_checksum(checksum);
    udp_buff.to_vec()
}

fn _build_icmp_packet() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut icmp_buff = [0u8; ICMP_HEADER_LEN + ICMP_DATA_LEN];
    let mut icmp_header = MutableIcmpPacket::new(&mut icmp_buff[..]).unwrap();
    icmp_header.set_icmp_code(IcmpCode(rng.gen()));
    icmp_header.set_icmp_type(IcmpType(rng.gen()));
    let checksum = icmp::checksum(&icmp_header.to_immutable());
    icmp_header.set_checksum(checksum);
    icmp_buff.to_vec()
}

pub fn send_ip_procotol_scan_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    protocol: IpNextHeaderProtocol,
    timeout: Duration,
    max_loop: usize,
) -> Result<IpScanStatus> {
    let next_protocol = Layer3(protocol);
    let (mut tx, mut rx) = match transport_channel(BUFF_SIZE, next_protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(e.into()),
    };

    let (_, mut icmp_rx) = return_layer3_icmp_channel(ICMP_BUFF_SIZE)?;
    let mut rng = rand::thread_rng();

    // an exception is made for certain popular protocols (including TCP, UDP, and ICMP)
    match protocol {
        IpNextHeaderProtocols::Tcp => {
            // ip header
            let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN];
            let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
            ip_header.set_version(4);
            ip_header.set_header_length(5);
            ip_header.set_total_length((IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN) as u16);
            let id = rng.gen();
            ip_header.set_identification(id);
            ip_header.set_flags(Ipv4Flags::DontFragment);
            ip_header.set_ttl(IP_TTL);
            ip_header.set_next_level_protocol(protocol);
            let c = ipv4::checksum(&ip_header.to_immutable());
            ip_header.set_checksum(c);
            ip_header.set_source(src_ipv4);
            ip_header.set_destination(dst_ipv4);

            let tcp_buff = _build_tcp_packet(src_ipv4, dst_ipv4);
            ip_header.set_payload(&tcp_buff);
            tx.send_to(ip_header, dst_ipv4.into())?;
        }
        IpNextHeaderProtocols::Udp => {
            // ip header
            let mut ip_buff = [0u8; IPV4_HEADER_LEN + UDP_HEADER_LEN + UDP_DATA_LEN];
            let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
            ip_header.set_version(4);
            ip_header.set_header_length(5);
            ip_header.set_total_length((IPV4_HEADER_LEN + UDP_HEADER_LEN + UDP_DATA_LEN) as u16);
            let id = rng.gen();
            ip_header.set_identification(id);
            ip_header.set_flags(Ipv4Flags::DontFragment);
            ip_header.set_ttl(IP_TTL);
            ip_header.set_next_level_protocol(protocol);
            let c = ipv4::checksum(&ip_header.to_immutable());
            ip_header.set_checksum(c);
            ip_header.set_source(src_ipv4);
            ip_header.set_destination(dst_ipv4);

            let tcp_buff = _build_udp_packet(src_ipv4, dst_ipv4);
            ip_header.set_payload(&tcp_buff);
            match tx.send_to(ip_header, dst_ipv4.into()) {
                _ => (),
            }
        }
        IpNextHeaderProtocols::Icmp => {
            // ip header
            let mut ip_buff = [0u8; IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_DATA_LEN];
            let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
            ip_header.set_version(4);
            ip_header.set_header_length(5);
            ip_header.set_total_length((IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_DATA_LEN) as u16);
            let id = rng.gen();
            ip_header.set_identification(id);
            ip_header.set_flags(Ipv4Flags::DontFragment);
            ip_header.set_ttl(IP_TTL);
            ip_header.set_next_level_protocol(protocol);
            let c = ipv4::checksum(&ip_header.to_immutable());
            ip_header.set_checksum(c);
            ip_header.set_source(src_ipv4);
            ip_header.set_destination(dst_ipv4);

            let icmp_buff = _build_icmp_packet();
            ip_header.set_payload(&icmp_buff);
            match tx.send_to(ip_header, dst_ipv4.into()) {
                _ => (),
            }
        }
        _ => {
            // ip header
            let mut ip_buff = [0u8; IPV4_HEADER_LEN];
            let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
            ip_header.set_version(4);
            ip_header.set_header_length(5);
            ip_header.set_total_length(IPV4_HEADER_LEN as u16);
            let id = rng.gen();
            ip_header.set_identification(id);
            ip_header.set_flags(Ipv4Flags::DontFragment);
            ip_header.set_ttl(IP_TTL);
            ip_header.set_next_level_protocol(protocol);
            let c = ipv4::checksum(&ip_header.to_immutable());
            ip_header.set_checksum(c);
            ip_header.set_source(src_ipv4);
            ip_header.set_destination(dst_ipv4);

            match tx.send_to(ip_header, dst_ipv4.into()) {
                _ => (),
            }
        }
    };

    let mut icmp_iter = ipv4_packet_iter(&mut icmp_rx);
    let mut iter = ipv4_packet_iter(&mut rx);
    for _ in 0..max_loop {
        match iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((_, addr)) => {
                    if addr == dst_ipv4 {
                        // any response in any protocol from target host
                        return Ok(IpScanStatus::Open);
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
                                    return Ok(IpScanStatus::Closed);
                                } else if codes_2.contains(&icmp_code) {
                                    // other icmp unreachable errors (type 3, code 1, 3, 9, 10, or 13)
                                    return Ok(IpScanStatus::Filtered);
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
    Ok(IpScanStatus::OpenOrFiltered)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ip_scan_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 206);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 119);
        let timeout = Duration::from_secs(1);
        let max_loop = 8;
        let protocol = IpNextHeaderProtocols::Tcp;
        let ret = send_ip_procotol_scan_packet(src_ipv4, dst_ipv4, protocol, timeout, max_loop);
        println!("{:?}", ret);
    }
}
