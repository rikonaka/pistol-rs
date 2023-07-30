use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::udp::{ipv4_checksum, MutableUdpPacket};
use pnet::transport::TransportChannelType::Layer3;
// use pnet::transport::TransportChannelType::Layer4;
// use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{icmp_packet_iter, ipv4_packet_iter, transport_channel};
use std::net::Ipv4Addr;
// use std::net::SocketAddr;
// use std::net::TcpStream;
// use std::time::Duration;

use crate::utils;

const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const UDP_DATA_LEN: usize = 0;

/// If port is open, return Some(syn, ack), else return None.
pub fn send_udp_scan_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    max_wait: usize,
) -> Option<bool> {
    // let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Udp));
    let protocol = Layer3(IpNextHeaderProtocols::Udp);
    // Create a new transport channel, dealing with layer 4 packets on a test protocol
    // It has a receive buffer of 4096 bytes.
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "an error occurred when creating the transport channel: {}",
            e
        ),
    };

    let mut ip_packet = [0u8; IPV4_HEADER_LEN + UDP_HEADER_LEN + UDP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_packet[..]).unwrap();
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

    let mut udp_packet = [0u8; UDP_HEADER_LEN + UDP_DATA_LEN];
    let mut udp_header = MutableUdpPacket::new(&mut udp_packet[..]).unwrap();
    udp_header.set_source(src_port);
    udp_header.set_destination(dst_port);
    udp_header.set_length((UDP_HEADER_LEN + UDP_DATA_LEN) as u16);
    let checksum = ipv4_checksum(&udp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    udp_header.set_checksum(checksum);

    ip_header.set_payload(&udp_packet);
    // Send the packet
    match tx.send_to(ip_header, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, IPV4_HEADER_LEN + UDP_HEADER_LEN + UDP_DATA_LEN),
        Err(e) => panic!("failed to send packet: {}", e),
    }

    // We treat received packets as if they were TCP packets
    // let mut iter = udp_packet_iter(&mut rx);
    // let mut iter = ipv4_packet_iter(&mut rx);
    let mut iter = icmp_packet_iter(&mut rx);
    for _ in 0..max_wait {
        match iter.next() {
            Ok((response_packet, response_addr)) => {
                println!(
                    "{} - {:?} - {:?}",
                    response_addr,
                    response_packet.get_icmp_type(),
                    response_packet.get_icmp_code()
                );
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("an error occurred while reading: {}", e);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_send_udp_scan_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 216);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let max_wait = 128;
        send_udp_scan_packet(src_ipv4, dst_ipv4, 54422, 59, max_wait);
    }
}
