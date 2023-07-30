use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::udp::{ipv4_checksum, MutableUdpPacket};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, udp_packet_iter};
use rand::Rng;
use std::net::Ipv4Addr;
// use std::net::SocketAddr;
// use std::net::TcpStream;
// use std::time::Duration;

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
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Udp));
    // Create a new transport channel, dealing with layer 4 packets on a test protocol
    // It has a receive buffer of 4096 bytes.
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "an error occurred when creating the transport channel: {}",
            e
        ),
    };

    let mut packet = [0u8; UDP_HEADER_LEN + UDP_DATA_LEN];
    let mut udp_packet = MutableUdpPacket::new(&mut packet[..]).unwrap();
    udp_packet.set_source(src_port);
    udp_packet.set_destination(dst_port);
    udp_packet.set_length((UDP_HEADER_LEN + UDP_DATA_LEN) as u16);
    let checksum = ipv4_checksum(&udp_packet.to_immutable(), &src_ipv4, &dst_ipv4);
    udp_packet.set_checksum(checksum);
    // Send the packet
    match tx.send_to(udp_packet, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, UDP_HEADER_LEN + UDP_DATA_LEN),
        Err(e) => panic!("failed to send packet: {}", e),
    }

    // We treat received packets as if they were TCP packets
    let mut iter = udp_packet_iter(&mut rx);
    for _ in 0..max_wait {
        match iter.next() {
            Ok((response_packet, response_addr)) => {
                println!("{}", response_packet.get_source());
                if response_addr == dst_ipv4
                    && response_packet.get_destination() == src_port
                    && response_packet.get_source() == dst_port
                {
                    return Some(true);
                }
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
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 33);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let max_wait = 64;
        send_udp_scan_packet(src_ipv4, dst_ipv4, 49511, 53, max_wait);
    }
}
