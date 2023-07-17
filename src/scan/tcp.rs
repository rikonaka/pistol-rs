use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet::packet::{MutablePacket, Packet};
// use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::{tcp_packet_iter, transport_channel};
use rand::Rng;
use std::net::Ipv4Addr;
use subnetwork::Ipv4Pool;

const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const TEST_DATA_LEN: usize = 0;

pub async fn tcp_syn_scan(ipv4_src: Ipv4Addr, ipv4_dst: Ipv4Addr, port_src: u16, port_dst: u16) {
    let mut rng = rand::thread_rng();
    let mut packet = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + TEST_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(ipv4_src);
    ip_header.set_destination(ipv4_dst);

    // Set data as 'lov3'
    // packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 0] = 'l' as u8;
    // packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 1] = 'o' as u8;
    // packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 2] = 'v' as u8;
    // packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 3] = '3' as u8;

    let mut tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
    tcp_header.set_source(port_src);
    tcp_header.set_destination(port_dst);

    // Get a random u32 value as seq
    let sequence: u32 = rng.gen();
    tcp_header.set_sequence(sequence);

    // First syn package ack is not used
    let acknowledgement: u32 = rng.gen();
    tcp_header.set_acknowledgement(acknowledgement);
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_window(4015);
    tcp_header.set_data_offset(5);

    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &ipv4_src, &ipv4_dst);
    tcp_header.set_checksum(checksum);

    // let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
    let protocol = Layer3(IpNextHeaderProtocols::Tcp);

    // Create a new transport channel, dealing with layer 4 packets on a test protocol
    // It has a receive buffer of 4096 bytes.
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };
    // Send the packet
    let send_packet = MutableTcpPacket::new(&mut packet).unwrap();
    match tx.send_to(send_packet, ipv4_dst.into()) {
        Ok(n) => println!("{}", n),
        Err(e) => panic!("failed to send packet: {}", e),
    }

    // We treat received packets as if they were TCP packets
    let mut iter = tcp_packet_iter(&mut rx);
    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                println!("{}", packet.get_flags());
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_tcp_syn_scan() {
        let ipv4_src = Ipv4Addr::new(192, 168, 1, 31);
        let ipv4_dst = Ipv4Addr::new(192, 168, 1, 1);
        tcp_syn_scan(ipv4_src, ipv4_dst, 7890, 80).await;
    }
}
