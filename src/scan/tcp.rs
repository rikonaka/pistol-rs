use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::TcpOption;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{tcp_packet_iter, transport_channel};
use rand::Rng;
use std::net::Ipv4Addr;
use subnetwork::Ipv4Pool;

const TCP_HEADER_LEN: usize = 20;
const TEST_DATA_LEN: usize = 4;

pub fn tcp_syn_scan(ipv4_src: Ipv4Addr, ipv4_dst: Ipv4Addr, port_src: u16, port_dst: u16) {
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Test1));

    // Create a new transport channel, dealing with layer 4 packets on a test protocol
    // It has a receive buffer of 4096 bytes.
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "an error occurred when creating the transport channel: {}",
            e
        ),
    };

    let mut rng = rand::thread_rng();
    let mut packet = [0u8; TCP_HEADER_LEN + TEST_DATA_LEN];

    let mut tcp_packet = MutableTcpPacket::new(&mut packet[..]).unwrap();

    tcp_packet.set_source(port_src);
    tcp_packet.set_destination(port_dst);

    // Get a random u32 value as seq
    let sequence: u32 = rng.gen();
    tcp_packet.set_sequence(sequence);
    // tcp_packet.set_sequence(0x9037d2b8);

    // First syn package ack is not used
    let acknowledgement: u32 = rng.gen();
    tcp_packet.set_acknowledgement(acknowledgement);
    // tcp_packet.set_acknowledgement(0x944bb276);
    assert_ne!(sequence, acknowledgement);

    tcp_packet.set_reserved(0);
    tcp_packet.set_flags(TcpFlags::SYN);
    // tcp_header.set_window(4015);
    tcp_packet.set_urgent_ptr(0);
    tcp_packet.set_window(4096);
    tcp_packet.set_data_offset(5);

    // Set data as 'lov3'
    // packet[TCP_HEADER_LEN + 0] = 'l' as u8;
    // packet[TCP_HEADER_LEN + 1] = 'o' as u8;
    // packet[TCP_HEADER_LEN + 2] = 'v' as u8;
    // packet[TCP_HEADER_LEN + 3] = '3' as u8;
    tcp_packet.set_payload("lov3".as_bytes());

    // let ts = TcpOption::timestamp(743951781, 44056978);
    // tcp_packet.set_options(&vec![TcpOption::nop(), TcpOption::nop(), ts]);

    let checksum = ipv4_checksum(&tcp_packet.to_immutable(), &ipv4_src, &ipv4_dst);
    tcp_packet.set_checksum(checksum);

    // Send the packet
    match tx.send_to(tcp_packet, ipv4_dst.into()) {
        Ok(n) => {
            // println!("{}", n);
            assert_eq!(n, TCP_HEADER_LEN + TEST_DATA_LEN);
        }
        Err(e) => panic!("failed to send packet: {}", e),
    }

    // We treat received packets as if they were TCP packets
    println!("Here >>>");
    let mut iter = tcp_packet_iter(&mut rx);
    match iter.next() {
        Ok((packet, addr)) => {
            println!("{}", addr);
            println!("{}", packet.get_destination());
            println!("{}", packet.get_source());
            println!("{}", packet.get_data_offset());
            println!("{}", packet.get_flags());
            println!("{}", TcpFlags::RST);
        }
        Err(e) => {
            // If an error occurs, we can handle it here
            panic!("an error occurred while reading: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // #[tokio::test]
    #[test]
    fn test_tcp_syn_scan() {
        let ipv4_src = Ipv4Addr::new(192, 168, 1, 33);
        let ipv4_dst = Ipv4Addr::new(192, 168, 1, 1);
        // tcp_syn_scan(ipv4_src, ipv4_dst, 37890, 80).await;
        tcp_syn_scan(ipv4_src, ipv4_dst, 49511, 80);
    }
}
