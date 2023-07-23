use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{tcp_packet_iter, transport_channel};
use rand::Rng;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::time::Duration;

pub fn send_syn_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> bool {
    const TCP_HEADER_LEN: usize = 20;
    const TEST_DATA_LEN: usize = 0;

    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
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
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
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
    // tcp_packet.set_payload("lov3".as_bytes());
    // let ts = TcpOption::timestamp(743951781, 44056978);
    // tcp_packet.set_options(&vec![TcpOption::nop(), TcpOption::nop(), ts]);
    let checksum = ipv4_checksum(&tcp_packet.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_packet.set_checksum(checksum);
    // Send the packet
    match tx.send_to(tcp_packet, dst_ipv4.into()) {
        Ok(n) => {
            // println!("{}", n);
            assert_eq!(n, TCP_HEADER_LEN + TEST_DATA_LEN);
        }
        Err(e) => panic!("failed to send packet: {}", e),
    }

    // We treat received packets as if they were TCP packets
    let mut iter = tcp_packet_iter(&mut rx);
    loop {
        match iter.next() {
            Ok((response_packet, response_addr)) => {
                // println!("{}", addr);
                if response_addr == dst_ipv4
                    && response_packet.get_destination() == src_port
                    && response_packet.get_source() == dst_port
                {
                    // println!("{}", packet.get_flags());
                    // println!("{}", TcpFlags::RST | TcpFlags::ACK); // PORT NOT OPEN
                    // println!("{}", TcpFlags::SYN | TcpFlags::ACK); // PORT OPEN
                    if response_packet.get_flags() == (TcpFlags::RST | TcpFlags::ACK) {
                        return false;
                    } else if response_packet.get_flags() == (TcpFlags::SYN | TcpFlags::ACK) {
                        return true;
                    } else {
                        // do nothing
                    }
                }
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("an error occurred while reading: {}", e);
            }
        }
    }
}

pub fn send_connect_packets(dst_ipv4: Ipv4Addr, dst_port: u16, timeout: Duration) -> bool {
    // let addr = format!("{}:{}", dst_ipv4, dst_port);
    let addr = SocketAddr::from((dst_ipv4, dst_port));
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => true,
        _ => false,
    }
}

#[test]
fn test_tcp_full_scan() {
    let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
    let duration = Duration::from_secs(1);
    let ret = send_connect_packets(dst_ipv4, 80, duration);
    assert_eq!(ret, true);
    let ret = send_connect_packets(dst_ipv4, 999, duration);
    // println!("{ret}");
    assert_eq!(ret, false);
}

#[test]
fn test_tcp_syn_scan() {
    let src_ipv4 = Ipv4Addr::new(192, 168, 72, 130);
    let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
    send_syn_packet(src_ipv4, dst_ipv4, 49511, 9999);
}
