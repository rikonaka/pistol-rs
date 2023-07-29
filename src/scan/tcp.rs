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

const TCP_HEADER_LEN: usize = 20;
const TCP_DATA_LEN: usize = 0;
const SEND_SYN_PACKET_MAX_WAIT_TIME: usize = 64;

/// If port is open, return (syn, ack), else return None.
pub fn send_syn_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Option<(u32, u32)> {
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
    let mut packet = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_packet = MutableTcpPacket::new(&mut packet[..]).unwrap();
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    // Get a random u32 value as seq
    let sequence: u32 = rng.gen();
    tcp_packet.set_sequence(sequence);
    // println!("{}", sequence);
    // tcp_packet.set_sequence(0x9037d2b8);
    // First syn package ack is not used
    let acknowledgement: u32 = rng.gen();
    tcp_packet.set_acknowledgement(acknowledgement);
    // tcp_packet.set_acknowledgement(0x944bb276);
    // assert_ne!(sequence, acknowledgement);
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
            assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN);
        }
        Err(e) => panic!("failed to send packet: {}", e),
    }

    // We treat received packets as if they were TCP packets
    let mut iter = tcp_packet_iter(&mut rx);
    for _ in 0..SEND_SYN_PACKET_MAX_WAIT_TIME {
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
                        return None;
                    } else if response_packet.get_flags() == (TcpFlags::SYN | TcpFlags::ACK) {
                        return Some((
                            response_packet.get_sequence(),
                            response_packet.get_acknowledgement(),
                        ));
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
    None
}

pub fn send_fin_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> bool {
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
    let mut packet = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
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
    tcp_packet.set_flags(TcpFlags::FIN);
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
            assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN);
        }
        Err(e) => panic!("failed to send packet: {}", e),
    }

    // We treat received packets as if they were TCP packets
    let mut iter = tcp_packet_iter(&mut rx);
    for _ in 0..SEND_SYN_PACKET_MAX_WAIT_TIME {
        match iter.next() {
            Ok((response_packet, response_addr)) => {
                // println!("{}", addr);
                if response_addr == dst_ipv4
                    && response_packet.get_destination() == src_port
                    && response_packet.get_source() == dst_port
                {
                    println!("{}", response_packet.get_flags());
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
    false
}

pub fn tcp_connect(dst_ipv4: Ipv4Addr, dst_port: u16, timeout: Duration) -> bool {
    // let addr = format!("{}:{}", dst_ipv4, dst_port);
    let addr = SocketAddr::from((dst_ipv4, dst_port));
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => true,
        _ => false,
    }
}

/// If port is open, return (syn, ack), else return None.
fn tcp_handshake_step_1(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Option<(u32, u32)> {
    send_syn_packet(src_ipv4, dst_ipv4, src_port, dst_port)
}

/// If success, return (syn, ack), else return None.
fn tcp_handshake_step_2(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    sequence: u32,
    acknowledgement: u32,
) -> Option<(u32, u32)> {
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

    let mut packet = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_packet = MutableTcpPacket::new(&mut packet[..]).unwrap();
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    // Get a random u32 value as seq
    tcp_packet.set_sequence(sequence);
    // tcp_packet.set_sequence(0x9037d2b8);
    // First syn package ack is not used
    tcp_packet.set_acknowledgement(acknowledgement);
    // tcp_packet.set_acknowledgement(0x944bb276);
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
            assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN);
        }
        Err(e) => panic!("failed to send packet: {}", e),
    }

    // We treat received packets as if they were TCP packets
    let mut iter = tcp_packet_iter(&mut rx);
    for _ in 0..SEND_SYN_PACKET_MAX_WAIT_TIME {
        match iter.next() {
            Ok((response_packet, response_addr)) => {
                // println!("{}", addr);
                if response_addr == dst_ipv4
                    && response_packet.get_destination() == src_port
                    && response_packet.get_source() == dst_port
                {
                    // println!("{}", response_packet.get_flags());
                    // println!("{}", response_packet.get_data_offset());
                    if response_packet.get_flags() == (TcpFlags::SYN | TcpFlags::ACK) {
                        return Some((
                            response_packet.get_sequence(),
                            response_packet.get_acknowledgement(),
                        ));
                    } else {
                        return None;
                    }
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

pub fn tcp_handshake(src_ipv4: Ipv4Addr, dst_ipv4: Ipv4Addr, src_port: u16, dst_port: u16) -> bool {
    match tcp_handshake_step_1(src_ipv4, dst_ipv4, src_port, dst_port) {
        Some((syn_1, ack_1)) => {
            // println!("syn: {} ack: {}", syn_1, ack_1);
            let acknowledgement = syn_1 + 1;
            let sequence = ack_1 + 1;
            match tcp_handshake_step_2(
                src_ipv4,
                dst_ipv4,
                src_port,
                dst_port,
                sequence,
                acknowledgement,
            ) {
                Some(_) => true,
                _ => false,
            }
        }
        _ => return false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_tcp_full_scan() {
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let duration = Duration::from_secs(1);
        let ret = tcp_connect(dst_ipv4, 80, duration);
        assert_eq!(ret, true);
        let ret = tcp_connect(dst_ipv4, 999, duration);
        // println!("{ret}");
        assert_eq!(ret, false);
    }
    #[test]
    fn test_send_syn_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 130);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        send_syn_packet(src_ipv4, dst_ipv4, 49511, 9999);
    }
    #[test]
    fn test_send_fin_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 130);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 3);
        send_fin_packet(src_ipv4, dst_ipv4, 49511, 80);
    }
    #[test]
    fn test_send_tcp_handshark() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 33);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let src_port = 45980;
        let dst_port = 80;
        let ret = tcp_handshake(src_ipv4, dst_ipv4, src_port, dst_port);
        println!("{}", ret);
    }
}
