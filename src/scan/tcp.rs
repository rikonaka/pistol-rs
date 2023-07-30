use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{tcp_packet_iter, transport_channel};
use rand::Rng;
use std::net::Ipv4Addr;
// use std::net::SocketAddr;
// use std::net::TcpStream;
// use std::time::Duration;

const TCP_HEADER_LEN: usize = 20;
const TCP_DATA_LEN: usize = 0;

/// If port is open, return Some(syn, ack), else return None.
pub fn send_syn_scan_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    max_wait: usize,
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
    // First syn package ack is not used
    let acknowledgement: u32 = rng.gen();
    tcp_packet.set_acknowledgement(acknowledgement);
    tcp_packet.set_reserved(0);
    tcp_packet.set_flags(TcpFlags::SYN);
    // tcp_header.set_window(4015);
    tcp_packet.set_urgent_ptr(0);
    tcp_packet.set_window(1024);
    tcp_packet.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_packet.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_packet.set_checksum(checksum);
    // Send the packet
    match tx.send_to(tcp_packet, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => panic!("failed to send packet: {}", e),
    }

    // We treat received packets as if they were TCP packets
    let mut iter = tcp_packet_iter(&mut rx);
    for _ in 0..max_wait {
        match iter.next() {
            Ok((response_packet, response_addr)) => {
                if response_addr == dst_ipv4
                    && response_packet.get_destination() == src_port
                    && response_packet.get_source() == dst_port
                {
                    // println!("{}", packet.get_flags());
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

/// If port is open, return Some(true), else return None.
pub fn send_fin_scan_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    max_wait: usize,
) -> Option<bool> {
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
    // First syn package ack is not used
    let acknowledgement: u32 = rng.gen();
    tcp_packet.set_acknowledgement(acknowledgement);
    assert_ne!(sequence, acknowledgement);
    tcp_packet.set_reserved(0);
    tcp_packet.set_flags(TcpFlags::FIN);
    // tcp_header.set_window(4015);
    tcp_packet.set_urgent_ptr(0);
    tcp_packet.set_window(1024);
    tcp_packet.set_data_offset(5);
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
    for _ in 0..max_wait {
        match iter.next() {
            Ok((response_packet, response_addr)) => {
                if response_addr == dst_ipv4
                    && response_packet.get_destination() == src_port
                    && response_packet.get_source() == dst_port
                {
                    // println!(">>> {}", response_packet.get_flags());
                    if response_packet.get_flags() == TcpFlags::RST | TcpFlags::ACK {
                        // close port
                        return None;
                    } else {
                        // do nothing
                        // it should not return any response if a port is open
                    }
                }
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("an error occurred while reading: {}", e);
            }
        }
    }
    Some(true)
}

/// If port is open, return Some(true), else return None.
pub fn send_ack_scan_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    max_wait: usize,
) -> Option<bool> {
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
    // First syn package ack is not used
    let acknowledgement: u32 = rng.gen();
    tcp_packet.set_acknowledgement(acknowledgement);
    assert_ne!(sequence, acknowledgement);
    tcp_packet.set_reserved(0);
    tcp_packet.set_flags(TcpFlags::ACK);
    // tcp_header.set_window(4015);
    tcp_packet.set_urgent_ptr(0);
    tcp_packet.set_window(1024);
    tcp_packet.set_data_offset(5);
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
    for _ in 0..max_wait {
        match iter.next() {
            Ok((response_packet, response_addr)) => {
                if response_addr == dst_ipv4
                    && response_packet.get_destination() == src_port
                    && response_packet.get_source() == dst_port
                {
                    // println!(">>> {}", response_packet.get_flags());
                    if response_packet.get_flags() == TcpFlags::RST {
                        // the port is unfiltered
                        return Some(true);
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
    // can not get response, the port is filtered
    None
}

// pub fn tcp_connect(dst_ipv4: Ipv4Addr, dst_port: u16, timeout: Duration) -> bool {
//     // let addr = format!("{}:{}", dst_ipv4, dst_port);
//     let addr = SocketAddr::from((dst_ipv4, dst_port));
//     match TcpStream::connect_timeout(&addr, timeout) {
//         Ok(_) => true,
//         _ => false,
//     }
// }

/// If port is open, return (syn, ack), else return None.
fn tcp_handshake_step_1(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    max_wait: usize,
) -> Option<(u32, u32)> {
    send_syn_scan_packet(src_ipv4, dst_ipv4, src_port, dst_port, max_wait)
}

/// If success, return (syn, ack), else return None.
fn tcp_handshake_step_2(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    sequence: u32,
    acknowledgement: u32,
    max_wait: usize,
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
    let checksum = ipv4_checksum(&tcp_packet.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_packet.set_checksum(checksum);
    // Send the packet
    match tx.send_to(tcp_packet, dst_ipv4.into()) {
        Ok(n) => {
            assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN);
        }
        Err(e) => panic!("failed to send packet: {}", e),
    }

    // We treat received packets as if they were TCP packets
    let mut iter = tcp_packet_iter(&mut rx);
    for _ in 0..max_wait {
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

pub fn tcp_handshake(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    max_wait: usize,
) -> bool {
    match tcp_handshake_step_1(src_ipv4, dst_ipv4, src_port, dst_port, max_wait) {
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
                max_wait,
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
    fn test_send_syn_scan_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 33);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let max_wait = 64;
        send_syn_scan_packet(src_ipv4, dst_ipv4, 49511, 9999, max_wait);
    }
    #[test]
    fn test_send_fin_scan_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 33);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let max_wait = 64;
        let ret = send_fin_scan_packet(src_ipv4, dst_ipv4, 49511, 80, max_wait);
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_ack_scan_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 33);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let max_wait = 64;
        let ret = send_ack_scan_packet(src_ipv4, dst_ipv4, 49511, 80, max_wait);
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_tcp_handshark() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 33);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let src_port = 45980;
        let dst_port = 80;
        let max_wait = 64;
        let ret = tcp_handshake(src_ipv4, dst_ipv4, src_port, dst_port, max_wait);
        println!("{}", ret);
    }
}
