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
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use subnetwork::Ipv4Pool;
use tokio::task::JoinSet;

use crate::utils;

const TCP_HEADER_LEN: usize = 20;
const TEST_DATA_LEN: usize = 0;

pub async fn send_tcp_syn_scan_packet(
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
            Ok((packet, addr)) => {
                // println!("{}", addr);
                if addr == dst_ipv4 {
                    // println!("{}", packet.get_flags());
                    // println!("{}", TcpFlags::RST | TcpFlags::ACK); // PORT NOT OPEN
                    // println!("{}", TcpFlags::SYN | TcpFlags::ACK); // PORT OPEN
                    if packet.get_flags() == (TcpFlags::RST | TcpFlags::ACK) {
                        return false;
                    } else if packet.get_flags() == (TcpFlags::SYN | TcpFlags::ACK) {
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

pub async fn tcp_port_syn_scan_single(interface: &str, dst_ipv4: Ipv4Addr, dst_port: u16) -> bool {
    let i = match utils::get_interface(interface) {
        Some(i) => i,
        _ => {
            eprintln!("not such interface: {}", interface);
            return false;
        }
    };
    let src_ipv4 = match utils::get_interface_ip(&i) {
        Some(i) => i,
        _ => {
            eprintln!("get interface ip failed: {}", interface);
            return false;
        }
    };
    let mut rng = rand::thread_rng();
    let src_port: u16 = rng.gen_range(1024..=49151);
    send_tcp_syn_scan_packet(src_ipv4, dst_ipv4, src_port, dst_port).await
}

pub async fn tcp_port_syn_scan_range(
    interface: &str,
    dst_ipv4: Ipv4Addr,
    start_port: u16,
    end_port: u16,
    print_result: bool,
) -> Option<HashMap<u16, bool>> {
    let i = match utils::get_interface(interface) {
        Some(i) => i,
        _ => {
            eprintln!("not such interface: {}", interface);
            return None;
        }
    };
    let src_ipv4 = match utils::get_interface_ip(&i) {
        Some(i) => i,
        _ => {
            eprintln!("get interface ip failed: {}", interface);
            return None;
        }
    };
    let mut rng = rand::thread_rng();
    let src_port: u16 = rng.gen_range(1024..=49151);
    let mut handles = Vec::new();
    let ret = Arc::new(Mutex::new(HashMap::new()));
    // let mut set = JoinSet::new();
    for dst_port in start_port..end_port {
        let ret_clone = ret.clone();
        handles.push(tokio::spawn(async move {
            // println!("dst_port: {}", dst_port);
            // tokio::time::sleep(tokio::time::Duration::from_secs_f32(1.0)).await;
            let dst_port_ret =
                send_tcp_syn_scan_packet(src_ipv4, dst_ipv4, src_port, dst_port).await;
            if print_result {
                if dst_port_ret {
                    println!("port {} is open", dst_port);
                } else {
                    println!("port {} is close", dst_port);
                }
            }
            ret_clone.lock().unwrap().insert(dst_port, dst_port_ret);
            // println!("dst_port quit: {}", dst_port);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    Some(Arc::try_unwrap(ret).unwrap().into_inner().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_tcp_syn_scan() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 130);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        send_tcp_syn_scan_packet(src_ipv4, dst_ipv4, 49511, 9999).await;
    }
    #[tokio::test]
    async fn test_tcp_syn_scan_single() {
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let i = "ens33";
        let ret = tcp_port_syn_scan_single(i, dst_ipv4, 80).await;
        assert_eq!(ret, true);
        let ret = tcp_port_syn_scan_single(i, dst_ipv4, 9999).await;
        assert_eq!(ret, false);
    }
    #[tokio::test]
    async fn test_tcp_syn_scan_multi() {
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let i = "ens33";
        let ret = tcp_port_syn_scan_range(i, dst_ipv4, 22, 443, true)
            .await
            .unwrap();
        println!("{:?}", ret);
    }
}
