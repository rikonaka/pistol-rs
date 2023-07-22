use pnet::packet::ip::IpNextHeaderProtocols;
// use pnet::packet::ipv4::MutableIpv4Packet;
// use pnet::packet::tcp::TcpOption;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{tcp_packet_iter, transport_channel};
use rand::Rng;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::mpsc::channel;
use subnetwork::Ipv4Pool;

use crate::utils;

#[derive(Debug)]
pub struct SynScanResults {
    pub alive_port_num: usize,
    pub alive_port_vec: Vec<u16>,
}

pub fn send_tcp_syn_scan_packet(
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

pub fn run_syn_scan_single(
    interface: &str,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
) -> Option<SynScanResults> {
    let i = match utils::find_interface_by_name(interface) {
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
    let src_port_ret = send_tcp_syn_scan_packet(src_ipv4, dst_ipv4, src_port, dst_port);
    if src_port_ret {
        Some(SynScanResults {
            alive_port_num: 1,
            alive_port_vec: vec![dst_port],
        })
    } else {
        Some(SynScanResults {
            alive_port_num: 0,
            alive_port_vec: vec![],
        })
    }
}

pub fn run_syn_scan_range(
    dst_ipv4: Ipv4Addr,
    interface: &str,
    start_port: u16,
    end_port: u16,
    threads_num: usize,
    print_result: bool,
) -> Option<SynScanResults> {
    let i = match utils::find_interface_by_name(interface) {
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
    let pool = utils::auto_threads_pool(threads_num);
    let (tx, rx) = channel();

    for dst_port in start_port..end_port {
        let tx = tx.clone();
        pool.execute(move || {
            let dst_port_ret = send_tcp_syn_scan_packet(src_ipv4, dst_ipv4, src_port, dst_port);
            if print_result {
                if dst_port_ret {
                    println!("port {} is open", dst_port);
                } else {
                    println!("port {} is close", dst_port);
                }
            }
            tx.send((dst_port, dst_port_ret))
                .expect("channel will be there waiting for the pool");
        });
    }

    let iter = rx.into_iter().take((end_port - start_port).into());
    let mut alive_port_vec = Vec::new();
    for (port, port_ret) in iter {
        if port_ret {
            alive_port_vec.push(port);
        }
    }
    Some(SynScanResults {
        alive_port_num: alive_port_vec.len(),
        alive_port_vec,
    })
}

pub fn run_syn_scan_subnet(
    subnet: Ipv4Pool,
    interface: &str,
    start_port: u16,
    end_port: u16,
    threads_num: usize,
    print_result: bool,
) -> Option<HashMap<Ipv4Addr, SynScanResults>> {
    let i = match utils::find_interface_by_name(interface) {
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

    let pool = utils::auto_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut rng = rand::thread_rng();
    for dst_ipv4 in subnet {
        let src_port: u16 = rng.gen_range(1024..=49151);
        for dst_port in start_port..end_port {
            let tx = tx.clone();
            pool.execute(move || {
                let dst_port_ret = send_tcp_syn_scan_packet(src_ipv4, dst_ipv4, src_port, dst_port);
                if print_result {
                    if dst_port_ret {
                        println!("ip {} port {} is open", dst_ipv4, dst_port);
                    } else {
                        println!("ip {} port {} is close", dst_ipv4, dst_port);
                    }
                }
                tx.send((dst_ipv4, dst_port, dst_port_ret))
                    .expect("channel will be there waiting for the pool");
            });
        }
    }

    let iter = rx
        .into_iter()
        .take(subnet.len() * (end_port - start_port) as usize);

    let mut ret: HashMap<Ipv4Addr, SynScanResults> = HashMap::new();
    for (dst_ipv4, dst_port, dst_port_ret) in iter {
        if dst_port_ret {
            if ret.contains_key(&dst_ipv4) {
                ret.get_mut(&dst_ipv4).unwrap().alive_port_num += 1;
                ret.get_mut(&dst_ipv4)
                    .unwrap()
                    .alive_port_vec
                    .push(dst_port);
            } else {
                let ssr = SynScanResults {
                    alive_port_num: 1,
                    alive_port_vec: vec![dst_port],
                };
                ret.insert(dst_ipv4, ssr);
            }
        }
    }

    Some(ret)
}

#[test]
fn test_tcp_syn_scan() {
    let src_ipv4 = Ipv4Addr::new(192, 168, 72, 130);
    let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
    send_tcp_syn_scan_packet(src_ipv4, dst_ipv4, 49511, 9999);
}
