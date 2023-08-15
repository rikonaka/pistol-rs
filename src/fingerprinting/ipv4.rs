use anyhow::Result;
use pnet::packet::icmp::{destination_unreachable, IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum, Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpOptionPacket, MutableTcpPacket, TcpPacket};
use pnet::packet::tcp::{TcpFlags, TcpOption};
use pnet::packet::Packet;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::{icmp_packet_iter, ipv4_packet_iter, tcp_packet_iter};
use rand::Rng;
use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::TcpStream;
use std::time::Duration;

use crate::utils;
use crate::utils::ICMP_BUFF_SIZE;
use crate::utils::IP_TTL;
use crate::utils::TCP_BUFF_SIZE;

fn forge_packet_1(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Result<Vec<u8>> {
    const TCP_HEADER_LEN: usize = 60; // 20 + 40 (options)
    const TCP_DATA_LEN: usize = 0;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // Packet #1: window scale (10), NOP, MSS (1460), timestamp (TSval: 0xFFFFFFFF; TSecr: 0), SACK permitted.
    tcp_header.set_options(&vec![
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::mss(1460),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
        TcpOption::sack_perm(),
    ]);
    // The window field is 1.
    tcp_header.set_window(1);

    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    Ok(tcp_buff.to_vec())
}

fn forge_packet_2(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Result<Vec<u8>> {
    const TCP_HEADER_LEN: usize = 60; // 20 + 40 (options)
    const TCP_DATA_LEN: usize = 0;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // Packet #2: MSS (1400), window scale (0), SACK permitted, timestamp (TSval: 0xFFFFFFFF; TSecr: 0), EOL.
    tcp_header.set_options(&vec![
        TcpOption::mss(1400),
        TcpOption::wscale(0),
        TcpOption::sack_perm(),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
    ]);
    // The window field is 63.
    tcp_header.set_window(63);

    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    Ok(tcp_buff.to_vec())
}

fn forge_packet_3(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Result<Vec<u8>> {
    const TCP_HEADER_LEN: usize = 60; // 20 + 40 (options)
    const TCP_DATA_LEN: usize = 0;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // Packet #3: Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), NOP, NOP, window scale (5), NOP, MSS (640).
    tcp_header.set_options(&vec![
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
        TcpOption::nop(),
        TcpOption::nop(),
        TcpOption::wscale(5),
        TcpOption::nop(),
        TcpOption::mss(6400),
    ]);
    // The window field is 4.
    tcp_header.set_window(4);

    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    Ok(tcp_buff.to_vec())
}

fn forge_packet_4(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Result<Vec<u8>> {
    const TCP_HEADER_LEN: usize = 60; // 20 + 40 (options)
    const TCP_DATA_LEN: usize = 0;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // Packet #4: SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), window scale (10), EOL.
    tcp_header.set_options(&vec![
        TcpOption::sack_perm(),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
        TcpOption::wscale(10),
    ]);
    // The window field is 4.
    tcp_header.set_window(4);

    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    Ok(tcp_buff.to_vec())
}

fn forge_packet_5(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Result<Vec<u8>> {
    const TCP_HEADER_LEN: usize = 60; // 20 + 40 (options)
    const TCP_DATA_LEN: usize = 0;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // Packet #5: MSS (536), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), window scale (10), EOL.
    tcp_header.set_options(&vec![
        TcpOption::mss(536),
        TcpOption::sack_perm(),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
        TcpOption::wscale(10),
    ]);
    // The window field is 16.
    tcp_header.set_window(16);

    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    Ok(tcp_buff.to_vec())
}

fn forge_packet_6(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Result<Vec<u8>> {
    const TCP_HEADER_LEN: usize = 60; // 20 + 40 (options)
    const TCP_DATA_LEN: usize = 0;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // Packet #6: MSS (265), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0).
    tcp_header.set_options(&vec![
        TcpOption::mss(265),
        TcpOption::sack_perm(),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
    ]);
    // The window field is 512.
    tcp_header.set_window(512);

    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    Ok(tcp_buff.to_vec())
}

pub fn sequence_generation() -> Result<()> {
    Ok(())
}
