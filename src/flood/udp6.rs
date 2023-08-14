use anyhow::Result;
use pnet::packet::udp::{ipv6_checksum, MutableUdpPacket};
use std::net::Ipv6Addr;

use crate::utils::return_layer4_udp6_channel;
use crate::utils::UDP_BUFF_SIZE;
use crate::utils::UDP_DATA_LEN;
use crate::utils::UDP_HEADER_LEN;

pub fn send_udp_flood_packet(
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    max_same_packet: usize,
) -> Result<()> {
    let (mut udp_tx, _) = return_layer4_udp6_channel(UDP_BUFF_SIZE)?;

    // udp header
    let mut udp_buff = [0u8; UDP_HEADER_LEN + UDP_DATA_LEN];
    let mut udp_header = MutableUdpPacket::new(&mut udp_buff[..]).unwrap();
    udp_header.set_source(src_port);
    udp_header.set_destination(dst_port);
    udp_header.set_length((UDP_HEADER_LEN + UDP_DATA_LEN) as u16);
    let checksum = ipv6_checksum(&udp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    udp_header.set_checksum(checksum);

    for _ in 0..max_same_packet {
        match udp_tx.send_to(&udp_header, dst_ipv6.into()) {
            _ => (),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_udp_flood_packet() {
        // 240e:34c:8b:25b0:17c1:ac6c:9baa:ade
        let src_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x17c1, 0xac6c, 0x9baa, 0xade);
        // 240e:34c:8b:25b0:20c:29ff:fe0c:237e
        let dst_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x20c, 0x29ff, 0xfe0c, 0x237e);
        let src_port = 57831;
        let dst_port = 80;
        let ret = send_udp_flood_packet(src_ipv6, src_port, dst_ipv6, dst_port, 1).unwrap();
        println!("{:?}", ret);
    }
}
