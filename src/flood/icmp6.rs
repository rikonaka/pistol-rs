use anyhow::Result;
use pnet::packet::icmpv6;
use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Type, MutableIcmpv6Packet};
use pnet_packet::icmpv6::echo_request::MutableEchoRequestPacket;
use std::net::Ipv6Addr;

use crate::utils::return_layer4_icmp_channel;
use crate::utils::ICMP_BUFF_SIZE;
use crate::utils::ICMP_DATA_LEN;
use crate::utils::ICMP_HEADER_LEN;

pub fn send_icmp_flood_packet(
    src_ipv6: Ipv6Addr,
    _: u16, // unified interface
    dst_ipv6: Ipv6Addr,
    _: u16, // unified interface
    max_same_packet: usize,
) -> Result<()> {
    let (mut icmp_tx, _) = return_layer4_icmp_channel(ICMP_BUFF_SIZE)?;

    let mut icmp_buff = [0u8; ICMP_HEADER_LEN + ICMP_DATA_LEN];
    let mut icmp_header = MutableEchoRequestPacket::new(&mut icmp_buff[..]).unwrap();
    icmp_header.set_icmpv6_type(Icmpv6Type(128));
    icmp_header.set_icmpv6_code(Icmpv6Code(0));
    icmp_header.set_sequence_number(1);
    icmp_header.set_identifier(2);

    let mut icmp_header = MutableIcmpv6Packet::new(&mut icmp_buff).unwrap();
    let checksum = icmpv6::checksum(&icmp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    icmp_header.set_checksum(checksum);

    for _ in 0..max_same_packet {
        match icmp_tx.send_to(&icmp_header, dst_ipv6.into()) {
            _ => (),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_icmp_flood_packet() {
        // 240e:34c:8b:25b0:17c1:ac6c:9baa:ade
        let src_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x17c1, 0xac6c, 0x9baa, 0xade);
        // 240e:34c:8b:25b0:20c:29ff:fe0c:237e
        let dst_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x20c, 0x29ff, 0xfe0c, 0x237e);
        let ret = send_icmp_flood_packet(src_ipv6, 0, dst_ipv6, 0, 1).unwrap();
        println!("{:?}", ret);
    }
}
