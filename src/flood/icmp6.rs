use anyhow::Result;
use pnet::packet::icmpv6;
use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Type};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::MutableIpv6Packet;
use std::net::Ipv6Addr;

use crate::layers::layer3_ipv6_send;
use crate::layers::{ICMPV6_ER_HEADER_SIZE, IPV6_HEADER_SIZE};

const TTL: u8 = 255;

pub fn send_icmpv6_flood_packet(
    src_ipv6: Ipv6Addr,
    _: u16, // unified interface
    dst_ipv6: Ipv6Addr,
    _: u16, // unified interface
    max_same_packet: usize,
) -> Result<()> {
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + ICMPV6_ER_HEADER_SIZE];
    let mut ipv6_header = MutableIpv6Packet::new(&mut ipv6_buff).unwrap();
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = ICMPV6_ER_HEADER_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Icmpv6);
    ipv6_header.set_hop_limit(TTL);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    let mut icmpv6_header =
        MutableEchoRequestPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]).unwrap();
    icmpv6_header.set_icmpv6_type(Icmpv6Type(128));
    icmpv6_header.set_icmpv6_code(Icmpv6Code(0));
    icmpv6_header.set_sequence_number(1);
    icmpv6_header.set_identifier(2);

    let mut icmp_header = MutableIcmpv6Packet::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]).unwrap();
    let checksum = icmpv6::checksum(&icmp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    icmp_header.set_checksum(checksum);

    for _ in 0..max_same_packet {
        let _ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &ipv6_buff, vec![], 0)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_icmp_flood_packet() {
        let src_ipv6: Ipv6Addr = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let ret = send_icmpv6_flood_packet(src_ipv6, 0, dst_ipv6, 0, 3).unwrap();
        println!("{:?}", ret);
    }
}
