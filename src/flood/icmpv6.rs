use anyhow::Result;
use chrono::Utc;
use pnet::packet::icmpv6;
use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmpv6::Icmpv6Code;
use pnet::packet::icmpv6::Icmpv6Type;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::MutableIpv6Packet;
use rand::Rng;
use std::net::Ipv6Addr;
use std::time::Duration;

use crate::layers::layer3_ipv6_send;
use crate::layers::ICMPV6_ER_HEADER_SIZE;
use crate::layers::IPV6_HEADER_SIZE;

const TTL: u8 = 255;

pub fn send_icmpv6_flood_packet(
    src_ipv6: Ipv6Addr,
    _: u16, // unified interface
    dst_ipv6: Ipv6Addr,
    _: u16, // unified interface
    max_same_packet: usize,
) -> Result<usize> {
    const ICMPV6_DATA_SIZE: usize = 16;
    let mut rng = rand::thread_rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + ICMPV6_ER_HEADER_SIZE + ICMPV6_DATA_SIZE];
    let mut ipv6_header = MutableIpv6Packet::new(&mut ipv6_buff).unwrap();
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = ICMPV6_ER_HEADER_SIZE + ICMPV6_DATA_SIZE;
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
    icmpv6_header.set_identifier(rng.gen());
    let mut tv_sec = Utc::now().timestamp().to_be_bytes();
    tv_sec.reverse(); // Big-Endian
    let mut tv_usec = Utc::now().timestamp_subsec_millis().to_be_bytes();
    tv_usec.reverse(); // Big-Endian
    let mut timestamp = Vec::new();
    timestamp.extend(tv_sec);
    timestamp.extend(tv_usec);
    // println!("{:?}", timestamp);
    icmpv6_header.set_payload(&timestamp);

    let mut icmp_header = MutableIcmpv6Packet::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]).unwrap();
    let checksum = icmpv6::checksum(&icmp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    icmp_header.set_checksum(checksum);
    let timeout = Duration::new(0, 0);

    let mut count = 0;
    for _ in 0..max_same_packet {
        let _ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &ipv6_buff, vec![], timeout)?;
        count += 1;
    }
    Ok(ipv6_buff.len() * count)
}
