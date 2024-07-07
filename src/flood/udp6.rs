use anyhow::Result;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::udp::ipv6_checksum;
use pnet::packet::udp::MutableUdpPacket;
use std::net::Ipv6Addr;
use std::time::Duration;

use crate::layers::layer3_ipv6_send;
use crate::layers::IPV6_HEADER_SIZE;
use crate::layers::UDP_HEADER_SIZE;

const UDP_DATA_SIZE: usize = 0;
const TTL: u8 = 255;

pub fn send_udp_flood_packet(
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    max_same_packet: usize,
) -> Result<usize> {
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE];
    let mut ipv6_header = MutableIpv6Packet::new(&mut ipv6_buff).unwrap();
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = UDP_HEADER_SIZE + UDP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Udp);
    ipv6_header.set_hop_limit(TTL);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // udp header
    let mut udp_header = MutableUdpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]).unwrap();
    udp_header.set_source(src_port);
    udp_header.set_destination(dst_port);
    udp_header.set_length((UDP_HEADER_SIZE + UDP_DATA_SIZE) as u16);
    let checksum = ipv6_checksum(&udp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    udp_header.set_checksum(checksum);
    let timeout = Duration::new(0, 0);

    let mut count = 0;
    for _ in 0..max_same_packet {
        let _ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &ipv6_buff, vec![], timeout)?;
        count += 1;
    }
    Ok(ipv6_buff.len() * count)
}
