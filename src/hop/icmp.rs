use chrono::Utc;
use pnet::packet::icmp;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpCode;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpType;
use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::Ipv4Flags;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::Packet;
use rand::Rng;

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::error::PistolError;
use crate::layers::layer3_ipv4_send;
use crate::layers::Layer3Match;
use crate::layers::Layer4MatchIcmp;
use crate::layers::LayersMatch;
use crate::layers::ICMP_HEADER_SIZE;
use crate::layers::IPV4_HEADER_SIZE;

pub fn send_icmp_ping_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    ttl: u8,
    timeout: Duration,
) -> Result<bool, PistolError> {
    const ICMP_DATA_SIZE: usize = 16;
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    ip_header.set_total_length((IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE) as u16);
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(ttl);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    let mut icmp_header = MutableEchoRequestPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]).unwrap();
    icmp_header.set_icmp_type(IcmpType(8));
    icmp_header.set_icmp_code(IcmpCode(0));
    icmp_header.set_sequence_number(1);
    icmp_header.set_identifier(rng.random());
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

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_icmp = Layer4MatchIcmp {
        layer3: Some(layer3),
        types: None,
        codes: None,
    };
    let layers_match = LayersMatch::Layer4MatchIcmp(layer4_icmp);

    let (ret, _rtt) = layer3_ipv4_send(src_ipv4, dst_ipv4, &ip_buff, vec![layers_match], timeout)?;
    match Ipv4Packet::new(&ret) {
        Some(ipv4_packet) => {
            match ipv4_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmp => {
                    match IcmpPacket::new(ipv4_packet.payload()) {
                        Some(icmp_packet) => {
                            let icmp_type = icmp_packet.get_icmp_type();
                            // let icmp_code = icmp_packet.get_icmp_code();
                            if icmp_type == IcmpType(0) {
                                return Ok(true);
                            }
                        }
                        None => (),
                    }
                }
                _ => (),
            }
        }
        None => (),
    }
    Ok(false)
}
