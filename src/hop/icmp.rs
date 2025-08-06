use pnet::packet::Packet;
use pnet::packet::icmp;
use pnet::packet::icmp::IcmpCode;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::Ipv4Flags;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv4::MutableIpv4Packet;
use std::panic::Location;

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::error::PistolError;
use crate::hop::HopStatus;
use crate::layer::ICMP_HEADER_SIZE;
use crate::layer::IPV4_HEADER_SIZE;
use crate::layer::Layer3Match;
use crate::layer::Layer4MatchIcmp;
use crate::layer::LayerMatch;
use crate::layer::PayloadMatch;
use crate::layer::PayloadMatchIcmp;
use crate::layer::PayloadMatchIp;
use crate::layer::layer3_ipv4_send;

pub fn send_icmp_trace_packet(
    dst_ipv4: Ipv4Addr,
    src_ipv4: Ipv4Addr,
    ip_id: u16,
    ttl: u8,
    icmp_id: u16,
    seq: u16,
    timeout: Option<Duration>,
) -> Result<(HopStatus, Duration), PistolError> {
    const ICMP_DATA_SIZE: usize = 32;
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE];
    let mut ip_header = match MutableIpv4Packet::new(&mut ip_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    ip_header.set_total_length((IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE) as u16);
    ip_header.set_identification(ip_id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(ttl);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    let mut icmp_header = match MutableEchoRequestPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    icmp_header.set_icmp_type(IcmpTypes::EchoRequest); // echo
    icmp_header.set_icmp_code(IcmpCode(0));
    icmp_header.set_identifier(icmp_id);
    icmp_header.set_sequence_number(seq);
    let icmp_payload = "HIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefg";
    assert_eq!(icmp_payload.len(), ICMP_DATA_SIZE);
    icmp_header.set_payload(&icmp_payload.as_bytes());

    let mut icmp_header = match MutableIcmpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    let checksum = icmp::checksum(&icmp_header.to_immutable());
    icmp_header.set_checksum(checksum);

    // time exceeded packet
    let layer3 = Layer3Match {
        layer2: None,
        src_addr: None, // usually this is the address of the router, not the address of the target machine.
        dst_addr: Some(src_ipv4.into()),
        ip_id: None,
    };
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv4.into()),
        dst_addr: Some(dst_ipv4.into()),
    };
    let payload_icmp = PayloadMatchIcmp {
        layer3: Some(payload_ip),
        icmp_type: Some(IcmpTypes::EchoRequest),
        icmp_code: None,
    };
    let payload = PayloadMatch::PayloadMatchIcmp(payload_icmp);
    let layer4_icmp = Layer4MatchIcmp {
        layer3: Some(layer3),
        icmp_type: Some(IcmpTypes::TimeExceeded),
        icmp_code: None,
        payload: Some(payload),
    };
    let layer_match_icmp_time_exceeded = LayerMatch::Layer4MatchIcmp(layer4_icmp);

    // icmp reply
    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
        ip_id: None,
    };
    let layer4_icmp = Layer4MatchIcmp {
        layer3: Some(layer3),
        icmp_type: Some(IcmpTypes::EchoReply),
        icmp_code: None,
        payload: None,
    };
    let layer_match_icmp_reply = LayerMatch::Layer4MatchIcmp(layer4_icmp);

    let (ret, rtt) = layer3_ipv4_send(
        dst_ipv4,
        src_ipv4,
        &ip_buff,
        vec![layer_match_icmp_time_exceeded, layer_match_icmp_reply],
        timeout,
        true,
    )?;
    match Ipv4Packet::new(&ret) {
        Some(ipv4_packet) => match ipv4_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Icmp => match IcmpPacket::new(ipv4_packet.payload()) {
                Some(icmp_packet) => {
                    let icmp_type = icmp_packet.get_icmp_type();
                    let ret_ip = ipv4_packet.get_source();
                    if icmp_type == IcmpTypes::TimeExceeded {
                        return Ok((HopStatus::TimeExceeded(ret_ip.into()), rtt));
                    } else if icmp_type == IcmpTypes::EchoReply {
                        return Ok((HopStatus::RecvReply(ret_ip.into()), rtt));
                    }
                }
                None => (),
            },
            _ => (),
        },
        None => (),
    }
    Ok((HopStatus::NoResponse, rtt))
}
