use pnet::packet::Packet;
use pnet::packet::icmpv6::Icmpv6Code;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::udp::ipv6_checksum;
use std::net::Ipv6Addr;
use std::panic::Location;
use std::time::Duration;

use crate::error::PistolError;
use crate::layer::IPV6_HEADER_SIZE;
use crate::layer::Layer3Match;
use crate::layer::Layer4MatchIcmpv6;
use crate::layer::Layer4MatchTcpUdp;
use crate::layer::LayerMatch;
use crate::layer::PayloadMatch;
use crate::layer::PayloadMatchIp;
use crate::layer::PayloadMatchTcpUdp;
use crate::layer::UDP_HEADER_SIZE;
use crate::layer::layer3_ipv6_send;
use crate::trace::HopStatus;
use crate::trace::UDP_DATA_SIZE;

pub fn send_udp_trace_packet(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    hop_limit: u8,
    timeout: Option<Duration>,
) -> Result<(HopStatus, Duration), PistolError> {
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE];
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
    let payload_length = UDP_HEADER_SIZE + UDP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Udp);
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // udp header
    let mut udp_header = match MutableUdpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    udp_header.set_source(src_port);
    udp_header.set_destination(dst_port);
    udp_header.set_length((UDP_HEADER_SIZE + UDP_DATA_SIZE) as u16);
    let udp_payload = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_";
    assert_eq!(udp_payload.len(), UDP_DATA_SIZE);
    udp_header.set_payload(&udp_payload.as_bytes());
    let checksum = ipv6_checksum(&udp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    udp_header.set_checksum(checksum);

    // generally speaking, the target random UDP port will not return any data.
    let layer3 = Layer3Match {
        name: String::from("udp6 trace layer3 1"),
        layer2: None,
        src_addr: None, // usually this is the address of the router, not the address of the target machine.
        dst_addr: Some(src_ipv6.into()),
    };
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv6.into()),
        dst_addr: Some(dst_ipv6.into()),
    };
    let payload_tcp_udp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcp_udp);
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        name: String::from("udp6 trace icmpv6 1"),
        layer3: Some(layer3),
        icmpv6_type: Some(Icmpv6Types::TimeExceeded),
        icmpv6_code: None,
        payload: Some(payload),
    };
    let layer_match_icmp_time_exceeded = LayerMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    // finally, the UDP packet arrives at the target machine.
    let layer3 = Layer3Match {
        name: String::from("udp6 trace layer3 2"),
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        name: String::from("udp6 trace icmpv6"),
        layer3: Some(layer3),
        icmpv6_type: Some(Icmpv6Types::DestinationUnreachable),
        icmpv6_code: Some(Icmpv6Code(4)), // port unreachable
        payload: None,
    };
    let layer_match_icmp_port_unreachable = LayerMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    // there is a small chance that the target's UDP port will be open.
    let layer3 = Layer3Match {
        name: String::from("udp6 trace layer3 3"),
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4 = Layer4MatchTcpUdp {
        name: String::from("udp6 trace tcp_udp"),
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    let layer_match_udp = LayerMatch::Layer4MatchTcpUdp(layer4);

    let (ret, rtt) = layer3_ipv6_send(
        dst_ipv6,
        src_ipv6,
        &ipv6_buff,
        vec![
            layer_match_icmp_time_exceeded,
            layer_match_icmp_port_unreachable,
            layer_match_udp,
        ],
        timeout,
        true,
    )?;
    match Ipv6Packet::new(&ret) {
        Some(ipv6_packet) => {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Udp => {
                    // any udp response from target port (unusual)
                    let ret_ip = ipv6_packet.get_source();
                    return Ok((HopStatus::RecvReply(ret_ip.into()), rtt));
                }
                IpNextHeaderProtocols::Icmpv6 => match Icmpv6Packet::new(ipv6_packet.payload()) {
                    Some(icmpv6_packet) => {
                        let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                        let icmpv6_code = icmpv6_packet.get_icmpv6_code();
                        let ret_ip = ipv6_packet.get_source();
                        if icmpv6_type == Icmpv6Types::TimeExceeded {
                            return Ok((HopStatus::TimeExceeded(ret_ip.into()), rtt));
                        } else if icmpv6_type == Icmpv6Types::DestinationUnreachable {
                            if icmpv6_code == Icmpv6Code(4) {
                                return Ok((HopStatus::Unreachable(ret_ip.into()), rtt));
                            }
                        }
                    }
                    None => (),
                },
                _ => (),
            }
        }
        None => (),
    }
    Ok((HopStatus::NoResponse, rtt))
}
