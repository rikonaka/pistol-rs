use pnet::packet::Packet;
use pnet::packet::icmp::IcmpCode;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::icmp::destination_unreachable;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::Ipv4Flags;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::udp::ipv4_checksum;
use rand::Rng;
use std::net::Ipv4Addr;
use std::panic::Location;
use std::time::Duration;

use crate::error::PistolError;
use crate::hop::HopStatus;
use crate::layer::IPV4_HEADER_SIZE;
use crate::layer::Layer3Match;
use crate::layer::Layer4MatchIcmp;
use crate::layer::Layer4MatchTcpUdp;
use crate::layer::LayerMatch;
use crate::layer::PayloadMatch;
use crate::layer::PayloadMatchIp;
use crate::layer::PayloadMatchTcpUdp;
use crate::layer::UDP_HEADER_SIZE;
use crate::layer::layer3_ipv4_send;

const UDP_DATA_SIZE: usize = 32;

pub fn send_udp_trace_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    ttl: u8,
    timeout: Option<Duration>,
) -> Result<(HopStatus, Duration), PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE];
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
    ip_header.set_total_length((IPV4_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE) as u16);
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(ttl);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // udp header
    let mut udp_header = match MutableUdpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
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
    let checksum = ipv4_checksum(&udp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    udp_header.set_checksum(checksum);

    // generally speaking, the target random UDP port will not return any data.
    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv4.into()),
        dst_addr: Some(dst_ipv4.into()),
    };
    let payload_tcp_udp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcp_udp);
    let layer4_icmp = Layer4MatchIcmp {
        layer3: Some(layer3),
        icmp_type: Some(IcmpTypes::TimeExceeded),
        icmp_code: Some(IcmpCode(0)),
        payload: Some(payload),
    };
    let layers_match_time_exceeded = LayerMatch::Layer4MatchIcmp(layer4_icmp);

    // finally, the UDP packet arrives at the target machine.
    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_icmp = Layer4MatchIcmp {
        layer3: Some(layer3),
        icmp_type: Some(IcmpTypes::DestinationUnreachable),
        icmp_code: Some(IcmpCode(3)),
        payload: None,
    };
    let layers_match_udp_port_unreachable = LayerMatch::Layer4MatchIcmp(layer4_icmp);

    // there is a small chance that the target's UDP port will be open.
    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    let layers_match_udp = LayerMatch::Layer4MatchTcpUdp(layer4);

    let (ret, rtt) = layer3_ipv4_send(
        dst_ipv4,
        src_ipv4,
        &ip_buff,
        vec![
            layers_match_time_exceeded,
            layers_match_udp_port_unreachable,
            layers_match_udp,
        ],
        timeout,
        true,
    )?;
    match Ipv4Packet::new(&ret) {
        Some(ipv4_packet) => {
            match ipv4_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Udp => {
                    return Ok((HopStatus::Open, rtt));
                }
                IpNextHeaderProtocols::Icmp => {
                    match IcmpPacket::new(ipv4_packet.payload()) {
                        Some(icmp_packet) => {
                            let icmp_type = icmp_packet.get_icmp_type();
                            let icmp_code = icmp_packet.get_icmp_code();
                            if icmp_type == IcmpTypes::DestinationUnreachable
                                && icmp_code == IcmpCode(0)
                            {
                                // icmp port unreachable error (type 3, code 3)
                                return Ok((PortStatus::Unreachable, rtt));
                            } else if codes_2.contains(&icmp_code) {
                                // other icmp unreachable errors (type 3, code 1, 2, 9, 10, or 13)
                                return Ok((PortStatus::Filtered, DataRecvStatus::Yes, rtt));
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
    // no response received (even after retransmissions)
    Ok((PortStatus::OpenOrFiltered, DataRecvStatus::No, rtt))
}
