use pnet::packet::Packet;
use pnet::packet::icmpv6::Icmpv6Code;
use pnet::packet::icmpv6::Icmpv6Packet;
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
use crate::scan::DataRecvStatus;
use crate::scan::PortStatus;

const UDP_DATA_SIZE: usize = 0;
const TTL: u8 = 255;

pub fn send_udp_scan_packet(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    timeout: Option<Duration>,
) -> Result<(PortStatus, DataRecvStatus, Duration), PistolError> {
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
    ipv6_header.set_hop_limit(TTL);
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
    let checksum = ipv6_checksum(&udp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    udp_header.set_checksum(checksum);

    let codes_1 = vec![
        Icmpv6Code(4), // port unreachable
    ];
    let codes_2 = vec![
        Icmpv6Code(1), // communication with destination administratively prohibited
        Icmpv6Code(3), // address unreachable
    ];

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    // set the icmp payload matchs
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
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
        payload: Some(payload),
    };
    let layers_match_1 = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);
    let layers_match_2 = LayerMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    let (ret, rtt) = layer3_ipv6_send(
        dst_ipv6,
        src_ipv6,
        &ipv6_buff,
        vec![layers_match_1, layers_match_2],
        timeout,
        true,
    )?;
    match Ipv6Packet::new(&ret) {
        Some(ipv6_packet) => {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Udp => {
                    // any udp response from target port (unusual)
                    return Ok((PortStatus::Open, DataRecvStatus::Yes, rtt));
                }
                IpNextHeaderProtocols::Icmpv6 => {
                    match Icmpv6Packet::new(ipv6_packet.payload()) {
                        Some(icmpv6_packet) => {
                            // let icmp_type = icmp_packet.get_icmp_type();
                            let icmpv6_code = icmpv6_packet.get_icmpv6_code();
                            if codes_1.contains(&icmpv6_code) {
                                // icmp port unreachable error (type 3, code 3)
                                return Ok((PortStatus::Closed, DataRecvStatus::Yes, rtt));
                            } else if codes_2.contains(&icmpv6_code) {
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
