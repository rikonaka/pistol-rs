use pnet::packet::Packet;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpOption;
use pnet::packet::tcp::ipv6_checksum;
use rand::Rng;
use std::net::Ipv6Addr;
use std::panic::Location;
use std::time::Duration;

use crate::error::PistolError;
use crate::trace::HopStatus;
use crate::layer::IPV6_HEADER_SIZE;
use crate::layer::Layer3Match;
use crate::layer::Layer4MatchIcmpv6;
use crate::layer::Layer4MatchTcpUdp;
use crate::layer::LayerMatch;
use crate::layer::PayloadMatch;
use crate::layer::PayloadMatchIp;
use crate::layer::PayloadMatchTcpUdp;
use crate::layer::TCP_HEADER_SIZE;
use crate::layer::layer3_ipv6_send;

const TCP_DATA_SIZE: usize = 0;
// TCP options size
const NOP_SIZE: usize = 1;
const MSS_SIZE: usize = 4;
const WSCALE_SIZE: usize = 3;
const TIMESTAMP_SIZE: usize = 10;
const SACK_PERM_SIZE: usize = 2;

pub fn send_syn_trace_packet(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    hop_limit: u8,
    timeout: Option<Duration>,
) -> Result<(HopStatus, Duration), PistolError> {
    const TCP_OPTIONS_SIZE: usize =
        MSS_SIZE + SACK_PERM_SIZE + TIMESTAMP_SIZE + NOP_SIZE + WSCALE_SIZE;

    let mut rng = rand::rng();
    // ipv6 header
    let mut ipv6_buff =
        [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
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
    let payload_length = TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.random());
    tcp_header.set_acknowledgement(0);
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(5840);
    tcp_header.set_data_offset(10);
    tcp_header.set_options(&vec![
        TcpOption::mss(1460),
        TcpOption::sack_perm(),
        TcpOption::timestamp(2017864790, 0x0),
        TcpOption::nop(),
        TcpOption::wscale(2),
    ]);
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    // time exceeded packet
    let layer3 = Layer3Match {
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
        layer3: Some(layer3),
        icmpv6_type: Some(Icmpv6Types::TimeExceeded),
        icmpv6_code: None,
        payload: Some(payload),
    };
    let layer_match_icmpv6_time_exceeded = LayerMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    // tcp syn, ack or rst packet
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
    let layer_match_tcp = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);

    let (ret, rtt) = layer3_ipv6_send(
        dst_ipv6,
        src_ipv6,
        &ipv6_buff,
        vec![layer_match_icmpv6_time_exceeded, layer_match_tcp],
        timeout,
        true,
    )?;

    match Ipv6Packet::new(&ret) {
        Some(ipv6_packet) => match ipv6_packet.get_next_header() {
            IpNextHeaderProtocols::Tcp => {
                let ret_ip = ipv6_packet.get_source();
                return Ok((HopStatus::RecvReply(ret_ip.into()), rtt));
            }
            IpNextHeaderProtocols::Icmpv6 => match Icmpv6Packet::new(ipv6_packet.payload()) {
                Some(icmpv6_packet) => {
                    let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                    let ret_ip = ipv6_packet.get_source();
                    if icmpv6_type == Icmpv6Types::TimeExceeded {
                        return Ok((HopStatus::TimeExceeded(ret_ip.into()), rtt));
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
