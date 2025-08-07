use pnet::packet::Packet;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::Ipv4Flags;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpOption;
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
use crate::layer::TCP_HEADER_SIZE;
use crate::layer::layer3_ipv4_send;

const TCP_DATA_SIZE: usize = 0;
// TCP options size
const NOP_SIZE: usize = 1;
const MSS_SIZE: usize = 4;
const WSCALE_SIZE: usize = 3;
const TIMESTAMP_SIZE: usize = 10;
const SACK_PERM_SIZE: usize = 2;

pub fn send_syn_trace_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    ip_id: u16,
    ttl: u8,
    timeout: Option<Duration>,
) -> Result<(HopStatus, Duration), PistolError> {
    const TCP_OPTIONS_SIZE: usize =
        MSS_SIZE + SACK_PERM_SIZE + TIMESTAMP_SIZE + NOP_SIZE + WSCALE_SIZE;

    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
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
    let total_length = IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE;
    ip_header.set_total_length(total_length as u16);
    ip_header.set_identification(ip_id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(ttl);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
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
        TcpOption::timestamp(2025080516, 0x0),
        TcpOption::nop(),
        TcpOption::wscale(2),
    ]);
    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    // time exceeded packet
    let layer3 = Layer3Match {
        layer2: None,
        src_addr: None, // usually this is the address of the router, not the address of the target machine.
        dst_addr: Some(src_ipv4.into()),
        
    };
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
        icmp_code: None,
        payload: Some(payload),
    };
    let layer_match_icmp_time_exceeded = LayerMatch::Layer4MatchIcmp(layer4_icmp);

    // tcp syn, ack or rst packet
    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    let layer_match_tcp = LayerMatch::Layer4MatchTcpUdp(layer4_tcp_udp);

    let (ret, rtt) = layer3_ipv4_send(
        dst_ipv4,
        src_ipv4,
        &ip_buff,
        vec![layer_match_icmp_time_exceeded, layer_match_tcp],
        timeout,
        true,
    )?;

    match Ipv4Packet::new(&ret) {
        Some(ipv4_packet) => {
            let protocol = ipv4_packet.get_next_level_protocol();
            match protocol {
                IpNextHeaderProtocols::Tcp => {
                    let ret_ip = ipv4_packet.get_source();
                    return Ok((HopStatus::RecvReply(ret_ip.into()), rtt));
                }
                IpNextHeaderProtocols::Icmp => match IcmpPacket::new(ipv4_packet.payload()) {
                    Some(icmp_packet) => {
                        let icmp_type = icmp_packet.get_icmp_type();
                        let ret_ip = ipv4_packet.get_source();
                        if icmp_type == IcmpTypes::TimeExceeded {
                            return Ok((HopStatus::TimeExceeded(ret_ip.into()), rtt));
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
