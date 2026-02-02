use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmpv6;
use pnet::packet::icmpv6::Icmpv6Code;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use std::net::Ipv6Addr;
use std::panic::Location;
use std::time::Duration;
use std::time::Instant;
use tracing::debug;

use crate::ask_runner;
use crate::error::PistolError;
use crate::layer::ICMPV6_ER_HEADER_SIZE;
use crate::layer::IPV6_HEADER_SIZE;
use crate::layer::Layer2;
use crate::layer::Layer3Filter;
use crate::layer::Layer4FilterIcmpv6;
use crate::layer::PacketFilter;
use crate::layer::PayloadMatch;
use crate::layer::PayloadMatchIcmpv6;
use crate::layer::PayloadMatchIp;
use crate::trace::HopStatus;

const ICMPV6_DATA_SIZE: usize = 32;

pub fn send_icmpv6_trace_packet(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    interface: &NetworkInterface,
    hop_limit: u8,
    icmpv6_id: u16,
    seq: u16,
    timeout: Duration,
) -> Result<(HopStatus, Duration), PistolError> {
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
    ipv6_header.set_hop_limit(hop_limit);
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
    icmpv6_header.set_icmpv6_type(Icmpv6Types::EchoRequest);
    icmpv6_header.set_icmpv6_code(Icmpv6Code(0));
    icmpv6_header.set_identifier(icmpv6_id);
    icmpv6_header.set_sequence_number(seq);
    let icmpv6_payload = "HIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefg";
    assert_eq!(icmpv6_payload.len(), ICMPV6_DATA_SIZE);
    icmpv6_header.set_payload(&icmpv6_payload.as_bytes());

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

    // time exceeded packet
    let layer3 = Layer3Filter {
        name: "icmpv6 trace time exceeded layer3",
        layer2: None,
        src_addr: None, // usually this is the address of the router, not the address of the target machine.
        dst_addr: Some(src_ipv6.into()),
    };
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv6.into()),
        dst_addr: Some(dst_ipv6.into()),
    };
    let payload_icmp = PayloadMatchIcmpv6 {
        layer3: Some(payload_ip),
        icmpv6_type: Some(Icmpv6Types::EchoRequest),
        icmpv6_code: None,
    };
    let payload = PayloadMatch::PayloadMatchIcmpv6(payload_icmp);
    let layer4_icmp = Layer4FilterIcmpv6 {
        name: "icmpv6 trace time exceeded icmpv6",
        layer3: Some(layer3),
        icmpv6_type: Some(Icmpv6Types::TimeExceeded),
        icmpv6_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterIcmpv6(layer4_icmp);

    // icmp reply
    let layer3 = Layer3Filter {
        name: "icmpv6 trace reply layer3",
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_icmpv6 = Layer4FilterIcmpv6 {
        name: "icmpv6 trace reply icmpv6",
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
        payload: None,
    };
    let filter_2 = PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv6;
    let receiver = ask_runner(iface, vec![filter_1, filter_2], timeout)?;
    let layer2 = Layer2::new(dst_mac, src_mac, interface, ether_type, timeout);

    let start = Instant::now();
    layer2.send(&ipv6_buff)?;
    let eth_buff = match receiver.recv_timeout(timeout) {
        Ok(b) => b,
        Err(e) => {
            debug!("{} recv icmpv6 trace response timeout: {}", dst_ipv6, e);
            Vec::new()
        }
    };
    let rtt = start.elapsed();

    if let Some(eth_packet) = EthernetPacket::new(&eth_buff) {
        if let Some(ipv6_packet) = Ipv6Packet::new(eth_packet.payload()) {
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Icmpv6 => {
                    if let Some(icmpv6_packet) = Icmpv6Packet::new(ipv6_packet.payload()) {
                        let icmpv6_type = icmpv6_packet.get_icmpv6_type();
                        let ret_ip = ipv6_packet.get_source();
                        if icmpv6_type == Icmpv6Types::TimeExceeded {
                            return Ok((HopStatus::TimeExceeded(ret_ip.into()), rtt));
                        } else if icmpv6_type == Icmpv6Types::EchoReply {
                            return Ok((HopStatus::RecvReply(ret_ip.into()), rtt));
                        }
                    }
                }
                _ => (),
            }
        }
    }
    Ok((HopStatus::NoResponse, rtt))
}
