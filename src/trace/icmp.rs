use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
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
use std::time::Instant;
use tracing::debug;

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::ask_runner;
use crate::error::PistolError;
use crate::layer::ICMP_HEADER_SIZE;
use crate::layer::IPV4_HEADER_SIZE;
use crate::layer::Layer2;
use crate::layer::Layer3Filter;
use crate::layer::Layer4FilterIcmp;
use crate::layer::PacketFilter;
use crate::layer::PayloadMatch;
use crate::layer::PayloadMatchIcmp;
use crate::layer::PayloadMatchIp;
use crate::trace::HopStatus;

const ICMP_DATA_SIZE: usize = 32;

pub fn send_icmp_trace_packet(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    interface: &NetworkInterface,
    ip_id: u16,
    ttl: u8,
    icmp_id: u16,
    seq: u16,
    timeout: Duration,
) -> Result<(HopStatus, Duration), PistolError> {
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
    let layer3 = Layer3Filter {
        name: "icmp trace time exceeded layer3".to_string(),
        layer2: None,
        src_addr: None, // usually this is the address of the router, not the address of the target machine.
        dst_addr: Some(src_ipv4.into()),
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
    let layer4_icmp = Layer4FilterIcmp {
        name: "icmp trace time exceeded icmp".to_string(),
        layer3: Some(layer3),
        icmp_type: Some(IcmpTypes::TimeExceeded),
        icmp_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    // icmp reply
    let layer3 = Layer3Filter {
        name: "icmp trace reply layer3".to_string(),
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_icmp = Layer4FilterIcmp {
        name: "icmp trace reply icmp".to_string(),
        layer3: Some(layer3),
        icmp_type: Some(IcmpTypes::EchoReply),
        icmp_code: None,
        payload: None,
    };
    let filter_2 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    let receiver = ask_runner(iface, vec![filter_1, filter_2], timeout)?;
    let layer2 = Layer2::new(dst_mac, src_mac, interface, ether_type, timeout);

    let start = Instant::now();
    layer2.send(&ip_buff)?;
    let eth_buff = match receiver.recv_timeout(timeout) {
        Ok(b) => b,
        Err(e) => {
            debug!("{} recv icmp trace response timeout: {}", dst_ipv4, e);
            Vec::new()
        }
    };
    let rtt = start.elapsed();

    if let Some(eth_packet) = EthernetPacket::new(&eth_buff) {
        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
            match ip_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmp => {
                    if let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) {
                        let icmp_type = icmp_packet.get_icmp_type();
                        let ret_ip = ip_packet.get_source();
                        if icmp_type == IcmpTypes::TimeExceeded {
                            return Ok((HopStatus::TimeExceeded(ret_ip.into()), rtt));
                        } else if icmp_type == IcmpTypes::EchoReply {
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
