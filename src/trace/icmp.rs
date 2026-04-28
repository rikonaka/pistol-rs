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
use pnet::datalink::MacAddr;
use pnet::packet::ipv4::MutableIpv4Packet;
use std::net::Ipv4Addr;
use std::panic::Location;
use std::sync::Arc;

use crate::SendPacketInput;
use crate::error::PistolError;
use crate::layer::ICMP_HEADER_SIZE;
use crate::layer::IPV4_HEADER_SIZE;
use crate::layer::Layer3Filter;
use crate::layer::Layer4FilterIcmp;
use crate::layer::PacketFilter;
use crate::layer::PayloadMatch;
use crate::layer::PayloadMatchIcmp;
use crate::layer::PayloadMatchIp;
use crate::trace::HopStatus;

const ICMP_DATA_SIZE: usize = 32;

pub(crate) fn send_icmp_trace_packet(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    if_name: String,
    ip_id: u16,
    ttl: u8,
    icmp_id: u16,
    seq: u16,
) -> Result<(SendPacketInput, Vec<Arc<PacketFilter>>), PistolError> {
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE];
    let mut ip_header = match MutableIpv4Packet::new(&mut ip_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: Location::caller().to_string(),
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
                location: Location::caller().to_string(),
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
                location: Location::caller().to_string(),
            });
        }
    };
    let checksum = icmp::checksum(&icmp_header.to_immutable());
    icmp_header.set_checksum(checksum);

    // time exceeded packet
    let layer3 = Layer3Filter {
        name: String::from("icmp trace time exceeded layer3"),
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
        name: String::from("icmp trace time exceeded icmp"),
        layer3: Some(layer3),
        icmp_type: Some(IcmpTypes::TimeExceeded),
        icmp_code: None,
        payload: Some(payload),
    };
    let filter_1 = Arc::new(PacketFilter::Layer4FilterIcmp(layer4_icmp));

    // icmp reply
    let layer3 = Layer3Filter {
        name: String::from("icmp trace reply layer3"),
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_icmp = Layer4FilterIcmp {
        name: String::from("icmp trace reply icmp"),
        layer3: Some(layer3),
        icmp_type: Some(IcmpTypes::EchoReply),
        icmp_code: None,
        payload: None,
    };
    let filter_2 = Arc::new(PacketFilter::Layer4FilterIcmp(layer4_icmp));

    let ip_buff = Arc::new(ip_buff);

    let send_packet_input = SendPacketInput {
        dst_mac,
        src_mac,
        eth_type: EtherTypes::Ipv4,
        l3_payload: ip_buff.clone(),
        if_name,
        retransmit: 1,
    };

    Ok((send_packet_input, vec![filter_1, filter_2]))
}

pub(crate) fn parse_icmp_trace_response(eth_response: &[u8]) -> Result<HopStatus, PistolError> {
    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
            if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
                match ip_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Icmp => {
                        if let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) {
                            let icmp_type = icmp_packet.get_icmp_type();
                            let ret_ip = ip_packet.get_source();
                            if icmp_type == IcmpTypes::TimeExceeded {
                                return Ok(HopStatus::TimeExceeded(ret_ip.into()));
                            } else if icmp_type == IcmpTypes::EchoReply {
                                return Ok(HopStatus::RecvReply(ret_ip.into()));
                            }
                        }
                    }
                    _ => (),
                }
            }
        }
    }
    Ok(HopStatus::NoResponse)
}
