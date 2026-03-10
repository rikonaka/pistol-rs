use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
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
use rand::RngExt;
use std::net::Ipv4Addr;
use std::panic::Location;
use std::sync::Arc;

use crate::error::PistolError;
use crate::layer::IPV4_HEADER_SIZE;
use crate::layer::Layer3Filter;
use crate::layer::Layer4FilterIcmp;
use crate::layer::Layer4FilterTcpUdp;
use crate::layer::PacketFilter;
use crate::layer::PayloadMatch;
use crate::layer::PayloadMatchIp;
use crate::layer::PayloadMatchTcpUdp;
use crate::layer::UDP_HEADER_SIZE;
use crate::scan::PortStatus;

const UDP_DATA_SIZE: usize = 0;
const TTL: u8 = 64;

pub(crate) fn build_udp_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<(Arc<[u8]>, Vec<Arc<PacketFilter>>), PistolError> {
    let mut rng = rand::rng();
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE];
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
    ip_header.set_total_length((IPV4_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE) as u16);
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
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
                location: Location::caller().to_string(),
            });
        }
    };
    udp_header.set_source(src_port);
    udp_header.set_destination(dst_port);
    udp_header.set_length((UDP_HEADER_SIZE + UDP_DATA_SIZE) as u16);
    // udp_header.set_payload(b"1234567890"); // udp test
    let checksum = ipv4_checksum(&udp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    udp_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: String::from("udp scan layer3"),
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("udp scan tcp_udp"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
        flag: None,
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
    let layer4_icmp = Layer4FilterIcmp {
        name: String::from("udp scan icmp"),
        layer3: Some(layer3),
        icmp_type: None,
        icmp_code: None,
        payload: Some(payload),
    };
    let filter_1 = Arc::new(PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp));
    let filter_2 = Arc::new(PacketFilter::Layer4FilterIcmp(layer4_icmp));

    let ip_buff = Arc::new(ip_buff);
    Ok((ip_buff, vec![filter_1, filter_2]))
}

pub(crate) fn parse_udp_scan_response(eth_response: Arc<[u8]>) -> Result<PortStatus, PistolError> {
    let codes_1 = vec![
        destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
    ];
    let codes_2 = vec![
        destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
        destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
        destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
        destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
        destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
    ];

    if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
            if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
                match ip_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Udp => {
                        // any udp response from target port (unusual)
                        return Ok(PortStatus::Open);
                    }
                    IpNextHeaderProtocols::Icmp => {
                        if let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) {
                            let icmp_type = icmp_packet.get_icmp_type();
                            let icmp_code = icmp_packet.get_icmp_code();
                            if icmp_type == IcmpTypes::DestinationUnreachable {
                                if codes_1.contains(&icmp_code) {
                                    // icmp port unreachable error (type 3, code 3)
                                    return Ok(PortStatus::Closed);
                                } else if codes_2.contains(&icmp_code) {
                                    // other icmp unreachable errors (type 3, code 1, 2, 9, 10, or 13)
                                    return Ok(PortStatus::Filtered);
                                }
                            }
                        }
                    }
                    _ => (),
                }
            }
        }
    }
    // no response received (even after retransmissions)
    Ok(PortStatus::OpenOrFiltered)
}
