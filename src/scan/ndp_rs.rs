use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::packet::icmpv6;
use pnet::packet::icmpv6::Icmpv6Code;
use pnet::packet::icmpv6::Icmpv6Type;
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::packet::icmpv6::ndp::MutableRouterSolicitPacket;
use pnet::packet::icmpv6::ndp::NdpOption;
use pnet::packet::icmpv6::ndp::NdpOptionTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::MutableIpv6Packet;
use std::net::Ipv6Addr;
use std::panic::Location;
use std::sync::Arc;

use crate::error::PistolError;
use crate::layer::ICMPV6_RA_HEADER_SIZE;
use crate::layer::IPV6_HEADER_SIZE;
use crate::layer::Layer3Filter;
use crate::layer::Layer4FilterIcmpv6;
use crate::layer::PacketFilter;
use crate::layer::PayloadMatch;
use crate::layer::PayloadMatchIcmpv6;
use crate::layer::PayloadMatchIp;
use crate::layer::find_interface_by_src_ip;

pub(crate) fn build_ndp_ra_scan_packet(
    src_ipv6: Ipv6Addr,
) -> Result<(MacAddr, NetworkInterface, Arc<[u8]>, Vec<Arc<PacketFilter>>), PistolError> {
    // router solicitation
    let route_addr_ipv6 = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x0002);
    // let route_addr_1 = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x0001);
    let interface = match find_interface_by_src_ip(src_ipv6.into()) {
        Some(i) => i,
        None => {
            return Err(PistolError::CanNotFoundInterface {
                i: format!("ipv6 src interface_name({})", src_ipv6),
            });
        }
    };
    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(PistolError::CanNotFoundSrcMacAddress),
    };

    // ipv6
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + ICMPV6_RA_HEADER_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: Location::caller().to_string(),
            });
        }
    };
    ipv6_header.set_version(6);
    ipv6_header.set_traffic_class(0);
    ipv6_header.set_flow_label(0);
    ipv6_header.set_payload_length(ICMPV6_RA_HEADER_SIZE as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Icmpv6);
    ipv6_header.set_hop_limit(255);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(route_addr_ipv6);

    // icmpv6
    let mut icmpv6_header =
        match MutableRouterSolicitPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
            Some(p) => p,
            None => {
                return Err(PistolError::BuildPacketError {
                    location: Location::caller().to_string(),
                });
            }
        };
    // Neighbor Solicitation
    icmpv6_header.set_icmpv6_type(Icmpv6Type(133));
    icmpv6_header.set_icmpv6_code(Icmpv6Code(0));
    icmpv6_header.set_reserved(0);
    let ndp_option = NdpOption {
        option_type: NdpOptionTypes::SourceLLAddr,
        length: 1,
        data: src_mac.octets().to_vec(),
    };
    icmpv6_header.set_options(&vec![ndp_option]);

    let mut icmpv6_header = match MutableIcmpv6Packet::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: Location::caller().to_string(),
            });
        }
    };
    let checksum = icmpv6::checksum(&icmpv6_header.to_immutable(), &src_ipv6, &route_addr_ipv6);
    icmpv6_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: String::from("ndp_ns layer3"),
        layer2: None,
        src_addr: None,
        dst_addr: None,
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: None,
        dst_addr: None,
    };
    let payload_icmpv6 = PayloadMatchIcmpv6 {
        layer3: Some(payload_ip),
        icmpv6_type: Some(Icmpv6Types::RouterSolicit),
        icmpv6_code: None,
    };
    let payload = PayloadMatch::PayloadMatchIcmpv6(payload_icmpv6);
    let layer4_icmpv6 = Layer4FilterIcmpv6 {
        name: String::from("ndp_ns icmpv6").to_string(),
        layer3: Some(layer3),
        icmpv6_type: Some(Icmpv6Types::RouterAdvert), // Type: Router Advertisement (134)
        icmpv6_code: None,
        payload: Some(payload),
    };
    let filter = Arc::new(PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6));
    let dst_mac = MacAddr(33, 33, 00, 00, 00, 02);
    let ipv6_buff = Arc::new(ipv6_buff);
    Ok((dst_mac, interface, ipv6_buff, vec![filter]))
}
