use pnet::datalink::MacAddr;
use pnet::packet::icmpv6;
use pnet::packet::icmpv6::Icmpv6Code;
use pnet::packet::icmpv6::Icmpv6Type;
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::packet::icmpv6::ndp::MutableNeighborSolicitPacket;
use pnet::packet::icmpv6::ndp::NdpOption;
use pnet::packet::icmpv6::ndp::NdpOptionTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::MutableIpv6Packet;
use std::net::Ipv6Addr;
use std::panic::Location;
use std::sync::Arc;
use subnetwork::Ipv6AddrExt;

use crate::error::PistolError;
use crate::layer::ICMPV6_NS_HEADER_SIZE;
use crate::layer::IPV6_HEADER_SIZE;
use crate::layer::Layer3Filter;
use crate::layer::Layer4FilterIcmpv6;
use crate::layer::PacketFilter;

pub fn build_ndp_ns_scan_packet(
    dst_ipv6: Ipv6Addr,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
) -> Result<(Arc<[u8]>, Vec<Arc<PacketFilter>>), PistolError> {
    let dst_ipv6_ext: Ipv6AddrExt = dst_ipv6.into();
    let dst_link_multicast_ipv6 = dst_ipv6_ext.link_multicast();

    // same as arp in ipv4, but use icmpv6 neighbor solicitation
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + ICMPV6_NS_HEADER_SIZE];
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
    ipv6_header.set_payload_length(ICMPV6_NS_HEADER_SIZE as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Icmpv6);
    ipv6_header.set_hop_limit(255);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_link_multicast_ipv6);

    // icmpv6
    let mut icmpv6_header =
        match MutableNeighborSolicitPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
            Some(p) => p,
            None => {
                return Err(PistolError::BuildPacketError {
                    location: Location::caller().to_string(),
                });
            }
        };
    // Neighbor Solicitation
    icmpv6_header.set_icmpv6_type(Icmpv6Type(135));
    icmpv6_header.set_icmpv6_code(Icmpv6Code(0));
    icmpv6_header.set_reserved(0);
    icmpv6_header.set_target_addr(dst_ipv6);
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
    let checksum = icmpv6::checksum(
        &icmpv6_header.to_immutable(),
        &src_ipv6,
        &dst_link_multicast_ipv6,
    );
    icmpv6_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: String::from("ndp_ns scan layer3"),
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_icmpv6 = Layer4FilterIcmpv6 {
        name: String::from("ndp_ns scan icmpv6"),
        layer3: Some(layer3),
        icmpv6_type: Some(Icmpv6Types::NeighborAdvert),
        icmpv6_code: None,
        payload: None,
    };
    let filter = Arc::new(PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6.clone()));

    let ipv6_buff = Arc::new(ipv6_buff);
    Ok((ipv6_buff, vec![filter]))
}
