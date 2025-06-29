use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmpv6;
use pnet::packet::icmpv6::Icmpv6Code;
use pnet::packet::icmpv6::Icmpv6Type;
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::packet::icmpv6::ndp::MutableNeighborSolicitPacket;
use pnet::packet::icmpv6::ndp::NdpOption;
use pnet::packet::icmpv6::ndp::NdpOptionTypes;
use pnet::packet::icmpv6::ndp::NeighborAdvertPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use std::net::Ipv6Addr;
use std::panic::Location;
use std::time::Duration;
use subnetwork::Ipv6AddrExt;

use crate::error::PistolError;
use crate::layers::ICMPV6_NS_HEADER_SIZE;
use crate::layers::IPV6_HEADER_SIZE;
use crate::layers::Layer3Match;
use crate::layers::Layer4MatchIcmpv6;
use crate::layers::LayerMatch;
use crate::layers::layer2_work;
use crate::layers::multicast_mac;

fn get_mac_from_ndp_ns(buff: &[u8]) -> Result<Option<MacAddr>, PistolError> {
    // return mac address from ndp
    let ethernet_packet = match EthernetPacket::new(buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
            });
        }
    };
    let ipv6_packet = match Ipv6Packet::new(ethernet_packet.payload()) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
            });
        }
    };
    let icmpv6_packet = match NeighborAdvertPacket::new(ipv6_packet.payload()) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
            });
        }
    };
    for o in icmpv6_packet.get_options() {
        let mac = MacAddr::new(
            o.data[0], o.data[1], o.data[2], o.data[3], o.data[4], o.data[5],
        );
        // println!("{:?}", mac);
        return Ok(Some(mac));
    }
    Ok(None)
}

pub fn send_ndp_ns_scan_packet(
    dst_ipv6: Ipv6Addr,
    src_ipv6: Ipv6Addr,
    src_mac: MacAddr,
    interface: NetworkInterface,
    timeout: Option<Duration>,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    // same as arp in ipv4
    // ipv6
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + ICMPV6_NS_HEADER_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
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
    let ipv6_ext: Ipv6AddrExt = dst_ipv6.into();
    let dst_multicast = ipv6_ext.link_multicast();
    ipv6_header.set_destination(dst_multicast);

    // icmpv6
    let mut icmpv6_header =
        match MutableNeighborSolicitPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
            Some(p) => p,
            None => {
                return Err(PistolError::BuildPacketError {
                    path: format!("{}", Location::caller()),
                });
            }
        };
    // Neighbor Solicitation
    icmpv6_header.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
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
                path: format!("{}", Location::caller()),
            });
        }
    };
    let checksum = icmpv6::checksum(&icmpv6_header.to_immutable(), &src_ipv6, &dst_multicast);
    icmpv6_header.set_checksum(checksum);

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        layer3: Some(layer3),
        icmpv6_type: Some(Icmpv6Type(136)),
        icmpv6_code: Some(Icmpv6Code(0)),
    };
    let layers_match = LayerMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    let ethernet_type = EtherTypes::Ipv6;
    let (r, rtt) = layer2_work(
        multicast_mac(dst_ipv6),
        interface.clone(),
        &ipv6_buff,
        IPV6_HEADER_SIZE + ICMPV6_NS_HEADER_SIZE,
        ethernet_type,
        vec![layers_match],
        timeout,
        true,
    )?;
    let mac = match layer4_icmpv6.do_match(&r) {
        true => get_mac_from_ndp_ns(&r)?,
        false => None,
    };
    Ok((mac, rtt))
}

#[cfg(feature = "scan")]
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_localtion() {
        let l = format!("{}", Location::caller());
        println!("{}", l);
    }
}
