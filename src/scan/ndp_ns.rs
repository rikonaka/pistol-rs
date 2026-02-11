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
use std::time::Instant;
use tracing::debug;

use crate::ask_runner;
use crate::error::PistolError;
use crate::layer::ICMPV6_NS_HEADER_SIZE;
use crate::layer::IPV6_HEADER_SIZE;
use crate::layer::Layer2;
use crate::layer::Layer3Filter;
use crate::layer::Layer4FilterIcmpv6;
use crate::layer::PacketFilter;

fn get_mac_from_ndp_ns(ethernet_packet: &[u8]) -> Option<MacAddr> {
    if ethernet_packet.len() == 0 {
        return None;
    }
    // return mac address from ndp
    let ethernet_packet = match EthernetPacket::new(ethernet_packet) {
        Some(p) => p,
        None => return None,
    };
    let ipv6_packet = match Ipv6Packet::new(ethernet_packet.payload()) {
        Some(p) => p,
        None => return None,
    };
    let icmpv6_packet = match NeighborAdvertPacket::new(ipv6_packet.payload()) {
        Some(p) => p,
        None => return None,
    };
    for o in icmpv6_packet.get_options() {
        let mac = MacAddr::new(
            o.data[0], o.data[1], o.data[2], o.data[3], o.data[4], o.data[5],
        );
        // println!("{:?}", mac);
        return Some(mac);
    }
    None
}

pub fn send_ndp_ns_scan_packet(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    // same as arp in ipv4, but use icmpv6 neighbor solicitation
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + ICMPV6_NS_HEADER_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
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
    ipv6_header.set_destination(dst_ipv6);

    // icmpv6
    let mut icmpv6_header =
        match MutableNeighborSolicitPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
            Some(p) => p,
            None => {
                return Err(PistolError::BuildPacketError {
                    location: format!("{}", Location::caller()),
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
                location: format!("{}", Location::caller()),
            });
        }
    };
    let checksum = icmpv6::checksum(&icmpv6_header.to_immutable(), &src_ipv6, &dst_ipv6);
    icmpv6_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: "ndp_ns scan layer3".to_string(),
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_icmpv6 = Layer4FilterIcmpv6 {
        name: "ndp_ns scan icmpv6".to_string(),
        layer3: Some(layer3),
        icmpv6_type: Some(Icmpv6Types::NeighborAdvert),
        icmpv6_code: None,
        payload: None,
    };
    let filters = vec![PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6.clone())];

    let iface = interface.name.clone();
    let receiver = ask_runner(iface, filters, timeout)?;
    let ether_type = EtherTypes::Ipv6;
    let layer2 = Layer2::new(dst_mac, src_mac, interface, ether_type, timeout);
    let start = Instant::now();
    layer2.send(&ipv6_buff)?;
    let eth_response = match receiver.recv_timeout(timeout) {
        Ok(b) => b,
        Err(e) => {
            debug!("{} recv ndp_ns response timeout: {}", dst_ipv6, e);
            Vec::new()
        }
    };
    let rtt = start.elapsed();

    let mac = get_mac_from_ndp_ns(&eth_response);
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
