use crossbeam::channel::Receiver;
use pnet::datalink::MacAddr;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
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
use std::time::Duration;
use std::time::Instant;

use crate::GLOBAL_NET_CACHES;
use crate::ask_runner;
use crate::error::PistolError;
use crate::get_response;
use crate::layer::ICMPV6_RA_HEADER_SIZE;
use crate::layer::IPV6_HEADER_SIZE;
use crate::layer::Layer3Filter;
use crate::layer::Layer4FilterIcmpv6;
use crate::layer::PacketFilter;
use crate::layer::PayloadMatch;
use crate::layer::PayloadMatchIcmpv6;
use crate::layer::PayloadMatchIp;
use crate::layer::find_interface_by_src_ip;

fn get_mac_from_ndp_rs(buff: &[u8]) -> Option<MacAddr> {
    // return mac address from ndp
    match EthernetPacket::new(buff) {
        Some(ethernet_packet) => {
            let mac = ethernet_packet.get_source();
            Some(mac)
        }
        None => None,
    }
}

pub(crate) fn send_ndp_ra_scan_packet(
    src_ipv6: Ipv6Addr,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
    // router solicitation
    let route_addr_ipv6 = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x0002);
    // let route_addr_1 = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x0001);
    let interface = match find_interface_by_src_ip(src_ipv6.into()) {
        Some(i) => i,
        None => {
            return Err(PistolError::CanNotFoundInterface {
                i: format!("ipv6 src iface({})", src_ipv6),
            });
        }
    };
    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(PistolError::CanNotFoundDstMacAddress),
    };

    // ipv6
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + ICMPV6_RA_HEADER_SIZE];
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
                    location: format!("{}", Location::caller()),
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
                location: format!("{}", Location::caller()),
            });
        }
    };
    let checksum = icmpv6::checksum(&icmpv6_header.to_immutable(), &src_ipv6, &route_addr_ipv6);
    icmpv6_header.set_checksum(checksum);

    let layer3 = Layer3Filter {
        name: "ndp_ns layer3".to_string().to_string(),
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
        name: "ndp_ns icmpv6".to_string().to_string(),
        layer3: Some(layer3),
        icmpv6_type: Some(Icmpv6Types::RouterAdvert), // Type: Router Advertisement (134)
        icmpv6_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6);

    let dst_mac = MacAddr(33, 33, 00, 00, 00, 02);
    let ether_type = EtherTypes::Ipv6;

    let iface = interface.name;
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &ipv6_buff,
        ether_type,
        vec![filter_1],
        timeout,
        0,
    )?;
    Ok(receiver)
}

pub(crate) fn recv_ndp_rs_scan_response(
    dst_ipv6: Ipv6Addr,
    start: Instant,
    timeout: Duration,
    receiver: Receiver<(Arc<[u8]>, Duration)>,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    let (eth_response, rtt) = get_response(receiver, start, timeout);
    let mac = if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        let eth_payload = eth_packet.payload();
        let mac = get_mac_from_ndp_rs(eth_payload);
        mac
    } else {
        None
    };
    match mac {
        Some(mac) => {
            let mut gncs = GLOBAL_NET_CACHES
                .lock()
                .map_err(|e| PistolError::LockGlobalVarFailed { e: e.to_string() })?;
            gncs.system_network_cache
                .update_neighbor_cache(dst_ipv6.into(), mac, Some(rtt));
        }
        None => {
            // this case may happen when the target host is down or the arp response packet is lost,
            // we just set the mac to 00:00:00:00:00:00 to indicate the host is down.
            let mut gncs = GLOBAL_NET_CACHES
                .lock()
                .map_err(|e| PistolError::LockGlobalVarFailed { e: e.to_string() })?;
            gncs.system_network_cache.update_neighbor_cache(
                dst_ipv6.into(),
                MacAddr::zero(),
                Some(rtt),
            );
        }
    }

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
