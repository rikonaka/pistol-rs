use crossbeam::channel::Receiver;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::packet::Packet;
use pnet::packet::arp::ArpHardwareTypes;
use pnet::packet::arp::ArpOperations;
use pnet::packet::arp::ArpPacket;
use pnet::packet::arp::MutableArpPacket;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use std::net::Ipv4Addr;
use std::panic::Location;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use crate::GLOBAL_NET_CACHES;
use crate::ask_runner;
use crate::error::PistolError;
use crate::get_response;
use crate::layer::ARP_HEADER_SIZE;
use crate::layer::Layer2Filter;
use crate::layer::Layer3Filter;
use crate::layer::PacketFilter;

fn get_mac_from_arp_response(ethernet_packet: &[u8]) -> Option<MacAddr> {
    if ethernet_packet.len() > 0 {
        match EthernetPacket::new(ethernet_packet) {
            Some(re) => match re.get_ethertype() {
                EtherTypes::Arp => match ArpPacket::new(re.payload()) {
                    Some(arp) => return Some(arp.get_sender_hw_addr()),
                    None => (),
                },
                _ => (),
            },
            None => (),
        }
    }
    None
}

pub fn send_arp_scan_packet(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<Receiver<(Arc<[u8]>, Duration)>, PistolError> {
    let iface = interface.name.clone();

    let mut arp_buff = [0u8; ARP_HEADER_SIZE];
    let mut arp_packet = match MutableArpPacket::new(&mut arp_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(src_mac);
    arp_packet.set_sender_proto_addr(src_ipv4);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(dst_ipv4);

    let ether_type = EtherTypes::Arp;
    let layer2 = Layer2Filter {
        name: String::from("arp scan layer2"),
        src_mac: None,
        dst_mac: Some(src_mac),
        ether_type: Some(ether_type),
    };
    let name = format!("arp scan layer3 {}", dst_ipv4);
    let layer3 = Layer3Filter {
        name,
        layer2: Some(layer2),
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let filter_1 = PacketFilter::Layer3Filter(layer3);

    // send the filters to runner
    let receiver = ask_runner(
        iface,
        dst_mac,
        src_mac,
        &arp_buff,
        ether_type,
        vec![filter_1],
        timeout,
        0,
    )?;
    Ok(receiver)
}

pub(crate) fn recv_arp_scan_response(
    dst_ipv4: Ipv4Addr,
    start: Instant,
    timeout: Duration,
    receiver: Receiver<(Arc<[u8]>, Duration)>,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    let (eth_response, rtt) = get_response(receiver, start, timeout);
    let mac = get_mac_from_arp_response(&eth_response);
    match mac {
        Some(mac) => {
            let mut gncs = GLOBAL_NET_CACHES
                .lock()
                .map_err(|e| PistolError::LockGlobalVarFailed { e: e.to_string() })?;
            gncs.system_network_cache
                .update_neighbor_cache(dst_ipv4.into(), mac, Some(rtt));
        }
        None => {
            // this case may happen when the target host is down or the arp response packet is lost,
            // we just set the mac to 00:00:00:00:00:00 to indicate the host is down.
            let mut gncs = GLOBAL_NET_CACHES
                .lock()
                .map_err(|e| PistolError::LockGlobalVarFailed { e: e.to_string() })?;
            gncs.system_network_cache.update_neighbor_cache(
                dst_ipv4.into(),
                MacAddr::zero(),
                Some(rtt),
            );
        }
    }

    Ok((mac, rtt))
}
