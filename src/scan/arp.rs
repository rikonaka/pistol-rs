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
use std::time::Duration;
use std::time::Instant;
use tracing::debug;

use crate::ask_runner;
use crate::error::PistolError;
use crate::layer::ARP_HEADER_SIZE;
use crate::layer::Layer2;
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
) -> Result<(Option<MacAddr>, Duration), PistolError> {
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
        name: "arp scan layer2",
        src_mac: None,
        dst_mac: Some(src_mac),
        ether_type: Some(ether_type),
    };
    let layer3 = Layer3Filter {
        name: "arp scan layer3",
        layer2: Some(layer2),
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let filters = vec![PacketFilter::Layer3Filter(layer3)];

    // send the filters to runner
    let receiver = ask_runner(iface, filters, timeout)?;
    let layer2 = Layer2::new(
        dst_mac,
        src_mac,
        interface.clone(),
        ether_type,
        timeout,
        true,
    );
    let start = Instant::now();
    layer2.send(&arp_buff)?;
    let eth_reponse = match receiver.recv_timeout(timeout) {
        Ok(b) => b,
        Err(e) => {
            debug!("{} recv arp response timeout: {}", dst_ipv4, e);
            Vec::new()
        }
    };
    let rtt = start.elapsed();

    // debug!("{} get ret from internet", dst_ipv4);
    let mac = get_mac_from_arp_response(&eth_reponse);
    // debug!("{}: {:?}", dst_ipv4, mac);
    Ok((mac, rtt))
}
