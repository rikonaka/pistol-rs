use anyhow::Result;
use pnet::datalink::{MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::EtherTypes;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::layers::{get_mac_from_arp, layer2_send, Layer2Match, Layer3Match, LayersMatch};

pub fn send_arp_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_mac: MacAddr,
    interface: NetworkInterface,
    timeout: Duration,
) -> Result<(Option<MacAddr>, Option<Duration>)> {
    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(src_mac);
    arp_packet.set_sender_proto_addr(src_ipv4);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(dst_ipv4);

    let ethernet_type = EtherTypes::Arp;
    let layer2 = Layer2Match {
        src_mac: None,
        dst_mac: Some(src_mac),
        ethernet_type: Some(ethernet_type),
    };
    let layer3 = Layer3Match {
        layer2: Some(layer2),
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layers_match = LayersMatch::Layer3Match(layer3);
    match layer2_send(
        dst_mac,
        interface,
        &arp_buffer,
        ethernet_type,
        vec![layers_match],
        timeout,
    )? {
        (Some(r), Some(rtt)) => Ok((get_mac_from_arp(&r), Some(rtt))),
        (_, _) => Ok((None, None)),
    }
}
