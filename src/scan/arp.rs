use pnet::datalink::{Channel, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::{MutablePacket, Packet};
use std::net::Ipv4Addr;

const ARP_SCAN_MAX_WAIT_TIME: usize = 32;

pub fn send_arp_scan_packet(
    interface: &NetworkInterface,
    dstaddr: &MacAddr,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> Option<MacAddr> {
    let (mut sender, mut receiver) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unknown channel type"),
        Err(e) => panic!("error happened {}", e),
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(*dstaddr);
    // ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    // ignore the send unexpect error
    match sender.send_to(ethernet_packet.packet(), None) {
        Some(_) => (),
        _ => (),
    }

    for _ in 0..ARP_SCAN_MAX_WAIT_TIME {
        let buf = receiver.next().unwrap();
        let arp = ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..]).unwrap();
        if arp.get_sender_proto_addr() == target_ip && arp.get_target_hw_addr() == source_mac {
            return Some(arp.get_sender_hw_addr());
        }
    }
    None
}
