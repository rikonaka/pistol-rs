use pnet::datalink::{channel, Channel, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::{MutablePacket, Packet};
use std::net::Ipv4Addr;

pub fn send_arp_scan_packet(
    interface: &NetworkInterface,
    dstaddr: &MacAddr,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
    target_ip: Ipv4Addr,
    max_loop: usize,
) -> Option<MacAddr> {
    let (mut sender, mut receiver) = match channel(&interface, Default::default()) {
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

    for _ in 0..max_loop {
        let buf = receiver.next().unwrap();
        let arp = ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..]).unwrap();
        if arp.get_sender_proto_addr() == target_ip && arp.get_target_hw_addr() == source_mac {
            return Some(arp.get_sender_hw_addr());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_send_arp_scan_packet() {
        use crate::utils;
        let interface: NetworkInterface = utils::find_interface_by_name("ens33").unwrap();
        let dstaddr: MacAddr = MacAddr::broadcast();
        let source_ip: Ipv4Addr = Ipv4Addr::new(192, 168,213, 129);
        let source_mac: MacAddr = interface.mac.unwrap();
        let target_ip: Ipv4Addr = Ipv4Addr::new(192, 168,213, 128);
        let ret = send_arp_scan_packet(&interface, &dstaddr, source_ip, source_mac, target_ip, 32)
            .unwrap();
        println!("{:?}", ret);
    }
}
