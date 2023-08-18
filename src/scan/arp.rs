use pnet::datalink::{channel, Channel, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::{MutablePacket, Packet};
use std::net::Ipv4Addr;

pub fn send_arp_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_mac: MacAddr,
    interface: NetworkInterface,
    max_loop: usize,
) -> Option<MacAddr> {
    let (mut sender, mut receiver) = match channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unknown channel type"),
        Err(e) => panic!("error happened {}", e),
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(dst_mac);
    // ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

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

    ethernet_packet.set_payload(arp_packet.packet_mut());

    // ignore the send unexpect error
    match sender.send_to(ethernet_packet.packet(), None) {
        Some(_) => (),
        _ => (),
    }

    for _ in 0..max_loop {
        let buf = receiver.next().unwrap();
        let arp = ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..]).unwrap();
        if arp.get_sender_proto_addr() == dst_ipv4 && arp.get_target_hw_addr() == src_mac {
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
        let dst_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 119);
        let dst_mac: MacAddr = MacAddr::broadcast();
        let src_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 206);
        let src_mac: MacAddr = interface.mac.unwrap();
        let max_loop = 32;
        let ret = send_arp_scan_packet(dst_ipv4, dst_mac, src_ipv4, src_mac, interface, max_loop)
            .unwrap();
        println!("{:?}", ret);
    }
}
