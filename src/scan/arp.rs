use pnet::datalink::MacAddr;
use pnet::packet::arp::ArpHardwareTypes;
use pnet::packet::arp::ArpOperations;
use pnet::packet::arp::MutableArpPacket;
use pnet::packet::ethernet::EtherTypes;
use std::net::Ipv4Addr;
use std::panic::Location;
use std::sync::Arc;

use crate::error::PistolError;
use crate::layer::ARP_HEADER_SIZE;
use crate::layer::Layer2Filter;
use crate::layer::Layer3Filter;
use crate::layer::PacketFilter;

pub fn build_arp_scan_packet(
    dst_ipv4: Ipv4Addr,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
) -> Result<(Arc<[u8]>, Vec<Arc<PacketFilter>>), PistolError> {
    let mut arp_buff = [0u8; ARP_HEADER_SIZE];
    let mut arp_packet = match MutableArpPacket::new(&mut arp_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: Location::caller().to_string(),
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
    let filter = Arc::new(PacketFilter::Layer3Filter(layer3));
    let arp_buff = Arc::new(arp_buff);
    Ok((arp_buff, vec![filter]))
}
