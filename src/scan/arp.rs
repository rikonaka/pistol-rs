use log::debug;
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

use crate::error::PistolError;
use crate::layers::ARP_HEADER_SIZE;
use crate::layers::Layer2Match;
use crate::layers::Layer3Match;
use crate::layers::LayersMatch;
use crate::layers::layer2_send;

fn get_mac_from_arp(ethernet_buff: &[u8]) -> Result<Option<MacAddr>, PistolError> {
    match EthernetPacket::new(ethernet_buff) {
        Some(re) => match re.get_ethertype() {
            EtherTypes::Arp => {
                let arp = match ArpPacket::new(re.payload()) {
                    Some(p) => p,
                    None => {
                        return Err(PistolError::BuildPacketError {
                            path: format!("{}", Location::caller()),
                        });
                    }
                };
                Ok(Some(arp.get_sender_hw_addr()))
            }
            _ => Ok(None),
        },
        None => Ok(None),
    }
}

pub fn send_arp_scan_packet(
    dst_ipv4: Ipv4Addr,
    dst_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_mac: MacAddr,
    interface: NetworkInterface,
    timeout: Option<Duration>,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    let mut arp_buffer = [0u8; ARP_HEADER_SIZE];
    let mut arp_packet = match MutableArpPacket::new(&mut arp_buffer) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
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

    let (ret, rtt) = layer2_send(
        dst_mac,
        interface,
        &arp_buffer,
        ARP_HEADER_SIZE,
        ethernet_type,
        vec![layers_match],
        timeout,
        true,
    )?;
    debug!("{} get ret from internet", dst_ipv4);
    let mac = get_mac_from_arp(&ret)?;
    debug!("{}: {:?}", dst_ipv4, mac);
    Ok((mac, rtt))
}
