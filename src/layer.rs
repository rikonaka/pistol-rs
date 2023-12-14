use anyhow::Result;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::EtherType;
use pnet::datalink::{DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::{Ipv4, Ipv6};
use pnet::transport::{transport_channel, TransportReceiver, TransportSender};
use pnet_packet::ethernet::EthernetPacket;
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use subnetwork;
use subnetwork::{Ipv4Pool, Ipv6Pool};
use threadpool::ThreadPool;

use crate::errors::{CanNotFoundInterface, CanNotFoundMacAddress, CreateDatalinkChannelFailed};

pub const ETHERNET_HEADER_SIZE: usize = 18;
pub const IPV4_HEADER_SIZE: usize = 20;
pub const IPV6_HEADER_SIZE: usize = 40;
pub const TCP_HADER_SIZE: usize = 20;
pub const UDP_HEADER_SIZE: usize = 20;
// big enough to store all data
const ETHERNET_BUFF_SIZE: usize = 1024;

fn datalink_channel(
    interface: &NetworkInterface,
) -> Result<Option<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)>> {
    match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => Ok(Some((tx, rx))),
        Ok(_) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn datalink_layer_ipv4(
    dst_mac: MacAddr,
    interface: NetworkInterface,
    payload: &[u8],
    max_loop: usize,
) -> Result<Option<Vec<u8>>> {
    let (mut sender, mut receiver) = match datalink_channel(&interface)? {
        Some((s, r)) => (s, r),
        None => return Err(CreateDatalinkChannelFailed::new().into()),
    };

    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(CanNotFoundMacAddress::new().into()),
    };

    let mut ethernet_buffer = [0u8; ETHERNET_BUFF_SIZE];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(dst_mac);
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);
    ethernet_packet.set_payload(payload);

    match sender.send_to(&ethernet_buffer, Some(interface)) {
        _ => (),
    }

    for _ in 0..max_loop {
        let buf = receiver.next()?;
        match EthernetPacket::new(&buf[..EthernetPacket::minimum_packet_size()]) {
            Some(r) => {
                if r.get_destination() == src_mac && r.get_source() == dst_mac {
                    let layer_3_payload = buf[EthernetPacket::minimum_packet_size()..].to_vec();
                    return Ok(Some(layer_3_payload));
                }
            }
            _ => (),
        }
    }
    Ok(None)
}

fn datalink_layer_ipv6(
    dst_mac: MacAddr,
    interface: NetworkInterface,
    payload: &[u8],
    max_loop: usize,
) -> Result<Option<Vec<u8>>> {
    let (mut sender, mut receiver) = match datalink_channel(&interface)? {
        Some((s, r)) => (s, r),
        None => return Err(CreateDatalinkChannelFailed::new().into()),
    };

    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(CanNotFoundMacAddress::new().into()),
    };

    let mut ethernet_buffer = [0u8; ETHERNET_BUFF_SIZE];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(dst_mac);
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(EtherTypes::Ipv6);
    ethernet_packet.set_payload(payload);

    match sender.send_to(&ethernet_buffer, Some(interface)) {
        _ => (),
    }

    for _ in 0..max_loop {
        let buf = receiver.next()?;
        match EthernetPacket::new(&buf[..EthernetPacket::minimum_packet_size()]) {
            Some(r) => {
                if r.get_destination() == src_mac && r.get_source() == dst_mac {
                    let layer_3_payload = buf[EthernetPacket::minimum_packet_size()..].to_vec();
                    return Ok(Some(layer_3_payload));
                }
            }
            _ => (),
        }
    }
    Ok(None)
}

fn find_interface(src_ipv4: Ipv4Addr) -> Option<NetworkInterface> {
    for interface in datalink::interfaces() {
        for ip in &interface.ips {
            match ip.ip() {
                IpAddr::V4(ipv4) => {
                    if ipv4 == src_ipv4 {
                        return Some(interface);
                    }
                }
                _ => (),
            }
        }
    }
    None
}

fn arp(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    max_loop: usize,
) -> Result<Option<(MacAddr, NetworkInterface)>> {
    let interface = match find_interface(src_ipv4) {
        Some(i) => i,
        None => return Err(CanNotFoundInterface::new().into()),
    };

    let (mut sender, mut receiver) = match datalink_channel(&interface)? {
        Some((s, r)) => (s, r),
        None => return Err(CreateDatalinkChannelFailed::new().into()),
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(CanNotFoundMacAddress::new().into()),
    };

    ethernet_packet.set_destination(MacAddr::broadcast());
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

    ethernet_packet.set_payload(&arp_buffer);

    // ignore the send unexpect error
    match sender.send_to(ethernet_packet.packet(), None) {
        _ => (),
    }

    for _ in 0..max_loop {
        let buf = receiver.next().unwrap();
        let re = EthernetPacket::new(buf).unwrap();
        let arp = ArpPacket::new(re.payload()).unwrap();
        if arp.get_sender_proto_addr() == dst_ipv4 && arp.get_target_hw_addr() == src_mac {
            return Ok(Some((arp.get_sender_hw_addr(), interface)));
        }
    }
    Ok(None)
}

pub fn send_ipv4_packet(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    payload: &[u8],
    max_loop: usize,
) -> Result<Option<Vec<u8>>> {
    match arp(src_ipv4, dst_ipv4, max_loop).unwrap() {
        Some((dst_mac, interface)) => {
            let ret = datalink_layer_ipv4(dst_mac, interface, payload, max_loop)?;
            Ok(ret)
        }
        None => Ok(None),
    }
}

pub fn send_ipv6_packet(src_ipv6: Ipv6Addr, dst_ipv6: Ipv6Addr, payload: &[u8], max_loop: usize) {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_send_arp_scan_packet() {
        let dst_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 72, 1);
        let src_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 72, 128);
        let max_loop = 32;
        match arp(src_ipv4, dst_ipv4, max_loop).unwrap() {
            Some((m, i)) => {
                println!("{}", m);
            }
            None => println!("None"),
        }
    }
}
