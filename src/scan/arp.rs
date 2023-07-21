use pnet::datalink::{Channel, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::{MutablePacket, Packet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use subnetwork::Ipv4Pool;

use crate::utils::{find_interface_by_subnet, get_interface_ip};

#[derive(Debug)]
pub struct HostInfo {
    pub host_ip: Ipv4Addr,
    pub host_mac: MacAddr,
}

#[derive(Debug)]
pub struct ArpScanResults {
    pub alive_hosts: usize,
    pub alive_hosts_info: Vec<HostInfo>,
}

fn send_arp_scan_packet(
    interface: &NetworkInterface,
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

    ethernet_packet.set_destination(MacAddr::broadcast());
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

    let buf = receiver.next().unwrap();
    let arp = ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..]).unwrap();
    if arp.get_sender_proto_addr() == target_ip && arp.get_target_hw_addr() == source_mac {
        return Some(arp.get_sender_hw_addr());
    }
    None
}

pub async fn run_arp_scan(subnet: &mut Ipv4Pool) -> Option<ArpScanResults> {
    match find_interface_by_subnet(subnet) {
        Some(interface) => match get_interface_ip(&interface) {
            Some(source_ip) => {
                let source_mac = interface.mac.unwrap();
                let interface = Arc::new(interface);
                let alive_hosts = Arc::new(Mutex::new(0));
                let alive_hosts_info = Arc::new(Mutex::new(Vec::new()));
                let mut handles = Vec::new();
                for target_ip in subnet {
                    let interface_clone = interface.clone();
                    let alive_hosts_clone = alive_hosts.clone();
                    let alive_hosts_info_clone = alive_hosts_info.clone();
                    handles.push(tokio::spawn(async move {
                        // println!("hi {}", i);
                        // tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                        match send_arp_scan_packet(
                            &interface_clone,
                            source_ip,
                            source_mac,
                            target_ip,
                        ) {
                            Some(target_mac) => {
                                // println!("alive host {}, mac {}", &target_ip, &target_mac);
                                let host_info = HostInfo {
                                    host_ip: target_ip,
                                    host_mac: target_mac,
                                };
                                *alive_hosts_clone.lock().unwrap() += 1;
                                alive_hosts_info_clone.lock().unwrap().push(host_info);
                            }
                            _ => (),
                        }
                        // println!("bye {}", i);
                    }));
                }
                for h in handles {
                    h.await.unwrap();
                }
                let a = Arc::try_unwrap(alive_hosts).unwrap().into_inner().unwrap();
                let b = Arc::try_unwrap(alive_hosts_info)
                    .unwrap()
                    .into_inner()
                    .unwrap();
                Some(ArpScanResults {
                    alive_hosts: a,
                    alive_hosts_info: b,
                })
            }
            _ => {
                eprintln!("can not find avaliable ip by interface {}", interface.name);
                None
            }
        },
        _ => {
            eprintln!("can not find interface by subnet {}", subnet);
            None
        }
    }
}
