use pnet::datalink::{Channel, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::{MutablePacket, Packet};
use std::net::Ipv4Addr;
use std::sync::mpsc::channel;
use subnetwork::Ipv4Pool;

use crate::utils::{self, find_interface_by_subnet, get_interface_ip};

const ARP_SCAN_MAX_WAIT_TIME: usize = 32;

#[derive(Debug)]
pub struct HostInfo {
    pub host_ip: Ipv4Addr,
    pub host_mac: Option<MacAddr>,
}

#[derive(Debug)]
pub struct ArpScanResults {
    pub alive_hosts_num: usize,
    pub alive_hosts_vec: Vec<HostInfo>,
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

    for _ in 0..ARP_SCAN_MAX_WAIT_TIME {
        let buf = receiver.next().unwrap();
        let arp = ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..]).unwrap();
        if arp.get_sender_proto_addr() == target_ip && arp.get_target_hw_addr() == source_mac {
            return Some(arp.get_sender_hw_addr());
        }
    }
    None
}

pub fn run_arp_scan(
    subnet: Ipv4Pool,
    threads_num: usize,
    print_result: bool,
) -> Option<ArpScanResults> {
    match find_interface_by_subnet(&subnet) {
        Some(interface) => match get_interface_ip(&interface) {
            Some(source_ip) => {
                let source_mac = interface.mac.unwrap();
                let (tx, rx) = channel();
                let pool = utils::auto_threads_pool(threads_num);

                for target_ip in subnet {
                    let tx = tx.clone();
                    let interface = interface.clone();
                    pool.execute(move || {
                        match send_arp_scan_packet(&interface, source_ip, source_mac, target_ip) {
                            Some(target_mac) => {
                                // println!("alive host {}, mac {}", &target_ip, &target_mac);
                                let host_info = HostInfo {
                                    host_ip: target_ip,
                                    host_mac: Some(target_mac),
                                };
                                if print_result {
                                    println!("{} => {}", target_ip, target_mac);
                                }
                                tx.send(host_info)
                                    .expect("channel will be there waiting for the pool");
                            }
                            _ => {
                                let host_info = HostInfo {
                                    host_ip: target_ip,
                                    host_mac: None,
                                };
                                tx.send(host_info)
                                    .expect("channel will be there waiting for the pool");
                            }
                        }
                    });
                }
                let iter = rx.into_iter().take(subnet.len());
                let mut alive_hosts_info = Vec::new();
                let mut alive_hosts = 0;
                for host_info in iter {
                    if host_info.host_mac.is_some() {
                        alive_hosts_info.push(host_info);
                        alive_hosts += 1;
                    }
                }
                Some(ArpScanResults {
                    alive_hosts_num: alive_hosts,
                    alive_hosts_vec: alive_hosts_info,
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
