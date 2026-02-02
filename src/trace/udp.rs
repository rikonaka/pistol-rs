use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmp::IcmpCode;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::Ipv4Flags;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::udp::ipv4_checksum;
use std::net::Ipv4Addr;
use std::panic::Location;
use std::time::Duration;
use std::time::Instant;
use tracing::debug;

use crate::ask_runner;
use crate::error::PistolError;
use crate::layer::IPV4_HEADER_SIZE;
use crate::layer::Layer2;
use crate::layer::Layer3Filter;
use crate::layer::Layer4FilterIcmp;
use crate::layer::Layer4FilterTcpUdp;
use crate::layer::PacketFilter;
use crate::layer::PayloadMatch;
use crate::layer::PayloadMatchIp;
use crate::layer::PayloadMatchTcpUdp;
use crate::layer::UDP_HEADER_SIZE;
use crate::trace::HopStatus;

const UDP_DATA_SIZE: usize = 32;

pub fn send_udp_trace_packet(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    interface: &NetworkInterface,
    ip_id: u16,
    ttl: u8,
    timeout: Duration,
) -> Result<(HopStatus, Duration), PistolError> {
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE];
    let mut ip_header = match MutableIpv4Packet::new(&mut ip_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE) as u16);
    ip_header.set_identification(ip_id);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(ttl);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // udp header
    let mut udp_header = match MutableUdpPacket::new(&mut ip_buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    udp_header.set_source(src_port);
    udp_header.set_destination(dst_port);
    udp_header.set_length((UDP_HEADER_SIZE + UDP_DATA_SIZE) as u16);
    let udp_payload = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_";
    assert_eq!(udp_payload.len(), UDP_DATA_SIZE);
    udp_header.set_payload(&udp_payload.as_bytes());
    let checksum = ipv4_checksum(&udp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    udp_header.set_checksum(checksum);

    // generally speaking, the target random UDP port will not return any data.
    let layer3 = Layer3Filter {
        name: "udp trace reply layer3 1",
        layer2: None,
        src_addr: None, // usually this is the address of the router, not the address of the target machine.
        dst_addr: Some(src_ipv4.into()),
    };
    // set the icmp payload matchs
    let payload_ip = PayloadMatchIp {
        src_addr: Some(src_ipv4.into()),
        dst_addr: Some(dst_ipv4.into()),
    };
    let payload_tcp_udp = PayloadMatchTcpUdp {
        layer3: Some(payload_ip),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
    };
    let payload = PayloadMatch::PayloadMatchTcpUdp(payload_tcp_udp);
    let layer4_icmp = Layer4FilterIcmp {
        name: "udp trace icmp 1",
        layer3: Some(layer3),
        icmp_type: Some(IcmpTypes::TimeExceeded),
        icmp_code: None,
        payload: Some(payload),
    };
    let filter_1 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    // finally, the UDP packet arrives at the target machine.
    let layer3 = Layer3Filter {
        name: "udp trace layer3 2",
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_icmp = Layer4FilterIcmp {
        name: "udp trace icmp 2",
        layer3: Some(layer3),
        icmp_type: Some(IcmpTypes::DestinationUnreachable),
        icmp_code: Some(IcmpCode(3)),
        payload: None,
    };
    let filter_2 = PacketFilter::Layer4FilterIcmp(layer4_icmp);

    // there is a small chance that the target's UDP port will be open.
    let layer3 = Layer3Filter {
        name: "udp trace layer3 3",
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4 = Layer4FilterTcpUdp {
        name: "udp trace tcp_udp",
        layer3: Some(layer3),
        src_port: Some(dst_port),
        dst_port: Some(src_port),
    };
    let filter_3 = PacketFilter::Layer4FilterTcpUdp(layer4);

    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv4;
    let receiver = ask_runner(iface, vec![filter_1, filter_2, filter_3], timeout)?;
    let layer2 = Layer2::new(dst_mac, src_mac, interface, ether_type, timeout);
    let start = Instant::now();
    layer2.send(&ip_buff)?;
    let eth_buff = match receiver.recv_timeout(timeout) {
        Ok(b) => b,
        Err(e) => {
            debug!("{} recv udp trace response timeout: {}", dst_ipv4, e);
            Vec::new()
        }
    };
    let rtt = start.elapsed();

    if let Some(eth_packet) = EthernetPacket::new(&eth_buff) {
        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
            match ip_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Udp => {
                    // any udp response from target port (unusual)
                    let ret_ip = ip_packet.get_source();
                    return Ok((HopStatus::RecvReply(ret_ip.into()), rtt));
                }
                IpNextHeaderProtocols::Icmp => {
                    if let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) {
                        let icmp_type = icmp_packet.get_icmp_type();
                        let icmp_code = icmp_packet.get_icmp_code();
                        let ret_ip = ip_packet.get_source();
                        if icmp_type == IcmpTypes::TimeExceeded {
                            return Ok((HopStatus::TimeExceeded(ret_ip.into()), rtt));
                        } else if icmp_type == IcmpTypes::DestinationUnreachable {
                            if icmp_code == IcmpCode(3) {
                                // icmp type 3, code 3 (port unreachable)
                                return Ok((HopStatus::Unreachable(ret_ip.into()), rtt));
                            }
                        }
                    }
                }
                _ => (),
            }
        }
    }
    Ok((HopStatus::NoResponse, rtt))
}
