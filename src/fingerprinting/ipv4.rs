use anyhow::Result;
use pnet::packet::icmp::{destination_unreachable, IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum, Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{
    ipv4_checksum, MutableTcpOptionPacket, MutableTcpPacket, TcpFlags, TcpPacket,
};
use pnet::packet::Packet;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::{icmp_packet_iter, ipv4_packet_iter, tcp_packet_iter};
use rand::Rng;
use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::TcpStream;
use std::time::Duration;

use crate::utils;
use crate::utils::ICMP_BUFF_SIZE;
use crate::utils::IP_TTL;
use crate::utils::TCP_BUFF_SIZE;

fn forge_packet_1(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Result<Vec<u8>> {
    const TCP_HEADER_LEN: usize = 60; // 20 + 40 (options)
    const TCP_OPTIONS_LEN: usize = 40;
    const TCP_DATA_LEN: usize = 0;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    let mut op_buff = [0u8; TCP_OPTIONS_LEN];
    let options = MutableTcpOptionPacket::new(&mut op_buff).unwrap();

    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);

    Ok(tcp_buff.to_vec())
}

pub fn sequence_generation() -> Result<()> {
    let tcp_protocol = Layer3(IpNextHeaderProtocols::Tcp);
    let (mut tcp_tx, mut tcp_rx) = match transport_channel(TCP_BUFF_SIZE, tcp_protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(e.into()),
    };
    let icmp_protocol = Layer3(IpNextHeaderProtocols::Icmp);
    let (_, mut icmp_rx) = match transport_channel(ICMP_BUFF_SIZE, icmp_protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(e.into()),
    };
    let mut tcp_iter = ipv4_packet_iter(&mut tcp_rx);
    let mut icmp_iter = ipv4_packet_iter(&mut icmp_rx);

    // 1. probe the zombie's ip id
    let ip_buff = _forge_syn_packet(src_ipv4, zombie_ipv4, src_port, zombie_port)?;
    let ip_packet = Ipv4Packet::new(&ip_buff).unwrap();
    match tcp_tx.send_to(ip_packet, zombie_ipv4.into()) {
        Ok(n) => assert_eq!(n, IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut zombie_ip_id_1 = 0;
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((packet, addr)) => {
                    if addr == zombie_ipv4 {
                        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                            if packet.get_destination() == src_ipv4 {
                                let ipv4_payload = packet.payload();
                                let tcp_packet = TcpPacket::new(ipv4_payload).unwrap();
                                println!(">>> {}", tcp_packet.get_flags());
                                if tcp_packet.get_source() == zombie_port
                                    && tcp_packet.get_destination() == src_port
                                {
                                    let tcp_flags = tcp_packet.get_flags();
                                    if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                        // 2. zombie return rst packet, get this packet ip id
                                        zombie_ip_id_1 = packet.get_identification();
                                        if zombie_ip_id_1 == 0 {
                                            return Err(IdleScanAllZeroError::new(
                                                zombie_ipv4,
                                                zombie_port,
                                            )
                                            .into());
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((packet, addr)) => {
                    if addr == dst_ipv4 {
                        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                            let ipv4_payload = packet.payload();
                            let icmp_packet = IcmpPacket::new(ipv4_payload).unwrap();
                            let icmp_type = icmp_packet.get_icmp_type();
                            let icmp_code = icmp_packet.get_icmp_code();
                            let codes = vec![
                                destination_unreachable::IcmpCodes::DestinationHostUnreachable, // 1
                                destination_unreachable::IcmpCodes::DestinationProtocolUnreachable, // 2
                                destination_unreachable::IcmpCodes::DestinationPortUnreachable, // 3
                                destination_unreachable::IcmpCodes::NetworkAdministrativelyProhibited, // 9
                                destination_unreachable::IcmpCodes::HostAdministrativelyProhibited, // 10
                                destination_unreachable::IcmpCodes::CommunicationAdministrativelyProhibited, // 13
                            ];
                            if icmp_type == IcmpTypes::DestinationUnreachable
                                && codes.contains(&icmp_code)
                            {
                                // dst is unreachable ignore this port
                                return Ok((TcpScanStatus::Unreachable, None));
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
