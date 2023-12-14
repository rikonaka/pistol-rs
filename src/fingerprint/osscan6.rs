use anyhow::Result;
use chrono::{DateTime, Local, Utc};
use pnet::datalink::MacAddr;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use rand::Rng;
use std::fmt;
use std::net::Ipv6Addr;
use std::sync::mpsc::channel;
use std::thread::sleep;
use std::time::Duration;

use crate::utils::find_mac_by_src_ip;
use crate::utils::get_threads_pool;
use crate::utils::random_port;
use crate::utils::random_port_multi;
use crate::utils::return_layer3_icmp6_channel;
use crate::utils::return_layer3_icmp_channel;
use crate::utils::return_layer3_tcp_channel;
use crate::utils::return_layer3_udp_channel;
use crate::utils::return_layer4_tcp_channel;
use crate::utils::ICMP_BUFF_SIZE;
use crate::utils::TCP_BUFF_SIZE;
use crate::utils::UDP_BUFF_SIZE;

use super::packet6;

// Each request corresponds to a response, all layer3 packet
#[derive(Debug, Clone)]
pub struct RequestAndResponse {
    pub name: String,
    pub request: Vec<u8>,  // layer3
    pub response: Vec<u8>, // layer3, if no response: response.len() == 0
}

#[derive(Debug, Clone)]
pub struct SEQRR {
    pub seq1: RequestAndResponse,
    pub seq2: RequestAndResponse,
    pub seq3: RequestAndResponse,
    pub seq4: RequestAndResponse,
    pub seq5: RequestAndResponse,
    pub seq6: RequestAndResponse,
}

#[derive(Debug, Clone)]
pub struct IERR {
    pub ie1: RequestAndResponse,
    pub ie2: RequestAndResponse,
}

#[derive(Debug, Clone)]
pub struct NXRR {
    pub ni: RequestAndResponse,
    pub ns: RequestAndResponse,
}

#[derive(Debug, Clone)]
pub struct TECNRR {
    pub ecn: RequestAndResponse,
}

#[derive(Debug, Clone)]
pub struct T2T7RR {
    pub t2: RequestAndResponse,
    pub t3: RequestAndResponse,
    pub t4: RequestAndResponse,
    pub t5: RequestAndResponse,
    pub t6: RequestAndResponse,
    pub t7: RequestAndResponse,
}

#[derive(Debug, Clone)]
pub struct U1RR {
    pub u1: RequestAndResponse,
}

// HashMap<Name, RR>
#[derive(Debug, Clone)]
pub struct AllPacketRR {
    pub seq: SEQRR,
    pub ie: IERR,
    pub ecn: TECNRR,
    pub t2t7: T2T7RR,
    pub u1: U1RR,
}

fn send_icmpv6_test_probes(
    src_ipv6: Ipv6Addr,
    src_port: Option<u16>,
    dst_ipv6: Ipv6Addr,
    max_loop: usize,
    read_timeout: Duration,
) {
    let buff = packet6::icmpv6_test_packet_layer3(src_ipv6, dst_ipv6).unwrap();
    println!("LEN {}", buff.len());

    let (mut tcp_tx, mut tcp_rx) = return_layer3_icmp6_channel(TCP_BUFF_SIZE).unwrap();
    let request_ipv6_packet = Ipv6Packet::new(&buff).unwrap();
    println!("flow label {:X}", request_ipv6_packet.get_flow_label());
    match tcp_tx.send_to(&request_ipv6_packet, dst_ipv6.into()) {
        Ok(n) => {
            println!("yyyyyyyyyyy");
            if n == buff.len() {
                println!("OKOKOK");
            }
        }
        Err(e) => (),
    }

    println!("zzzzzzzzzzzzzzz");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test() {
        let src_ipv6 = Ipv6Addr::new(
            0xfe80, 0xfe80, 0xfe80, 0xfe80, 0x20c, 0x29ff, 0xfe43, 0x9c82,
        );
        // fe80::fa1d:58e:7449:e54b
        // let dst_ipv6 = Ipv6Addr::new(
        //     0xfe80, 0xfe80, 0xfe80, 0xfe80, 0xfa1d, 0x58e, 0x7449, 0xe54b,
        // );
        let dst_ipv6 = "fe80::47c:7f4a:10a8:7f4a".parse().unwrap();
        // let dst_ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let src_port = None;
        let dst_open_port = 22;
        let max_loop = 32;
        let read_timeout = Duration::from_secs_f32(3.0);
        send_icmpv6_test_probes(src_ipv6, src_port, dst_ipv6, max_loop, read_timeout);
    }
}
