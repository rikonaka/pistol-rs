use anyhow::Result;
use chrono::{DateTime, Local, Utc};
use crc32fast;
use gcdx::gcdx;
use pnet::datalink::MacAddr;
use pnet::packet::icmp;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::icmp::{destination_unreachable, IcmpCode, IcmpPacket, IcmpType, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpOptionPacket, MutableTcpPacket, TcpPacket};
use pnet::packet::tcp::{TcpFlags, TcpOption, TcpOptionNumbers};
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::{
    icmp_packet_iter, ipv4_packet_iter, tcp_packet_iter, Ipv4TransportChannelIterator,
};
use pnet::transport::{transport_channel, TransportReceiver};
use rand::Rng;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fmt::Display;
use std::iter::zip;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::TcpStream;
use std::ops::AddAssign;
use std::ops::Div;
use std::ops::Rem;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

use crate::utils::get_threads_pool;
use crate::utils::random_port;
use crate::utils::random_port_multi;
use crate::utils::return_layer3_icmp_channel;
use crate::utils::return_layer3_tcp_channel;
use crate::utils::return_layer3_udp_channel;
use crate::utils::ICMP_BUFF_SIZE;
use crate::utils::TCP_BUFF_SIZE;
use crate::utils::UDP_BUFF_SIZE;

use super::dbparser::{MixValue, NmapOsDb, NmapOsDbValueTypes, ECN, IE, OPS, SEQ, TX, U1, WIN};
use super::operator::{tcp_cc, tcp_o, tcp_t, tcp_tg, tcp_ti_ci_ii, tcp_ts, tcp_w, tcp_wx};
use super::operator::{tcp_df, tcp_gcd, tcp_isr, tcp_ox, tcp_q, tcp_r, tcp_sp, tcp_ss};
use super::packet;

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

impl SEQRR {
    pub fn response_num(&self) -> u32 {
        let mut seq_response_num = 0;
        if self.seq1.response.len() > 0 {
            seq_response_num += 1;
        }
        if self.seq2.response.len() > 0 {
            seq_response_num += 1;
        }
        if self.seq3.response.len() > 0 {
            seq_response_num += 1;
        }
        if self.seq4.response.len() > 0 {
            seq_response_num += 1;
        }
        if self.seq5.response.len() > 0 {
            seq_response_num += 1;
        }
        if self.seq6.response.len() > 0 {
            seq_response_num += 1;
        }
        seq_response_num
    }
}

#[derive(Debug, Clone)]
pub struct IERR {
    pub ie1: RequestAndResponse,
    pub ie2: RequestAndResponse,
}

#[derive(Debug, Clone)]
pub struct ECNRR {
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
pub struct AllRRPacket {
    pub seq: SEQRR,
    pub ie: IERR,
    pub ecn: ECNRR,
    pub t2t7: T2T7RR,
    pub u1: U1RR,
}

pub fn get_scan_line(
    dst_mac: Option<MacAddr>,
    dst_open_tcp_port: u16,
    dst_closed_tcp_port: u16,
    dst_closed_udp_port: u16,
    dst_ipv4: Ipv4Addr,
    htops: Option<u8>,
    good_results: bool,
) -> String {
    // Nmap version number (V).
    let v = "pistol";
    // Date of scan (D) in the form month/day.
    let now: DateTime<Local> = Local::now();
    let date = format!("{}", now.format("%-m/%-d"));
    // Private IP space (PV) is Y if the target is on the 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16 private networks (RFC 1918).
    // Otherwise it is N.
    // Network distance (DS) is the network hop distance from the target. It is 0 if the target is localhost, 1 if directly connected on an ethernet network, or the exact distance if discovered by Nmap.
    // If the distance is unknown, this test is omitted.
    // The distance calculation method (DC) indicates how the network distance (DS) was calculated.
    // It can take on these values:
    // L for localhost (DS=0);
    // D for a direct subnet connection (DS=1);
    // I for a TTL calculation based on an ICMP response to the U1 OS detection probe;
    // and T for a count of traceroute hops (I don't particularly understand how this sentence is implemented).
    // This test exists because it is possible for the ICMP TTL calculation to be incorrect when intermediate machines change the TTL;
    // it distinguishes between a host that is truly directly connected and what may be just a miscalculation.
    let (pv, ds, dc) = if dst_ipv4.is_loopback() {
        ("Y", 0, "L")
    } else if dst_ipv4.is_private() {
        ("Y", 1, "D")
    } else {
        ("N", htops.unwrap(), "I")
    };
    // Good results (G) is Y if conditions and results seem good enough to submit this fingerprint to Nmap.Org.
    // It is N otherwise. Unless you force them by enabling debugging (-d) or extreme verbosity (-vv), G=N fingerprints aren't printed by Nmap.
    let g = if good_results { "Y" } else { "N" };
    // Target MAC prefix (M) is the first six hex digits of the target MAC address, which correspond to the vendor name.
    // Leading zeros are not included. This field is omitted unless the target is on the same ethernet network (DS=1).
    let m = if ds == 1 {
        let mut dst_mac_vec: [u8; 6] = dst_mac.unwrap().octets();
        let mut dst_mac_str = String::from("");
        for m in &mut dst_mac_vec[0..3] {
            dst_mac_str = format!("{}{:X}", dst_mac_str, m);
        }
        dst_mac_str
    } else {
        "".to_string()
    };
    // The OS scan time (TM) is provided in Unix time_t format (in hexadecimal).
    let now: DateTime<Utc> = Utc::now();
    let tm = format!("{:X}", now.timestamp());
    // The platform Nmap was compiled for is given in the P field.
    let p = "rust";

    // SCAN(V=5.05BETA1%D=8/23%OT=22%CT=1%CU=42341%PV=N%DS=0%DC=L%G=Y%TM=4A91CB90%P=i686-pc-linux-gnu)
    let info_str = if m.len() > 0 {
        format!("SCAN(V={v}%D={date}%OT={dst_open_tcp_port}%CT={dst_closed_tcp_port}%CU={dst_closed_udp_port}PV={pv}%DS={ds}%DC={dc}%G={g}%M={m}%TM={tm}%P={p})", )
    } else {
        format!("SCAN(V={v}%D={date}%OT={dst_open_tcp_port}%CT={dst_closed_tcp_port}%CU={dst_closed_udp_port}PV={pv}%DS={ds}%DC={dc}%G={g}%TM={tm}%P={p})", )
    };
    info_str
}

fn send_seq_probes(
    src_ipv4: Ipv4Addr,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_open_port: u16,
    max_loop: usize,
    read_timeout: Duration,
) -> Result<SEQRR> {
    // 6 packets with 6 threads
    let pool = get_threads_pool(6);
    let (tx, rx) = channel();

    let src_ports = match src_port {
        Some(s) => vec![s; 6],
        None => random_port_multi(6),
    };

    let buff_1 = packet::seq_packet_1_layer3(src_ipv4, src_ports[0], dst_ipv4, dst_open_port)?;
    let buff_2 = packet::seq_packet_2_layer3(src_ipv4, src_ports[1], dst_ipv4, dst_open_port)?;
    let buff_3 = packet::seq_packet_3_layer3(src_ipv4, src_ports[2], dst_ipv4, dst_open_port)?;
    let buff_4 = packet::seq_packet_4_layer3(src_ipv4, src_ports[3], dst_ipv4, dst_open_port)?;
    let buff_5 = packet::seq_packet_5_layer3(src_ipv4, src_ports[4], dst_ipv4, dst_open_port)?;
    let buff_6 = packet::seq_packet_6_layer3(src_ipv4, src_ports[5], dst_ipv4, dst_open_port)?;

    let buffs = vec![buff_1, buff_2, buff_3, buff_4, buff_5, buff_6];
    let buffs_len = buffs.len();
    let mut id = 1;

    for buff in buffs {
        let tx = tx.clone();
        pool.execute(move || {
            let (mut tcp_tx, mut tcp_rx) = return_layer3_tcp_channel(TCP_BUFF_SIZE).unwrap();
            let request_ipv4_packet = Ipv4Packet::new(&buff).unwrap();
            match tcp_tx.send_to(&request_ipv4_packet, dst_ipv4.into()) {
                Ok(n) => {
                    if n == buff.len() {
                        let mut ipv4_iter = ipv4_packet_iter(&mut tcp_rx); // we need some ip header info
                        let mut recv_flag = false;
                        for _ in 0..max_loop {
                            match ipv4_iter.next_with_timeout(read_timeout) {
                                Ok(r) => match r {
                                    Some((response_ipv4_packet, addr)) => {
                                        if addr == dst_ipv4
                                            && response_ipv4_packet.get_next_level_protocol()
                                                == IpNextHeaderProtocols::Tcp
                                        {
                                            let request_tcp_packet =
                                                TcpPacket::new(request_ipv4_packet.payload())
                                                    .unwrap();
                                            let response_tcp_packet =
                                                TcpPacket::new(response_ipv4_packet.payload())
                                                    .unwrap();

                                            let src_port_1 = request_tcp_packet.get_source();
                                            let dst_port_1 = request_tcp_packet.get_destination();
                                            let src_port_2 = response_tcp_packet.get_source();
                                            let dst_port_2 = response_tcp_packet.get_destination();

                                            if src_port_1 == dst_port_2 && dst_port_1 == src_port_2
                                            {
                                                // println!(
                                                //     "id: {}, response seq: {}",
                                                //     id,
                                                //     response_tcp_packet.get_sequence()
                                                // );
                                                let msg = Ok((
                                                    id,
                                                    request_ipv4_packet.packet().to_vec(),
                                                    response_ipv4_packet.packet().to_vec(),
                                                ));
                                                match tx.send(msg) {
                                                    _ => (),
                                                }
                                                recv_flag = true;
                                            }
                                        }
                                    }
                                    _ => (), // do nothing
                                },
                                Err(_) => (),
                            }
                            if recv_flag {
                                break; // we have recv packet so just exit early
                            }
                        }
                        if !recv_flag {
                            // we did not recv any packet
                            let msg = Ok((id, request_ipv4_packet.packet().to_vec(), vec![]));
                            match tx.send(msg) {
                                _ => (),
                            }
                        }
                    }
                }
                Err(e) => match tx.send(Err(e)) {
                    _ => (),
                },
            }
        });
        // the probes are sent exactly 100 milliseconds apart so the total time taken is 500 ms
        sleep(Duration::from_millis(100));
        id += 1;
    }

    let mut seq1 = None;
    let mut seq2 = None;
    let mut seq3 = None;
    let mut seq4 = None;
    let mut seq5 = None;
    let mut seq6 = None;

    let iter = rx.into_iter().take(buffs_len);
    for value in iter {
        match value {
            Ok(tp) => {
                let name = format!("seq{}", tp.0);
                let request = tp.1;
                let response = tp.2;
                let rr = RequestAndResponse {
                    name: name.clone(),
                    request,
                    response,
                };
                match tp.0 {
                    1 => seq1 = Some(rr),
                    2 => seq2 = Some(rr),
                    3 => seq3 = Some(rr),
                    4 => seq4 = Some(rr),
                    5 => seq5 = Some(rr),
                    6 => seq6 = Some(rr),
                    _ => (),
                }
            }
            Err(e) => return Err(e.into()),
        }
    }

    let seqrr = SEQRR {
        seq1: seq1.unwrap(),
        seq2: seq2.unwrap(),
        seq3: seq3.unwrap(),
        seq4: seq4.unwrap(),
        seq5: seq5.unwrap(),
        seq6: seq6.unwrap(),
    };

    Ok(seqrr)
}

fn send_ie_probe(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    max_loop: usize,
    read_timeout: Duration,
) -> Result<IERR> {
    // 2 packets with 2 threads
    let pool = get_threads_pool(2);
    let (tx, rx) = channel();

    let mut rng = rand::thread_rng();
    let id_1 = rng.gen();
    // and the ICMP request ID and sequence numbers are incremented by one from the previous query values
    let id_2 = id_1 + 1;
    let buff_1 = packet::ie_packet_1_layer3(src_ipv4, dst_ipv4, id_1)?;
    let buff_2 = packet::ie_packet_2_layer3(src_ipv4, dst_ipv4, id_2)?;

    let buffs = vec![buff_1, buff_2];
    let buffs_len = buffs.len();
    let mut id = 1;
    for buff in buffs {
        let tx = tx.clone();
        pool.execute(move || {
            let (mut icmp_tx, mut icmp_rx) = return_layer3_icmp_channel(ICMP_BUFF_SIZE).unwrap();
            let request_ipv4_packet = Ipv4Packet::new(&buff).unwrap();
            match icmp_tx.send_to(&request_ipv4_packet, dst_ipv4.into()) {
                Ok(n) => {
                    // two ie packet had diffierent length
                    if n > 0 {
                        let mut icmp_iter = ipv4_packet_iter(&mut icmp_rx);
                        let mut recv_flag = false;
                        for _ in 0..max_loop {
                            match icmp_iter.next_with_timeout(read_timeout) {
                                Ok(r) => match r {
                                    Some((response_ipv4_packet, addr)) => {
                                        if addr == dst_ipv4
                                            && response_ipv4_packet.get_next_level_protocol()
                                                == IpNextHeaderProtocols::Icmp
                                        {
                                            let msg = Ok((
                                                id,
                                                request_ipv4_packet.packet().to_vec(),
                                                response_ipv4_packet.packet().to_vec(),
                                            ));

                                            match tx.send(msg) {
                                                _ => (),
                                            }
                                            recv_flag = true;
                                            // get what we need, so break
                                            break;
                                        }
                                    }
                                    _ => (), // do nothing
                                },
                                Err(_) => (),
                            }
                            if recv_flag {
                                break;
                            }
                        }
                        if !recv_flag {
                            // we did not recv any packet
                            let msg = Ok((id, request_ipv4_packet.packet().to_vec(), vec![]));
                            match tx.send(msg) {
                                _ => (),
                            }
                        }
                    }
                }
                Err(e) => match tx.send(Err(e)) {
                    _ => (),
                },
            }
        });
        // here sleep is non-hard requirements
        sleep(Duration::from_millis(100));
        id += 1;
    }

    let mut ie1 = None;
    let mut ie2 = None;

    let iter = rx.into_iter().take(buffs_len);
    for value in iter {
        match value {
            Ok(tp) => {
                let name = format!("ie{}", tp.0);
                let request = tp.1;
                let response = tp.2;
                let rr = RequestAndResponse {
                    name: name.clone(),
                    request,
                    response,
                };
                match tp.0 {
                    1 => ie1 = Some(rr),
                    2 => ie2 = Some(rr),
                    _ => (),
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    let ierr = IERR {
        ie1: ie1.unwrap(),
        ie2: ie2.unwrap(),
    };
    Ok(ierr)
}

fn send_ecn_probe(
    src_ipv4: Ipv4Addr,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_open_port: u16,
    max_loop: usize,
    read_timeout: Duration,
) -> Result<ECNRR> {
    // 1 packets with 1 threads
    let pool = get_threads_pool(1);
    let (tx, rx) = channel();

    let src_port_p = match src_port {
        Some(s) => s,
        None => random_port(),
    };

    let buff = packet::ecn_packet_layer3(src_ipv4, src_port_p, dst_ipv4, dst_open_port)?;

    let tx = tx.clone();
    pool.execute(move || {
        let (mut tcp_tx, mut tcp_rx) = return_layer3_tcp_channel(TCP_BUFF_SIZE).unwrap();
        let request_ipv4_packet = Ipv4Packet::new(&buff).unwrap();
        match tcp_tx.send_to(&request_ipv4_packet, dst_ipv4.into()) {
            Ok(n) => {
                if n == buff.len() {
                    let mut ipv4_iter = ipv4_packet_iter(&mut tcp_rx); // we need some ip header info
                    let mut recv_flag = false;
                    for _ in 0..max_loop {
                        match ipv4_iter.next_with_timeout(read_timeout) {
                            Ok(r) => match r {
                                Some((response_ipv4_packet, addr)) => {
                                    if addr == dst_ipv4
                                        && response_ipv4_packet.get_next_level_protocol()
                                            == IpNextHeaderProtocols::Tcp
                                    {
                                        let request_tcp_packet =
                                            TcpPacket::new(request_ipv4_packet.payload()).unwrap();
                                        let response_tcp_packet =
                                            TcpPacket::new(response_ipv4_packet.payload()).unwrap();

                                        let src_port_1 = request_tcp_packet.get_source();
                                        let dst_port_1 = request_tcp_packet.get_destination();
                                        let src_port_2 = response_tcp_packet.get_source();
                                        let dst_port_2 = response_tcp_packet.get_destination();

                                        if src_port_1 == dst_port_2 && dst_port_1 == src_port_2 {
                                            let msg = Ok((
                                                1,
                                                request_ipv4_packet.packet().to_vec(),
                                                response_ipv4_packet.packet().to_vec(),
                                            ));
                                            match tx.send(msg) {
                                                _ => (),
                                            }
                                            recv_flag = true;
                                        }
                                    }
                                }
                                _ => (), // do nothing
                            },
                            Err(_) => (),
                        }
                        if recv_flag {
                            break;
                        }
                    }
                    if !recv_flag {
                        // we did not recv any packet
                        let msg = Ok((1, request_ipv4_packet.packet().to_vec(), vec![]));
                        match tx.send(msg) {
                            _ => (),
                        }
                    }
                }
            }
            Err(e) => match tx.send(Err(e)) {
                _ => (),
            },
        }
    });

    let mut iter = rx.into_iter().take(1);
    let value = iter.next().unwrap();
    match value {
        Ok(tp) => {
            // only one packet
            let name = String::from("ecn");
            let request = tp.1;
            let response = tp.2;
            let rr = RequestAndResponse {
                name,
                request,
                response,
            };
            let ecnrr = ECNRR { ecn: rr };
            return Ok(ecnrr);
        }
        Err(e) => return Err(e.into()),
    }
}

fn send_t2_t7_probes(
    src_ipv4: Ipv4Addr,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_open_port: u16,
    dst_closed_port: u16,
    max_loop: usize,
    read_timeout: Duration,
) -> Result<T2T7RR> {
    // 6 packets with 6 threads
    let pool = get_threads_pool(6);
    let (tx, rx) = channel();

    let src_ports = match src_port {
        Some(s) => vec![s; 6],
        None => random_port_multi(6),
    };

    // T2 sends a TCP null (no flags set) packet with the IP DF bit set and a window field of 128 to an open port.
    let buff_2 = packet::t2_packet_layer3(src_ipv4, src_ports[0], dst_ipv4, dst_open_port)?;
    // T3 sends a TCP packet with the SYN, FIN, URG, and PSH flags set and a window field of 256 to an open port. The IP DF bit is not set.
    let buff_3 = packet::t3_packet_layer3(src_ipv4, src_ports[1], dst_ipv4, dst_open_port)?;
    // T4 sends a TCP ACK packet with IP DF and a window field of 1024 to an open port.
    let buff_4 = packet::t4_packet_layer3(src_ipv4, src_ports[2], dst_ipv4, dst_open_port)?;
    // T5 sends a TCP SYN packet without IP DF and a window field of 31337 to a closed port.
    let buff_5 = packet::t5_packet_layer3(src_ipv4, src_ports[3], dst_ipv4, dst_closed_port)?;
    // T6 sends a TCP ACK packet with IP DF and a window field of 32768 to a closed port.
    let buff_6 = packet::t6_packet_layer3(src_ipv4, src_ports[4], dst_ipv4, dst_closed_port)?;
    // T7 sends a TCP packet with the FIN, PSH, and URG flags set and a window field of 65535 to a closed port. The IP DF bit is not set.
    let buff_7 = packet::t7_packet_layer3(src_ipv4, src_ports[5], dst_ipv4, dst_closed_port)?;

    let buffs = vec![buff_2, buff_3, buff_4, buff_5, buff_6, buff_7];
    let buffs_len = buffs.len();
    let mut id = 2;
    for buff in buffs {
        let tx = tx.clone();
        pool.execute(move || {
            let (mut tcp_tx, mut tcp_rx) = return_layer3_tcp_channel(TCP_BUFF_SIZE).unwrap();
            let request_ipv4_packet = Ipv4Packet::new(&buff).unwrap();
            match tcp_tx.send_to(&request_ipv4_packet, dst_ipv4.into()) {
                Ok(n) => {
                    if n == buff.len() {
                        let mut ipv4_iter = ipv4_packet_iter(&mut tcp_rx); // we need some ip header info
                        let mut recv_flag = false;
                        for _ in 0..max_loop {
                            match ipv4_iter.next_with_timeout(read_timeout) {
                                Ok(r) => match r {
                                    Some((response_ipv4_packet, addr)) => {
                                        if addr == dst_ipv4
                                            && response_ipv4_packet.get_next_level_protocol()
                                                == IpNextHeaderProtocols::Tcp
                                        {
                                            let request_tcp_packet =
                                                TcpPacket::new(request_ipv4_packet.payload())
                                                    .unwrap();
                                            let response_tcp_packet =
                                                TcpPacket::new(response_ipv4_packet.payload())
                                                    .unwrap();

                                            let src_port_1 = request_tcp_packet.get_source();
                                            let dst_port_1 = request_tcp_packet.get_destination();
                                            let src_port_2 = response_tcp_packet.get_source();
                                            let dst_port_2 = response_tcp_packet.get_destination();

                                            if src_port_1 == dst_port_2 && dst_port_1 == src_port_2
                                            {
                                                let msg = Ok((
                                                    id,
                                                    request_ipv4_packet.packet().to_vec(),
                                                    response_ipv4_packet.packet().to_vec(),
                                                ));
                                                match tx.send(msg) {
                                                    _ => (),
                                                }
                                                recv_flag = true;
                                            }
                                        }
                                    }
                                    _ => (), // do nothing
                                },
                                Err(_) => (),
                            }
                            if recv_flag {
                                break;
                            }
                        }
                        if !recv_flag {
                            // we did not recv any packet
                            let msg = Ok((id, request_ipv4_packet.packet().to_vec(), vec![]));
                            match tx.send(msg) {
                                _ => (),
                            }
                        }
                    }
                }
                Err(e) => match tx.send(Err(e)) {
                    _ => (),
                },
            }
        });
        // the probes are sent exactly 100 milliseconds apart so the total time taken is 500 ms
        // sleep(Duration::from_millis(100));
        id += 1;
    }

    let mut t2 = None;
    let mut t3 = None;
    let mut t4 = None;
    let mut t5 = None;
    let mut t6 = None;
    let mut t7 = None;

    let iter = rx.into_iter().take(buffs_len);
    for value in iter {
        match value {
            Ok(tp) => {
                let name = format!("t{}", tp.0);
                let request = tp.1;
                let response = tp.2;
                let rr = RequestAndResponse {
                    name: name.clone(),
                    request,
                    response,
                };
                match tp.0 {
                    2 => t2 = Some(rr),
                    3 => t3 = Some(rr),
                    4 => t4 = Some(rr),
                    5 => t5 = Some(rr),
                    6 => t6 = Some(rr),
                    7 => t7 = Some(rr),
                    _ => (),
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    let t2t7rr = T2T7RR {
        t2: t2.unwrap(),
        t3: t3.unwrap(),
        t4: t4.unwrap(),
        t5: t5.unwrap(),
        t6: t6.unwrap(),
        t7: t7.unwrap(),
    };
    Ok(t2t7rr)
}

fn send_u1_probe(
    src_ipv4: Ipv4Addr,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_closed_port: u16, //should be an closed port
    max_loop: usize,
    read_timeout: Duration,
) -> Result<U1RR> {
    // 1 packets with 1 threads
    let pool = get_threads_pool(1);
    let (tx, rx) = channel();

    let src_port_p = match src_port {
        Some(s) => s,
        None => random_port(),
    };

    let buff = packet::udp_packet_layer3(src_ipv4, src_port_p, dst_ipv4, dst_closed_port)?;

    let tx = tx.clone();
    pool.execute(move || {
        let (mut udp_tx, _) = return_layer3_udp_channel(UDP_BUFF_SIZE).unwrap();
        let (_, mut icmp_rx) = return_layer3_icmp_channel(ICMP_BUFF_SIZE).unwrap();
        let request_ipv4_packet = Ipv4Packet::new(&buff).unwrap();
        match udp_tx.send_to(&request_ipv4_packet, dst_ipv4.into()) {
            Ok(n) => {
                if n == buff.len() {
                    let mut ipv4_iter = ipv4_packet_iter(&mut icmp_rx); // we need some ip header info
                    let mut recv_flag = false;
                    for _ in 0..max_loop {
                        match ipv4_iter.next_with_timeout(read_timeout) {
                            Ok(r) => match r {
                                Some((response_ipv4_packet, addr)) => {
                                    if addr == dst_ipv4
                                        && response_ipv4_packet.get_next_level_protocol()
                                            == IpNextHeaderProtocols::Icmp
                                    {
                                        let msg = Ok((
                                            1,
                                            request_ipv4_packet.packet().to_vec(),
                                            response_ipv4_packet.packet().to_vec(),
                                        ));
                                        match tx.send(msg) {
                                            _ => (),
                                        }
                                        recv_flag = true;
                                    }
                                }
                                _ => (), // do nothing
                            },
                            Err(_) => (),
                        }
                        if recv_flag {
                            break;
                        }
                    }
                    if !recv_flag {
                        // we did not recv any packet
                        let msg = Ok((1, request_ipv4_packet.packet().to_vec(), vec![]));
                        match tx.send(msg) {
                            _ => (),
                        }
                    }
                }
            }
            Err(e) => match tx.send(Err(e)) {
                _ => (),
            },
        }
    });

    let mut iter = rx.into_iter().take(1);
    let value = iter.next().unwrap();
    match value {
        Ok(tp) => {
            // only one packet
            let name = String::from("u1");
            let request = tp.1;
            let response = tp.2;
            let rr = RequestAndResponse {
                name: name.clone(),
                request,
                response,
            };
            let u1rr = U1RR { u1: rr };
            return Ok(u1rr);
        }
        Err(e) => return Err(e.into()),
    }
}

fn send_all_probes(
    src_ipv4: Ipv4Addr,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_open_port: u16,
    dst_closed_port: u16,
    max_loop: usize,
    read_timeout: Duration,
) -> Result<AllRRPacket> {
    let seq = send_seq_probes(
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_open_port,
        max_loop,
        read_timeout,
    )?;
    let ie = send_ie_probe(src_ipv4, dst_ipv4, max_loop, read_timeout)?;
    let ecn = send_ecn_probe(
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_open_port,
        max_loop,
        read_timeout,
    )?;
    let t2_t7 = send_t2_t7_probes(
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_open_port,
        dst_closed_port,
        max_loop,
        read_timeout,
    )?;
    let u1 = send_u1_probe(
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_closed_port,
        max_loop,
        read_timeout,
    )?;

    let ap = AllRRPacket {
        seq,
        ie,
        ecn,
        t2t7: t2_t7,
        u1,
    };

    Ok(ap)
}

pub struct SEQX {
    pub sp: u32,
    pub gcd: u32,
    pub isr: u32,
    pub ti: String,
    pub ci: String,
    pub ii: String,
    pub ss: String,
    pub ts: String,
}

impl fmt::Display for SEQX {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = format!(
            "SEQ(SP={:X}%GCD={:X}%ISR={:X}%TI={}%CI={}%II={}%SS={}%TS={})",
            self.sp, self.gcd, self.isr, self.ti, self.ci, self.ii, self.ss, self.ts
        );
        write!(f, "{}", output)
    }
}

fn seq_fingerprint(ap: &AllRRPacket) -> SEQX {
    let (gcd, diff) = tcp_gcd(&ap.seq).unwrap(); // None mean error
    let (isr, seq_rates) = tcp_isr(diff);
    let sp = tcp_sp(seq_rates, gcd);
    let (ti, ci, ii) = tcp_ti_ci_ii(&ap.seq, &ap.t2t7, &ap.ie);
    let ss = tcp_ss(&ap.seq, &ap.ie, &ti, &ii);
    let ts = tcp_ts(&ap.seq);

    let sp = match sp {
        Some(sp) => sp,
        None => 0,
    };
    let ss = match ss {
        Some(ss) => ss,
        None => String::from(""),
    };

    SEQX {
        sp,
        gcd,
        isr,
        ti,
        ci,
        ii,
        ss,
        ts,
    }
}

pub struct OPSX {
    pub o1: String,
    pub o2: String,
    pub o3: String,
    pub o4: String,
    pub o5: String,
    pub o6: String,
}

impl fmt::Display for OPSX {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = format!(
            "OPS(O1={}%O2={}%O3={}%O4={}%O5={}%O6={})",
            self.o1, self.o2, self.o3, self.o4, self.o5, self.o6
        );
        write!(f, "{}", output)
    }
}

fn ops_fingerprint(ap: &AllRRPacket) -> OPSX {
    let (o1, o2, o3, o4, o5, o6) = tcp_ox(&ap.seq);
    let ovalue = |x: Option<String>, i: i32| -> String {
        match x {
            Some(v) => v,
            None => {
                println!("o{i} is empty");
                String::from("")
            }
        }
    };

    OPSX {
        o1: ovalue(o1, 1),
        o2: ovalue(o2, 2),
        o3: ovalue(o3, 3),
        o4: ovalue(o4, 4),
        o5: ovalue(o5, 5),
        o6: ovalue(o6, 6),
    }
}

pub struct WINX {
    pub w1: String,
    pub w2: String,
    pub w3: String,
    pub w4: String,
    pub w5: String,
    pub w6: String,
}

impl fmt::Display for WINX {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = format!(
            "WIN(W1={}%W2={}%W3={}%W4={}%W5={}%W6={})",
            self.w1, self.w2, self.w3, self.w4, self.w5, self.w6
        );
        write!(f, "{}", output)
    }
}

fn win_fingerprint(ap: &AllRRPacket) -> WINX {
    let (w1, w2, w3, w4, w5, w6) = tcp_wx(&ap.seq);
    let wvalue = |x: Option<String>, i: i32| -> String {
        match x {
            Some(v) => v,
            None => {
                println!("w{i} is empty");
                String::from("")
            }
        }
    };

    WINX {
        w1: wvalue(w1, 1),
        w2: wvalue(w2, 2),
        w3: wvalue(w3, 3),
        w4: wvalue(w4, 4),
        w5: wvalue(w5, 5),
        w6: wvalue(w6, 6),
    }
}

pub struct ECNX {
    pub r: String,
    pub df: String,
    pub t: u16,
    pub tg: u8,
    pub w: String,
    pub o: String,
    pub cc: String,
    pub q: String,
}

impl fmt::Display for ECNX {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = format!(
            "ECN(R={}%DF={}%T={:X}%TG={:X}%W={}%O={}%CC={}%Q={})",
            self.r, self.df, self.t, self.tg, self.w, self.o, self.cc, self.q,
        );
        write!(f, "{}", output)
    }
}

fn ecn_fingerprint(ap: &AllRRPacket) -> ECNX {
    let r = tcp_r(&ap.ecn.ecn.response);
    let (df, t, tg, w, o, cc, q) = match r.as_str() {
        "Y" => {
            let df = tcp_df(&ap.ecn.ecn.response);
            let t = tcp_t(&ap.ecn.ecn.response, &ap.u1);
            let tg = tcp_tg(&ap.ecn.ecn.response);
            let w = tcp_w(&ap.ecn.ecn.response);
            let o = tcp_o(&ap.ecn.ecn.response);
            let cc = tcp_cc(&ap.ecn.ecn.response);
            let q = tcp_q(&ap.ecn.ecn.response);

            let evalue = |x: Option<String>, name: &str| match x {
                Some(v) => v,
                None => {
                    println!("{name} is empty");
                    String::from("")
                }
            };

            let df = evalue(df, "df");
            let w = evalue(w, "w");
            let o = evalue(o, "o");

            let t = match t {
                Some(t) => t,
                None => 0,
            };

            (df, t, tg, w, o, cc, q)
        }
        _ => {
            let df = String::from("");
            let t = 0;
            let tg = 0;
            let w = String::from("");
            let o = String::from("");
            let cc = String::from("");
            let q = String::from("");
            (df, t, tg, w, o, cc, q)
        }
    };

    ECNX {
        r,
        df,
        t,
        tg,
        w,
        o,
        cc,
        q,
    }
}

pub fn os_detect(
    src_ipv4: Ipv4Addr,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_open_port: u16,
    dst_closed_port: u16,
    max_loop: usize,
    read_timeout: Duration,
) -> Result<()> {
    let ap = send_all_probes(
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_open_port,
        dst_closed_port,
        max_loop,
        read_timeout,
    )?;

    let seq = seq_fingerprint(&ap);
    let ops = ops_fingerprint(&ap);
    let win = win_fingerprint(&ap);
    let ecn = ecn_fingerprint(&ap);

    println!("{}", seq);
    println!("{}", ops);
    println!("{}", win);
    println!("{}", ecn);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_detect() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        let src_port = None;
        let dst_open_port = 80;
        let dst_closed_port = 9999;
        let max_loop = 8;
        let read_timeout = Duration::from_secs_f32(0.5);
        let _ = os_detect(
            src_ipv4,
            src_port,
            dst_ipv4,
            dst_open_port,
            dst_closed_port,
            max_loop,
            read_timeout,
        );
    }
    #[test]
    fn test_w() {
        let a = 7;
        let b = 8;
        let c = format!("W{:X}W{:X}", a, b);
        println!("{c}");
    }
    #[test]
    fn test_scan_str() {
        let dst_mac = MacAddr::new(01, 12, 34, 56, 00, 90);
        let dst_open_tcp_port = 22;
        let dst_closed_tcp_port = 1;
        let dst_closed_udp_port = 42341;
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        let ret = get_scan_line(
            Some(dst_mac),
            dst_open_tcp_port,
            dst_closed_tcp_port,
            dst_closed_udp_port,
            dst_ipv4,
            None,
            true,
        );
        println!("{}", ret);
    }
    #[test]
    fn test_seq_probes() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        let src_port = None;
        let dst_open_port = 22;
        let max_loop = 32;
        let read_timeout = Duration::from_secs_f32(3.0);
        let seqrr = send_seq_probes(
            src_ipv4,
            src_port,
            dst_ipv4,
            dst_open_port,
            max_loop,
            read_timeout,
        )
        .unwrap();
        println!("{}", seqrr.seq1.name);
        println!("{}", seqrr.seq2.name);
        println!("{}", seqrr.seq3.name);
        println!("{}", seqrr.seq4.name);
        println!("{}", seqrr.seq5.name);
        println!("{}", seqrr.seq6.name);
    }
    #[test]
    fn test_ie_probe() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        let max_loop = 32;
        let read_timeout = Duration::from_secs_f32(3.0);
        let ierr = send_ie_probe(src_ipv4, dst_ipv4, max_loop, read_timeout).unwrap();
        println!("{}", ierr.ie1.name);
        println!("{}", ierr.ie2.name);
    }
    #[test]
    fn test_ecn_probe() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        let src_port = None;
        let dst_open_port = 22;
        let max_loop = 32;
        let read_timeout = Duration::from_secs_f32(3.0);
        let ecnrr = send_ecn_probe(
            src_ipv4,
            src_port,
            dst_ipv4,
            dst_open_port,
            max_loop,
            read_timeout,
        )
        .unwrap();
        println!("{}", ecnrr.ecn.name);
    }
    #[test]
    fn test_t2_t7_probes() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        let src_port = None;
        let dst_open_port = 22;
        let dst_closed_port = 9999;
        let max_loop = 32;
        let read_timeout = Duration::from_secs_f32(3.0);
        let t2t7rr = send_t2_t7_probes(
            src_ipv4,
            src_port,
            dst_ipv4,
            dst_open_port,
            dst_closed_port,
            max_loop,
            read_timeout,
        )
        .unwrap();
        println!("{}", t2t7rr.t2.name);
        println!("{}", t2t7rr.t3.name);
        println!("{}", t2t7rr.t4.name);
        println!("{}", t2t7rr.t5.name);
        println!("{}", t2t7rr.t6.name);
        println!("{}", t2t7rr.t7.name);
    }
    #[test]
    fn test_u1_probe() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        let src_port = None;
        let dst_closed_port = 9999;
        let max_loop = 32;
        let read_timeout = Duration::from_secs_f32(1.0);
        let u1rr = send_u1_probe(
            src_ipv4,
            src_port,
            dst_ipv4,
            dst_closed_port,
            max_loop,
            read_timeout,
        )
        .unwrap();
        println!("{}", u1rr.u1.name);
    }
    #[test]
    fn test_all_probe() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        let src_port = None;
        let dst_open_port = 22;
        let dst_closed_port = 9999;
        let max_loop = 32;
        let read_timeout = Duration::from_secs_f32(3.0);
        let ap = send_all_probes(
            src_ipv4,
            src_port,
            dst_ipv4,
            dst_open_port,
            dst_closed_port,
            max_loop,
            read_timeout,
        )
        .unwrap();
    }
}
