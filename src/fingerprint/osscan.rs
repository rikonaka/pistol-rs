use anyhow::Result;
use chrono::{DateTime, Local, Utc};
use pnet::datalink::MacAddr;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use pnet::transport::ipv4_packet_iter;
use rand::Rng;
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::mpsc::channel;
use std::thread::sleep;
use std::time::Duration;

use crate::utils::find_mac_by_src_ip;
use crate::utils::get_threads_pool;
use crate::utils::random_port;
use crate::utils::random_port_multi;
use crate::utils::return_layer3_icmp_channel;
use crate::utils::return_layer3_tcp_channel;
use crate::utils::return_layer3_udp_channel;
use crate::utils::ICMP_BUFF_SIZE;
use crate::utils::TCP_BUFF_SIZE;
use crate::utils::UDP_BUFF_SIZE;

use super::operator::{icmp_cd, icmp_dfi, udp_ripck, udp_ruck, udp_rud};
use super::operator::{tcp_a, tcp_cc, tcp_o, tcp_q, tcp_s, tcp_sp, tcp_ss};
use super::operator::{tcp_f, tcp_gcd, tcp_isr, tcp_ox, tcp_rd};
use super::operator::{tcp_ti_ci_ii, tcp_ts, tcp_udp_icmp_t, tcp_udp_icmp_tg, tcp_w, tcp_wx};
use super::operator::{tcp_udp_df, tcp_udp_icmp_r, udp_ipl, udp_rid, udp_ripl, udp_un};
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
    hops: Option<u8>,
    good_results: bool,
) -> String {
    // Nmap version number (V).
    let v = "PISTOL";
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
        ("N", hops.unwrap(), "I")
    };
    // Good results (G) is Y if conditions and results seem good enough to submit this fingerprint to Nmap.Org.
    // It is N otherwise. Unless you force them by enabling debugging (-d) or extreme verbosity (-vv), G=N fingerprints aren't printed by Nmap.
    let g = if good_results { "Y" } else { "N" };
    // Target MAC prefix (M) is the first six hex digits of the target MAC address, which correspond to the vendor name.
    // Leading zeros are not included. This field is omitted unless the target is on the same ethernet network (DS=1).
    let m = if ds == 1 {
        let mut dst_mac_vec: [u8; 6] = dst_mac.unwrap().octets();
        let mut dst_mac_str = String::new();
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
    let p = "RUST";

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
        // Avoid two ip id become same.
        sleep(Duration::from_millis(10));
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
    dst_open_tcp_port: u16,
    dst_closed_tcp_port: u16,
    dst_closed_udp_port: u16,
    max_loop: usize,
    read_timeout: Duration,
) -> Result<AllRRPacket> {
    let seq = send_seq_probes(
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_open_tcp_port,
        max_loop,
        read_timeout,
    )?;
    let ie = send_ie_probe(src_ipv4, dst_ipv4, max_loop, read_timeout)?;
    let ecn = send_ecn_probe(
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_open_tcp_port,
        max_loop,
        read_timeout,
    )?;
    let t2_t7 = send_t2_t7_probes(
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_open_tcp_port,
        dst_closed_tcp_port,
        max_loop,
        read_timeout,
    )?;
    let u1 = send_u1_probe(
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_closed_udp_port,
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
    // SP, GCD, ISR, TI, CI, II, SS, and TS.
    pub sp: u32,
    pub gcd: u32,
    pub isr: u32,
    pub ti: String,
    pub ci: String,
    pub ii: String,
    pub ss: String,
    pub ts: String,
    // Fit the db file.
    pub r: String,
}

impl fmt::Display for SEQX {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.r.as_str() {
            "Y" => {
                // Do not show R if R == Y.
                let mut output =
                    format!("SEQ(SP={:X}%GCD={:X}%ISR={:X}", self.sp, self.gcd, self.isr);
                if self.ti.len() > 0 {
                    let ti_str = format!("%TI={}", self.ti);
                    output += &ti_str;
                }
                if self.ci.len() > 0 {
                    let ci_str = format!("%CI={}", self.ci);
                    output += &ci_str;
                }
                if self.ii.len() > 0 {
                    let ii_str = format!("%II={}", self.ii);
                    output += &ii_str;
                }
                if self.ss.len() > 0 {
                    let ss_str = format!("%SS={}", self.ss);
                    output += &ss_str;
                }
                if self.ts.len() > 0 {
                    let ts_str = format!("%TS={}", self.ts);
                    output += &ts_str;
                }
                output += ")";
                write!(f, "{}", output)
            }
            _ => {
                let output = format!("SEQ(R={})", self.r);
                write!(f, "{}", output)
            }
        }
    }
}

pub fn seq_fingerprint(ap: &AllRRPacket) -> Result<SEQX> {
    let rynum = |rvec: Vec<String>| -> usize {
        let mut num = 0;
        for r in rvec {
            if r == "Y" {
                num += 1;
            }
        }
        num
    };
    let r1 = tcp_udp_icmp_r(&ap.seq.seq1.response)?;
    let r2 = tcp_udp_icmp_r(&ap.seq.seq2.response)?;
    let r3 = tcp_udp_icmp_r(&ap.seq.seq3.response)?;
    let r4 = tcp_udp_icmp_r(&ap.seq.seq4.response)?;
    let r5 = tcp_udp_icmp_r(&ap.seq.seq5.response)?;
    let r6 = tcp_udp_icmp_r(&ap.seq.seq6.response)?;
    let rvec = vec![r1, r2, r3, r4, r5, r6];
    let num = rynum(rvec);

    // At least four responses should be returned.
    let (r, sp, gcd, isr, ti, ci, ii, ss, ts) = if num >= 4 {
        let (gcd, diff) = tcp_gcd(&ap.seq)?; // None mean error
        let (isr, seq_rates) = tcp_isr(diff)?;
        let sp = tcp_sp(seq_rates, gcd)?;
        let (ti, ci, ii) = tcp_ti_ci_ii(&ap.seq, &ap.t2t7, &ap.ie)?;
        let ss = tcp_ss(&ap.seq, &ap.ie, &ti, &ii)?;
        let ts = tcp_ts(&ap.seq)?;
        let r = String::from("Y");
        (r, sp, gcd, isr, ti, ci, ii, ss, ts)
    } else {
        let r = String::from("N");
        let gcd = 0;
        let isr = 0;
        let sp = 0;
        let ti = String::new();
        let ci = String::new();
        let ii = String::new();
        let ss = String::new();
        let ts = String::new();
        (r, sp, gcd, isr, ti, ci, ii, ss, ts)
    };
    Ok(SEQX {
        sp,
        gcd,
        isr,
        ti,
        ci,
        ii,
        ss,
        ts,
        r,
    })
}

pub struct OPSX {
    pub o1: String,
    pub o2: String,
    pub o3: String,
    pub o4: String,
    pub o5: String,
    pub o6: String,
    // Fit the db file.
    pub r: String,
}

impl fmt::Display for OPSX {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.r.as_str() {
            "Y" => {
                let mut first_elem = true;
                let mut output = String::from("OPS(");
                if self.o1.len() > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("O1={}", self.o1)
                    } else {
                        format!("%O1={}", self.o1)
                    };
                    output += &ox_str;
                }
                if self.o2.len() > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("O2={}", self.o2)
                    } else {
                        format!("%O2={}", self.o2)
                    };
                    output += &ox_str;
                }
                if self.o3.len() > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("O3={}", self.o3)
                    } else {
                        format!("%O3={}", self.o3)
                    };
                    output += &ox_str;
                }
                if self.o4.len() > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("O4={}", self.o4)
                    } else {
                        format!("%O4={}", self.o4)
                    };
                    output += &ox_str;
                }
                if self.o5.len() > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("O5={}", self.o5)
                    } else {
                        format!("%O5={}", self.o5)
                    };
                    output += &ox_str;
                }
                if self.o6.len() > 0 {
                    let ox_str = if first_elem {
                        // first_elem = false;
                        format!("O6={}", self.o6)
                    } else {
                        format!("%O6={}", self.o6)
                    };
                    output += &ox_str;
                }
                output += ")";
                write!(f, "{}", output)
            }
            _ => {
                let output = format!("OPS(R={})", self.r);
                write!(f, "{}", output)
            }
        }
    }
}

pub fn ops_fingerprint(ap: &AllRRPacket) -> Result<OPSX> {
    let rops = |rvec: Vec<String>| -> bool {
        let mut flag = true;
        for r in rvec {
            if r == "N" {
                flag = false;
            }
        }
        flag
    };
    let r1 = tcp_udp_icmp_r(&ap.seq.seq1.response)?;
    let r2 = tcp_udp_icmp_r(&ap.seq.seq2.response)?;
    let r3 = tcp_udp_icmp_r(&ap.seq.seq3.response)?;
    let r4 = tcp_udp_icmp_r(&ap.seq.seq4.response)?;
    let r5 = tcp_udp_icmp_r(&ap.seq.seq5.response)?;
    let r6 = tcp_udp_icmp_r(&ap.seq.seq6.response)?;
    let rvec = vec![r1, r2, r3, r4, r5, r6];
    let flag = rops(rvec);
    let r = if flag {
        String::from("Y")
    } else {
        String::from("N")
    };

    let (o1, o2, o3, o4, o5, o6) = tcp_ox(&ap.seq)?;

    Ok(OPSX {
        o1,
        o2,
        o3,
        o4,
        o5,
        o6,
        r,
    })
}

pub struct WINX {
    pub w1: u16,
    pub w2: u16,
    pub w3: u16,
    pub w4: u16,
    pub w5: u16,
    pub w6: u16,
    // Fit.
    pub r: String,
}

impl fmt::Display for WINX {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.r.as_str() {
            "Y" => {
                let mut first_elem = true;
                let mut output = String::from("WIN(");
                if self.w1 > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("W1={:X}", self.w1)
                    } else {
                        format!("%W1={:X}", self.w1)
                    };
                    output += &ox_str;
                }
                if self.w2 > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("W2={:X}", self.w2)
                    } else {
                        format!("%W2={:X}", self.w2)
                    };
                    output += &ox_str;
                }
                if self.w3 > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("W3={:X}", self.w3)
                    } else {
                        format!("%W3={:X}", self.w3)
                    };
                    output += &ox_str;
                }
                if self.w4 > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("W4={:X}", self.w4)
                    } else {
                        format!("%W4={:X}", self.w4)
                    };
                    output += &ox_str;
                }
                if self.w5 > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("W5={:X}", self.w5)
                    } else {
                        format!("%W5={:X}", self.w5)
                    };
                    output += &ox_str;
                }
                if self.w6 > 0 {
                    let ox_str = if first_elem {
                        // first_elem = false;
                        format!("W6={:X}", self.w6)
                    } else {
                        format!("%W6={:X}", self.w6)
                    };
                    output += &ox_str;
                }
                output += ")";
                write!(f, "{}", output)
            }
            _ => {
                let output = format!("WIN(R={})", self.r);
                write!(f, "{}", output)
            }
        }
    }
}

pub fn win_fingerprint(ap: &AllRRPacket) -> Result<WINX> {
    let rwin = |rvec: Vec<String>| -> bool {
        let mut flag = true;
        for r in rvec {
            if r == "N" {
                flag = false;
            }
        }
        flag
    };
    let r1 = tcp_udp_icmp_r(&ap.seq.seq1.response)?;
    let r2 = tcp_udp_icmp_r(&ap.seq.seq2.response)?;
    let r3 = tcp_udp_icmp_r(&ap.seq.seq3.response)?;
    let r4 = tcp_udp_icmp_r(&ap.seq.seq4.response)?;
    let r5 = tcp_udp_icmp_r(&ap.seq.seq5.response)?;
    let r6 = tcp_udp_icmp_r(&ap.seq.seq6.response)?;
    let rvec = vec![r1, r2, r3, r4, r5, r6];
    let flag = rwin(rvec);
    let r = if flag {
        String::from("Y")
    } else {
        String::from("N")
    };

    let (w1, w2, w3, w4, w5, w6) = tcp_wx(&ap.seq)?;
    Ok(WINX {
        w1,
        w2,
        w3,
        w4,
        w5,
        w6,
        r,
    })
}

pub struct ECNX {
    // R, DF, T, TG, W, O, CC, and Q tests.
    pub r: String,
    pub df: String,
    pub t: u16,
    pub tg: u8,
    pub w: u16,
    pub o: String,
    pub cc: String,
    pub q: String,
}

impl fmt::Display for ECNX {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.r.as_str() {
            "Y" => {
                let mut first_elem = true;
                let mut output = String::from("ECN(");
                if self.r.len() > 0 {
                    let r_str = if first_elem {
                        first_elem = false;
                        format!("R={}", self.r)
                    } else {
                        format!("%R={}", self.r)
                    };
                    output += &r_str;
                }
                if self.df.len() > 0 {
                    let df_str = if first_elem {
                        first_elem = false;
                        format!("DF={}", self.df)
                    } else {
                        format!("%DF={}", self.df)
                    };
                    output += &df_str;
                }
                if self.t > 0 {
                    let t_str = if first_elem {
                        first_elem = false;
                        // format!("T={:X}", self.t)
                        format!("TG={:X}", self.t)
                    } else {
                        // format!("%T={:X}", self.t)
                        format!("%TG={:X}", self.t)
                    };
                    output += &t_str;
                } else if self.tg > 0 {
                    // This TTL guess field is not printed in a subject fingerprint if the actual TTL (T) value was discovered.
                    let tg_str = if first_elem {
                        first_elem = false;
                        format!("TG={:X}", self.tg)
                    } else {
                        format!("%TG={:X}", self.tg)
                    };
                    output += &tg_str;
                }
                if self.w > 0 {
                    let w_str = if first_elem {
                        first_elem = false;
                        format!("W={:X}", self.w)
                    } else {
                        format!("%W={:X}", self.w)
                    };
                    output += &w_str;
                }
                if self.o.len() > 0 {
                    let o_str = if first_elem {
                        first_elem = false;
                        format!("O={}", self.o)
                    } else {
                        format!("%O={}", self.o)
                    };
                    output += &o_str;
                }
                if self.cc.len() > 0 {
                    let cc_str = if first_elem {
                        first_elem = false;
                        format!("CC={}", self.cc)
                    } else {
                        format!("%CC={}", self.cc)
                    };
                    output += &cc_str;
                }
                let q_str = if first_elem {
                    // first_elem = false;
                    format!("Q={}", self.q)
                } else {
                    format!("%Q={}", self.q)
                };
                output += &q_str;
                output += ")";
                write!(f, "{}", output)
            }
            _ => {
                let output = format!("ECN(R={})", self.r);
                write!(f, "{}", output)
            }
        }
    }
}

pub fn ecn_fingerprint(ap: &AllRRPacket) -> Result<ECNX> {
    let r = tcp_udp_icmp_r(&ap.ecn.ecn.response)?;
    let (df, t, tg, w, o, cc, q) = match r.as_str() {
        "Y" => {
            let df = tcp_udp_df(&ap.ecn.ecn.response)?;
            let t = tcp_udp_icmp_t(&ap.ecn.ecn.response, &ap.u1)?;
            let tg = tcp_udp_icmp_tg(&ap.ecn.ecn.response)?;
            let w = tcp_w(&ap.ecn.ecn.response)?;
            let o = tcp_o(&ap.ecn.ecn.response)?;
            let cc = tcp_cc(&ap.ecn.ecn.response)?;
            let q = tcp_q(&ap.ecn.ecn.response)?;

            (df, t, tg, w, o, cc, q)
        }
        _ => {
            //  If there is no reply, remaining fields for the test are omitted.
            let df = String::new();
            let t = 0;
            let tg = 0;
            let w = 0;
            let o = String::new();
            let cc = String::new();
            let q = String::new();
            (df, t, tg, w, o, cc, q)
        }
    };

    Ok(ECNX {
        r,
        df,
        t,
        tg,
        w,
        o,
        cc,
        q,
    })
}

pub struct TXX {
    pub name: String,
    // R, DF, T, TG, W, S, A, F, O, RD, and Q tests.
    pub r: String,
    pub df: String,
    pub t: u16,
    pub tg: u8,
    pub w: u16,
    pub s: String,
    pub a: String,
    pub f: String,
    pub o: String,
    pub rd: u32, // CRC32
    pub q: String,
}

impl fmt::Display for TXX {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.r.as_str() {
            "Y" => {
                let mut first_elem = true;
                let mut output = format!("{}(", self.name);
                if self.r.len() > 0 {
                    let r_str = if first_elem {
                        first_elem = false;
                        format!("R={}", self.r)
                    } else {
                        format!("%R={}", self.r)
                    };
                    output += &r_str;
                }
                if self.df.len() > 0 {
                    let df_str = if first_elem {
                        first_elem = false;
                        format!("DF={}", self.df)
                    } else {
                        format!("%DF={}", self.df)
                    };
                    output += &df_str;
                }
                if self.t > 0 {
                    let t_str = if first_elem {
                        first_elem = false;
                        // format!("T={:X}", self.t)
                        format!("TG={:X}", self.t)
                    } else {
                        // format!("%T={:X}", self.t)
                        format!("%TG={:X}", self.t)
                    };
                    output += &t_str;
                } else if self.tg > 0 {
                    // This TTL guess field is not printed in a subject fingerprint if the actual TTL (T) value was discovered.
                    let tg_str = if first_elem {
                        first_elem = false;
                        format!("TG={:X}", self.tg)
                    } else {
                        format!("%TG={:X}", self.tg)
                    };
                    output += &tg_str;
                }
                if self.name != "T1" {
                    let w_str = if first_elem {
                        first_elem = false;
                        format!("W={:X}", self.w)
                    } else {
                        format!("%W={:X}", self.w)
                    };
                    output += &w_str;
                }
                if self.s.len() > 0 {
                    let s_str = if first_elem {
                        first_elem = false;
                        format!("S={}", self.s)
                    } else {
                        format!("%S={}", self.s)
                    };
                    output += &s_str;
                }
                if self.a.len() > 0 {
                    let a_str = if first_elem {
                        first_elem = false;
                        format!("A={}", self.a)
                    } else {
                        format!("%A={}", self.a)
                    };
                    output += &a_str;
                }
                if self.f.len() > 0 {
                    let f_str = if first_elem {
                        first_elem = false;
                        format!("F={}", self.f)
                    } else {
                        format!("%F={}", self.f)
                    };
                    output += &f_str;
                }
                if self.name != "T1" {
                    let o_str = if first_elem {
                        first_elem = false;
                        format!("O={}", self.o)
                    } else {
                        format!("%O={}", self.o)
                    };
                    output += &o_str;
                }
                let rd_str = if first_elem {
                    first_elem = false;
                    format!("RD={:X}", self.rd)
                } else {
                    format!("%RD={:X}", self.rd)
                };
                output += &rd_str;
                let q_str = if first_elem {
                    // first_elem = false;
                    format!("Q={}", self.q)
                } else {
                    format!("%Q={}", self.q)
                };
                output += &q_str;
                output += ")";

                write!(f, "{}", output)
            }
            _ => {
                let output = format!("{}(R={})", self.name, self.r);
                write!(f, "{}", output)
            }
        }
    }
}

fn _tx_fingerprint(tx: &RequestAndResponse, u1rr: &U1RR, name: &str) -> Result<TXX> {
    let r = tcp_udp_icmp_r(&tx.response)?;
    let (df, t, tg, w, s, a, f, o, rd, q) = match r.as_str() {
        "Y" => {
            let df = tcp_udp_df(&tx.response)?;
            let t = tcp_udp_icmp_t(&tx.response, u1rr)?;
            let tg = tcp_udp_icmp_tg(&tx.response)?;
            let w = tcp_w(&tx.response)?;
            let s = tcp_s(&tx.request, &tx.response)?;
            let a = tcp_a(&tx.request, &tx.response)?;
            let f = tcp_f(&tx.response)?;
            let o = tcp_o(&tx.response)?;
            let rd = tcp_rd(&tx.response)?;
            let q = tcp_q(&tx.response)?;

            (df, t, tg, w, s, a, f, o, rd, q)
        }
        _ => {
            let df = String::new();
            let t = 0;
            let tg = 0;
            let w = 0;
            let s = String::new();
            let a = String::new();
            let f = String::new();
            let o = String::new();
            let rd = 0;
            let q = String::new();
            (df, t, tg, w, s, a, f, o, rd, q)
        }
    };

    Ok(TXX {
        name: name.to_string(),
        r,
        df,
        t,
        tg,
        w,
        s,
        a,
        f,
        o,
        rd,
        q,
    })
}

pub fn tx_fingerprint(ap: &AllRRPacket) -> Result<(TXX, TXX, TXX, TXX, TXX, TXX, TXX)> {
    // The final line related to these probes, T1, contains various test values for packet #1.
    let t1 = _tx_fingerprint(&ap.seq.seq1, &ap.u1, "T1")?;
    let t2 = _tx_fingerprint(&ap.t2t7.t2, &ap.u1, "T2")?;
    let t3 = _tx_fingerprint(&ap.t2t7.t3, &ap.u1, "T3")?;
    let t4 = _tx_fingerprint(&ap.t2t7.t4, &ap.u1, "T4")?;
    let t5 = _tx_fingerprint(&ap.t2t7.t5, &ap.u1, "T5")?;
    let t6 = _tx_fingerprint(&ap.t2t7.t6, &ap.u1, "T6")?;
    let t7 = _tx_fingerprint(&ap.t2t7.t7, &ap.u1, "T7")?;

    Ok((t1, t2, t3, t4, t5, t6, t7))
}

pub struct U1X {
    // R, DF, T, TG, IPL, UN, RIPL, RID, RIPCK, RUCK, and RUD tests.
    pub r: String,
    pub df: String,
    pub t: u16,
    pub tg: u8,
    pub ipl: usize,
    pub un: u32,
    pub ripl: String,
    pub rid: String,
    pub ripck: String,
    pub ruck: String,
    pub rud: String,
}

impl fmt::Display for U1X {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first_elem = true;
        let mut output = String::from("U1(");
        if self.r.len() > 0 {
            let r_str = if first_elem {
                first_elem = false;
                format!("R={}", self.r)
            } else {
                format!("%R={}", self.r)
            };
            output += &r_str;
        }
        if self.df.len() > 0 {
            let df_str = if first_elem {
                first_elem = false;
                format!("DF={}", self.df)
            } else {
                format!("%DF={}", self.df)
            };
            output += &df_str;
        }
        if self.t > 0 {
            let t_str = if first_elem {
                first_elem = false;
                // format!("T={:X}", self.t)
                format!("TG={:X}", self.t)
            } else {
                // format!("%T={:X}", self.t)
                format!("%TG={:X}", self.t)
            };
            output += &t_str;
        } else if self.tg > 0 {
            // This TTL guess field is not printed in a subject fingerprint if the actual TTL (T) value was discovered.
            let tg_str = if first_elem {
                first_elem = false;
                format!("TG={}", self.tg)
            } else {
                format!("%TG={}", self.tg)
            };
            output += &tg_str;
        }
        if self.ipl > 0 {
            let ipl_str = if first_elem {
                first_elem = false;
                format!("IPL={:X}", self.ipl)
            } else {
                format!("%IPL={:X}", self.ipl)
            };
            output += &ipl_str;
        }
        let un_str = if first_elem {
            first_elem = false;
            format!("UN={:X}", self.un)
        } else {
            format!("%UN={:X}", self.un)
        };
        output += &un_str;
        if self.ripl.len() > 0 {
            let ripl_str = if first_elem {
                first_elem = false;
                format!("RIPL={}", self.ripl)
            } else {
                format!("%RIPL={}", self.ripl)
            };
            output += &ripl_str;
        }
        if self.rid.len() > 0 {
            let rid_str = if first_elem {
                first_elem = false;
                format!("RID={}", self.rid)
            } else {
                format!("%RID={}", self.rid)
            };
            output += &rid_str;
        }
        if self.ripck.len() > 0 {
            let ripck_str = if first_elem {
                first_elem = false;
                format!("RIPCK={}", self.ripck)
            } else {
                format!("%RIPCK={}", self.ripck)
            };
            output += &ripck_str;
        }
        if self.ruck.len() > 0 {
            let ruck_str = if first_elem {
                first_elem = false;
                format!("RUCK={}", self.ruck)
            } else {
                format!("%RUCK={}", self.ruck)
            };
            output += &ruck_str;
        }
        if self.rud.len() > 0 {
            let rud_str = if first_elem {
                // first_elem = false;
                format!("RUD={}", self.rud)
            } else {
                format!("%RUD={}", self.rud)
            };
            output += &rud_str;
        }
        output += ")";
        write!(f, "{}", output)
    }
}

pub fn u1_fingerprint(ap: &AllRRPacket) -> Result<U1X> {
    let r = tcp_udp_icmp_r(&ap.u1.u1.response)?;
    let (df, t, tg, ipl, un, ripl, rid, ripck, ruck, rud) = match r.as_str() {
        "Y" => {
            let df = tcp_udp_df(&ap.u1.u1.response)?;
            let t = tcp_udp_icmp_t(&ap.u1.u1.response, &ap.u1)?;
            let tg = tcp_udp_icmp_tg(&ap.u1.u1.response)?;
            let ipl = udp_ipl(&ap.u1)?;
            let un = udp_un(&ap.u1)?;
            let ripl = udp_ripl(&ap.u1)?;
            let rid = udp_rid(&ap.u1)?;
            let ripck = udp_ripck(&ap.u1)?;
            let ruck = udp_ruck(&ap.u1)?;
            let rud = udp_rud(&ap.u1)?;

            (df, t, tg, ipl, un, ripl, rid, ripck, ruck, rud)
        }
        _ => {
            let df = String::new();
            let t = 0;
            let tg = 0;
            let ipl = 0;
            let un = 0;
            let ripl = String::new();
            let rid = String::new();
            let ripck = String::new();
            let ruck = String::new();
            let rud = String::new();

            (df, t, tg, ipl, un, ripl, rid, ripck, ruck, rud)
        }
    };

    Ok(U1X {
        r,
        df,
        t,
        tg,
        ipl,
        un,
        ripl,
        rid,
        ripck,
        ruck,
        rud,
    })
}

pub struct IEX {
    // R, DFI, T, TG, and CD tests.
    pub r: String,
    pub dfi: String,
    pub t: u16,
    pub tg: u8,
    pub cd: String,
}

impl fmt::Display for IEX {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first_elem = true;
        let mut output = String::from("IE(");
        if self.r.len() > 0 {
            let r_str = if first_elem {
                first_elem = false;
                format!("R={}", self.r)
            } else {
                format!("%R={}", self.r)
            };
            output += &r_str;
        }
        if self.dfi.len() > 0 {
            let dfi_str = if first_elem {
                first_elem = false;
                format!("DFI={}", self.dfi)
            } else {
                format!("%DFI={}", self.dfi)
            };
            output += &dfi_str;
        }
        if self.t > 0 {
            let t_str = if first_elem {
                first_elem = false;
                // format!("T={:X}", self.t)
                format!("TG={:X}", self.t)
            } else {
                // format!("%T={:X}", self.t)
                format!("%TG={:X}", self.t)
            };
            output += &t_str;
        } else if self.tg > 0 {
            // This TTL guess field is not printed in a subject fingerprint if the actual TTL (T) value was discovered.
            let tg_str = if first_elem {
                first_elem = false;
                format!("TG={}", self.tg)
            } else {
                format!("%TG={}", self.tg)
            };
            output += &tg_str;
        }
        if self.cd.len() > 0 {
            let cd_str = if first_elem {
                // first_elem = false;
                format!("CD={}", self.cd)
            } else {
                format!("%CD={}", self.cd)
            };
            output += &cd_str;
        }
        output += ")";
        write!(f, "{}", output)
    }
}

pub fn ie_fingerprint(ap: &AllRRPacket) -> Result<IEX> {
    let r1 = tcp_udp_icmp_r(&ap.ie.ie1.response)?;
    let r2 = tcp_udp_icmp_r(&ap.ie.ie2.response)?;
    let (r, dfi, t, tg, cd) = if r1 == "Y" && r2 == "Y" {
        // The R value is only true (Y) if both probes elicit responses.
        let r = String::from("Y");
        let dfi = icmp_dfi(&ap.ie)?;
        let t = tcp_udp_icmp_t(&ap.ie.ie1.response, &ap.u1)?;
        let tg = tcp_udp_icmp_tg(&ap.ie.ie1.response)?;
        let cd = icmp_cd(&ap.ie)?;

        (r, dfi, t, tg, cd)
    } else {
        let r = String::from("N");
        let dfi = String::new();
        let t = 0;
        let tg = 0;
        let cd = String::new();

        (r, dfi, t, tg, cd)
    };

    Ok(IEX { r, dfi, t, tg, cd })
}

pub struct NmapFingerprint {
    pub scan: String,
    pub seqx: SEQX,
    pub opsx: OPSX,
    pub winx: WINX,
    pub ecnx: ECNX,
    pub t1x: TXX,
    pub t2x: TXX,
    pub t3x: TXX,
    pub t4x: TXX,
    pub t5x: TXX,
    pub t6x: TXX,
    pub t7x: TXX,
    pub u1x: U1X,
    pub iex: IEX,
}

impl fmt::Display for NmapFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = format!("{}", self.scan);
        let seqx_str = format!("\n{}", self.seqx);
        let opsx_str = format!("\n{}", self.opsx);
        let winx_str = format!("\n{}", self.winx);
        let ecnx_str = format!("\n{}", self.ecnx);
        let t1x_str = format!("\n{}", self.t1x);
        let t2x_str = format!("\n{}", self.t2x);
        let t3x_str = format!("\n{}", self.t3x);
        let t4x_str = format!("\n{}", self.t4x);
        let t5x_str = format!("\n{}", self.t5x);
        let t6x_str = format!("\n{}", self.t6x);
        let t7x_str = format!("\n{}", self.t7x);
        let u1x_str = format!("\n{}", self.u1x);
        let iex_str = format!("\n{}", self.iex);
        output += &seqx_str;
        output += &opsx_str;
        output += &winx_str;
        output += &ecnx_str;
        output += &t1x_str;
        output += &t2x_str;
        output += &t3x_str;
        output += &t4x_str;
        output += &t5x_str;
        output += &t6x_str;
        output += &t7x_str;
        output += &u1x_str;
        output += &iex_str;
        write!(f, "{}", output)
    }
}

pub fn os_probe(
    src_ipv4: Ipv4Addr,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_open_tcp_port: u16,
    dst_closed_tcp_port: u16,
    dst_closed_udp_port: u16,
    max_loop: usize,
    read_timeout: Duration,
) -> Result<NmapFingerprint> {
    let ap = send_all_probes(
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_open_tcp_port,
        dst_closed_tcp_port,
        dst_closed_udp_port,
        max_loop,
        read_timeout,
    )?;

    let dst_mac = find_mac_by_src_ip(&src_ipv4);
    let hops = None;
    let good_results = true;
    let scan = get_scan_line(
        dst_mac,
        dst_open_tcp_port,
        dst_closed_tcp_port,
        dst_closed_udp_port,
        dst_ipv4,
        hops,
        good_results,
    );

    // Use seq to judge target is alive or not.
    let seqx = seq_fingerprint(&ap);
    match seqx {
        Ok(seqx) => {
            let opsx = ops_fingerprint(&ap)?;
            let winx = win_fingerprint(&ap)?;
            let ecnx = ecn_fingerprint(&ap)?;
            let (t1x, t2x, t3x, t4x, t5x, t6x, t7x) = tx_fingerprint(&ap)?;
            let u1x = u1_fingerprint(&ap)?;
            let iex = ie_fingerprint(&ap)?;

            Ok(NmapFingerprint {
                scan,
                seqx,
                opsx,
                winx,
                ecnx,
                t1x,
                t2x,
                t3x,
                t4x,
                t5x,
                t6x,
                t7x,
                u1x,
                iex,
            })
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_detect() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        let src_port = None;
        let dst_open_tcp_port = 80;
        let dst_closed_tcp_port = 9999;
        let dst_closed_udp_port = 11111;
        let max_loop = 8;
        let read_timeout = Duration::from_secs_f32(0.5);

        let _ = os_probe(
            src_ipv4,
            src_port,
            dst_ipv4,
            dst_open_tcp_port,
            dst_closed_tcp_port,
            dst_closed_udp_port,
            max_loop,
            read_timeout,
        )
        .unwrap();
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
}
