use anyhow::Result;
use chrono::{DateTime, Local, Utc};
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
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::{icmp_packet_iter, ipv4_packet_iter, tcp_packet_iter};
use rand::Rng;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::TcpStream;
use std::sync::mpsc::channel;
use std::thread::sleep;
use std::time::Duration;

use crate::fingerprinting::packet;
use crate::utils::gcd_vec;
use crate::utils::get_threads_pool;
use crate::utils::return_layer3_icmp_channel;
use crate::utils::return_layer3_tcp_channel;
use crate::utils::return_layer3_udp_channel;
use crate::utils::standard_deviation_vec;
use crate::utils::ICMP_BUFF_SIZE;
use crate::utils::TCP_BUFF_SIZE;
use crate::utils::UDP_BUFF_SIZE;

#[derive(Debug)]
struct SEQ {
    seq: u32,
    id: u16,
    tsval: u32,
    o: String,
    window: u16,
    r: String,
    df: String,
}

#[derive(Debug)]
struct IE {
    id: u16,
    odfi: String,
    dfi: String,
}

#[derive(Debug)]
struct U1 {
    t: u8,
    tg: u8,
}

#[derive(Debug)]
pub struct ProbeResults {
    pub gcd: u32,
    pub isr: f32,
    pub sp: f32,
    pub ti: String,
    pub ci: String,
    pub ii: String,
    pub ss: String,
    pub ts: String,
    pub o1: String,
    pub o2: String,
    pub o3: String,
    pub o4: String,
    pub o5: String,
    pub o6: String,
    pub w1: u16,
    pub w2: u16,
    pub w3: u16,
    pub w4: u16,
    pub w5: u16,
    pub w6: u16,
    pub df: String,
    pub dfi: String,
    pub t: u8,
    pub tg: u8,
}

fn tcp_packet_get_info(tcp_packet: TcpPacket) -> (u32, u32, String, u16) {
    let seq = tcp_packet.get_sequence();
    let options_vec = tcp_packet.get_options();
    let mut tsval_vec = Vec::new();
    let mut o = String::from("");
    let window = tcp_packet.get_window();
    for option in options_vec {
        match option.number {
            TcpOptionNumbers::EOL => {
                o = format!("{}{}", o, "L");
            }
            TcpOptionNumbers::NOP => {
                o = format!("{}{}", o, "N");
            }
            TcpOptionNumbers::MSS => {
                o = format!("{}{}", o, "M");
                let mut data = 0;
                let mut i = option.data.len();
                for d in &option.data {
                    let t = *d as u32;
                    data += t << ((i - 1) * 8);
                    i -= 1;
                }
                o = format!("{}{:X}", o, data);
            }
            TcpOptionNumbers::WSCALE => {
                o = format!("{}{}", o, "W");
                let mut data = 0;
                let mut i = option.data.len();
                for d in &option.data {
                    let t = *d as u32;
                    data += t << ((i - 1) * 8);
                    i -= 1;
                }
                o = format!("{}{:X}", o, data);
            }
            TcpOptionNumbers::TIMESTAMPS => {
                o = format!("{}{}", o, "T");
                let mut t0 = Vec::new();
                let mut t1 = Vec::new();
                for i in 0..option.data.len() {
                    if i < 4 {
                        // get first 4 u8 values
                        tsval_vec.push(option.data[i]);
                        t0.push(option.data[i]);
                    } else {
                        t1.push(option.data[i]);
                    }
                }
                let mut t0_u32 = 0;
                let mut t1_u32 = 0;
                let mut i = t0.len();
                for d in &t0 {
                    let t = *d as u32;
                    t0_u32 += t << ((i - 1) * 8);
                    i -= 1;
                }
                let mut i = t1.len();
                for d in &t1 {
                    let t = *d as u32;
                    t1_u32 += t << ((i - 1) * 8);
                    i -= 1;
                }
                if t0_u32 == 0 {
                    o = format!("{}{}", o, 0);
                } else {
                    o = format!("{}{}", o, 1);
                }
                if t1_u32 == 0 {
                    o = format!("{}{}", o, 0);
                } else {
                    o = format!("{}{}", o, 1);
                }
            }
            TcpOptionNumbers::SACK_PERMITTED => {
                o = format!("{}{}", o, "S");
            }
            _ => (), // do nothing
        }
    }
    let mut tsval = 0;
    let mut i = tsval_vec.len();
    for t in &tsval_vec {
        let t = *t as u32;
        tsval += t << ((i - 1) * 8);
        i -= 1;
    }
    (seq, tsval, o, window)
}

fn send_six_seq_probes(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_open_port: u16,
) -> Result<HashMap<usize, SEQ>> {
    let max_loop = 32;
    let read_timeout = Duration::from_secs_f32(9.0);

    // 6 packets with 6 threads
    let pool = get_threads_pool(6);
    let (tx, rx) = channel();

    let buff_1 = packet::seq_packet_1_layer3(src_ipv4, src_port, dst_ipv4, dst_open_port)?;
    let buff_2 = packet::seq_packet_2_layer3(src_ipv4, src_port, dst_ipv4, dst_open_port)?;
    let buff_3 = packet::seq_packet_3_layer3(src_ipv4, src_port, dst_ipv4, dst_open_port)?;
    let buff_4 = packet::seq_packet_4_layer3(src_ipv4, src_port, dst_ipv4, dst_open_port)?;
    let buff_5 = packet::seq_packet_5_layer3(src_ipv4, src_port, dst_ipv4, dst_open_port)?;
    let buff_6 = packet::seq_packet_6_layer3(src_ipv4, src_port, dst_ipv4, dst_open_port)?;

    let buffs = vec![buff_1, buff_2, buff_3, buff_4, buff_5, buff_6];
    let mut recv_size = 0;
    for buff in buffs {
        recv_size += 1;
        let tx = tx.clone();
        pool.execute(move || {
            let (mut tcp_tx, mut tcp_rx) = return_layer3_tcp_channel(TCP_BUFF_SIZE).unwrap();
            let packet = Ipv4Packet::new(&buff).unwrap();
            match tcp_tx.send_to(&packet, dst_ipv4.into()) {
                Ok(n) => {
                    if n == buff.len() {
                        let mut tcp_iter = ipv4_packet_iter(&mut tcp_rx);
                        let mut send_flag = false;
                        for _ in 0..max_loop {
                            match tcp_iter.next_with_timeout(read_timeout) {
                                Ok(r) => match r {
                                    Some((ipv4_packet, addr)) => {
                                        if addr == dst_ipv4 {
                                            if ipv4_packet.get_next_level_protocol()
                                                == IpNextHeaderProtocols::Tcp
                                            {
                                                let tcp_packet =
                                                    TcpPacket::new(ipv4_packet.payload()).unwrap();
                                                if tcp_packet.get_source() == dst_open_port
                                                    && tcp_packet.get_destination() == src_port
                                                {
                                                    let id = ipv4_packet.get_identification();
                                                    let (seq, tsval, o, window) =
                                                        tcp_packet_get_info(tcp_packet);

                                                    let df = if packet.get_flags()
                                                        == Ipv4Flags::DontFragment
                                                    {
                                                        String::from("Y")
                                                    } else {
                                                        String::from("N")
                                                    };
                                                    let send_value = Some((
                                                        recv_size, seq, id, tsval, o, window, df,
                                                    ));
                                                    match tx.send(Ok(send_value)) {
                                                        _ => (),
                                                    }
                                                    send_flag = true;
                                                    // get what we need, so break
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    _ => (), // do nothing
                                },
                                Err(e) => {
                                    match tx.send(Err(e)) {
                                        _ => (),
                                    }
                                    send_flag = true;
                                    // error break
                                    break;
                                }
                            }
                        }
                        if !send_flag {
                            match tx.send(Ok(None)) {
                                _ => (),
                            }
                        }
                    } else {
                        match tx.send(Ok(None)) {
                            _ => (),
                        }
                    };
                }
                Err(e) => match tx.send(Err(e)) {
                    _ => (),
                },
            }
        });
        // the probes are sent exactly 100 milliseconds apart so the total time taken is 500 ms
        sleep(Duration::from_millis(100));
    }

    let mut result = HashMap::new();
    let iter = rx.into_iter().take(recv_size);
    for ret in iter {
        match ret {
            Ok(v) => match v {
                Some((packet_id, seq, id, tsval, o, window, df)) => {
                    let r = if seq == 0 && id == 0 && tsval == 0 && window == 0 && o.len() == 0 {
                        String::from("N")
                    } else {
                        String::from("Y")
                    };
                    let data = SEQ {
                        seq,
                        id,
                        tsval,
                        o,
                        window,
                        r,
                        df,
                    };
                    result.insert(packet_id, data);
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }

    Ok(result)
}

fn send_t5_t6_t7_probes(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_closed_port: u16,
) -> Result<HashMap<usize, SEQ>> {
    let max_loop = 32;
    let read_timeout = Duration::from_secs_f32(9.0);

    // 6 packets with 6 threads
    let pool = get_threads_pool(6);
    let (tx, rx) = channel();

    let buff_1 = packet::t5_packet_layer3(src_ipv4, src_port, dst_ipv4, dst_closed_port)?;
    let buff_2 = packet::t6_packet_layer3(src_ipv4, src_port, dst_ipv4, dst_closed_port)?;
    let buff_3 = packet::t7_packet_layer3(src_ipv4, src_port, dst_ipv4, dst_closed_port)?;

    let buffs = vec![buff_1, buff_2, buff_3];
    let mut recv_size = 0;
    for buff in buffs {
        recv_size += 1;
        let tx = tx.clone();
        pool.execute(move || {
            let (mut tcp_tx, mut tcp_rx) = return_layer3_tcp_channel(TCP_BUFF_SIZE).unwrap();
            let packet = Ipv4Packet::new(&buff).unwrap();
            match tcp_tx.send_to(&packet, dst_ipv4.into()) {
                Ok(n) => {
                    if n == buff.len() {
                        let mut tcp_iter = ipv4_packet_iter(&mut tcp_rx);
                        let mut send_flag = false;
                        for _ in 0..max_loop {
                            match tcp_iter.next_with_timeout(read_timeout) {
                                Ok(r) => match r {
                                    Some((ipv4_packet, addr)) => {
                                        if addr == dst_ipv4 {
                                            if ipv4_packet.get_next_level_protocol()
                                                == IpNextHeaderProtocols::Tcp
                                            {
                                                let tcp_packet =
                                                    TcpPacket::new(ipv4_packet.payload()).unwrap();
                                                if tcp_packet.get_source() == dst_closed_port
                                                    && tcp_packet.get_destination() == src_port
                                                {
                                                    let id = ipv4_packet.get_identification();
                                                    let (seq, tsval, o, window) =
                                                        tcp_packet_get_info(tcp_packet);
                                                    let df = if packet.get_flags()
                                                        == Ipv4Flags::DontFragment
                                                    {
                                                        String::from("Y")
                                                    } else {
                                                        String::from("N")
                                                    };
                                                    match tx.send(Ok(Some((
                                                        recv_size, seq, id, tsval, o, window, df,
                                                    )))) {
                                                        _ => (),
                                                    }
                                                    send_flag = true;
                                                    // get what we need, so break
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    _ => (), // do nothing
                                },
                                Err(e) => {
                                    match tx.send(Err(e)) {
                                        _ => (),
                                    }
                                    send_flag = true;
                                    // error break
                                    break;
                                }
                            }
                        }
                        if !send_flag {
                            match tx.send(Ok(None)) {
                                _ => (),
                            }
                        }
                    } else {
                        match tx.send(Ok(None)) {
                            _ => (),
                        }
                    };
                }
                Err(e) => match tx.send(Err(e)) {
                    _ => (),
                },
            }
        });
        // the probes are sent exactly 100 milliseconds apart so the total time taken is 500 ms
        sleep(Duration::from_millis(100));
    }

    let mut result = HashMap::new();
    let iter = rx.into_iter().take(recv_size);
    for ret in iter {
        match ret {
            Ok(r) => match r {
                Some((packet_id, seq, id, tsval, o, window, df)) => {
                    let r = if seq == 0 && id == 0 && tsval == 0 && window == 0 && o.len() == 0 {
                        String::from("N")
                    } else {
                        String::from("Y")
                    };
                    let data = SEQ {
                        seq,
                        id,
                        tsval,
                        o,
                        window,
                        r,
                        df,
                    };
                    result.insert(packet_id, data);
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }

    Ok(result)
}

fn send_ie_probes(src_ipv4: Ipv4Addr, dst_ipv4: Ipv4Addr) -> Result<HashMap<usize, IE>> {
    const ICMP_DATA_LEN: usize = 120;
    let max_loop = 32;
    let read_timeout = Duration::from_secs_f32(9.0);

    // 6 packets with 6 threads
    let pool = get_threads_pool(6);
    let (tx, rx) = channel();

    let (buff_1, icmp_id) = packet::icmp_echo_packet_1_layer3(src_ipv4, dst_ipv4)?;
    let buff_2 = packet::icmp_echo_packet_2_layer3(src_ipv4, dst_ipv4, icmp_id)?;

    let buffs = vec![buff_1, buff_2];
    let mut recv_size = 0;
    for buff in buffs {
        recv_size += 1;
        let tx = tx.clone();
        pool.execute(move || {
            let (mut icmp_tx, mut icmp_rx) = return_layer3_icmp_channel(ICMP_BUFF_SIZE).unwrap();
            let packet = Ipv4Packet::new(&buff).unwrap();
            match icmp_tx.send_to(&packet, dst_ipv4.into()) {
                Ok(n) => {
                    // two ie packet had diffierent length
                    if n > 0 {
                        let mut icmp_iter = ipv4_packet_iter(&mut icmp_rx);
                        let mut send_flag = false;
                        for _ in 0..max_loop {
                            match icmp_iter.next_with_timeout(read_timeout) {
                                Ok(r) => match r {
                                    Some((ipv4_packet, addr)) => {
                                        if addr == dst_ipv4 {
                                            if ipv4_packet.get_next_level_protocol()
                                                == IpNextHeaderProtocols::Icmp
                                            {
                                                let id = ipv4_packet.get_identification();
                                                let odfi = if packet.get_flags()
                                                    == Ipv4Flags::DontFragment
                                                {
                                                    String::from("Y")
                                                } else {
                                                    String::from("N")
                                                };
                                                let dfi = if ipv4_packet.get_flags()
                                                    == Ipv4Flags::DontFragment
                                                {
                                                    String::from("Y")
                                                } else {
                                                    String::from("N")
                                                };
                                                // (packet_id, ip_id, dfi)
                                                match tx.send(Ok(Some((recv_size, id, odfi, dfi))))
                                                {
                                                    _ => (),
                                                }
                                                send_flag = true;
                                                // get what we need, so break
                                                break;
                                            }
                                        }
                                    }
                                    _ => (), // do nothing
                                },
                                Err(e) => {
                                    match tx.send(Err(e)) {
                                        _ => (),
                                    }
                                    send_flag = true;
                                    // error break
                                    break;
                                }
                            }
                        }
                        if !send_flag {
                            match tx.send(Ok(None)) {
                                _ => (),
                            }
                        }
                    } else {
                        match tx.send(Ok(None)) {
                            _ => (),
                        }
                    };
                }
                Err(e) => match tx.send(Err(e)) {
                    _ => (),
                },
            }
        });
        // the probes are sent exactly 100 milliseconds apart so the total time taken is 500 ms
        sleep(Duration::from_millis(100));
    }

    let mut result = HashMap::new();
    let iter = rx.into_iter().take(recv_size);
    for ret in iter {
        match ret {
            Ok(r) => match r {
                Some((packet_id, id, odfi, dfi)) => {
                    let data = IE { id, odfi, dfi };
                    result.insert(packet_id, data);
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }

    Ok(result)
}

fn send_u1_probe(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_closed_port: u16,
) -> Result<U1> {
    const ICMP_DATA_LEN: usize = 120;
    let max_loop = 32;
    let read_timeout = Duration::from_secs_f32(9.0);

    let buff = packet::udp_packet_layer3(src_ipv4, src_port, dst_ipv4, dst_closed_port)?;
    let (mut udp_tx, _) = return_layer3_udp_channel(UDP_BUFF_SIZE).unwrap();
    let (_, mut icmp_rx) = return_layer3_icmp_channel(ICMP_BUFF_SIZE).unwrap();

    let packet = Ipv4Packet::new(&buff).unwrap();
    match udp_tx.send_to(&packet, dst_ipv4.into()) {
        Ok(n) => assert_eq!(n, buff.len()),
        Err(e) => return Err(e.into()),
    }

    let mut icmp_iter = ipv4_packet_iter(&mut icmp_rx);
    let packet_ttl_1 = packet.get_ttl();
    let mut htops = 0;
    let mut response_ttl = 0;

    let mut recv_packet = false;
    for _ in 0..max_loop {
        match icmp_iter.next_with_timeout(read_timeout) {
            Ok(r) => match r {
                Some((ipv4_packet, addr)) => {
                    if addr == dst_ipv4 {
                        if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                            // the UDP packet was send to closed port, ICMP should be return first
                            response_ttl = ipv4_packet.get_ttl();
                            let icmp_packet = IcmpPacket::new(ipv4_packet.payload()).unwrap();
                            let unreachable_ip_packet =
                                Ipv4Packet::new(icmp_packet.payload()).unwrap();
                            let packet_ttl_2 = unreachable_ip_packet.get_ttl();
                            htops = packet_ttl_1 - packet_ttl_2;
                            // get what we need, so break
                            recv_packet = true;
                            break;
                        }
                    }
                }
                _ => (), // do nothing
            },
            Err(e) => return Err(e.into()),
        }
    }
    let tg = if recv_packet {
        0
    } else {
        if response_ttl <= 32 {
            32
        } else if response_ttl <= 64 && response_ttl > 32 {
            64
        } else if response_ttl <= 128 && response_ttl > 64 {
            128
        } else if response_ttl > 128 {
            255
        } else {
            0
        }
    };

    let t = response_ttl + htops;
    let result = U1 { t, tg };

    Ok(result)
}

pub fn return_scan_line(
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

pub fn return_seq_line(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_open_port: u16,
    dst_closed_port: u16,
) -> Result<String> {
    let sq_response = send_six_seq_probes(src_ipv4, src_port, dst_ipv4, dst_open_port)?;
    let t5_t6_t7_response = send_t5_t6_t7_probes(src_ipv4, src_port, dst_ipv4, dst_closed_port)?;
    let ie_response = send_ie_probes(src_ipv4, dst_ipv4)?;
    // GCD
    let mut diff1: Vec<u32> = Vec::new();
    for i in 1..sq_response.len() {
        let sq_x = sq_response.get(&i).unwrap();
        let sq_y = sq_response.get(&(i + 1)).unwrap();
        let rseq_x = sq_x.seq;
        let rseq_y = sq_y.seq;
        let diff = if rseq_x < rseq_y {
            rseq_y - rseq_x
        } else {
            !(rseq_y - rseq_x)
        };
        diff1.push(diff);
    }
    // println!("{:?}", diffs);
    let gcd = gcd_vec(&mut diff1.clone());
    // println!("{:?}", diffs);
    // println!("{}", gcd);

    // ISR
    let mut seq_rates: Vec<f32> = Vec::new();
    let mut sum_seq_rates = 0.0;
    for d in diff1 {
        let f = (d as f32) / 0.1;
        sum_seq_rates += f;
        seq_rates.push(f);
    }
    let average_seq_rate = sum_seq_rates / 5.0;
    let isr = if average_seq_rate < 1.0 {
        0.0
    } else {
        8.0 * average_seq_rate.log2()
    };

    // SP
    if gcd > 9 {
        for i in 0..seq_rates.len() {
            seq_rates[i] /= gcd as f32;
        }
    }

    let sd = standard_deviation_vec(&seq_rates);
    let sp = if sd <= 1.0 {
        0.0
    } else {
        (8.0 * sd.log2()).round()
    };

    // TI
    let vec_all_zero_u16 = |values_vec: &Vec<u16>| -> bool {
        let mut zero_num = 0;
        for id in values_vec {
            if *id == 0 {
                zero_num += 1;
            }
        }
        if zero_num == values_vec.len() {
            true
        } else {
            false
        }
    };
    let diff1_ge_20000_u16 = |diff1: &Vec<u16>| -> bool {
        let mut id_min = u16::MAX;
        for diff in diff1 {
            if *diff < id_min {
                id_min = *diff;
            }
        }
        if id_min >= 20000 {
            true
        } else {
            false
        }
    };
    let vec_all_same_u16 = |ip_id_vec: &Vec<u16>| -> bool {
        let mut all_same = true;
        for i in 0..(ip_id_vec.len() - 1) {
            if ip_id_vec[i] != ip_id_vec[i + 1] {
                all_same = false;
            }
        }
        all_same
    };
    let diff1_ge_1000_u16 = |diff1: &Vec<u16>| -> bool {
        let mut id_min = u16::MAX;
        let mut evenly_divisible = true;
        for diff in diff1 {
            if *diff < id_min {
                id_min = *diff;
            }
            if *diff % 256 != 0 {
                evenly_divisible = false;
            }
        }
        if id_min >= 1000 && !evenly_divisible {
            true
        } else {
            false
        }
    };
    let diff1_divisible_by_256_u16 = |diff1: &Vec<u16>| -> bool {
        let mut id_max = u16::MIN;
        let mut evenly_divisible = true;
        for diff in diff1 {
            if *diff > id_max {
                id_max = *diff;
            }
            if *diff % 256 != 0 {
                evenly_divisible = false;
            }
        }
        if id_max <= 5120 && evenly_divisible {
            true
        } else {
            false
        }
    };
    let diff1_le_10_u16 = |diff1: &Vec<u16>| -> bool {
        let mut id_max = u16::MIN;
        for diff in diff1 {
            if *diff > id_max {
                id_max = *diff;
            }
        }
        if id_max <= 10 {
            true
        } else {
            false
        }
    };

    let mut ip_id_vec = Vec::new();
    for i in 1..=sq_response.len() {
        let sq = sq_response.get(&i).unwrap();
        ip_id_vec.push(sq.id);
    }
    let mut ip_id_diff1 = Vec::new();
    for i in 0..(ip_id_vec.len() - 1) {
        let id_x = ip_id_vec[i];
        let id_y = ip_id_vec[i + 1];
        let diff = if id_x < id_y {
            id_y - id_x
        } else {
            !(id_y - id_x)
        };
        ip_id_diff1.push(diff);
    }
    let ti = if vec_all_zero_u16(&ip_id_vec) {
        // If all of the ID numbers are zero, the value of the test is Z.
        String::from("Z")
    } else if diff1_ge_20000_u16(&ip_id_diff1) {
        // If the IP ID sequence ever increases by at least 20,000, the value is RD (random).
        // This result isn't possible for II because there are not enough samples to support it.
        String::from("RD")
    } else if vec_all_same_u16(&ip_id_vec) {
        // If all of the IP IDs are identical, the test is set to that value in hex.
        format!("{:X}", ip_id_vec[0])
    } else if diff1_ge_1000_u16(&ip_id_diff1) {
        // If any of the differences between two consecutive IDs exceeds 1,000, and is not evenly divisible by 256,
        // the test's value is RI (random positive increments).
        // If the difference is evenly divisible by 256, it must be at least 256,000 to cause this RI result.
        String::from("RI")
    } else if diff1_divisible_by_256_u16(&ip_id_diff1) {
        // If all of the differences are divisible by 256 and no greater than 5,120, the test is set to BI (broken increment).
        // This happens on systems like Microsoft Windows where the IP ID is sent in host byte order rather than network byte order.
        // It works fine and isn't any sort of RFC violation, though it does give away host architecture details which can be useful to attackers.
        String::from("BI")
    } else if diff1_le_10_u16(&ip_id_diff1) {
        // If all of the differences are less than ten, the value is I (incremental).
        // We allow difference up to ten here (rather than requiring sequential ordering) because traffic from other hosts can cause sequence gaps.
        String::from("I")
    } else {
        // If none of the previous steps identify the generation algorithm, the test is omitted from the fingerprint.
        String::from("")
    };

    // CI
    let mut t_ip_id_vec = Vec::new();
    for i in 1..=t5_t6_t7_response.len() {
        let sq = t5_t6_t7_response.get(&i).unwrap();
        t_ip_id_vec.push(sq.id);
    }
    let mut t_ip_id_diff1 = Vec::new();
    for i in 0..(t_ip_id_vec.len() - 1) {
        let id_x = t_ip_id_vec[i];
        let id_y = t_ip_id_vec[i + 1];
        let diff = if id_x < id_y {
            id_y - id_x
        } else {
            !(id_y - id_x)
        };
        t_ip_id_diff1.push(diff);
    }
    let ci = if vec_all_zero_u16(&t_ip_id_vec) {
        // If all of the ID numbers are zero, the value of the test is Z.
        String::from("Z")
    } else if diff1_ge_20000_u16(&t_ip_id_diff1) {
        // If the IP ID sequence ever increases by at least 20,000, the value is RD (random).
        // This result isn't possible for II because there are not enough samples to support it.
        String::from("RD")
    } else if vec_all_same_u16(&t_ip_id_vec) {
        // If all of the IP IDs are identical, the test is set to that value in hex.
        format!("{:X}", t_ip_id_vec[0])
    } else if diff1_ge_1000_u16(&t_ip_id_diff1) {
        // If any of the differences between two consecutive IDs exceeds 1,000, and is not evenly divisible by 256,
        // the test's value is RI (random positive increments).
        // If the difference is evenly divisible by 256, it must be at least 256,000 to cause this RI result.
        String::from("RI")
    } else if diff1_divisible_by_256_u16(&t_ip_id_diff1) {
        // If all of the differences are divisible by 256 and no greater than 5,120, the test is set to BI (broken increment).
        // This happens on systems like Microsoft Windows where the IP ID is sent in host byte order rather than network byte order.
        // It works fine and isn't any sort of RFC violation, though it does give away host architecture details which can be useful to attackers.
        String::from("BI")
    } else if diff1_le_10_u16(&t_ip_id_diff1) {
        // If all of the differences are less than ten, the value is I (incremental).
        // We allow difference up to ten here (rather than requiring sequential ordering) because traffic from other hosts can cause sequence gaps.
        String::from("I")
    } else {
        // If none of the previous steps identify the generation algorithm, the test is omitted from the fingerprint.
        String::from("")
    };

    // II
    let mut ie_ip_id_vec = Vec::new();
    for i in 1..=ie_response.len() {
        let sq = ie_response.get(&i).unwrap();
        ie_ip_id_vec.push(sq.id);
    }
    let mut ie_ip_id_diff1 = Vec::new();
    for i in 0..(ie_ip_id_vec.len() - 1) {
        let id_x = ie_ip_id_vec[i];
        let id_y = ie_ip_id_vec[i + 1];
        println!("x {} y {}", id_x, id_y);
        let diff = if id_x < id_y {
            id_y - id_x
        } else {
            !(id_y - id_x)
        };
        ie_ip_id_diff1.push(diff);
    }
    let ii = if vec_all_zero_u16(&ie_ip_id_vec) {
        // If all of the ID numbers are zero, the value of the test is Z.
        String::from("Z")
    } else if vec_all_same_u16(&ie_ip_id_vec) {
        // If all of the IP IDs are identical, the test is set to that value in hex.
        format!("{:X}", ie_ip_id_vec[0])
    } else if diff1_ge_1000_u16(&ie_ip_id_diff1) {
        // If any of the differences between two consecutive IDs exceeds 1,000, and is not evenly divisible by 256,
        // the test's value is RI (random positive increments).
        // If the difference is evenly divisible by 256, it must be at least 256,000 to cause this RI result.
        String::from("RI")
    } else if diff1_divisible_by_256_u16(&ie_ip_id_diff1) {
        // If all of the differences are divisible by 256 and no greater than 5,120, the test is set to BI (broken increment).
        // This happens on systems like Microsoft Windows where the IP ID is sent in host byte order rather than network byte order.
        // It works fine and isn't any sort of RFC violation, though it does give away host architecture details which can be useful to attackers.
        String::from("BI")
    } else if diff1_le_10_u16(&ie_ip_id_diff1) {
        // If all of the differences are less than ten, the value is I (incremental).
        // We allow difference up to ten here (rather than requiring sequential ordering) because traffic from other hosts can cause sequence gaps.
        String::from("I")
    } else {
        // If none of the previous steps identify the generation algorithm, the test is omitted from the fingerprint.
        String::from("")
    };

    // SS
    let ss = if (ii == "RI" || ii == "BI" || ii == "I") && ii == ti {
        // This test is only included if II is RI, BI, or I and TI is the same.
        // If SS is included, the result is S if the sequence is shared and O (other) if it is not.
        let seq_1 = sq_response.get(&1).unwrap();
        let seq_n = sq_response.get(&sq_response.len()).unwrap();
        let difference = if seq_n.id > seq_1.id {
            seq_n.id - seq_n.id
        } else {
            !(seq_n.id - seq_n.id)
        };
        let avg = difference as f32 / (sq_response.len() - 1) as f32;
        let ie_1 = ie_response.get(&1).unwrap();
        if (ie_1.id as f32) < seq_n.id as f32 + 3.0 * avg {
            String::from("S")
        } else {
            String::from("O")
        }
    } else {
        String::from("")
    };

    // TS
    let vec_one_zero_u32 = |ip_id_vec: &Vec<u32>| -> bool {
        let mut zero = false;
        for id in ip_id_vec {
            if *id == 0 {
                zero = true;
            }
        }
        zero
    };
    let vec_all_zero_u32 = |values_vec: &Vec<u32>| -> bool {
        let mut zero_num = 0;
        for id in values_vec {
            if *id == 0 {
                zero_num += 1;
            }
        }
        if zero_num == values_vec.len() {
            true
        } else {
            false
        }
    };
    let vec_avg_u32 = |values_vec: &Vec<u32>| -> usize {
        let mut sum = 0;
        for v in values_vec {
            sum += v;
        }
        let avg = sum as f32 / values_vec.len() as f32;
        if avg >= 0.0 && avg <= 5.66 {
            1
        } else if avg >= 70.0 && avg <= 150.0 {
            7
        } else if avg >= 150.0 && avg <= 350.0 {
            8
        } else {
            0
        }
    };
    let mut tsval_vec = Vec::new();
    for i in 1..(sq_response.len() + 1) {
        let seq = sq_response.get(&i).unwrap();
        let tsval = &seq.tsval;
        // It takes the difference between each consecutive TSval and divides that by the amount of time elapsed
        // between Nmap sending the two probes which generated those responses.
        tsval_vec.push(tsval * 10); // = tsval / 0.1
    }
    let ts = if vec_all_zero_u32(&tsval_vec) {
        // If any of the responses have no timestamp option, TS is set to U (unsupported).
        String::from("U")
    } else if vec_one_zero_u32(&tsval_vec) {
        // If any of the timestamp values are zero, TS is set to 0.
        String::from("0")
    } else if vec_avg_u32(&tsval_vec) != 0 {
        // If the average increments per second falls within the ranges 0-5.66, 70-150, or 150-350, TS is set to 1, 7, or 8, respectively.
        // These three ranges get special treatment because they correspond to the 2 Hz, 100 Hz, and 200 Hz frequencies used by many hosts.
        let v = vec_avg_u32(&tsval_vec);
        format!("{}", v)
    } else {
        // In all other cases, Nmap records the binary logarithm of the average increments per second, rounded to the nearest integer.
        // Since most hosts use 1,000 Hz frequencies, A is a common result.
        String::from("A")
    };

    Ok(format!(
        "SEQ(SP={sp}%GCD={gcd}%ISR={isr}%TI={ti}%CI={ci}%II={ii}%TS={ts})"
    ))
}

pub fn not_finish(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_open_port: u16,
    dst_closed_port: u16,
) -> Result<()> {
    let sq_response = send_six_seq_probes(src_ipv4, src_port, dst_ipv4, dst_open_port)?;
    let t5_t6_t7_response = send_t5_t6_t7_probes(src_ipv4, src_port, dst_ipv4, dst_closed_port)?;
    let ie_response = send_ie_probes(src_ipv4, dst_ipv4)?;
    let u1_response = send_u1_probe(src_ipv4, src_port, dst_ipv4, dst_closed_port)?;

    // O1-O6
    let o1 = sq_response.get(&1).unwrap().o.clone();
    let o2 = sq_response.get(&2).unwrap().o.clone();
    let o3 = sq_response.get(&3).unwrap().o.clone();
    let o4 = sq_response.get(&4).unwrap().o.clone();
    let o5 = sq_response.get(&5).unwrap().o.clone();
    let o6 = sq_response.get(&6).unwrap().o.clone();

    // W1–W6
    let w1 = sq_response.get(&1).unwrap().window;
    let w2 = sq_response.get(&2).unwrap().window;
    let w3 = sq_response.get(&3).unwrap().window;
    let w4 = sq_response.get(&4).unwrap().window;
    let w5 = sq_response.get(&5).unwrap().window;
    let w6 = sq_response.get(&6).unwrap().window;

    // DF
    let df = sq_response.get(&1).unwrap().df.clone();

    // DFI
    let dfi = if ie_response.len() >= 2 {
        let dfi1 = ie_response.get(&1).unwrap().dfi.clone();
        let dfi2 = ie_response.get(&2).unwrap().dfi.clone();
        let odfi1 = ie_response.get(&1).unwrap().odfi.clone();
        let odfi2 = ie_response.get(&2).unwrap().odfi.clone();
        if dfi1 == "N" && dfi2 == "N" {
            // Neither of the ping responses have the DF bit set.
            String::from("N")
        } else if odfi1 == dfi1 && odfi2 == dfi2 {
            // Both responses echo the DF value of the probe.
            String::from("S")
        } else if dfi1 == "Y" && dfi2 == "Y" {
            // Both of the response DF bits are set.
            String::from("Y")
        } else if odfi1 != dfi1 && odfi2 != dfi2 {
            // The one remaining other combination—both responses have the DF bit toggled.
            String::from("O")
        } else {
            String::from("")
        }
    } else {
        String::from("")
    };

    // T
    let t = u1_response.t;

    // TG
    let tg = u1_response.tg;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;
    #[test]
    fn test_scan_str() {
        let dst_mac = MacAddr::new(01, 12, 34, 56, 00, 90);
        let dst_open_tcp_port = 22;
        let dst_closed_tcp_port = 1;
        let dst_closed_udp_port = 42341;
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        return_scan_line(
            Some(dst_mac),
            dst_open_tcp_port,
            dst_closed_tcp_port,
            dst_closed_udp_port,
            dst_ipv4,
            None,
            true,
        );
    }
    #[test]
    fn test_sub() {
        let a: u32 = 0xFFFFFF00;
        let b: u32 = 0xC000;
        println!("{:X}", a);
        assert_eq!(a - b, 0xFFFF3F00);
        assert_eq!(!(a - b), 0xC0FF);
    }
    #[test]
    fn test_sh() {
        let test: Vec<u8> = vec![100, 97, 141, 217];
        let test = &test;
        let mut tsval: u32 = 0;
        let mut i = test.len();
        for t in test {
            println!("{:X}", t);
            let t = *t as u32;
            let t = t << ((i - 1) * 8);
            println!("new {:X}", t);
            tsval += t;
            i -= 1;
        }
        println!("{:X}", tsval)
    }
    #[test]
    fn test_seq() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 206);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 119);
        let src_port = utils::random_port();
        let dst_open_port = 80;
        let dst_closed_port = 81;
        let ret =
            return_seq_line(src_ipv4, src_port, dst_ipv4, dst_open_port, dst_closed_port).unwrap();
        println!("{:?}", ret);
    }
}
