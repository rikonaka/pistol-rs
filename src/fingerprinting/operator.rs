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
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

use super::osscan::{RequestAndResponse, ECNRR, IERR, SEQRR, T2T7RR, U1RR};

use crate::utils::Hex;

fn get_tcp_seq(ipv4_buff: &Vec<u8>) -> Option<u32> {
    match Ipv4Packet::new(&ipv4_buff) {
        Some(ipv4_packet) => match TcpPacket::new(ipv4_packet.payload()) {
            Some(tcp_packet) => Some(tcp_packet.get_sequence()),
            None => None,
        },
        None => None,
    }
}

fn get_diff_u32(input: &Vec<u32>) -> Vec<u32> {
    let mut vec_1 = Vec::new();
    vec_1.push(0);
    vec_1.extend(input.clone()); // [0, 1, 2]
    let mut vec_2 = input.clone();
    vec_2.push(u32::MAX); // [1, 2, 0]

    let mut diff = Vec::new();
    for (x, y) in zip(vec_1, vec_2) {
        let k = if x < y { y - x } else { !(x - y) };
        diff.push(k);
    }
    diff.remove(0);
    if diff.len() > 0 {
        diff.remove(diff.len() - 1);
    }

    diff
}

fn get_diff_u16(input: &Vec<u16>) -> Vec<u16> {
    let mut vec_1 = Vec::new();
    vec_1.push(0);
    vec_1.extend(input.clone()); // [0, 1, 2]
    let mut vec_2 = input.clone();
    vec_2.push(u16::MAX); // [1, 2, 0]

    let mut diff = Vec::new();
    for (x, y) in zip(vec_1, vec_2) {
        let k = if x < y { y - x } else { !(x - y) };
        diff.push(k);
    }
    diff.remove(0);
    diff.remove(diff.len() - 1);

    diff
}

/// TCP ISN greatest common divisor (GCD)
pub fn tcp_gcd(seqrr: &SEQRR) -> Option<(u32, Vec<u32>)> {
    let s1 = get_tcp_seq(&seqrr.seq1.response);
    let s2 = get_tcp_seq(&seqrr.seq2.response);
    let s3 = get_tcp_seq(&seqrr.seq3.response);
    let s4 = get_tcp_seq(&seqrr.seq4.response);
    let s5 = get_tcp_seq(&seqrr.seq5.response);
    let s6 = get_tcp_seq(&seqrr.seq6.response);

    let mut seq_vec: Vec<u32> = Vec::new();
    let mut seq_push = |x: Option<u32>| match x {
        Some(x) => seq_vec.push(x),
        None => (),
    };
    seq_push(s1);
    seq_push(s2);
    seq_push(s3);
    seq_push(s4);
    seq_push(s5);
    seq_push(s6);

    let diff = get_diff_u32(&seq_vec);
    if diff.len() > 1 {
        let gcd = gcdx(&diff).unwrap();
        Some((gcd, diff))
    } else {
        None
    }
}

/// TCP ISN counter rate (ISR)
pub fn tcp_isr(diff: Vec<u32>) -> (u32, Vec<f32>) {
    let mut seq_rates: Vec<f32> = Vec::new();
    let mut sum = 0.0;
    for d in &diff {
        let f = (*d as f32) / 0.1;
        seq_rates.push(f);
        sum += f;
    }
    let avg = sum / diff.len() as f32;
    let isr = if avg < 1.0 {
        0
    } else {
        (8.0 * avg.log2()).round() as u32
    };
    (isr, seq_rates)
}

/// Calculate standard deviation
fn vec_std(values: &Vec<f32>) -> f32 {
    let mut sum = 0.0;
    for v in values {
        sum += *v;
    }
    let mean = sum / values.len() as f32;
    let mut ret = 0.0;
    for v in values {
        ret += (v - mean).powi(2);
    }
    ret.sqrt()
}

/// TCP ISN sequence predictability index (SP)
pub fn tcp_sp(seq_rates: Vec<f32>, gcd: u32) -> Option<u32> {
    // This test is only performed if at least four responses were seen.
    if seq_rates.len() >= 3 {
        let mut seq_rates_clone = seq_rates.clone();
        // If the previously computed GCD value is greater than nine.
        if gcd > 9 {
            for i in 0..seq_rates.len() {
                seq_rates_clone[i] /= gcd as f32;
            }
        }
        let sd = vec_std(&seq_rates);
        let sp = if sd <= 1.0 {
            0
        } else {
            (8.0 * sd.log2()).round() as u32
        };
        Some(sp)
    } else {
        None // mean omitting
    }
}

fn get_ip_id(ipv4_buff: &Vec<u8>) -> Option<u16> {
    match Ipv4Packet::new(ipv4_buff) {
        Some(ipv4_packet) => Some(ipv4_packet.get_identification()),
        None => None,
    }
}

/// IP ID sequence generation algorithm (TI, CI, II)
pub fn tcp_ti_ci_ii(seqrr: &SEQRR, t2t7rr: &T2T7RR, ierr: &IERR) -> (String, String, String) {
    let get_ip_id_vec = |temp_vec: &[Option<u16>]| -> Vec<u16> {
        let mut ip_id_vec = Vec::new();
        for v in temp_vec {
            if v.is_some() {
                ip_id_vec.push(v.unwrap() as u16);
            }
        }
        ip_id_vec
    };

    let z_judgement = |x: &Vec<u16>| -> bool {
        let mut conditon = true; // all of the ID numbers are zero
        for v in x {
            if *v != 0 {
                conditon = false;
            }
        }
        conditon
    };
    let rd_judgement = |diff: &Vec<u16>| -> bool {
        let mut condition = true; // IP ID sequence ever increases by at least 20,000
        for d in diff {
            if *d < 20000 {
                condition = false;
            }
        }
        condition
    };
    let hex_judgement = |ip_id_vec: &Vec<u16>| -> bool {
        let v3 = get_diff_u16(ip_id_vec);
        let mut sum = 0;
        for v in v3 {
            sum += v;
        }

        if sum == 0 {
            true
        } else {
            false
        }
    };
    let ri_judgement = |diff: &Vec<u16>| -> bool {
        let mut condition_1 = true; // any of the differences exceeds 1000
        let mut condition_2 = true; // any of the differences not evenly divisiable by 256
        for d in diff {
            if *d < 1000 {
                condition_1 = false;
            }
            if *d % 256 == 0 {
                condition_2 = false;
            }
        }

        if condition_1 && condition_2 {
            true
        } else {
            false
        }
    };
    let bi_judgement = |diff: &[u16]| -> bool {
        let mut condition_1 = true; // all of the differences are divisible by 256
        let mut condition_2 = true; // all of the differences are no greater than 5,120
        for d in diff {
            if *d % 256 != 0 {
                condition_1 = false;
            }
            if *d > 5120 {
                condition_2 = false;
            }
        }

        if condition_1 && condition_2 {
            true
        } else {
            false
        }
    };
    let i_judgement = |diff: &[u16]| -> bool {
        let mut condition = true; // all of the differences are less than ten
        for d in diff {
            if *d >= 10 {
                condition = false;
            }
        }
        condition
    };

    let seq1_ip_id = get_ip_id(&seqrr.seq1.response);
    let seq2_ip_id = get_ip_id(&seqrr.seq2.response);
    let seq3_ip_id = get_ip_id(&seqrr.seq3.response);
    let seq4_ip_id = get_ip_id(&seqrr.seq4.response);
    let seq5_ip_id = get_ip_id(&seqrr.seq5.response);
    let seq6_ip_id = get_ip_id(&seqrr.seq6.response);

    let temp_vec = vec![
        seq1_ip_id, seq2_ip_id, seq3_ip_id, seq4_ip_id, seq5_ip_id, seq6_ip_id,
    ];
    let seq_ip_id_vec = get_ip_id_vec(&temp_vec);
    let seq_diff = get_diff_u16(&seq_ip_id_vec);

    // TI is based on responses to the TCP SEQ probes.
    let ti = if seq_ip_id_vec.len() >= 3 {
        if z_judgement(&seq_ip_id_vec) {
            // If all of the ID numbers are zero, the value of the test is Z.
            String::from("Z")
        } else if ri_judgement(&seq_diff) {
            // If the IP ID sequence ever increases by at least 20,000, the value is RD (random).
            // This result isn't possible for II because there are not enough samples to support it.
            String::from("RD")
        } else if hex_judgement(&seq_ip_id_vec) {
            // If all of the IP IDs are identical, the test is set to that value in hex.
            format!("{:X}", seq_ip_id_vec[0])
        } else if ri_judgement(&seq_diff) {
            // If any of the differences between two consecutive IDs exceeds 1,000, and is not evenly divisible by 256,
            // the test's value is RI (random positive increments).
            // If the difference is evenly divisible by 256, it must be at least 256,000 to cause this RI result.
            String::from("RI")
        } else if bi_judgement(&seq_diff) {
            // If all of the differences are divisible by 256 and no greater than 5,120, the test is set to BI (broken increment).
            // This happens on systems like Microsoft Windows where the IP ID is sent in host byte order rather than network byte order.
            // It works fine and isn't any sort of RFC violation, though it does give away host architecture details which can be useful to attackers.
            String::from("BI")
        } else if i_judgement(&seq_diff) {
            // If all of the differences are less than ten, the value is I (incremental).
            // We allow difference up to ten here (rather than requiring sequential ordering) because traffic from other hosts can cause sequence gaps.
            String::from("I")
        } else {
            // If none of the previous steps identify the generation algorithm, the test is omitted from the fingerprint.
            String::from("")
        }
    } else {
        // For TI, at least three responses must be received for the test to be included.
        String::from("")
    };

    // CI is from the responses to the three TCP probes sent to a closed port: T5, T6, and T7.
    let t5_ip_id = get_ip_id(&t2t7rr.t5.response);
    let t6_ip_id = get_ip_id(&t2t7rr.t6.response);
    let t7_ip_id = get_ip_id(&t2t7rr.t7.response);

    let temp_vec = vec![t5_ip_id, t6_ip_id, t7_ip_id];
    let t_ip_id_vec = get_ip_id_vec(&temp_vec);

    let t_diff = get_diff_u16(&t_ip_id_vec);

    let ci = if t_ip_id_vec.len() >= 2 {
        if z_judgement(&t_ip_id_vec) {
            // If all of the ID numbers are zero, the value of the test is Z.
            String::from("Z")
        } else if rd_judgement(&t_diff) {
            // If the IP ID sequence ever increases by at least 20,000, the value is RD (random).
            // This result isn't possible for II because there are not enough samples to support it.
            String::from("RD")
        } else if hex_judgement(&t_ip_id_vec) {
            // If all of the IP IDs are identical, the test is set to that value in hex.
            format!("{:X}", t_ip_id_vec[0])
        } else if ri_judgement(&t_diff) {
            // If any of the differences between two consecutive IDs exceeds 1,000, and is not evenly divisible by 256,
            // the test's value is RI (random positive increments).
            // If the difference is evenly divisible by 256, it must be at least 256,000 to cause this RI result.
            String::from("RI")
        } else if bi_judgement(&t_diff) {
            // If all of the differences are divisible by 256 and no greater than 5,120, the test is set to BI (broken increment).
            // This happens on systems like Microsoft Windows where the IP ID is sent in host byte order rather than network byte order.
            // It works fine and isn't any sort of RFC violation, though it does give away host architecture details which can be useful to attackers.
            String::from("BI")
        } else if i_judgement(&t_diff) {
            // If all of the differences are less than ten, the value is I (incremental).
            // We allow difference up to ten here (rather than requiring sequential ordering) because traffic from other hosts can cause sequence gaps.
            String::from("I")
        } else {
            // If none of the previous steps identify the generation algorithm, the test is omitted from the fingerprint.
            String::from("")
        }
    } else {
        // for CI, at least two responses are required.
        String::from("")
    };

    // II comes from the ICMP responses to the two IE ping probes.
    let ie1_ip_id = get_ip_id(&ierr.ie1.response);
    let ie2_ip_id = get_ip_id(&ierr.ie2.response);

    let temp_vec = vec![ie1_ip_id, ie2_ip_id];
    let ie_ip_id_vec = get_ip_id_vec(&temp_vec);

    let ie_diff = get_diff_u16(&ie_ip_id_vec);

    // RD result isn't possible for II because there are not enough samples to support it.
    let ii = if ie_ip_id_vec.len() >= 2 {
        if z_judgement(&ie_ip_id_vec) {
            // If all of the ID numbers are zero, the value of the test is Z.
            String::from("Z")
        } else if hex_judgement(&ie_ip_id_vec) {
            // If all of the IP IDs are identical, the test is set to that value in hex.
            format!("{:X}", ie_ip_id_vec[0])
        } else if ri_judgement(&ie_diff) {
            // If any of the differences between two consecutive IDs exceeds 1,000, and is not evenly divisible by 256,
            // the test's value is RI (random positive increments).
            // If the difference is evenly divisible by 256, it must be at least 256,000 to cause this RI result.
            String::from("RI")
        } else if bi_judgement(&ie_diff) {
            // If all of the differences are divisible by 256 and no greater than 5,120, the test is set to BI (broken increment).
            // This happens on systems like Microsoft Windows where the IP ID is sent in host byte order rather than network byte order.
            // It works fine and isn't any sort of RFC violation, though it does give away host architecture details which can be useful to attackers.
            String::from("BI")
        } else if i_judgement(&ie_diff) {
            // If all of the differences are less than ten, the value is I (incremental).
            // We allow difference up to ten here (rather than requiring sequential ordering) because traffic from other hosts can cause sequence gaps.
            String::from("I")
        } else {
            // If none of the previous steps identify the generation algorithm, the test is omitted from the fingerprint.
            String::from("")
        }
    } else {
        // and for II, both ICMP responses must be received.
        String::from("")
    };
    (ti, ci, ii)
}

/// Shared IP ID sequence Boolean (SS)
pub fn tcp_ss(seqrr: &SEQRR, ierr: &IERR, ti: &str, ii: &str) -> Option<String> {
    let judge_value = |x: &str| -> bool {
        if x == "RI" || x == "BI" || x == "I" {
            true
        } else {
            false
        }
    };
    // This test is only included if II is RI, BI, or I and TI is the same.
    let c1 = judge_value(ii);
    let c2 = judge_value(ti);

    if c1 && c2 {
        let (seq_first_ip_id, first) = if seqrr.seq1.response.len() > 0 {
            (get_ip_id(&seqrr.seq1.response).unwrap(), 1)
        } else if seqrr.seq2.response.len() > 0 {
            (get_ip_id(&seqrr.seq2.response).unwrap(), 2)
        } else if seqrr.seq3.response.len() > 0 {
            (get_ip_id(&seqrr.seq3.response).unwrap(), 3)
        } else if seqrr.seq4.response.len() > 0 {
            (get_ip_id(&seqrr.seq4.response).unwrap(), 4)
        } else if seqrr.seq5.response.len() > 0 {
            (get_ip_id(&seqrr.seq5.response).unwrap(), 5)
        } else if seqrr.seq6.response.len() > 0 {
            (get_ip_id(&seqrr.seq6.response).unwrap(), 6)
        } else {
            return None;
        };

        let (seq_last_ip_id, last) = if seqrr.seq6.response.len() > 0 {
            (get_ip_id(&seqrr.seq6.response).unwrap(), 6)
        } else if seqrr.seq5.response.len() > 0 {
            (get_ip_id(&seqrr.seq5.response).unwrap(), 5)
        } else if seqrr.seq4.response.len() > 0 {
            (get_ip_id(&seqrr.seq4.response).unwrap(), 4)
        } else if seqrr.seq3.response.len() > 0 {
            (get_ip_id(&seqrr.seq3.response).unwrap(), 3)
        } else if seqrr.seq2.response.len() > 0 {
            (get_ip_id(&seqrr.seq2.response).unwrap(), 2)
        } else if seqrr.seq1.response.len() > 0 {
            (get_ip_id(&seqrr.seq1.response).unwrap(), 1)
        } else {
            return None;
        };

        if last <= first {
            return None;
        }

        let difference = if seq_last_ip_id > seq_first_ip_id {
            seq_last_ip_id - seq_first_ip_id
        } else {
            !(seq_first_ip_id - seq_last_ip_id)
        };

        let avg = difference as f32 / (last - first) as f32;
        let ie1_ip_id = get_ip_id(&ierr.ie1.response).unwrap();
        // If the first ICMP echo response IP ID is less than the final TCP sequence response IP ID plus three times avg,
        // the SS result is S. Otherwise it is O.
        let temp_value = seq_last_ip_id as f32 + (3.0 * avg);
        let ss = if (ie1_ip_id as f32) < temp_value {
            String::from("S")
        } else {
            String::from("O")
        };
        Some(ss)
    } else {
        None
    }
}

fn gen_ipv4_pakcet(ipv4_buff: &Vec<u8>) -> Option<Ipv4Packet> {
    Ipv4Packet::new(ipv4_buff)
}

fn gen_tcp_packet(tcp_buff: &Vec<u8>) -> Option<TcpPacket> {
    TcpPacket::new(tcp_buff)
}

fn get_tsval(ipv4_buff: &Vec<u8>) -> Option<u32> {
    match gen_ipv4_pakcet(ipv4_buff) {
        Some(ipv4_packet) => {
            let tcp_buff = ipv4_packet.payload().to_vec();
            match gen_tcp_packet(&tcp_buff) {
                Some(tcp_packet) => {
                    let options_vec = tcp_packet.get_options();
                    let mut tsval_vec: Vec<u8> = Vec::new();
                    for option in options_vec {
                        match option.number {
                            TcpOptionNumbers::TIMESTAMPS => {
                                // println!("{:?}", option.data);
                                for i in 0..option.data.len() {
                                    if i < 4 {
                                        // get first 4 u8 values
                                        tsval_vec.push(option.data[i]);
                                    }
                                }
                            }
                            _ => (),
                        }
                    }
                    if tsval_vec.len() != 0 {
                        let tsval = Hex::vec_4u8_to_u32(tsval_vec);
                        Some(tsval)
                    } else {
                        None
                    }
                }
                None => None,
            }
        }
        None => None,
    }
}

/// TCP timestamp option algorithm (TS)
pub fn tcp_ts(seqrr: &SEQRR) -> String {
    let tsval_1 = get_tsval(&seqrr.seq1.response);
    let tsval_2 = get_tsval(&seqrr.seq2.response);
    let tsval_3 = get_tsval(&seqrr.seq3.response);
    let tsval_4 = get_tsval(&seqrr.seq4.response);
    let tsval_5 = get_tsval(&seqrr.seq5.response);
    let tsval_6 = get_tsval(&seqrr.seq6.response);

    let tsval_vec = vec![tsval_1, tsval_2, tsval_3, tsval_4, tsval_5, tsval_6];

    let mut one_tsval_none = false;
    let mut one_tsval_zero = false;
    let mut tsval_true = Vec::new();
    for tsval in tsval_vec {
        match tsval {
            Some(t) => {
                if t == 0 {
                    one_tsval_zero = true;
                }
                tsval_true.push(t);
            }
            None => {
                one_tsval_none = true;
            }
        }
    }

    let ts = if one_tsval_none {
        // If any of the responses have no timestamp option, TS is set to U (unsupported).
        String::from("U")
    } else if one_tsval_zero {
        // If any of the timestamp values are zero, TS is set to 0.
        String::from("0")
    } else {
        let diff = get_diff_u32(&tsval_true);
        let mut sum = 0.0;
        for d in &diff {
            // It takes the difference between each consecutive TSval
            // and divides that by the amount of time elapsed between Nmap sending the two probes which generated those responses.
            sum += *d as f64 / 0.1;
        }
        let avg = sum / diff.len() as f64;

        // If the average increments per second falls within the ranges 0-5.66, 70-150, or 150-350, TS is set to 1, 7, or 8, respectively.
        // These three ranges get special treatment because they correspond to the 2 Hz, 100 Hz, and 200 Hz frequencies used by many hosts.
        let ts = if avg > 0.0 && avg <= 5.66 {
            String::from("1")
        } else if avg > 70.0 && avg <= 150.0 {
            String::from("7")
        } else if avg > 150.0 && avg <= 350.0 {
            String::from("8")
        } else {
            // In all other cases, Nmap records the binary logarithm of the average increments per second, rounded to the nearest integer.
            // Since most hosts use 1,000 Hz frequencies, A is a common result.
            // A(hex)=10(dec), log_2(1024)=10
            let a = avg.log2().round() as u64;
            let hex_str = format!("{:X}", a);
            hex_str
        };
        ts
    };
    ts
}

fn get_ox(ipv4_buff: &Vec<u8>) -> Option<String> {
    match gen_ipv4_pakcet(ipv4_buff) {
        Some(ipv4_packet) => {
            let tcp_buff = ipv4_packet.payload().to_vec();
            match gen_tcp_packet(&tcp_buff) {
                Some(tcp_packet) => {
                    let options_vec = tcp_packet.get_options();
                    let mut o = String::from("");
                    for option in options_vec {
                        match option.number {
                            TcpOptionNumbers::MSS => {
                                let data = Hex::vec_4u8_to_u32(option.data);
                                o = format!("{}M{:X}", o, data);
                            }
                            TcpOptionNumbers::SACK_PERMITTED => {
                                o = format!("{}{}", o, "S");
                            }
                            TcpOptionNumbers::EOL => {
                                o = format!("{}{}", o, "L");
                            }
                            TcpOptionNumbers::NOP => {
                                o = format!("{}{}", o, "N");
                            }
                            TcpOptionNumbers::WSCALE => {
                                let data = Hex::vec_4u8_to_u32(option.data);
                                o = format!("{}W{:X}", o, data);
                            }
                            TcpOptionNumbers::TIMESTAMPS => {
                                o = format!("{}{}", o, "T");
                                let mut t0 = Vec::new();
                                let mut t1 = Vec::new();
                                for i in 0..option.data.len() {
                                    if i < 4 {
                                        // get first 4 u8 values
                                        t0.push(option.data[i]);
                                    } else {
                                        t1.push(option.data[i]);
                                    }
                                }
                                let t0_u32 = Hex::vec_4u8_to_u32(t0);
                                let t1_u32 = Hex::vec_4u8_to_u32(t1);
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
                            _ => (),
                        }
                    }
                    Some(o)
                }
                None => None,
            }
        }
        None => None,
    }
}

pub fn tcp_ox(
    seqrr: &SEQRR,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let o1 = get_ox(&seqrr.seq1.response);
    let o2 = get_ox(&seqrr.seq2.response);
    let o3 = get_ox(&seqrr.seq3.response);
    let o4 = get_ox(&seqrr.seq4.response);
    let o5 = get_ox(&seqrr.seq5.response);
    let o6 = get_ox(&seqrr.seq6.response);
    (o1, o2, o3, o4, o5, o6)
}

fn get_wx(ipv4_buff: &Vec<u8>) -> Option<String> {
    match gen_ipv4_pakcet(ipv4_buff) {
        Some(ipv4_packet) => {
            let tcp_buff = ipv4_packet.payload().to_vec();
            match gen_tcp_packet(&tcp_buff) {
                Some(tcp_packet) => {
                    let window = tcp_packet.get_window();
                    let window_hex = format!("{:X}", window);
                    Some(window_hex)
                }
                None => None,
            }
        }
        None => None,
    }
}

pub fn tcp_wx(
    seqrr: &SEQRR,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let w1 = get_wx(&seqrr.seq1.response);
    let w2 = get_wx(&seqrr.seq2.response);
    let w3 = get_wx(&seqrr.seq3.response);
    let w4 = get_wx(&seqrr.seq4.response);
    let w5 = get_wx(&seqrr.seq5.response);
    let w6 = get_wx(&seqrr.seq6.response);
    (w1, w2, w3, w4, w5, w6)
}

fn tcp_r(ipv4_buff: &Vec<u8>) -> String {
    match ipv4_buff.len() {
        0 => String::from("N"),
        _ => String::from("Y"),
    }
}

fn tcp_df(ipv4_buff: &Vec<u8>) -> Option<String> {
    match gen_ipv4_pakcet(ipv4_buff) {
        Some(ipv4_packet) => {
            let ipv4_flags = ipv4_packet.get_flags();
            let df_mask: u8 = 0b0010;
            let ret = if ipv4_flags & df_mask == df_mask {
                String::from("Y")
            } else {
                String::from("N")
            };
            Some(ret)
        }
        None => None,
    }
}

fn udp_hops(u1rr: &U1RR) -> u8 {
    let request = Ipv4Packet::new(&u1rr.u1.request).unwrap();
    let response = Ipv4Packet::new(&u1rr.u1.response).unwrap();
    let request_ttl = request.get_ttl();
    let response_ttl = response.get_ttl();
    let hops = request_ttl - response_ttl;
    hops
}

fn tcp_t(seqrr: &SEQRR, u1rr: &U1RR) {
    let hops = udp_hops(u1rr);
}
