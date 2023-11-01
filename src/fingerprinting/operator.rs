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

use super::ip::{ECNRR, IERR, SEQRR, T2T7RR, U1RR};

/// TCP ISN greatest common divisor (GCD)
pub fn tcp_gcd(seqrr: &SEQRR) -> Option<(u32, Vec<u32>)> {
    let get_tcp_seq = |x: &Option<Vec<u8>>| -> i64 {
        match x {
            Some(v) => {
                let ipv4_packet = Ipv4Packet::new(&v).unwrap();
                let tcp_packet = TcpPacket::new(ipv4_packet.packet()).unwrap();
                tcp_packet.get_sequence() as i64 // convert u32 to i32 will loss one bit, so there use u32 to i64
            }
            _ => -1,
        }
    };
    let s1 = get_tcp_seq(&seqrr.seq1.response);
    let s2 = get_tcp_seq(&seqrr.seq1.response);
    let s3 = get_tcp_seq(&seqrr.seq1.response);
    let s4 = get_tcp_seq(&seqrr.seq1.response);
    let s5 = get_tcp_seq(&seqrr.seq1.response);
    let s6 = get_tcp_seq(&seqrr.seq1.response);

    let mut seq_vec: Vec<u32> = Vec::new();
    let mut seq_push = |x: i64| {
        if x != -1 {
            seq_vec.push(x as u32);
        }
    };
    seq_push(s1);
    seq_push(s2);
    seq_push(s3);
    seq_push(s4);
    seq_push(s5);
    seq_push(s6);

    if seq_vec.len() > 1 {
        let mut vec_1 = Vec::new();
        vec_1.push(0);
        vec_1.extend(seq_vec.clone()); // [0, 1, 2]
        let mut vec_2 = seq_vec;
        vec_2.push(0); // [1, 2, 0]

        let mut diff = Vec::new();
        for (x, y) in zip(vec_1, vec_2) {
            let k = if x < y { y - x } else { !(x - y) };
            diff.push(k);
        }
        diff.remove(0);
        diff.remove(diff.len());

        let gcd = gcdx(&diff).unwrap();
        Some((gcd, diff))
    } else {
        None
    }
}

/// TCP ISN counter rate (ISR)
pub fn tcp_isr(diff: Vec<u32>) -> (f32, Vec<f32>) {
    let mut seq_rates: Vec<f32> = Vec::new();
    let mut sum = 0.0;
    for d in &diff {
        let f = (*d as f32) / 0.1;
        seq_rates.push(f);
        sum += f;
    }
    let avg = sum / diff.len() as f32;
    let isr = if avg < 1.0 {
        0.0
    } else {
        (8.0 * avg.log2()).round()
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

fn get_ip_id(ipv4_buff: &Option<Vec<u8>>) -> Option<u16> {
    match ipv4_buff {
        Some(v) => {
            let ipv4_packet = Ipv4Packet::new(&v).unwrap();
            Some(ipv4_packet.get_identification())
        }
        _ => None,
    }
}

/// IP ID sequence generation algorithm (TI, CI, II)
pub fn tcp_ti_ci_ii(
    seqrr: &SEQRR,
    t2t7rr: &T2T7RR,
    ierr: &IERR,
) -> Option<(String, String, String)> {
    let get_ip_id_vec = |temp_vec: &[Option<u16>]| -> Vec<u16> {
        let mut ip_id_vec = Vec::new();
        for v in temp_vec {
            if v.is_some() {
                ip_id_vec.push(v.unwrap() as u16);
            }
        }
        ip_id_vec
    };
    let get_ip_id_diff_vec = |ip_id_vec: &[u16]| -> Vec<u16> {
        let mut vec_1 = Vec::new();
        vec_1.push(0);
        vec_1.extend(ip_id_vec.to_vec()); // [0, 1, 2]
        let mut vec_2 = ip_id_vec.to_vec();
        vec_2.push(0); // [1, 2, 0]

        let mut diff = Vec::new();
        for (x, y) in zip(vec_1, vec_2) {
            let k = if x < y { y - x } else { !(x - y) };
            diff.push(k);
        }
        diff.remove(0);
        diff.remove(diff.len());
        diff
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

    if seq_ip_id_vec.len() <= 1 {
        return None;
    }
    let seq_diff = get_ip_id_diff_vec(&seq_ip_id_vec);

    let z_judgement = |x: &[u16]| -> bool {
        let mut conditon = true; // all of the ID numbers are zero
        for v in x {
            if *v != 0 {
                conditon = false;
            }
        }
        conditon
    };
    let rd_judgement = |diff: &[u16]| -> bool {
        let mut condition = true; // IP ID sequence ever increases by at least 20,000
        for d in diff {
            if *d < 20000 {
                condition = false;
            }
        }
        condition
    };
    let hex_judgement = |ip_id_vec: &[u16]| -> bool {
        let mut v1 = vec![0]; // [0, 1, 2]
        v1.extend(ip_id_vec);
        let mut v2 = ip_id_vec.to_vec();
        v2.push(0); // [1, 2, 0]

        let mut v3 = Vec::new();
        for (a, b) in zip(v1, v2) {
            v3.push(b - a);
        }

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
    let ri_judgement = |diff: &[u16]| -> bool {
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

    // TI is based on responses to the TCP SEQ probes.
    let ti = if z_judgement(&seq_ip_id_vec) {
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
    };

    // CI is from the responses to the three TCP probes sent to a closed port: T5, T6, and T7.
    let t5_ip_id = get_ip_id(&t2t7rr.t5.response);
    let t6_ip_id = get_ip_id(&t2t7rr.t6.response);
    let t7_ip_id = get_ip_id(&t2t7rr.t7.response);

    let temp_vec = vec![t5_ip_id, t6_ip_id, t7_ip_id];
    let t_ip_id_vec = get_ip_id_vec(&temp_vec);

    if t_ip_id_vec.len() <= 1 {
        return None;
    }
    let t_diff = get_ip_id_diff_vec(&t_ip_id_vec);

    let ci = if z_judgement(&t_ip_id_vec) {
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
    };

    // II comes from the ICMP responses to the two IE ping probes.
    let ie1_ip_id = get_ip_id(&ierr.ie1.response);
    let ie2_ip_id = get_ip_id(&ierr.ie2.response);

    let temp_vec = vec![ie1_ip_id, ie2_ip_id];
    let ie_ip_id_vec = get_ip_id_vec(&temp_vec);

    if ie_ip_id_vec.len() <= 1 {
        return None;
    }
    let ie_diff = get_ip_id_diff_vec(&ie_ip_id_vec);

    let ii = if z_judgement(&ie_ip_id_vec) {
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
    };
    Some((ti, ci, ii))
}

/// Shared IP ID sequence Boolean (SS)
pub fn tcp_ss(seqrr: &SEQRR, ierr: &IERR, ti: &str, ii: &str) -> Option<String> {
    // This test is only included if II is RI, BI, or I and TI is the same.
    let judge_value = |x: &str| -> bool {
        let mut condition = true; // x is RI, BI or I
        if x != "RI" && x != "BI" && x != "I" {
            condition = false;
        }
        condition
    };
    let c1 = judge_value(ti);
    let c2 = judge_value(ii);

    if c1 && c2 {
        let (seq_first_ip_id, first) = if seqrr.seq1.response.is_some() {
            (get_ip_id(&seqrr.seq1.response).unwrap(), 1)
        } else if seqrr.seq2.response.is_some() {
            (get_ip_id(&seqrr.seq2.response).unwrap(), 2)
        } else if seqrr.seq3.response.is_some() {
            (get_ip_id(&seqrr.seq3.response).unwrap(), 3)
        } else if seqrr.seq4.response.is_some() {
            (get_ip_id(&seqrr.seq4.response).unwrap(), 4)
        } else if seqrr.seq5.response.is_some() {
            (get_ip_id(&seqrr.seq5.response).unwrap(), 5)
        } else if seqrr.seq6.response.is_some() {
            (get_ip_id(&seqrr.seq6.response).unwrap(), 6)
        } else {
            return None;
        };

        let (seq_last_ip_id, last) = if seqrr.seq6.response.is_some() {
            (get_ip_id(&seqrr.seq6.response).unwrap(), 6)
        } else if seqrr.seq5.response.is_some() {
            (get_ip_id(&seqrr.seq5.response).unwrap(), 5)
        } else if seqrr.seq4.response.is_some() {
            (get_ip_id(&seqrr.seq4.response).unwrap(), 4)
        } else if seqrr.seq3.response.is_some() {
            (get_ip_id(&seqrr.seq3.response).unwrap(), 3)
        } else if seqrr.seq2.response.is_some() {
            (get_ip_id(&seqrr.seq2.response).unwrap(), 2)
        } else if seqrr.seq1.response.is_some() {
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
