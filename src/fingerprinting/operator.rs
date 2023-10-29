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

use crate::fingerprinting::ip::{ECNRR, IERR, SEQRR, U1RR};

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
fn sd_vec(values: &Vec<f32>) -> f32 {
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
        if gcd > 9 {
            for i in 0..seq_rates.len() {
                seq_rates_clone[i] /= gcd as f32;
            }
        }
        let sd = sd_vec(&seq_rates);
        let sp = if sd <= 1.0 {
            0
        } else {
            (8.0 * sd.log2()).round() as u32
        };
        Some(sp)
    } else {
        None
    }
}

/// IP ID sequence generation algorithm (TI, CI, II)
pub fn tcp_ti_ci_ii(seqrr: &SEQRR) -> Option<()> {
    let get_ip_id = |x: &Option<Vec<u8>>| -> i32 {
        match x {
            Some(v) => {
                let ipv4_packet = Ipv4Packet::new(&v).unwrap();
                ipv4_packet.get_identification() as i32 // convert u16 to i16 will loss one bit, so there use u16 to i32
            }
            _ => -1,
        }
    };
    let ip_id_1 = get_ip_id(&seqrr.seq1.response);
    let ip_id_2 = get_ip_id(&seqrr.seq2.response);
    let ip_id_3 = get_ip_id(&seqrr.seq3.response);
    let ip_id_4 = get_ip_id(&seqrr.seq4.response);
    let ip_id_5 = get_ip_id(&seqrr.seq5.response);
    let ip_id_6 = get_ip_id(&seqrr.seq6.response);

    let mut ip_id_vec = Vec::new();
    let mut ip_id_push = |x: i32| {
        if x != -1 {
            ip_id_vec.push(x as u16);
        }
    };
    ip_id_push(ip_id_1);
    ip_id_push(ip_id_2);
    ip_id_push(ip_id_3);
    ip_id_push(ip_id_4);
    ip_id_push(ip_id_5);
    ip_id_push(ip_id_6);

    if ip_id_vec.len() <= 1 {
        return None;
    }

    let mut diff = Vec::new();
    let mut vec_1 = Vec::new();
    vec_1.push(0);
    vec_1.extend(ip_id_vec.clone()); // [0, 1, 2]
    let mut vec_2 = ip_id_vec;
    vec_2.push(0); // [1, 2, 0]

    let mut diff = Vec::new();
    for (x, y) in zip(vec_1, vec_2) {
        let k = if x < y { y - x } else { !(x - y) };
        diff.push(k);
    }
    diff.remove(0);
    diff.remove(diff.len());

    /* some function that use to judge */
    let vec_all_zero = |x: &[u16]| -> bool {
        for v in x {
            if *v != 0 {
                return false;
            }
        }
        true
    };
    let ever_increases_2000 = |x: &[u16]| -> bool {
        let mut min = u16::MAX;
        for v in x {
            if *v < min {
                min = *v;
            }
        }

        if min >= 2000 {
            true
        } else {
            false
        }
    };
    let vec_all_same = |x: &[u16]| -> bool {
        let mut last_value = x[0];
        for v in x {
            if *v != last_value {
                return false;
            }
        }
        true
    };

    let ti = if vec_all_zero(&ip_id_vec) {
        // If all of the ID numbers are zero, the value of the test is Z.
        String::from("Z")
    } else if ever_increases_2000(&diff) {
        // If the IP ID sequence ever increases by at least 20,000, the value is RD (random).
        // This result isn't possible for II because there are not enough samples to support it.
        String::from("RD")
    } else if vec_all_same(&ip_id_vec) {
        // If all of the IP IDs are identical, the test is set to that value in hex.
        format!("{:X}", ip_id_vec[0])
    } else if diff1_ge_1000(&diff) {
        // If any of the differences between two consecutive IDs exceeds 1,000, and is not evenly divisible by 256,
        // the test's value is RI (random positive increments).
        // If the difference is evenly divisible by 256, it must be at least 256,000 to cause this RI result.
        String::from("RI")
    } else if diff1_divisible_by_256(&diff) {
        // If all of the differences are divisible by 256 and no greater than 5,120, the test is set to BI (broken increment).
        // This happens on systems like Microsoft Windows where the IP ID is sent in host byte order rather than network byte order.
        // It works fine and isn't any sort of RFC violation, though it does give away host architecture details which can be useful to attackers.
        String::from("BI")
    } else if diff1_le_10(&diff) {
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
    let ci = if vec_all_zero(&t_ip_id_vec) {
        // If all of the ID numbers are zero, the value of the test is Z.
        String::from("Z")
    } else if diff1_ge_20000(&t_ip_id_diff1) {
        // If the IP ID sequence ever increases by at least 20,000, the value is RD (random).
        // This result isn't possible for II because there are not enough samples to support it.
        String::from("RD")
    } else if vec_all_same(&t_ip_id_vec) {
        // If all of the IP IDs are identical, the test is set to that value in hex.
        format!("{:X}", t_ip_id_vec[0])
    } else if diff1_ge_1000(&t_ip_id_diff1) {
        // If any of the differences between two consecutive IDs exceeds 1,000, and is not evenly divisible by 256,
        // the test's value is RI (random positive increments).
        // If the difference is evenly divisible by 256, it must be at least 256,000 to cause this RI result.
        String::from("RI")
    } else if diff1_divisible_by_256(&t_ip_id_diff1) {
        // If all of the differences are divisible by 256 and no greater than 5,120, the test is set to BI (broken increment).
        // This happens on systems like Microsoft Windows where the IP ID is sent in host byte order rather than network byte order.
        // It works fine and isn't any sort of RFC violation, though it does give away host architecture details which can be useful to attackers.
        String::from("BI")
    } else if diff1_le_10(&t_ip_id_diff1) {
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
        // println!("x {} y {}", id_x, id_y);
        let diff = if id_x < id_y {
            id_y - id_x
        } else {
            !(id_y - id_x)
        };
        ie_ip_id_diff1.push(diff);
    }
    let ii = if vec_all_zero(&ie_ip_id_vec) {
        // If all of the ID numbers are zero, the value of the test is Z.
        String::from("Z")
    } else if vec_all_same(&ie_ip_id_vec) {
        // If all of the IP IDs are identical, the test is set to that value in hex.
        format!("{:X}", ie_ip_id_vec[0])
    } else if diff1_ge_1000(&ie_ip_id_diff1) {
        // If any of the differences between two consecutive IDs exceeds 1,000, and is not evenly divisible by 256,
        // the test's value is RI (random positive increments).
        // If the difference is evenly divisible by 256, it must be at least 256,000 to cause this RI result.
        String::from("RI")
    } else if diff1_divisible_by_256(&ie_ip_id_diff1) {
        // If all of the differences are divisible by 256 and no greater than 5,120, the test is set to BI (broken increment).
        // This happens on systems like Microsoft Windows where the IP ID is sent in host byte order rather than network byte order.
        // It works fine and isn't any sort of RFC violation, though it does give away host architecture details which can be useful to attackers.
        String::from("BI")
    } else if diff1_le_10(&ie_ip_id_diff1) {
        // If all of the differences are less than ten, the value is I (incremental).
        // We allow difference up to ten here (rather than requiring sequential ordering) because traffic from other hosts can cause sequence gaps.
        String::from("I")
    } else {
        // If none of the previous steps identify the generation algorithm, the test is omitted from the fingerprint.
        String::from("")
    };
    Some(())
}
