use std::u16;

use crc32fast;
use gcdx::gcdx;
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmp::IcmpCode;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ipv4;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpOptionNumbers;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use tracing::warn;

use crate::os::rr::IERR;
use crate::os::rr::SEQRR;
use crate::os::rr::TXRR;
use crate::os::rr::U1RR;
use crate::utils::vec_to_u32;

const CWR_MASK: u8 = 0b10000000;
const ECE_MASK: u8 = 0b01000000;
const URG_MASK: u8 = 0b00100000;
const ACK_MASK: u8 = 0b00010000;
const PSH_MASK: u8 = 0b00001000;
const RST_MASK: u8 = 0b00000100;
const SYN_MASK: u8 = 0b00000010;
const FIN_MASK: u8 = 0b00000001;

// Because different programs wait, process, and send probebao for different times,
// so there is a certain error in the two indicators calculated based on time.
// Program estimation error, ISR, SP use.
// const PROGRAM_ESTIMATION_ERROR_ISR: f64 = 0.35;
// const PROGRAM_ESTIMATION_ERROR_SP: f64 = 0.35;
const ISR_ERROR: f64 = 0.0;
const SP_ERROR: f64 = 0.0;

fn build_eth_packet<'a>(eth_buff: &'a [u8], probe_name: &str) -> Option<EthernetPacket<'a>> {
    match EthernetPacket::new(eth_buff) {
        Some(p) => Some(p),
        None => {
            warn!("build {} ethernet packet failed", probe_name);
            None
        }
    }
}

fn build_ipv4_packet<'a>(ipv4_buff: &'a [u8], probe_name: &str) -> Option<Ipv4Packet<'a>> {
    match Ipv4Packet::new(ipv4_buff) {
        Some(p) => Some(p),
        None => {
            warn!("build {} ipv4 packet failed", probe_name);
            None
        }
    }
}

fn build_tcp_packet<'a>(tcp_buff: &'a [u8], probe_name: &str) -> Option<TcpPacket<'a>> {
    match TcpPacket::new(tcp_buff) {
        Some(p) => Some(p),
        None => {
            warn!("build {} tcp packet failed", probe_name);
            None
        }
    }
}

fn build_icmp_packet<'a>(icmp_buff: &'a [u8], probe_name: &str) -> Option<IcmpPacket<'a>> {
    match IcmpPacket::new(icmp_buff) {
        Some(p) => Some(p),
        None => {
            warn!("build {} icmp packet failed", probe_name);
            None
        }
    }
}

fn build_udp_packet<'a>(udp_buff: &'a [u8], probe_name: &str) -> Option<UdpPacket<'a>> {
    match UdpPacket::new(udp_buff) {
        Some(p) => Some(p),
        None => {
            warn!("build {} udp packet failed", probe_name);
            None
        }
    }
}

fn get_tcp_seq(eth_response: &[u8], probe_name: &str) -> Option<u32> {
    if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
        if let Some(ipv4_packet) = build_ipv4_packet(eth_packet.payload(), probe_name) {
            if let Some(tcp_packet) = build_tcp_packet(ipv4_packet.payload(), probe_name) {
                return Some(tcp_packet.get_sequence());
            }
        }
    }
    None
}

fn get_diff_u32(input: &[u32]) -> Vec<u32> {
    if input.len() >= 2 {
        let input_slice = input[0..(input.len() - 1)].to_vec();
        let mut diff = Vec::new();
        for (i, x) in input_slice.iter().enumerate() {
            let y = input[i + 1];
            let x = *x;
            let k = if x <= y { y - x } else { !(x - y) };
            diff.push(k);
        }
        diff
    } else {
        Vec::new()
    }
}

fn get_diff_u16(input: &[u16]) -> Vec<u16> {
    if input.len() >= 2 {
        // The received data packets may be out of order, so sorting is used here.
        let mut sorted = input.to_vec();
        sorted.sort();

        // o: [1, 2, 3, 4]
        // a: [1, 2, 3, 4, 5]
        // b: [0, 1, 2, 3, 4]

        let mut sorted_a = sorted.clone();
        sorted_a.push(u16::MAX);
        let mut sorted_b = vec![0];
        sorted_b.extend(sorted);

        let mut diff = Vec::new();
        for (a, b) in sorted_a.into_iter().zip(sorted_b) {
            diff.push(a - b)
        }

        let _ = diff.remove(0);
        let _ = diff.pop();

        diff
    } else {
        Vec::new()
    }
}

/// TCP ISN greatest common divisor (GCD).
pub(crate) fn tcp_gcd(seqrr: &SEQRR) -> Option<(u32, Vec<u32>)> {
    let s1 = get_tcp_seq(&seqrr.seq1.response2, "seq1");
    let s2 = get_tcp_seq(&seqrr.seq2.response2, "seq2");
    let s3 = get_tcp_seq(&seqrr.seq3.response2, "seq3");
    let s4 = get_tcp_seq(&seqrr.seq4.response2, "seq4");
    let s5 = get_tcp_seq(&seqrr.seq5.response2, "seq5");
    let s6 = get_tcp_seq(&seqrr.seq6.response2, "seq6");
    let mut tmp_vec = Vec::new();
    tmp_vec.push(s1);
    tmp_vec.push(s2);
    tmp_vec.push(s3);
    tmp_vec.push(s4);
    tmp_vec.push(s5);
    tmp_vec.push(s6);

    let mut seq_vec: Vec<u32> = Vec::new();
    for s in tmp_vec {
        match s {
            Some(s) => seq_vec.push(s),
            None => warn!(
                "get tcp seq failed, the response packet may be not tcp packet or the packet is too short to parse tcp header"
            ),
        }
    }

    let diff = get_diff_u32(&seq_vec);
    if diff.len() > 1 {
        let gcd = match gcdx(&diff) {
            Some(g) => g,
            None => return None,
        };
        Some((gcd, diff))
    } else if diff.len() == 1 {
        let gcd = diff[0];
        Some((gcd, diff))
    } else {
        None
    }
}

/// Calculate standard deviation.
fn vec_std(values: &[f64]) -> f64 {
    let mut sum = 0.0;
    for v in values {
        sum += v;
    }
    let mean = sum / values.len() as f64;
    let mut ret = 0.0;
    for v in values {
        ret += (v - mean).powi(2);
    }
    ret.sqrt()
}

/// TCP ISN counter rate (ISR).
/// This value reports the average rate of increase for the returned TCP initial sequence number.
pub(crate) fn tcp_isr(diff: Vec<u32>) -> Option<(u32, Vec<f64>)> {
    if diff.len() > 0 {
        let mut seq_rates = Vec::new();
        let mut sum = 0.0;
        for d in &diff {
            // The 0.1 is the time interval between two probes,
            // which is estimated by program, so there is a certain error here.
            let f = (*d as f64) / 0.1;
            seq_rates.push(f);
            sum += f;
        }
        let avg = sum / diff.len() as f64;
        let isr = if avg < 1.0 {
            0
        } else {
            ((8.0 - ISR_ERROR) * avg.log2()).round() as u32
        };
        Some((isr, seq_rates))
    } else {
        None
    }
}

/// TCP ISN sequence predictability index (SP).
pub(crate) fn tcp_sp(seq_rates: Vec<f64>, gcd: u32) -> u32 {
    // This test is only performed if at least four responses were seen.
    if seq_rates.len() >= 4 {
        let mut seq_rates_new = seq_rates.clone();
        // If the previously computed GCD value is greater than nine.
        if gcd > 9 {
            for s in &mut seq_rates_new {
                *s /= gcd as f64;
            }
        }
        // A standard deviation of the array of the resultant values is then taken.
        let sd = vec_std(&seq_rates_new);
        let sp = if sd <= 1.0 {
            // If the result is one or less, SP is zero.
            0
        } else {
            // Otherwise the binary logarithm of the result is computed,
            // then it is multiplied by eight, rounded to the nearest integer, and stored as SP.
            ((8.0 - SP_ERROR) * sd.log2()).round() as u32
        };
        // println!("sp: {}, sd: {}, gcd: {}", sp, sd, gcd);
        sp
    } else {
        0 // mean omitting
    }
}

fn get_ip_id(eth_response: &[u8], probe_name: &str) -> Option<u16> {
    if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
        if let Some(ipv4_packet) = build_ipv4_packet(eth_packet.payload(), probe_name) {
            return Some(ipv4_packet.get_identification());
        }
    }
    None
}

/// IP ID sequence generation algorithm (TI, CI, II).
pub(crate) fn tcp_ti_ci_ii(
    seqrr: &SEQRR,
    txrr: &TXRR,
    ierr: &IERR,
) -> (Option<String>, Option<String>, Option<String>) {
    /// If all of the ID numbers are zero, the value of the test is Z.
    fn z_judgement(values: &[u16]) -> bool {
        let mut conditon = true;
        for &v in values {
            if v != 0 {
                conditon = false;
            }
        }
        conditon
    }
    /// If the IP ID sequence ever increases by at least 20,000, the value is RD (random).
    /// This result isn't possible for II because there are not enough samples to support it.
    fn rd_judgement(diff: &[u16]) -> bool {
        let mut condition = true;
        for &d in diff {
            if d < 20000 {
                condition = false;
            }
        }
        condition
    }
    /// If all of the IP IDs are identical, the test is set to that value in hex.
    fn hex_judgement(ip_id_vec: &[u16]) -> bool {
        let diff = get_diff_u16(ip_id_vec);
        let mut sum = 0;
        for d in diff {
            sum += d;
        }

        if sum == 0 { true } else { false }
    }
    /// If any of the differences between two consecutive IDs exceeds 1,000,
    /// and is not evenly divisible by 256, the test's value is RI (random positive increments).
    /// If the difference is evenly divisible by 256, it must be at least 256,000 to cause this RI result.
    fn ri_judgement(diff: &[u16]) -> bool {
        let mut condition_1 = true; // any of the differences exceeds 1000
        let mut condition_2 = true; // any of the differences not evenly divisiable by 256
        for &d in diff {
            if d < 1000 {
                condition_1 = false;
            }
            if d % 256 == 0 {
                condition_2 = false;
            }
        }

        if condition_1 && condition_2 {
            true
        } else {
            false
        }
    }
    /// If all of the differences are divisible by 256 and no greater than 5,120,
    /// the test is set to BI (broken increment).
    /// This happens on systems like Microsoft Windows where the IP ID
    /// is sent in host byte order rather than network byte order. It works fine and isn't any sort of RFC violation,
    /// though it does give away host architecture details which can be useful to attackers.
    fn bi_judgement(diff: &[u16]) -> bool {
        let mut condition_1 = true; // all of the differences are divisible by 256
        let mut condition_2 = true; // all of the differences are no greater than 5,120
        for &d in diff {
            if d % 256 != 0 {
                condition_1 = false;
            }
            if d > 5120 {
                condition_2 = false;
            }
        }

        if condition_1 && condition_2 {
            true
        } else {
            false
        }
    }
    /// If all of the differences are less than ten, the value is I (incremental).
    /// We allow difference up to ten here (rather than requiring sequential ordering)
    /// because traffic from other hosts can cause sequence gaps.
    fn i_judgement(diff: &[u16]) -> bool {
        let mut condition = true; // all of the differences are less than ten
        for &d in diff {
            if d >= 10 {
                condition = false;
            }
        }
        condition
    }

    let seq1_ip_id = get_ip_id(&seqrr.seq1.response2, "seq1");
    let seq2_ip_id = get_ip_id(&seqrr.seq2.response2, "seq2");
    let seq3_ip_id = get_ip_id(&seqrr.seq3.response2, "seq3");
    let seq4_ip_id = get_ip_id(&seqrr.seq4.response2, "seq4");
    let seq5_ip_id = get_ip_id(&seqrr.seq5.response2, "seq5");
    let seq6_ip_id = get_ip_id(&seqrr.seq6.response2, "seq6");
    let mut tmp_vec = Vec::new();
    tmp_vec.push(seq1_ip_id);
    tmp_vec.push(seq2_ip_id);
    tmp_vec.push(seq3_ip_id);
    tmp_vec.push(seq4_ip_id);
    tmp_vec.push(seq5_ip_id);
    tmp_vec.push(seq6_ip_id);

    let mut seq_ip_id_vec = Vec::new();
    for s in tmp_vec {
        match s {
            Some(s) => seq_ip_id_vec.push(s),
            None => (),
        }
    }

    let seq_diff = get_diff_u16(&seq_ip_id_vec);

    // TI is based on responses to the TCP SEQ probes.
    let ti = if seq_ip_id_vec.len() >= 3 {
        if z_judgement(&seq_ip_id_vec) {
            // If all of the ID numbers are zero, the value of the test is Z.
            Some(String::from("Z"))
        } else if ri_judgement(&seq_diff) {
            // If the IP ID sequence ever increases by at least 20,000, the value is RD (random).
            // This result isn't possible for II because there are not enough samples to support it.
            Some(String::from("RD"))
        } else if hex_judgement(&seq_ip_id_vec) {
            // If all of the IP IDs are identical, the test is set to that value in hex.
            Some(format!("{:X}", seq_ip_id_vec[0]))
        } else if ri_judgement(&seq_diff) {
            // If any of the differences between two consecutive IDs exceeds 1,000, and is not evenly divisible by 256,
            // the test's value is RI (random positive increments).
            // If the difference is evenly divisible by 256, it must be at least 256,000 to cause this RI result.
            Some(String::from("RI"))
        } else if bi_judgement(&seq_diff) {
            // If all of the differences are divisible by 256 and no greater than 5,120, the test is set to BI (broken increment).
            // This happens on systems like Microsoft Windows where the IP ID is sent in host byte order rather than network byte order.
            // It works fine and isn't any sort of RFC violation, though it does give away host architecture details which can be useful to attackers.
            Some(String::from("BI"))
        } else if i_judgement(&seq_diff) {
            // If all of the differences are less than ten, the value is I (incremental).
            // We allow difference up to ten here (rather than requiring sequential ordering) because traffic from other hosts can cause sequence gaps.
            Some(String::from("I"))
        } else {
            // If none of the previous steps identify the generation algorithm, the test is omitted from the fingerprint.
            None
        }
    } else {
        // For TI, at least three responses must be received for the test to be included.
        None
    };

    // CI is from the responses to the three TCP probes sent to a closed port: T5, T6, and T7.
    let t5_ip_id = get_ip_id(&txrr.t5.response2, "t5");
    let t6_ip_id = get_ip_id(&txrr.t6.response2, "t6");
    let t7_ip_id = get_ip_id(&txrr.t7.response2, "t7");
    let mut tmp_vec = Vec::new();
    tmp_vec.push(t5_ip_id);
    tmp_vec.push(t6_ip_id);
    tmp_vec.push(t7_ip_id);

    let mut t_ip_id_vec = Vec::new();
    for t in tmp_vec {
        match t {
            Some(t) => t_ip_id_vec.push(t),
            None => (),
        }
    }
    let t_diff = get_diff_u16(&t_ip_id_vec);

    let ci = if t_ip_id_vec.len() >= 2 {
        if z_judgement(&t_ip_id_vec) {
            // If all of the ID numbers are zero, the value of the test is Z.
            Some(String::from("Z"))
        } else if rd_judgement(&t_diff) {
            // If the IP ID sequence ever increases by at least 20,000, the value is RD (random).
            // This result isn't possible for II because there are not enough samples to support it.
            Some(String::from("RD"))
        } else if hex_judgement(&t_ip_id_vec) {
            // If all of the IP IDs are identical, the test is set to that value in hex.
            Some(format!("{:X}", t_ip_id_vec[0]))
        } else if ri_judgement(&t_diff) {
            // If any of the differences between two consecutive IDs exceeds 1,000, and is not evenly divisible by 256,
            // the test's value is RI (random positive increments).
            // If the difference is evenly divisible by 256, it must be at least 256,000 to cause this RI result.
            Some(String::from("RI"))
        } else if bi_judgement(&t_diff) {
            // If all of the differences are divisible by 256 and no greater than 5,120, the test is set to BI (broken increment).
            // This happens on systems like Microsoft Windows where the IP ID is sent in host byte order rather than network byte order.
            // It works fine and isn't any sort of RFC violation, though it does give away host architecture details which can be useful to attackers.
            Some(String::from("BI"))
        } else if i_judgement(&t_diff) {
            // If all of the differences are less than ten, the value is I (incremental).
            // We allow difference up to ten here (rather than requiring sequential ordering) because traffic from other hosts can cause sequence gaps.
            Some(String::from("I"))
        } else {
            // If none of the previous steps identify the generation algorithm, the test is omitted from the fingerprint.
            None
        }
    } else {
        // for CI, at least two responses are required.
        None
    };

    // II comes from the ICMP responses to the two IE ping probes.
    let ie1_ip_id = get_ip_id(&ierr.ie1.response2, "ie1");
    let ie2_ip_id = get_ip_id(&ierr.ie2.response2, "ie2");
    let mut tmp_vec = Vec::new();
    tmp_vec.push(ie1_ip_id);
    tmp_vec.push(ie2_ip_id);

    let mut ie_ip_id_vec = Vec::new();
    for i in tmp_vec {
        match i {
            Some(i) => ie_ip_id_vec.push(i),
            None => (),
        }
    }
    let ie_diff = get_diff_u16(&ie_ip_id_vec);
    println!("{:?}", ie_ip_id_vec);
    println!("{:?}", ie_diff);

    // RD result isn't possible for II because there are not enough samples to support it.
    let ii = if ie_ip_id_vec.len() == 2 {
        if z_judgement(&ie_ip_id_vec) {
            // If all of the ID numbers are zero, the value of the test is Z.
            Some(String::from("Z"))
        } else if hex_judgement(&ie_ip_id_vec) {
            // If all of the IP IDs are identical, the test is set to that value in hex.
            Some(format!("{:X}", ie_ip_id_vec[0]))
        } else if ri_judgement(&ie_diff) {
            // If any of the differences between two consecutive IDs exceeds 1,000, and is not evenly divisible by 256,
            // the test's value is RI (random positive increments).
            // If the difference is evenly divisible by 256, it must be at least 256,000 to cause this RI result.
            Some(String::from("RI"))
        } else if bi_judgement(&ie_diff) {
            // If all of the differences are divisible by 256 and no greater than 5,120, the test is set to BI (broken increment).
            // This happens on systems like Microsoft Windows where the IP ID is sent in host byte order rather than network byte order.
            // It works fine and isn't any sort of RFC violation, though it does give away host architecture details which can be useful to attackers.
            Some(String::from("BI"))
        } else if i_judgement(&ie_diff) {
            // If all of the differences are less than ten, the value is I (incremental).
            // We allow difference up to ten here (rather than requiring sequential ordering) because traffic from other hosts can cause sequence gaps.
            Some(String::from("I"))
        } else {
            // If none of the previous steps identify the generation algorithm, the test is omitted from the fingerprint.
            None
        }
    } else {
        // and for II, both ICMP responses must be received.
        None
    };
    (ti, ci, ii)
}

/// Shared IP ID sequence Boolean (SS).
pub(crate) fn tcp_ss(
    seqrr: &SEQRR,
    ierr: &IERR,
    ti: &Option<String>,
    ii: &Option<String>,
) -> Option<String> {
    let judge_value = |x: &Option<String>| -> bool {
        if let Some(x) = x {
            if x == "RI" || x == "BI" || x == "I" {
                true
            } else {
                false
            }
        } else {
            false
        }
    };

    // This test is only included if II is RI, BI, or I and TI is the same.
    let c1 = judge_value(ii);
    let c2 = judge_value(ti);

    if c1 && c2 {
        let seq1_ip_id = get_ip_id(&seqrr.seq1.response2, "seq1");
        let seq2_ip_id = get_ip_id(&seqrr.seq2.response2, "seq2");
        let seq3_ip_id = get_ip_id(&seqrr.seq3.response2, "seq3");
        let seq4_ip_id = get_ip_id(&seqrr.seq4.response2, "seq4");
        let seq5_ip_id = get_ip_id(&seqrr.seq5.response2, "seq5");
        let seq6_ip_id = get_ip_id(&seqrr.seq6.response2, "seq6");
        let mut tmp_vec = Vec::new();
        tmp_vec.push(seq1_ip_id);
        tmp_vec.push(seq2_ip_id);
        tmp_vec.push(seq3_ip_id);
        tmp_vec.push(seq4_ip_id);
        tmp_vec.push(seq5_ip_id);
        tmp_vec.push(seq6_ip_id);

        let mut ip_id_vec = Vec::new();
        for i in tmp_vec {
            match i {
                Some(i) => ip_id_vec.push(Some(i)),
                None => {
                    ip_id_vec.push(None) // need None value here to identified the localtion of specific value
                }
            }
        }

        let first_ip_id = |ip_id_vec: &[Option<u16>]| -> Option<(u16, usize)> {
            for (i, ip_id) in ip_id_vec.iter().enumerate() {
                match ip_id {
                    Some(ip_id) => return Some((*ip_id, i)),
                    None => (),
                }
            }
            None
        };
        let last_ip_id = |ip_id_vec: &[Option<u16>]| -> Option<(u16, usize)> {
            for (i, ip_id) in ip_id_vec.iter().rev().enumerate() {
                match ip_id {
                    Some(ip_id) => return Some((*ip_id, ip_id_vec.len() - i)),
                    None => (),
                }
            }
            None
        };

        let (seq_first_ip_id, first) = match first_ip_id(&ip_id_vec) {
            Some((s, f)) => (s, f),
            None => return None,
        };

        let (seq_last_ip_id, last) = match last_ip_id(&ip_id_vec) {
            Some((s, f)) => (s, f),
            None => return None,
        };

        if last <= first {
            return None;
        }

        let difference = if seq_last_ip_id > seq_first_ip_id {
            seq_last_ip_id - seq_first_ip_id
        } else {
            !(seq_first_ip_id - seq_last_ip_id)
        };

        let avg = difference as f64 / (last - first) as f64;
        let ie1_ip_id = get_ip_id(&ierr.ie1.response2, "ie1");
        let ss = match ie1_ip_id {
            Some(ie1_ip_id) => {
                // If the first ICMP echo response IP ID is less than the final TCP sequence response IP ID plus three times avg,
                // the SS result is S. Otherwise it is O.
                let temp_value = seq_last_ip_id as f64 + (3.0 * avg);
                let ss = if (ie1_ip_id as f64) < temp_value {
                    String::from("S")
                } else {
                    String::from("O")
                };
                ss
            }
            None => return None,
        };
        Some(ss)
    } else {
        None
    }
}

fn get_tsval(eth_response: &[u8], probe_name: &str) -> Option<u32> {
    if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
        if let Some(ipv4_packet) = build_ipv4_packet(eth_packet.payload(), probe_name) {
            if let Some(tcp_packet) = build_tcp_packet(ipv4_packet.payload(), probe_name) {
                let options_vec = tcp_packet.get_options();
                for option in options_vec {
                    match option.number {
                        TcpOptionNumbers::TIMESTAMPS => {
                            // get first 4 u8 values
                            let tsval_vec = if option.data.len() >= 4 {
                                &option.data[0..4]
                            } else {
                                &option.data
                            };
                            let tsval = vec_to_u32(tsval_vec);
                            return Some(tsval);
                        }
                        _ => (),
                    }
                }
            }
        }
    }
    None
}

/// TCP timestamp option algorithm (TS).
pub(crate) fn tcp_ts(seqrr: &SEQRR) -> Option<String> {
    let tsval_1 = get_tsval(&seqrr.seq1.response2, "seq1");
    let tsval_2 = get_tsval(&seqrr.seq2.response2, "seq2");
    let tsval_3 = get_tsval(&seqrr.seq3.response2, "seq3");
    let tsval_4 = get_tsval(&seqrr.seq4.response2, "seq4");
    let tsval_5 = get_tsval(&seqrr.seq5.response2, "seq5");
    let tsval_6 = get_tsval(&seqrr.seq6.response2, "seq6");
    let mut tmp_vec = Vec::new();
    tmp_vec.push(tsval_1);
    tmp_vec.push(tsval_2);
    tmp_vec.push(tsval_3);
    tmp_vec.push(tsval_4);
    tmp_vec.push(tsval_5);
    tmp_vec.push(tsval_6);

    let mut tsval_vec = Vec::new();
    for t in tmp_vec {
        match t {
            Some(t) => tsval_vec.push(t),
            None => warn!("tsval is null"),
        }
    }

    let mut one_tsval_zero = false;
    for tsval in &tsval_vec {
        if *tsval == 0 {
            one_tsval_zero = true;
        }
    }

    let ts = if tsval_vec.len() == 0 {
        // If any of the responses have no timestamp option, TS is set to U (unsupported).
        String::from("U")
    } else if one_tsval_zero {
        // If any of the timestamp values are zero, TS is set to 0.
        String::from("0")
    } else {
        let diff = get_diff_u32(&tsval_vec);
        let ts = if diff.len() > 0 {
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
        } else {
            return None;
        };
        ts
    };
    Some(ts)
}

pub(crate) fn tcp_o(eth_response: &[u8], probe_name: &str) -> Option<String> {
    if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
        if let Some(ipv4_packet) = build_ipv4_packet(eth_packet.payload(), probe_name) {
            if let Some(tcp_packet) = build_tcp_packet(ipv4_packet.payload(), probe_name) {
                let options_vec = tcp_packet.get_options();
                let mut o_ret = String::new();
                for option in options_vec {
                    match option.number {
                        TcpOptionNumbers::MSS => {
                            let data = if option.data.len() > 4 {
                                &option.data[0..4]
                            } else {
                                &option.data
                            };
                            let mss = vec_to_u32(data);
                            let o_str = format!("M{:X}", mss);
                            o_ret += &o_str;
                        }
                        TcpOptionNumbers::SACK_PERMITTED => {
                            o_ret += "S";
                        }
                        TcpOptionNumbers::EOL => {
                            o_ret += "L";
                        }
                        TcpOptionNumbers::NOP => {
                            o_ret += "N";
                        }
                        TcpOptionNumbers::WSCALE => {
                            let data = if option.data.len() > 4 {
                                &option.data[0..4]
                            } else {
                                &option.data
                            };

                            let wscale = vec_to_u32(data);
                            let o_str = format!("W{:X}", wscale);
                            o_ret += &o_str;
                        }
                        TcpOptionNumbers::TIMESTAMPS => {
                            o_ret += "T";
                            let t0 = if option.data.len() > 0 {
                                if option.data.len() >= 4 {
                                    &option.data[0..4]
                                } else {
                                    &[0; 4]
                                }
                            } else {
                                &[0; 4]
                            };

                            let t1 = if option.data.len() > 4 {
                                if option.data.len() >= 8 {
                                    &option.data[4..8]
                                } else {
                                    &[0; 4]
                                }
                            } else {
                                &[0; 4]
                            };

                            let t0_u32 = vec_to_u32(t0);
                            let t1_u32 = vec_to_u32(t1);
                            if t0_u32 == 0 {
                                o_ret += "0";
                            } else {
                                o_ret += "1";
                            }
                            if t1_u32 == 0 {
                                o_ret += "0";
                            } else {
                                o_ret += "1";
                            }
                        }
                        _ => (),
                    }
                }
                return Some(o_ret);
            }
        }
    }
    None
}

/// TCP options (O, O1–O6).
pub(crate) fn tcp_ox(
    seqrr: &SEQRR,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let o1 = tcp_o(&seqrr.seq1.response2, "seq1");
    let o2 = tcp_o(&seqrr.seq2.response2, "seq2");
    let o3 = tcp_o(&seqrr.seq3.response2, "seq3");
    let o4 = tcp_o(&seqrr.seq4.response2, "seq4");
    let o5 = tcp_o(&seqrr.seq5.response2, "seq5");
    let o6 = tcp_o(&seqrr.seq6.response2, "seq6");
    (o1, o2, o3, o4, o5, o6)
}

pub(crate) fn tcp_w(eth_response: &[u8], probe_name: &str) -> Option<u16> {
    if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
        if let Some(ipv4_packet) = build_ipv4_packet(eth_packet.payload(), probe_name) {
            if let Some(tcp_packet) = build_tcp_packet(ipv4_packet.payload(), probe_name) {
                let window = tcp_packet.get_window();
                return Some(window);
            }
        }
    }
    None
}

/// TCP initial window size (W, W1–W6).
pub(crate) fn tcp_wx(
    seqrr: &SEQRR,
) -> (
    Option<u16>,
    Option<u16>,
    Option<u16>,
    Option<u16>,
    Option<u16>,
    Option<u16>,
) {
    let w1 = tcp_w(&seqrr.seq1.response2, "seq1");
    let w2 = tcp_w(&seqrr.seq2.response2, "seq2");
    let w3 = tcp_w(&seqrr.seq3.response2, "seq3");
    let w4 = tcp_w(&seqrr.seq4.response2, "seq4");
    let w5 = tcp_w(&seqrr.seq5.response2, "seq5");
    let w6 = tcp_w(&seqrr.seq6.response2, "seq6");
    (w1, w2, w3, w4, w5, w6)
}

/// Responsiveness (R).
pub(crate) fn tcp_udp_icmp_r(eth_response: &[u8], probe_name: &str) -> Option<String> {
    if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
        if let Some(ipv4_packet) = build_ipv4_packet(eth_packet.payload(), probe_name) {
            let ret = match ipv4_packet.payload().len() {
                0 => String::from("N"),
                _ => String::from("Y"),
            };
            return Some(ret);
        }
    }
    None
}

/// IP don't fragment bit (DF).
pub(crate) fn tcp_udp_df(eth_response: &[u8], probe_name: &str) -> Option<String> {
    if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
        if let Some(ipv4_packet) = build_ipv4_packet(eth_packet.payload(), probe_name) {
            let ipv4_flags = ipv4_packet.get_flags();
            let df_mask: u8 = 0b0010;
            let ret = if (ipv4_flags & df_mask) != 0 {
                String::from("Y")
            } else {
                String::from("N")
            };
            return Some(ret);
        }
    }
    None
}

fn udp_hops(u1rr: &U1RR, probe_name: &str) -> Option<u8> {
    let ipv4_request = &u1rr.u1.request3;
    if let Some(request_ipv4_packet) = build_ipv4_packet(ipv4_request, probe_name) {
        // must have request
        let eth_response = &u1rr.u1.response2;
        if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
            if let Some(ipv4_packet) = build_ipv4_packet(eth_packet.payload(), probe_name) {
                if let Some(icmp_packet) = build_icmp_packet(ipv4_packet.payload(), probe_name) {
                    let r_ipv4_buff = &icmp_packet.payload()[4..];
                    if let Some(r_ipv4_packet) = build_ipv4_packet(r_ipv4_buff, probe_name) {
                        let ttl_1 = request_ipv4_packet.get_ttl();
                        let ttl_2 = r_ipv4_packet.get_ttl();
                        let hops = if ttl_1 > ttl_2 {
                            ttl_1 - ttl_2
                        } else {
                            ttl_2 - ttl_1
                        };
                        // It is not uncommon for Nmap to receive no response to the U1 probe.
                        return Some(hops);
                    }
                }
            }
        }
    }
    // It is common for Nmap to receive no response when target is Windows.
    None
}

/// IP initial time-to-live (T).
pub(crate) fn tcp_udp_icmp_t(eth_response: &[u8], u1rr: &U1RR, probe_name: &str) -> Option<u16> {
    let hops = udp_hops(u1rr, probe_name);
    match hops {
        Some(hops) => {
            if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
                if let Some(ipv4_packet) = build_ipv4_packet(eth_packet.payload(), probe_name) {
                    let ipv4_ttl = ipv4_packet.get_ttl();
                    // avoid overflow in integer addition
                    return Some(hops as u16 + ipv4_ttl as u16);
                }
            }
        }
        None => (), // no udp return, ignore t and use tg instead
    }
    None
}

/// IP initial time-to-live guess (TG).
pub(crate) fn tcp_udp_icmp_tg(eth_response: &[u8], probe_name: &str) -> Option<u16> {
    if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
        if let Some(ipv4_packet) = build_ipv4_packet(eth_packet.payload(), probe_name) {
            let ipv4_ttl = ipv4_packet.get_ttl() as u16;

            let er_lim = 5;
            let regual_ttl_vec = vec![32, 64, 128, 255];
            let mut guess_value = 0;

            for r in regual_ttl_vec {
                if ipv4_ttl > r {
                    if ipv4_ttl - r <= er_lim {
                        guess_value = r;
                    }
                } else {
                    if r - ipv4_ttl <= er_lim {
                        guess_value = r;
                    }
                }
            }

            if guess_value != 0 {
                return Some(guess_value);
            } else {
                // take the observed value
                return Some(ipv4_ttl);
            }
        }
    }
    None
}

/// Explicit congestion notification (CC).
pub(crate) fn tcp_cc(eth_response: &[u8], probe_name: &str) -> Option<String> {
    if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
        if let Some(ipv4_packet) = build_ipv4_packet(eth_packet.payload(), probe_name) {
            if let Some(tcp_packet) = build_tcp_packet(ipv4_packet.payload(), probe_name) {
                let tcp_flag = tcp_packet.get_flags();
                let ret = if (tcp_flag & ECE_MASK != 0) && (tcp_flag & CWR_MASK == 0) {
                    // Only the ECE bit is set (not CWR). This host supports ECN.
                    String::from("Y")
                } else if (tcp_flag & CWR_MASK == 0) && (tcp_flag & ECE_MASK == 0) {
                    // Neither of these two bits is set. The target does not support ECN.
                    String::from("N")
                } else if (tcp_flag & CWR_MASK != 0) && (tcp_flag & ECE_MASK != 0) {
                    // Both bits are set. The target does not support ECN, but it echoes back what it thinks is a reserved bit.
                    String::from("S")
                } else {
                    // The one remaining combination of these two bits (other).
                    String::from("O")
                };
                return Some(ret);
            }
        }
    }
    None
}

/// TCP miscellaneous quirks (Q).
pub(crate) fn tcp_q(eth_response: &[u8], probe_name: &str) -> Option<String> {
    if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
        if let Some(ipv4_packet) = build_ipv4_packet(eth_packet.payload(), probe_name) {
            if let Some(tcp_packet) = build_tcp_packet(ipv4_packet.payload(), probe_name) {
                let mut ret = String::new();
                let tcp_reserved = tcp_packet.get_reserved();
                if tcp_reserved != 0 {
                    // The first is that the reserved field in the TCP header (right after the header length) is nonzero.
                    // This is particularly likely to happen in response to the ECN test as that one sets a reserved bit in the probe.
                    // If this is seen in a packet, an "R" is recorded in the Q string.
                    ret += "R"
                }
                if tcp_packet.get_urgent_ptr() != 0 {
                    // The other quirk Nmap tests for is a nonzero urgent pointer field value when the URG flag is not set.
                    // This is also particularly likely to be seen in response to the ECN probe, which sets a non-zero urgent field.
                    // A "U" is appended to the Q string when this is seen.
                    ret += "U"
                }
                return Some(ret);
            }
        }
    }
    None
}

/// TCP sequence number (S).
pub(crate) fn tcp_s(ipv4_request: &[u8], eth_response: &[u8], probe_name: &str) -> Option<String> {
    if let Some(ipv4_packet_request) = build_ipv4_packet(ipv4_request, probe_name) {
        if let Some(tcp_packet_request) =
            build_tcp_packet(ipv4_packet_request.payload(), probe_name)
        {
            if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
                if let Some(ipv4_packet_response) =
                    build_ipv4_packet(eth_packet.payload(), probe_name)
                {
                    if let Some(tcp_packet_response) =
                        build_tcp_packet(ipv4_packet_response.payload(), probe_name)
                    {
                        let ack_request = tcp_packet_request.get_acknowledgement();
                        let seq_response = tcp_packet_response.get_sequence();
                        let ret = if seq_response == 0 {
                            // Sequence number is zero.
                            String::from("Z")
                        } else if seq_response == ack_request {
                            // Sequence number is the same as the acknowledgment number in the probe.
                            String::from("A")
                        } else if seq_response == (ack_request + 1) {
                            // Sequence number is the same as the acknowledgment number in the probe plus one.
                            String::from("A+")
                        } else {
                            // Sequence number is something else (other).
                            String::from("O")
                        };
                        return Some(ret);
                    }
                }
            }
        }
    }
    None
}

/// TCP acknowledgment number (A).
pub(crate) fn tcp_a(ipv4_request: &[u8], eth_response: &[u8], probe_name: &str) -> Option<String> {
    if let Some(ipv4_packet_request) = build_ipv4_packet(ipv4_request, probe_name) {
        if let Some(tcp_packet_request) =
            build_tcp_packet(ipv4_packet_request.payload(), probe_name)
        {
            if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
                if let Some(ipv4_packet_response) =
                    build_ipv4_packet(eth_packet.payload(), probe_name)
                {
                    if let Some(tcp_packet_response) =
                        build_tcp_packet(ipv4_packet_response.payload(), probe_name)
                    {
                        let seq_request = tcp_packet_request.get_sequence();
                        let ack_response = tcp_packet_response.get_acknowledgement();
                        let ret = if ack_response == 0 {
                            // Acknowledgment number is zero.
                            String::from("Z")
                        } else if ack_response == seq_request {
                            // Acknowledgment number is the same as the sequence number in the probe.
                            String::from("S")
                        } else if ack_response == (seq_request + 1) {
                            // Acknowledgment number is the same as the sequence number in the probe plus one.
                            String::from("S+")
                        } else {
                            // Acknowledgment number is something else (other).
                            String::from("O")
                        };
                        return Some(ret);
                    }
                }
            }
        }
    }
    None
}

/// TCP flags (F).
pub(crate) fn tcp_f(eth_response: &[u8], probe_name: &str) -> Option<String> {
    if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
        if let Some(ipv4_packet) = build_ipv4_packet(eth_packet.payload(), probe_name) {
            if let Some(tcp_packet) = build_tcp_packet(ipv4_packet.payload(), probe_name) {
                let tcp_flag = tcp_packet.get_flags();
                let mut ret = String::new();
                if tcp_flag & ECE_MASK != 0 {
                    // ECN Echo (ECE)
                    ret += "E";
                }
                if tcp_flag & URG_MASK != 0 {
                    // Urgent Data (URG)
                    ret += "U";
                }
                if tcp_flag & ACK_MASK != 0 {
                    // Acknowledgment (ACK)
                    ret += "A";
                }
                if tcp_flag & PSH_MASK != 0 {
                    // Push (PSH)
                    ret += "P";
                }
                if tcp_flag & RST_MASK != 0 {
                    // Reset (RST)
                    ret += "R";
                }
                if tcp_flag & SYN_MASK != 0 {
                    // Synchronize (SYN)
                    ret += "S";
                }
                if tcp_flag & FIN_MASK != 0 {
                    // Final (FIN)
                    ret += "F";
                }
                return Some(ret);
            }
        }
    }
    None
}

/// TCP RST data checksum (RD).
pub(crate) fn tcp_rd(eth_response: &[u8], probe_name: &str) -> Option<u32> {
    if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
        if let Some(ipv4_packet) = build_ipv4_packet(eth_packet.payload(), probe_name) {
            if let Some(tcp_packet) = build_tcp_packet(ipv4_packet.payload(), probe_name) {
                let tcp_payload = tcp_packet.payload();
                return Some(crc32fast::hash(tcp_payload));
            }
        }
    }
    None
}

/// IP total length (IPL).
pub(crate) fn udp_ipl(u1: &U1RR) -> u32 {
    let response = &u1.u1.response2;
    response.len() as u32
}

/// Unused port unreachable field nonzero (UN).
pub(crate) fn udp_un(u1: &U1RR, probe_name: &str) -> Option<u32> {
    // An ICMP port unreachable message header is eight bytes long,
    // but only the first four are used. RFC 792 states that the last four bytes must be zero.
    // A few implementations (mostly ethernet switches and some specialized embedded devices) set it anyway.
    // The value of those last four bytes is recorded in this field.
    let eth_response = &u1.u1.response2;
    if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
        if let Some(ipv4_packet) = build_ipv4_packet(eth_packet.payload(), probe_name) {
            let icmp_buff = ipv4_packet.payload();
            if icmp_buff.len() > 4 {
                let rest_of_header = if icmp_buff.len() >= 8 {
                    &icmp_buff[4..8]
                } else {
                    &icmp_buff[4..icmp_buff.len() - 1]
                };
                let un = vec_to_u32(rest_of_header);
                return Some(un);
            } else {
                return Some(0);
            }
        }
    }
    None
}

/// Returned probe IP total length value (RIPL).
pub(crate) fn udp_ripl(u1: &U1RR, probe_name: &str) -> Option<String> {
    let eth_response = &u1.u1.response2;
    if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
        if let Some(ipv4_packet) = build_ipv4_packet(eth_packet.payload(), probe_name) {
            if let Some(icmp_packet) = build_icmp_packet(ipv4_packet.payload(), probe_name) {
                let ripl = icmp_packet.payload().len() - 4;
                let ret = if ripl == 328 {
                    // If the correct value of 0x148 (328) is returned, the value G (for good) is stored instead of the actual value.
                    String::from("G")
                } else {
                    format!("{:X}", ripl)
                };
                return Some(ret);
            }
        }
    }
    None
}

/// Returned probe IP ID value (RID).
pub(crate) fn udp_rid(u1: &U1RR, probe_name: &str) -> Option<String> {
    let eth_response = &u1.u1.response2;
    if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
        if let Some(ipv4_packet) = build_ipv4_packet(eth_packet.payload(), probe_name) {
            if let Some(icmp_packet) = build_icmp_packet(ipv4_packet.payload(), probe_name) {
                let r_ipv4_buff = &icmp_packet.payload()[4..];
                if let Some(r_ipv4_packet) = build_ipv4_packet(r_ipv4_buff, probe_name) {
                    let rid = r_ipv4_packet.get_identification();
                    let ret = if rid == 0x1042 {
                        // The U1 probe has a static IP ID value of 0x1042.
                        // If that value is returned in the port unreachable message, the value G is stored for this test.
                        String::from("G")
                    } else {
                        format!("{:X}", rid)
                    };
                    return Some(ret);
                }
            }
        }
    }
    None
}

/// Integrity of returned probe IP checksum value (RIPCK).
pub(crate) fn udp_ripck(u1: &U1RR, probe_name: &str) -> Option<String> {
    let eth_response = &u1.u1.response2;
    if let Some(eth_packet) = build_eth_packet(eth_response, probe_name) {
        if let Some(ipv4_packet) = build_ipv4_packet(eth_packet.payload(), probe_name) {
            let o_checksum = ipv4_packet.get_checksum();
            let t_checksum = ipv4::checksum(&ipv4_packet.to_immutable());
            let ret = if o_checksum == t_checksum {
                // However, the checksum we receive should match the enclosing IP packet.
                // If it does, the value G (good) is stored for this test.
                String::from("G")
            } else if o_checksum == 0 {
                // If the returned value is zero, then Z is stored.
                String::from("Z")
            } else {
                // Otherwise the result is I (invalid).
                String::from("I")
            };
            return Some(ret);
        }
    }
    None
}

/// Integrity of returned probe UDP checksum (RUCK).
pub(crate) fn udp_ruck(u1: &U1RR, probe_name: &str) -> Option<String> {
    let ipv4_request = &u1.u1.request3;
    let eth_response = &u1.u1.response2;

    let ipv4_packet_request = match build_ipv4_packet(ipv4_request, probe_name) {
        Some(p) => p,
        None => return None, // must have request
    };
    let udp_packet_request = match build_udp_packet(ipv4_packet_request.payload(), probe_name) {
        Some(p) => p,
        None => return None,
    };
    let checksum_request = udp_packet_request.get_checksum();

    let eth_packet = match build_eth_packet(eth_response, probe_name) {
        Some(p) => p,
        None => return None,
    };
    let ipv4_packet_response = match build_ipv4_packet(eth_packet.payload(), probe_name) {
        Some(p) => p,
        None => return None,
    };
    let icmp_packet_response = match build_icmp_packet(ipv4_packet_response.payload(), probe_name) {
        Some(p) => p,
        None => return None,
    };
    let r_ipv4_buff = &icmp_packet_response.payload()[4..];
    let r_ipv4_packet_response = match build_ipv4_packet(r_ipv4_buff, probe_name) {
        Some(p) => p,
        None => return None,
    };
    let udp_packet_response = match build_udp_packet(r_ipv4_packet_response.payload(), probe_name) {
        Some(p) => p,
        None => return None,
    };
    let checksum_response = udp_packet_response.get_checksum();
    let ret = if checksum_response == checksum_request {
        // The UDP header checksum value should be returned exactly as it was sent.
        // If it is, G is recorded for this test. Otherwise the value actually returned is recorded.
        String::from("G")
    } else {
        format!("{:X}", checksum_response)
    };
    Some(ret)
}

/// Integrity of returned UDP data (RUD).
pub(crate) fn udp_rud(u1: &U1RR, probe_name: &str) -> Option<String> {
    let eth_response = &u1.u1.response2;
    let eth_packet = match build_eth_packet(eth_response, probe_name) {
        Some(p) => p,
        None => return None,
    };
    let ipv4_packet_response = match build_ipv4_packet(eth_packet.payload(), probe_name) {
        Some(p) => p,
        None => return None,
    };
    let icmp_packet_response = match build_icmp_packet(ipv4_packet_response.payload(), probe_name) {
        Some(p) => p,
        None => return None,
    };
    let r_ipv4_buff = &icmp_packet_response.payload()[4..];
    let r_ipv4_packet_response = match build_ipv4_packet(r_ipv4_buff, probe_name) {
        Some(p) => p,
        None => return None,
    };
    let r_udp_packet_response =
        match build_udp_packet(&r_ipv4_packet_response.payload(), probe_name) {
            Some(p) => p,
            None => return None,
        };
    let payload_c_judge = |payload: &[u8]| -> bool {
        for p in payload {
            if *p != 0x43 {
                return false;
            }
        }
        true
    };
    let c = payload_c_judge(r_udp_packet_response.payload());
    let ret = if c || r_udp_packet_response.payload().len() == 0 {
        // This test checks the integrity of the (possibly truncated) returned UDP payload.
        // If all the payload bytes are the expected 'C' (0x43), or if the payload was truncated to zero length, G is recorded;
        String::from("G")
    } else {
        // Otherwise, I (invalid) is recorded.
        String::from("I")
    };
    Some(ret)
}

/// Don't fragment (ICMP) (DFI).
pub(crate) fn icmp_dfi(ie: &IERR, probe_name: &str) -> Option<String> {
    let df_mask: u8 = 0b0010;

    let ipv4_request_1 = &ie.ie1.request3;
    let ipv4_request_2 = &ie.ie2.request3;
    let eth_response_1 = &ie.ie1.response2;
    let eth_response_2 = &ie.ie2.response2;

    let ipv4_packet_1 = match build_ipv4_packet(ipv4_request_1, probe_name) {
        Some(p) => p,
        None => return None,
    };
    let flag_1 = ipv4_packet_1.get_flags();
    let df_1_set = if flag_1 & df_mask != 0 { true } else { false };

    let ipv4_packet_2 = match build_ipv4_packet(ipv4_request_2, probe_name) {
        Some(p) => p,
        None => return None,
    };
    let flag_2 = ipv4_packet_2.get_flags();
    let df_2_set = if flag_2 & df_mask != 0 { true } else { false };

    let eth_packet_1 = match build_eth_packet(eth_response_1, probe_name) {
        Some(p) => p,
        None => return None,
    };
    let ipv4_packet_3 = match build_ipv4_packet(eth_packet_1.payload(), probe_name) {
        Some(p) => p,
        None => return None,
    };
    let flag_3 = ipv4_packet_3.get_flags();
    let df_3_set = if flag_3 & df_mask != 0 { true } else { false };

    let eth_packet_2 = match build_eth_packet(eth_response_2, probe_name) {
        Some(p) => p,
        None => return None,
    };
    let ipv4_packet_4 = match build_ipv4_packet(eth_packet_2.payload(), probe_name) {
        Some(p) => p,
        None => return None,
    };
    let flag_4 = ipv4_packet_4.get_flags();
    let df_4_set = if flag_4 & df_mask != 0 { true } else { false };

    let ret = if !df_3_set && !df_4_set {
        // Neither of the ping responses have the DF bit set.
        String::from("N")
    } else if (df_1_set == df_3_set) && (df_2_set == df_4_set) {
        // Both responses echo the DF value of the probe.
        String::from("S")
    } else if df_3_set && df_4_set {
        // 	Both of the response DF bits are set.
        String::from("Y")
    } else {
        String::from("O")
    };
    Some(ret)
}

/// ICMP response code (CD).
pub(crate) fn icmp_cd(ie: &IERR, probe_name: &str) -> Option<String> {
    let ipv4_request_1 = &ie.ie1.request3;
    let ipv4_request_2 = &ie.ie2.request3;
    let eth_response_1 = &ie.ie1.response2;
    let eth_response_2 = &ie.ie2.response2;

    if eth_response_1.len() > 0 && eth_response_2.len() > 0 {
        let ipv4_packet_1 = match build_ipv4_packet(&ipv4_request_1, probe_name) {
            Some(p) => p,
            None => return None,
        };
        let icmp_packet_1 = match build_icmp_packet(ipv4_packet_1.payload(), probe_name) {
            Some(p) => p,
            None => return None,
        };
        let ipv4_packet_2 = match build_ipv4_packet(&ipv4_request_2, probe_name) {
            Some(p) => p,
            None => return None,
        };
        let icmp_packet_2 = match build_icmp_packet(ipv4_packet_2.payload(), probe_name) {
            Some(p) => p,
            None => return None,
        };
        let code_1 = icmp_packet_1.get_icmp_code();
        let code_2 = icmp_packet_2.get_icmp_code();

        let eth_packet_1 = match build_eth_packet(eth_response_1, probe_name) {
            Some(p) => p,
            None => return None,
        };
        let ipv4_packet_3 = match build_ipv4_packet(eth_packet_1.payload(), probe_name) {
            Some(p) => p,
            None => return None,
        };
        let icmp_packet_3 = match build_icmp_packet(ipv4_packet_3.payload(), probe_name) {
            Some(p) => p,
            None => return None,
        };
        let eth_packet_2 = match build_eth_packet(eth_response_2, probe_name) {
            Some(p) => p,
            None => return None,
        };
        let ipv4_packet_4 = match build_ipv4_packet(eth_packet_2.payload(), probe_name) {
            Some(p) => p,
            None => return None,
        };
        let icmp_packet_4 = match build_icmp_packet(ipv4_packet_4.payload(), probe_name) {
            Some(p) => p,
            None => return None,
        };
        let code_3 = icmp_packet_3.get_icmp_code();
        let code_4 = icmp_packet_4.get_icmp_code();

        let ret = if (code_3 == IcmpCode(0)) && (code_4 == IcmpCode(0)) {
            // Both code values are zero.
            String::from("Z")
        } else if (code_1 == code_3) && (code_2 == code_4) {
            // Both code values are the same as in the corresponding probe.
            String::from("S")
        } else if code_3 == code_4 {
            // When they both use the same non-zero number, it is shown here.
            format!("{:X}", code_3.0)
        } else {
            String::from("O")
        };
        Some(ret)
    } else {
        Some(String::new())
    }
}
