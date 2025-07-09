use crc32fast;
use gcdx::gcdx;
use tracing::warn;
use pnet::packet::Packet;
use pnet::packet::icmp::IcmpCode;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ipv4;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpOptionNumbers;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::panic::Location;

use super::rr::IERR;
use super::rr::SEQRR;
use super::rr::TXRR;
use super::rr::U1RR;

use crate::error::PistolError;
use crate::utils::SpHex;

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
// const PROGRAM_ESTIMATION_ERROR_ISR: f32 = 0.35;
// const PROGRAM_ESTIMATION_ERROR_SP: f32 = 0.35;
const PROGRAM_ESTIMATION_ERROR_ISR: f32 = 0.0;
const PROGRAM_ESTIMATION_ERROR_SP: f32 = 0.0;

fn get_ipv4_packet(ipv4_buff: &[u8]) -> Result<Ipv4Packet, PistolError> {
    if ipv4_buff.len() > 0 {
        match Ipv4Packet::new(ipv4_buff) {
            Some(p) => return Ok(p),
            None => (),
        }
    }
    Err(PistolError::GetIpv4PacketFailed)
}

fn get_tcp_packet(tcp_buff: &[u8]) -> Result<TcpPacket, PistolError> {
    if tcp_buff.len() > 0 {
        match TcpPacket::new(tcp_buff) {
            Some(p) => return Ok(p),
            None => (),
        }
    }
    Err(PistolError::GetTcpPacketFailed)
}

fn get_icmp_packet(icmp_buff: &[u8]) -> Result<IcmpPacket, PistolError> {
    if icmp_buff.len() > 0 {
        match IcmpPacket::new(icmp_buff) {
            Some(p) => return Ok(p),
            None => (),
        }
    }
    Err(PistolError::GetIcmpPacketFailed)
}

fn get_udp_packet(udp_buff: &[u8]) -> Result<UdpPacket, PistolError> {
    if udp_buff.len() > 0 {
        match UdpPacket::new(udp_buff) {
            Some(p) => return Ok(p),
            None => (),
        }
    }
    Err(PistolError::GetUdpPacketFailed)
}

fn get_tcp_seq(ipv4_buff: &[u8]) -> Result<u32, PistolError> {
    let ipv4_packet = get_ipv4_packet(ipv4_buff)?;
    let tcp_packet = get_tcp_packet(ipv4_packet.payload())?;
    Ok(tcp_packet.get_sequence())
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

/// TCP ISN greatest common divisor (GCD)
pub fn tcp_gcd(seqrr: &SEQRR) -> Result<(u32, Vec<u32>), PistolError> {
    let s1 = get_tcp_seq(&seqrr.seq1.response);
    let s2 = get_tcp_seq(&seqrr.seq2.response);
    let s3 = get_tcp_seq(&seqrr.seq3.response);
    let s4 = get_tcp_seq(&seqrr.seq4.response);
    let s5 = get_tcp_seq(&seqrr.seq5.response);
    let s6 = get_tcp_seq(&seqrr.seq6.response);
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
            Ok(s) => seq_vec.push(s),
            Err(e) => warn!("{}", e),
        }
    }

    let diff = get_diff_u32(&seq_vec);
    if diff.len() > 1 {
        let gcd = match gcdx(&diff) {
            Some(g) => g,
            None => return Err(PistolError::CalcDiffFailed),
        };
        Ok((gcd, diff))
    } else if diff.len() == 1 {
        let gcd = diff[0];
        Ok((gcd, diff))
    } else {
        Err(PistolError::CalcDiffFailed)
    }
}

/// TCP ISN counter rate (ISR)
pub fn tcp_isr(diff: Vec<u32>, elapsed: f32) -> Result<(u32, Vec<f32>), PistolError> {
    if diff.len() > 0 {
        let mut seq_rates: Vec<f32> = Vec::new();
        let mut sum = 0.0;
        for d in &diff {
            let f = (*d as f32) / elapsed;
            seq_rates.push(f);
            sum += f;
        }
        let avg = sum / diff.len() as f32;
        let isr = if avg < 1.0 {
            0
        } else {
            ((8.0 - PROGRAM_ESTIMATION_ERROR_ISR) * avg.log2()).round() as u32
        };
        Ok((isr, seq_rates))
    } else {
        Err(PistolError::CalcISRFailed)
    }
}

/// Calculate standard deviation
fn vec_std(values: &[f32]) -> f32 {
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
pub fn tcp_sp(seq_rates: Vec<f32>, gcd: u32) -> Result<u32, PistolError> {
    // This test is only performed if at least four responses were seen.
    if seq_rates.len() >= 4 {
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
            ((8.0 - PROGRAM_ESTIMATION_ERROR_SP) * sd.log2()).round() as u32
        };
        Ok(sp)
    } else {
        Ok(0) // mean omitting
    }
}

fn get_ip_id(ipv4_buff: &[u8]) -> Result<u16, PistolError> {
    let ipv4_packet = get_ipv4_packet(ipv4_buff)?;
    Ok(ipv4_packet.get_identification())
}

/// IP ID sequence generation algorithm (TI, CI, II)
pub fn tcp_ti_ci_ii(
    seqrr: &SEQRR,
    t2t7rr: &TXRR,
    ierr: &IERR,
) -> Result<(String, String, String), PistolError> {
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
    let hex_judgement = |ip_id_vec: &[u16]| -> Result<bool, PistolError> {
        let v3 = get_diff_u16(ip_id_vec);
        let mut sum = 0;
        for v in v3 {
            sum += v;
        }

        if sum == 0 { Ok(true) } else { Ok(false) }
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

    let seq1_ip_id = get_ip_id(&seqrr.seq1.response);
    let seq2_ip_id = get_ip_id(&seqrr.seq2.response);
    let seq3_ip_id = get_ip_id(&seqrr.seq3.response);
    let seq4_ip_id = get_ip_id(&seqrr.seq4.response);
    let seq5_ip_id = get_ip_id(&seqrr.seq5.response);
    let seq6_ip_id = get_ip_id(&seqrr.seq6.response);
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
            Ok(s) => seq_ip_id_vec.push(s),
            Err(e) => warn!("{}", e),
        }
    }

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
        } else if hex_judgement(&seq_ip_id_vec)? {
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
            String::new()
        }
    } else {
        // For TI, at least three responses must be received for the test to be included.
        String::new()
    };

    // CI is from the responses to the three TCP probes sent to a closed port: T5, T6, and T7.
    let t5_ip_id = get_ip_id(&t2t7rr.t5.response);
    let t6_ip_id = get_ip_id(&t2t7rr.t6.response);
    let t7_ip_id = get_ip_id(&t2t7rr.t7.response);
    let mut tmp_vec = Vec::new();
    tmp_vec.push(t5_ip_id);
    tmp_vec.push(t6_ip_id);
    tmp_vec.push(t7_ip_id);

    let mut t_ip_id_vec = Vec::new();
    for t in tmp_vec {
        match t {
            Ok(t) => t_ip_id_vec.push(t),
            Err(e) => warn!("{}", e),
        }
    }
    let t_diff = get_diff_u16(&t_ip_id_vec);

    let ci = if t_ip_id_vec.len() >= 2 {
        if z_judgement(&t_ip_id_vec) {
            // If all of the ID numbers are zero, the value of the test is Z.
            String::from("Z")
        } else if rd_judgement(&t_diff) {
            // If the IP ID sequence ever increases by at least 20,000, the value is RD (random).
            // This result isn't possible for II because there are not enough samples to support it.
            String::from("RD")
        } else if hex_judgement(&t_ip_id_vec)? {
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
            String::new()
        }
    } else {
        // for CI, at least two responses are required.
        String::new()
    };

    // II comes from the ICMP responses to the two IE ping probes.
    let ie1_ip_id = get_ip_id(&ierr.ie1.response);
    let ie2_ip_id = get_ip_id(&ierr.ie2.response);
    let mut tmp_vec = Vec::new();
    tmp_vec.push(ie1_ip_id);
    tmp_vec.push(ie2_ip_id);

    let mut ie_ip_id_vec = Vec::new();
    for i in tmp_vec {
        match i {
            Ok(i) => ie_ip_id_vec.push(i),
            Err(e) => warn!("{}", e),
        }
    }
    let ie_diff = get_diff_u16(&ie_ip_id_vec);
    // println!("{:?}", ie_ip_id_vec);
    // println!("{:?}", ie_diff);

    // RD result isn't possible for II because there are not enough samples to support it.
    let ii = if ie_ip_id_vec.len() >= 2 {
        if z_judgement(&ie_ip_id_vec) {
            // If all of the ID numbers are zero, the value of the test is Z.
            String::from("Z")
        } else if hex_judgement(&ie_ip_id_vec)? {
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
            String::new()
        }
    } else {
        // and for II, both ICMP responses must be received.
        String::new()
    };
    Ok((ti, ci, ii))
}

/// Shared IP ID sequence Boolean (SS)
pub fn tcp_ss(seqrr: &SEQRR, ierr: &IERR, ti: &str, ii: &str) -> Result<String, PistolError> {
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
        let seq1_ip_id = get_ip_id(&seqrr.seq1.response);
        let seq2_ip_id = get_ip_id(&seqrr.seq2.response);
        let seq3_ip_id = get_ip_id(&seqrr.seq3.response);
        let seq4_ip_id = get_ip_id(&seqrr.seq4.response);
        let seq5_ip_id = get_ip_id(&seqrr.seq5.response);
        let seq6_ip_id = get_ip_id(&seqrr.seq6.response);
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
                Ok(i) => ip_id_vec.push(Some(i)),
                Err(e) => {
                    warn!("{}", e);
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
            None => return Err(PistolError::CalcSSFailed),
        };

        let (seq_last_ip_id, last) = match last_ip_id(&ip_id_vec) {
            Some((s, f)) => (s, f),
            None => return Err(PistolError::CalcSSFailed),
        };

        if last <= first {
            return Ok(String::new());
        }

        let difference = if seq_last_ip_id > seq_first_ip_id {
            seq_last_ip_id - seq_first_ip_id
        } else {
            !(seq_first_ip_id - seq_last_ip_id)
        };

        let avg = difference as f32 / (last - first) as f32;
        let ie1_ip_id = get_ip_id(&ierr.ie1.response);
        let ss = match ie1_ip_id {
            Ok(ie1_ip_id) => {
                // If the first ICMP echo response IP ID is less than the final TCP sequence response IP ID plus three times avg,
                // the SS result is S. Otherwise it is O.
                let temp_value = seq_last_ip_id as f32 + (3.0 * avg);
                let ss = if (ie1_ip_id as f32) < temp_value {
                    String::from("S")
                } else {
                    String::from("O")
                };
                ss
            }
            Err(e) => {
                warn!("{}", e);
                String::new()
            }
        };
        Ok(ss)
    } else {
        Ok(String::new())
    }
}

fn get_tsval(ipv4_response: &[u8]) -> Result<u32, PistolError> {
    let ipv4_packet = get_ipv4_packet(ipv4_response)?;
    let tcp_packet = get_tcp_packet(ipv4_packet.payload())?;
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
        let tsval = SpHex::vec_4u8_to_u32(&tsval_vec);
        Ok(tsval)
    } else {
        Err(PistolError::TsValIsNull)
    }
}

/// TCP timestamp option algorithm (TS)
pub fn tcp_ts(seqrr: &SEQRR) -> Result<String, PistolError> {
    let tsval_1 = get_tsval(&seqrr.seq1.response);
    let tsval_2 = get_tsval(&seqrr.seq2.response);
    let tsval_3 = get_tsval(&seqrr.seq3.response);
    let tsval_4 = get_tsval(&seqrr.seq4.response);
    let tsval_5 = get_tsval(&seqrr.seq5.response);
    let tsval_6 = get_tsval(&seqrr.seq6.response);
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
            Ok(t) => tsval_vec.push(t),
            Err(e) => warn!("{}", e),
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
            String::new()
        };
        ts
    };
    Ok(ts)
}

/// TCP options (O, O1–O6)
pub fn tcp_o(ipv4_response: &[u8]) -> Result<String, PistolError> {
    let ipv4_packet = get_ipv4_packet(ipv4_response)?;
    let tcp_packet = get_tcp_packet(ipv4_packet.payload())?;
    let options_vec = tcp_packet.get_options();
    let mut o_ret = String::new();
    for option in options_vec {
        match option.number {
            TcpOptionNumbers::MSS => {
                let data = SpHex::vec_4u8_to_u32(&option.data);
                let o_str = format!("M{:X}", data);
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
                let data = SpHex::vec_4u8_to_u32(&option.data);
                let o_str = format!("W{:X}", data);
                o_ret += &o_str;
            }
            TcpOptionNumbers::TIMESTAMPS => {
                o_ret += "T";
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
                let t0_u32 = SpHex::vec_4u8_to_u32(&t0);
                let t1_u32 = SpHex::vec_4u8_to_u32(&t1);
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
    return Ok(o_ret);
}

/// TCP options (O, O1–O6)
pub fn tcp_ox(
    seqrr: &SEQRR,
) -> Result<(String, String, String, String, String, String), PistolError> {
    let o1 = tcp_o(&seqrr.seq1.response)?;
    let o2 = tcp_o(&seqrr.seq2.response)?;
    let o3 = tcp_o(&seqrr.seq3.response)?;
    let o4 = tcp_o(&seqrr.seq4.response)?;
    let o5 = tcp_o(&seqrr.seq5.response)?;
    let o6 = tcp_o(&seqrr.seq6.response)?;
    Ok((o1, o2, o3, o4, o5, o6))
}

/// TCP initial window size (W, W1–W6)
pub fn tcp_w(ipv4_response: &[u8]) -> Result<u16, PistolError> {
    let ipv4_packet = get_ipv4_packet(ipv4_response)?;
    let tcp_packet = get_tcp_packet(ipv4_packet.payload())?;
    let window = tcp_packet.get_window();
    Ok(window)
}

/// TCP initial window size (W, W1–W6)
pub fn tcp_wx(seqrr: &SEQRR) -> Result<(u16, u16, u16, u16, u16, u16), PistolError> {
    let w1 = tcp_w(&seqrr.seq1.response)?;
    let w2 = tcp_w(&seqrr.seq2.response)?;
    let w3 = tcp_w(&seqrr.seq3.response)?;
    let w4 = tcp_w(&seqrr.seq4.response)?;
    let w5 = tcp_w(&seqrr.seq5.response)?;
    let w6 = tcp_w(&seqrr.seq6.response)?;
    Ok((w1, w2, w3, w4, w5, w6))
}

/// Responsiveness (R)
pub fn tcp_udp_icmp_r(ipv4_response: &[u8]) -> Result<String, PistolError> {
    match ipv4_response.len() {
        0 => Ok(String::from("N")),
        _ => Ok(String::from("Y")),
    }
}

/// IP don't fragment bit (DF)
pub fn tcp_udp_df(ipv4_response: &[u8]) -> Result<String, PistolError> {
    let ipv4_packet = get_ipv4_packet(ipv4_response)?;
    let ipv4_flags = ipv4_packet.get_flags();
    let df_mask: u8 = 0b0010;
    let ret = if (ipv4_flags & df_mask) != 0 {
        String::from("Y")
    } else {
        String::from("N")
    };
    Ok(ret)
}

/// IP initial time-to-live (T)
pub fn tcp_udp_icmp_t(ipv4_response: &[u8], u1rr: &U1RR) -> Result<u16, PistolError> {
    let hops = udp_hops(u1rr)?;
    let response = match Ipv4Packet::new(ipv4_response) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                path: format!("{}", Location::caller()),
            });
        }
    };
    let response_ttl = response.get_ttl();
    // Avoid overflow in integer addition.
    Ok(hops as u16 + response_ttl as u16)
}

fn udp_hops(u1rr: &U1RR) -> Result<u8, PistolError> {
    let request = get_ipv4_packet(&u1rr.u1.request)?; // must have request
    let ipv4_packet = get_ipv4_packet(&u1rr.u1.response)?;
    let icmp_packet = get_icmp_packet(ipv4_packet.payload())?;
    let r_ipv4_buff = icmp_packet.payload()[4..].to_vec();
    let r_ipv4_packet = get_ipv4_packet(&r_ipv4_buff)?;
    let ttl_1 = request.get_ttl();
    let ttl_2 = r_ipv4_packet.get_ttl();
    let hops = ttl_1 - ttl_2;
    // It is not uncommon for Nmap to receive no response to the U1 probe.
    Ok(hops)
}

/// IP initial time-to-live guess (TG)
pub fn tcp_udp_icmp_tg(ipv4_response: &[u8]) -> Result<u8, PistolError> {
    let response = get_ipv4_packet(ipv4_response)?;
    let response_ttl = response.get_ttl();
    let ret = if response_ttl <= 32 {
        32
    } else if response_ttl <= 64 {
        64
    } else if response_ttl <= 128 {
        128
    } else {
        // if response <= 255
        255
    };
    Ok(ret)
}

/// Explicit congestion notification (CC)
pub fn tcp_cc(ipv4_response: &[u8]) -> Result<String, PistolError> {
    let ipv4_packet = get_ipv4_packet(ipv4_response)?;
    let tcp_packet = get_tcp_packet(ipv4_packet.payload())?;
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
    Ok(ret)
}

/// TCP miscellaneous quirks (Q)
pub fn tcp_q(ipv4_response: &[u8]) -> Result<String, PistolError> {
    let ipv4_packet = get_ipv4_packet(ipv4_response)?;
    let tcp_packet = get_tcp_packet(ipv4_packet.payload())?;
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
    Ok(ret)
}

/// TCP sequence number (S)
pub fn tcp_s(ipv4_request: &[u8], ipv4_response: &[u8]) -> Result<String, PistolError> {
    let ipv4_packet_request = get_ipv4_packet(ipv4_request)?; // must have
    let tcp_packet_request = get_tcp_packet(ipv4_packet_request.payload())?; // must have

    let ipv4_packet_response = get_ipv4_packet(ipv4_response)?;
    let tcp_packet_response = get_tcp_packet(ipv4_packet_response.payload())?;
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
    Ok(ret)
}

/// TCP acknowledgment number (A)
pub fn tcp_a(ipv4_request: &[u8], ipv4_response: &[u8]) -> Result<String, PistolError> {
    let ipv4_packet_request = get_ipv4_packet(ipv4_request)?; // must have
    let tcp_packet_request = get_tcp_packet(ipv4_packet_request.payload())?; // must have

    let ipv4_packet_response = get_ipv4_packet(ipv4_response)?;
    let tcp_packet_response = get_tcp_packet(ipv4_packet_response.payload())?;
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
    Ok(ret)
}

/// TCP flags (F)
pub fn tcp_f(ipv4_response: &[u8]) -> Result<String, PistolError> {
    let ipv4_packet = get_ipv4_packet(ipv4_response)?;
    let tcp_packet = get_tcp_packet(ipv4_packet.payload())?;
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
    Ok(ret)
}

/// TCP RST data checksum (RD)
pub fn tcp_rd(ipv4_response: &[u8]) -> Result<u32, PistolError> {
    let ipv4_packet = get_ipv4_packet(ipv4_response)?;
    let tcp_packet = get_tcp_packet(ipv4_packet.payload())?;
    let tcp_payload = tcp_packet.payload();
    Ok(crc32fast::hash(tcp_payload))
}

/// IP total length (IPL)
pub fn udp_ipl(u1: &U1RR) -> Result<usize, PistolError> {
    let response = &u1.u1.response;
    Ok(response.len())
}

/// Unused port unreachable field nonzero (UN)
pub fn udp_un(u1: &U1RR) -> Result<u32, PistolError> {
    let response = &u1.u1.response;
    let ipv4_packet = get_ipv4_packet(response)?;
    let icmp_packet = get_icmp_packet(ipv4_packet.payload())?;
    let rest_of_header = icmp_packet.payload()[0..4].to_vec();
    let un = SpHex::vec_4u8_to_u32(&rest_of_header);
    Ok(un)
}

/// Returned probe IP total length value (RIPL)
pub fn udp_ripl(u1: &U1RR) -> Result<String, PistolError> {
    let response = &u1.u1.response;
    let ipv4_packet = get_ipv4_packet(response)?;
    let icmp_packet = get_icmp_packet(ipv4_packet.payload())?;
    let ripl = icmp_packet.payload().len() - 4;
    let ret = if ripl == 328 {
        // If the correct value of 0x148 (328) is returned, the value G (for good) is stored instead of the actual value.
        String::from("G")
    } else {
        format!("{:X}", ripl)
    };
    Ok(ret)
}

/// Returned probe IP ID value (RID)
pub fn udp_rid(u1: &U1RR) -> Result<String, PistolError> {
    let response = &u1.u1.response;
    let ipv4_packet = get_ipv4_packet(response)?;
    let icmp_packet = get_icmp_packet(ipv4_packet.payload())?;
    let r_ipv4_packet = get_ipv4_packet(&icmp_packet.payload()[4..])?;
    let rid = r_ipv4_packet.get_identification();
    let ret = if rid == 0x1042 {
        // The U1 probe has a static IP ID value of 0x1042.
        // If that value is returned in the port unreachable message, the value G is stored for this test.
        String::from("G")
    } else {
        format!("{:X}", rid)
    };
    Ok(ret)
}

/// Integrity of returned probe IP checksum value (RIPCK)
pub fn udp_ripck(u1: &U1RR) -> Result<String, PistolError> {
    let response = &u1.u1.response;
    let ipv4_packet = get_ipv4_packet(response)?;
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
    Ok(ret)
}

/// Integrity of returned probe UDP checksum (RUCK)
pub fn udp_ruck(u1: &U1RR) -> Result<String, PistolError> {
    let request = &u1.u1.request;
    let response = &u1.u1.response;

    let ipv4_packet_request = get_ipv4_packet(request)?; // must have
    let udp_packet_request = get_udp_packet(ipv4_packet_request.payload())?; // must have
    let checksum_request = udp_packet_request.get_checksum();

    let ipv4_packet_response = get_ipv4_packet(response)?;
    let icmp_packet_response = get_icmp_packet(ipv4_packet_response.payload())?;
    let r_ipv4_packet_response = get_ipv4_packet(&icmp_packet_response.payload()[4..])?;
    let udp_packet_response = get_udp_packet(r_ipv4_packet_response.payload())?;
    let checksum_response = udp_packet_response.get_checksum();
    let ret = if checksum_response == checksum_request {
        // The UDP header checksum value should be returned exactly as it was sent.
        // If it is, G is recorded for this test. Otherwise the value actually returned is recorded.
        String::from("G")
    } else {
        format!("{:X}", checksum_response)
    };
    Ok(ret)
}

/// Integrity of returned UDP data (RUD)
pub fn udp_rud(u1: &U1RR) -> Result<String, PistolError> {
    let response = &u1.u1.response;
    let ipv4_packet_response = get_ipv4_packet(response)?;
    let icmp_packet_response = get_icmp_packet(ipv4_packet_response.payload())?;
    let r_ipv4_packet_response = get_ipv4_packet(&icmp_packet_response.payload()[4..])?;
    let r_udp_packet_response = get_udp_packet(&r_ipv4_packet_response.payload())?;
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
    Ok(ret)
}

/// Don't fragment (ICMP) (DFI)
pub fn icmp_dfi(ie: &IERR) -> Result<String, PistolError> {
    let df_mask: u8 = 0b0010;

    let request_1 = &ie.ie1.request;
    let request_2 = &ie.ie2.request;
    let response_1 = &ie.ie1.response;
    let response_2 = &ie.ie2.response;

    let ipv4_packet_1 = get_ipv4_packet(request_1)?;
    let flag_1 = ipv4_packet_1.get_flags();
    let df_1_set = if flag_1 & df_mask != 0 { true } else { false };

    let ipv4_packet_2 = get_ipv4_packet(request_2)?;
    let flag_2 = ipv4_packet_2.get_flags();
    let df_2_set = if flag_2 & df_mask != 0 { true } else { false };

    let ipv4_packet_3 = get_ipv4_packet(response_1)?;
    let flag_3 = ipv4_packet_3.get_flags();
    let df_3_set = if flag_3 & df_mask != 0 { true } else { false };

    let ipv4_packet_4 = get_ipv4_packet(response_2)?;
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
    Ok(ret)
}

/// ICMP response code (CD)
pub fn icmp_cd(ie: &IERR) -> Result<String, PistolError> {
    let request_1 = &ie.ie1.request;
    let request_2 = &ie.ie2.request;
    let response_1 = &ie.ie1.response;
    let response_2 = &ie.ie2.response;

    if response_1.len() > 0 && response_2.len() > 0 {
        let ipv4_packet_1 = get_ipv4_packet(&request_1)?;
        let icmp_packet_1 = get_icmp_packet(ipv4_packet_1.payload())?;
        let ipv4_packet_2 = get_ipv4_packet(&request_2)?;
        let icmp_packet_2 = get_icmp_packet(ipv4_packet_2.payload())?;
        let code_1 = icmp_packet_1.get_icmp_code();
        let code_2 = icmp_packet_2.get_icmp_code();

        let ipv4_packet_3 = get_ipv4_packet(&response_1)?;
        let icmp_packet_3 = get_icmp_packet(ipv4_packet_3.payload())?;
        let ipv4_packet_4 = get_ipv4_packet(&response_2)?;
        let icmp_packet_4 = get_icmp_packet(ipv4_packet_4.payload())?;
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
        Ok(ret)
    } else {
        Ok(String::new())
    }
}
