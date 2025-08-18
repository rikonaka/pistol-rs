use pnet::packet::Packet;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpOptionNumbers;
use pnet::packet::tcp::TcpPacket;
use std::iter::zip;
use tracing::warn;

use crate::error::PistolError;
use crate::os::rr::AllPacketRR6;
use crate::utils::PistolHex;

const CWR_MASK: u8 = 0b10000000;
const ECE_MASK: u8 = 0b01000000;
const URG_MASK: u8 = 0b00100000;
const ACK_MASK: u8 = 0b00010000;
const PSH_MASK: u8 = 0b00001000;
const RST_MASK: u8 = 0b00000100;
const SYN_MASK: u8 = 0b00000010;
const FIN_MASK: u8 = 0b00000001;

fn get_response_by_name(ap: &AllPacketRR6, name: &str) -> Vec<u8> {
    match name {
        "S1" => ap.seq.seq1.response.to_vec(),
        "S2" => ap.seq.seq2.response.to_vec(),
        "S3" => ap.seq.seq3.response.to_vec(),
        "S4" => ap.seq.seq4.response.to_vec(),
        "S5" => ap.seq.seq5.response.to_vec(),
        "S6" => ap.seq.seq6.response.to_vec(),
        "IE1" => ap.ie.ie1.response.to_vec(),
        "IE2" => ap.ie.ie2.response.to_vec(),
        "NI" => ap.nx.ni.response.to_vec(),
        "NS" => ap.nx.ns.response.to_vec(),
        "U1" => ap.u1.u1.response.to_vec(),
        "TECN" => ap.tecn.tecn.response.to_vec(),
        "T2" => ap.tx.t2.response.to_vec(),
        "T3" => ap.tx.t3.response.to_vec(),
        "T4" => ap.tx.t4.response.to_vec(),
        "T5" => ap.tx.t5.response.to_vec(),
        "T6" => ap.tx.t6.response.to_vec(),
        "T7" => ap.tx.t7.response.to_vec(),
        _ => vec![],
    }
}

fn build_ipv6_packet<'a>(
    ipv6_buff: &'a [u8],
    probe_name: &str,
) -> Result<Ipv6Packet<'a>, PistolError> {
    // println!("{}", ipv6_buff.len());
    if ipv6_buff.len() > 0 {
        match Ipv6Packet::new(ipv6_buff) {
            Some(p) => return Ok(p),
            None => (),
        }
    }
    Err(PistolError::BuildIpv6PacketFailed {
        probe_name: probe_name.to_string(),
    })
}

fn build_icmpv6_packet<'a>(
    icmpv6_buff: &'a [u8],
    probe_name: &str,
) -> Result<Icmpv6Packet<'a>, PistolError> {
    if icmpv6_buff.len() > 0 {
        match Icmpv6Packet::new(icmpv6_buff) {
            Some(p) => return Ok(p),
            None => (),
        }
    }
    Err(PistolError::BuildIcmpv6PacketFailed {
        probe_name: probe_name.to_string(),
    })
}

fn build_tcp_packet<'a>(
    tcp_buff: &'a [u8],
    probe_name: &str,
) -> Result<TcpPacket<'a>, PistolError> {
    if tcp_buff.len() > 0 {
        match TcpPacket::new(tcp_buff) {
            Some(p) => return Ok(p),
            None => (),
        }
    }
    Err(PistolError::BuildTcpPacketFailed {
        probe_name: probe_name.to_string(),
    })
}

/// IPv6 Payload Length field.
/// IPv6 Traffic Class field.
fn ipv6_plen_tc(ipv6_buff: &[u8], probe_name: &str) -> Result<(f64, f64), PistolError> {
    let (plen, tc) = match build_ipv6_packet(ipv6_buff, probe_name) {
        Ok(ipv6_packet) => (
            ipv6_packet.get_payload_length() as f64,
            ipv6_packet.get_traffic_class() as f64,
        ),
        Err(_) => {
            warn!("plen tc get ipv6 packet failed");
            (-1.0, -1.0)
        }
    };
    Ok((plen, tc))
}

/// Get tcp sequence number.
fn tcp_seq(ipv6_buff: &[u8], probe_name: &str) -> Result<u32, PistolError> {
    let ipv6_packet = build_ipv6_packet(ipv6_buff, probe_name)?;
    let tcp_packet = build_tcp_packet(ipv6_packet.payload(), probe_name)?;
    Ok(tcp_packet.get_sequence())
}

/// TCP ISN counter rate. This is derived from the S1–S6 sequence probes, which are sent 100 ms apart.
/// The differences between consecutive sequence responses are added up, then this sum is divided by the time elapsed between the first and last probe.
fn tcp_isr(ap: &AllPacketRR6) -> Result<f64, PistolError> {
    let mut seq_vec = Vec::new();
    let s1 = tcp_seq(&ap.seq.seq1.response, "seq1")?;
    let s2 = tcp_seq(&ap.seq.seq2.response, "seq2")?;
    let s3 = tcp_seq(&ap.seq.seq3.response, "seq3")?;
    let s4 = tcp_seq(&ap.seq.seq4.response, "seq4")?;
    let s5 = tcp_seq(&ap.seq.seq5.response, "seq5")?;
    let s6 = tcp_seq(&ap.seq.seq6.response, "seq6")?;
    seq_vec.push(s1);
    seq_vec.push(s2);
    seq_vec.push(s3);
    seq_vec.push(s4);
    seq_vec.push(s5);
    seq_vec.push(s6);

    let mut diff = Vec::new();
    if seq_vec.len() >= 2 {
        for i in 0..(seq_vec.len() - 1) {
            let a = seq_vec[i];
            let b = seq_vec[i + 1];
            let x = if a <= b { b - a } else { !(a - b) };
            // println!("{} {} {}", a, b, x);
            diff.push(x);
        }
    }

    let mut sum: u64 = 0; // avoid overflow
    for d in diff {
        sum += d as u64;
    }

    let e = (ap.seq.elapsed / 6.0) * 5.0;
    // println!("sum: {}", sum);
    // println!("e: {}", e);
    Ok(sum as f64 / e as f64)
}

/// A guess at the original value of the IPv6 Hop Limit field.
fn ipv6_hlim(ipv6_response: &[u8], probe_name: &str) -> Result<f64, PistolError> {
    let hlim = match build_ipv6_packet(ipv6_response, probe_name) {
        Ok(ipv6_response_packet) => ipv6_response_packet.get_hop_limit() as f64,
        Err(_) => {
            warn!("ipv6 hlim build ipv6 packet failed");
            0.0
        }
    };
    let er_lim = 5;
    let hlim = if (32 - er_lim) as f64 <= hlim && hlim <= (32 + 5) as f64 {
        32
    } else if (64 - er_lim) as f64 <= hlim && hlim <= (64 + 5) as f64 {
        64
    } else if (128 - er_lim) as f64 <= hlim && hlim <= (128 + 5) as f64 {
        128
    } else if (255 - er_lim) as f64 <= hlim && hlim <= (255 + 5) as f64 {
        255
    } else {
        -1
    };
    Ok(hlim as f64)
}

/// TCP window size.
fn tcp_window(ipv6_buff: &[u8], probe_name: &str) -> Result<f64, PistolError> {
    match build_ipv6_packet(ipv6_buff, probe_name) {
        Ok(ipv6_packet) => {
            let tcp_packet = build_tcp_packet(ipv6_packet.payload(), probe_name)?;
            Ok(tcp_packet.get_window() as f64)
        }
        Err(_) => {
            warn!("tcp windows build ipv6 packet failed");
            Ok(-1.0)
        }
    }
}

/// TCP flags. Each flag becomes a feature with the value 0 or 1.
/// TCP_FLAG_F, TCP_FLAG_S, TCP_FLAG_R, TCP_FLAG_P, TCP_FLAG_A, TCP_FLAG_U, TCP_FLAG_E, TCP_FLAG_C.
fn tcp_flags(ipv6_buff: &[u8], probe_name: &str) -> Result<Vec<f64>, PistolError> {
    match build_ipv6_packet(ipv6_buff, probe_name) {
        Ok(ipv6_packet) => {
            let tcp_packet = build_tcp_packet(ipv6_packet.payload(), probe_name)?;
            let flags = tcp_packet.get_flags();
            let cwr = ((flags & CWR_MASK) >> 7) as f64;
            let ece = ((flags & ECE_MASK) >> 6) as f64;
            let urg = ((flags & URG_MASK) >> 5) as f64;
            let ack = ((flags & ACK_MASK) >> 4) as f64;
            let psh = ((flags & PSH_MASK) >> 3) as f64;
            let rst = ((flags & RST_MASK) >> 2) as f64;
            let syn = ((flags & SYN_MASK) >> 1) as f64;
            let fin = ((flags & FIN_MASK) >> 0) as f64;
            let ret = vec![fin, syn, rst, psh, ack, urg, ece, cwr];
            Ok(ret)
        }
        Err(_) => {
            warn!("tcp flags get ipv6 packet failed");
            Ok(vec![-1.0; 8])
        }
    }
}

/// These are the four bits of the reserved part of the TCP header.
/// RFC 3540 defines TCP_FLAG_RES8 as the nonce sum (NS) bit.
/// TCP_FLAG_RES8, TCP_FLAG_RES9, TCP_FLAG_RES10, TCP_FLAG_RES11.
fn tcp_reserved(ipv6_buff: &[u8], probe_name: &str) -> Result<Vec<f64>, PistolError> {
    match build_ipv6_packet(ipv6_buff, probe_name) {
        Ok(ipv6_packet) => {
            let tcp_packet = build_tcp_packet(ipv6_packet.payload(), probe_name)?;
            let mask_1: u8 = 0b1000;
            let mask_2: u8 = 0b0100;
            let mask_3: u8 = 0b0010;
            let mask_4: u8 = 0b0001;
            let reserved = tcp_packet.get_reserved();
            let v1 = ((reserved & mask_1) >> 3) as f64;
            let v2 = ((reserved & mask_2) >> 2) as f64;
            let v3 = ((reserved & mask_3) >> 1) as f64;
            let v4 = ((reserved & mask_4) >> 0) as f64;
            let ret = vec![v4, v3, v2, v1];
            Ok(ret)
        }
        Err(_) => {
            warn!("tcp reserved get ipv6 packet failed");
            Ok(vec![-1.0; 4])
        }
    }
}

/// Type codes for the first 16 TCP options.
fn tcp_option_code(ipv6_buff: &[u8], probe_name: &str) -> Result<Vec<f64>, PistolError> {
    match build_ipv6_packet(ipv6_buff, probe_name) {
        Ok(ipv6_packet) => {
            let tcp_packet = build_tcp_packet(ipv6_packet.payload(), probe_name)?;
            let options = tcp_packet.get_options();
            let mut ret = Vec::new();
            for option in options {
                ret.push(option.number.0 as f64);
            }
            if ret.len() < 16 {
                for _ in 0..(16 - ret.len()) {
                    ret.push(-1.0);
                }
            }
            if ret.len() > 16 {
                ret = ret[0..16].to_vec();
            }
            Ok(ret)
        }
        Err(_) => {
            warn!("tcp option code get ipv6 packet failed");
            Ok(vec![-1.0; 16])
        }
    }
}

/// Lengths of the first 16 TCP options.
fn tcp_option_len(ipv6_buff: &[u8], probe_name: &str) -> Result<Vec<f64>, PistolError> {
    match build_ipv6_packet(ipv6_buff, probe_name) {
        Ok(ipv6_packet) => {
            let tcp_packet = build_tcp_packet(ipv6_packet.payload(), probe_name)?;
            let options = tcp_packet.get_options();
            let mut ret = Vec::new();
            for option in options {
                let t = &option.length;
                // println!("{:?}", t);
                if t.len() != 0 {
                    ret.push(t[0] as f64);
                } else {
                    ret.push(1.0); // only header
                }
            }
            if ret.len() < 16 {
                for _ in 0..(16 - ret.len()) {
                    ret.push(-1.0);
                }
            }
            // println!("{}", ret.len());
            if ret.len() > 16 {
                ret = ret[0..16].to_vec();
            }
            Ok(ret)
        }
        Err(_) => {
            warn!("tcp option len get ipv6 packet failed");
            Ok(vec![-1.0; 16])
        }
    }
}

/// Value of the first MSS option, if present.
fn tcp_option_mss(ipv6_buff: &[u8], probe_name: &str) -> Result<f64, PistolError> {
    match build_ipv6_packet(ipv6_buff, probe_name) {
        Ok(ipv6_packet) => {
            let tcp_packet = build_tcp_packet(ipv6_packet.payload(), probe_name)?;
            let options = tcp_packet.get_options();
            for option in options {
                match option.number {
                    TcpOptionNumbers::MSS => {
                        let mss = PistolHex::convert_4u8_to_u32(&option.data);
                        return Ok(mss as f64);
                    }
                    _ => (),
                }
            }
            Ok(-1.0)
        }
        Err(_) => {
            warn!("tcp option mss get ipv6 packet failed");
            Ok(-1.0)
        }
    }
}

/// 1 if the SACK-permitted option is present, 0 otherwise.
fn tcp_option_sackok(ipv6_buff: &[u8], probe_name: &str) -> Result<f64, PistolError> {
    match build_ipv6_packet(ipv6_buff, probe_name) {
        Ok(ipv6_packet) => {
            let tcp_packet = build_tcp_packet(ipv6_packet.payload(), probe_name)?;
            let options = tcp_packet.get_options();
            for option in options {
                match option.number {
                    TcpOptionNumbers::SACK_PERMITTED => {
                        return Ok(1.0);
                    }
                    _ => (),
                }
            }
            Ok(-1.0)
        }
        Err(_) => {
            warn!("tcp option sackok get ipv6 packet failed");
            Ok(-1.0)
        }
    }
}

fn tcp_option_wscale(ipv6_buff: &[u8], probe_name: &str) -> Result<f64, PistolError> {
    match build_ipv6_packet(ipv6_buff, probe_name) {
        Ok(ipv6_packet) => {
            let tcp_packet = build_tcp_packet(ipv6_packet.payload(), probe_name)?;
            let options = tcp_packet.get_options();
            for option in options {
                match option.number {
                    TcpOptionNumbers::WSCALE => {
                        if option.data.len() > 0 {
                            return Ok(option.data[0] as f64);
                        }
                    }
                    _ => (),
                }
            }
            Ok(-1.0)
        }
        Err(_) => {
            warn!("tcp option wscale get ipv6 packet failed");
            Ok(-1.0)
        }
    }
}

fn icmpv6_type_code(ipv6_buff: &[u8], probe_name: &str) -> Result<(f64, f64), PistolError> {
    match build_ipv6_packet(ipv6_buff, probe_name) {
        Ok(ipv6_packet) => {
            let icmpv6_packet = build_icmpv6_packet(ipv6_packet.payload(), probe_name)?;
            Ok((
                icmpv6_packet.get_icmpv6_type().0 as f64,
                icmpv6_packet.get_icmpv6_code().0 as f64,
            ))
        }
        Err(_) => {
            warn!("icmpv6 type code get ipv6 packet failed");
            Ok((-1.0, -1.0))
        }
    }
}

pub fn vectorize(ap: &AllPacketRR6) -> Result<Vec<f64>, PistolError> {
    let ipv6_probe_names: Vec<&str> = vec![
        "S1", "S2", "S3", "S4", "S5", "S6", "IE1", "IE2", "NS", "U1", "TECN", "T2", "T3", "T4",
        "T5", "T6", "T7",
    ]; // 17 * 3 + 1 => 51 + 1 features
    let tcp_probe_names: Vec<&str> = vec![
        "S1", "S2", "S3", "S4", "S5", "S6", "TECN", "T2", "T3", "T4", "T5", "T6", "T7",
    ]; // 637 features
    let icmpv6_probe_names: Vec<&str> = vec!["IE1", "IE2", "NS"]; // 6 features

    let mut features: Vec<f64> = Vec::new();
    for name in ipv6_probe_names {
        let ipv6_response = get_response_by_name(ap, name);
        let (plen, tc) = ipv6_plen_tc(&ipv6_response, &name.to_lowercase())?;
        // println!("name: {}, plen: {}", name, plen);
        features.push(plen);
        features.push(tc);
        let hlim = ipv6_hlim(&ipv6_response, &name.to_lowercase())?;
        features.push(hlim);
    }
    let isr = tcp_isr(ap)?;
    // println!("{}", isr);
    features.push(isr);

    for name in tcp_probe_names {
        // Each round will add 49 features.
        let ipv6_response = get_response_by_name(ap, name);
        let window = tcp_window(&ipv6_response, &name.to_lowercase())?;
        features.push(window);

        let flags = tcp_flags(&ipv6_response, &name.to_lowercase())?;
        assert_eq!(flags.len(), 8);

        features.extend(flags);

        let reserved = tcp_reserved(&ipv6_response, &name.to_lowercase())?;
        assert_eq!(reserved.len(), 4);
        features.extend(reserved);

        let opt_code = tcp_option_code(&ipv6_response, &name.to_lowercase())?;
        assert_eq!(opt_code.len(), 16);
        // println!("{:?}", opt_code);
        features.extend(opt_code);

        let opt_len = tcp_option_len(&ipv6_response, &name.to_lowercase())?;
        assert_eq!(opt_len.len(), 16);
        // println!("{:?}", opt_len);
        features.extend(opt_len);

        let mss = tcp_option_mss(&ipv6_response, &name.to_lowercase())?;
        features.push(mss);

        let sackok = tcp_option_sackok(&ipv6_response, &name.to_lowercase())?;
        features.push(sackok);

        let wscale = tcp_option_wscale(&ipv6_response, &name.to_lowercase())?;
        features.push(wscale);

        if mss != 0.0 && mss != -1.0 {
            features.push(window / mss);
        } else {
            features.push(-1.0);
        }
    }

    for name in icmpv6_probe_names {
        let ipv6_response = get_response_by_name(ap, name);
        let (t, c) = icmpv6_type_code(&ipv6_response, &name.to_lowercase())?;
        features.push(t);
        features.push(c);
    }

    assert_eq!(features.len(), 695);
    Ok(features)
}

pub fn apply_scale(features: &[f64], scale: &[Vec<f64>]) -> Vec<f64> {
    let mut new_features = Vec::new();
    for (f, ab) in zip(features, scale) {
        if *f < 0.0 {
            new_features.push(*f);
        } else {
            let new_f = (f + ab[0]) * ab[1];
            new_features.push(new_f);
        }
    }
    new_features
}
