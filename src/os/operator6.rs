use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpOptionNumbers;
use pnet::packet::tcp::TcpPacket;
use std::iter::zip;
use std::sync::Arc;
use tracing::debug;
use tracing::warn;

use crate::os::operator::get_diffs;
use crate::os::rr::AllPacketRR6;
use crate::utils::v4u8_to_u32;

const CWR_MASK: u8 = 0b10000000;
const ECE_MASK: u8 = 0b01000000;
const URG_MASK: u8 = 0b00100000;
const ACK_MASK: u8 = 0b00010000;
const PSH_MASK: u8 = 0b00001000;
const RST_MASK: u8 = 0b00000100;
const SYN_MASK: u8 = 0b00000010;
const FIN_MASK: u8 = 0b00000001;

fn get_eth_response_by_name(ap: &AllPacketRR6, name: &str) -> Arc<[u8]> {
    match name {
        "s1" => ap.seq.seq1.response2.clone(),
        "s2" => ap.seq.seq2.response2.clone(),
        "s3" => ap.seq.seq3.response2.clone(),
        "s4" => ap.seq.seq4.response2.clone(),
        "s5" => ap.seq.seq5.response2.clone(),
        "s6" => ap.seq.seq6.response2.clone(),
        "ie1" => ap.ie.ie1.response2.clone(),
        "ie2" => ap.ie.ie2.response2.clone(),
        "ni" => ap.nx.ni.response2.clone(),
        "ns" => ap.nx.ns.response2.clone(),
        "u1" => ap.u1.u1.response2.clone(),
        "tecn" => ap.tecn.tecn.response2.clone(),
        "t2" => ap.tx.t2.response2.clone(),
        "t3" => ap.tx.t3.response2.clone(),
        "t4" => ap.tx.t4.response2.clone(),
        "t5" => ap.tx.t5.response2.clone(),
        "t6" => ap.tx.t6.response2.clone(),
        "t7" => ap.tx.t7.response2.clone(),
        _ => Arc::new([]),
    }
}

fn build_ipv6_packet<'a>(eth_response: &'a [u8], probe_name: &str) -> Option<Ipv6Packet<'a>> {
    let eth_packet = match EthernetPacket::new(eth_response) {
        Some(p) => p,
        None => {
            warn!("build eth packet failed for probe {}", probe_name);
            return None;
        }
    };
    let ethertype = eth_packet.get_ethertype();
    if ethertype != EtherTypes::Ipv6 {
        warn!(
            "ethertype is not ipv6 for probe {}, ethertype: {:?}",
            probe_name, ethertype
        );
        return None;
    }

    let ipv6_buff = eth_packet.payload().to_vec();
    match Ipv6Packet::owned(ipv6_buff) {
        Some(ipv6_packet) => Some(ipv6_packet),
        None => {
            warn!("build ipv6 packet failed for probe {}", probe_name);
            None
        }
    }
}

fn build_icmpv6_packet<'a>(eth_response: &'a [u8], probe_name: &str) -> Option<Icmpv6Packet<'a>> {
    let eth_packet = match EthernetPacket::new(eth_response) {
        Some(p) => p,
        None => {
            warn!("build eth packet failed for probe {}", probe_name);
            return None;
        }
    };

    let ethertype = eth_packet.get_ethertype();
    if ethertype != EtherTypes::Ipv6 {
        warn!(
            "ethertype is not ipv6 for probe {}, ethertype: {:?}",
            probe_name, ethertype
        );
        return None;
    }

    let ipv6_packet = match Ipv6Packet::new(eth_packet.payload()) {
        Some(p) => p,
        None => {
            warn!("build ipv6 packet failed for probe {}", probe_name);
            return None;
        }
    };

    let next_header = ipv6_packet.get_next_header();
    if next_header != IpNextHeaderProtocols::Icmpv6 {
        warn!(
            "next header is not icmpv6 for probe {}, next header: {:?}",
            probe_name, next_header
        );
        return None;
    }

    let icmpv6_buff = ipv6_packet.payload().to_vec();
    match Icmpv6Packet::owned(icmpv6_buff) {
        Some(icmpv6_packet) => Some(icmpv6_packet),
        None => {
            warn!("build icmpv6 packet failed for probe {}", probe_name);
            None
        }
    }
}

fn build_tcp_packet<'a>(eth_response: &'a [u8], probe_name: &str) -> Option<TcpPacket<'a>> {
    let eth_packet = match EthernetPacket::new(eth_response) {
        Some(p) => p,
        None => {
            warn!("build eth packet failed for probe {}", probe_name);
            return None;
        }
    };
    let ethertype = eth_packet.get_ethertype();
    if ethertype != EtherTypes::Ipv6 {
        warn!(
            "ethertype is not ipv6 for probe {}, ethertype: {:?}",
            probe_name, ethertype
        );
        return None;
    }

    let ipv6_packet = match Ipv6Packet::new(eth_packet.payload()) {
        Some(p) => p,
        None => {
            warn!("build ipv6 packet failed for probe {}", probe_name);
            return None;
        }
    };

    let next_header = ipv6_packet.get_next_header();
    if next_header != IpNextHeaderProtocols::Tcp {
        warn!(
            "next header is not tcp for probe {}, next header: {:?}",
            probe_name, next_header
        );
        return None;
    }

    let tcp_buff = ipv6_packet.payload().to_vec();
    match TcpPacket::owned(tcp_buff) {
        Some(tcp_packet) => Some(tcp_packet),
        None => {
            warn!("build tcp packet failed for probe {}", probe_name);
            None
        }
    }
}

/// IPv6 Payload Length field and IPv6 Traffic Class field.
fn ipv6_plen_tc(eth_response: &[u8], probe_name: &str) -> (f64, f64) {
    match build_ipv6_packet(eth_response, probe_name) {
        Some(ipv6_packet) => {
            let plen = ipv6_packet.get_payload_length() as f64;
            let tc = ipv6_packet.get_traffic_class() as f64;
            (plen, tc)
        }
        None => {
            warn!(
                "build ipv6 packet failed for probe {}, return default value for plen and tc",
                probe_name
            );
            (-1.0, -1.0)
        }
    }
}

/// Get tcp sequence number.
fn tcp_seq(eth_response: &[u8], probe_name: &str) -> Option<u32> {
    match build_tcp_packet(eth_response, probe_name) {
        Some(tcp_packet) => Some(tcp_packet.get_sequence()),
        None => {
            warn!(
                "build tcp packet failed for probe {}, return default value for sequence number",
                probe_name
            );
            None
        }
    }
}

/// TCP ISN counter rate.
/// This calculation method differs from that of IPv4.
fn tcp_isr(ap: &AllPacketRR6) -> f64 {
    let mut seq_vec = Vec::new();
    let s1 = tcp_seq(&ap.seq.seq1.response2, "seq1");
    let s2 = tcp_seq(&ap.seq.seq2.response2, "seq2");
    let s3 = tcp_seq(&ap.seq.seq3.response2, "seq3");
    let s4 = tcp_seq(&ap.seq.seq4.response2, "seq4");
    let s5 = tcp_seq(&ap.seq.seq5.response2, "seq5");
    let s6 = tcp_seq(&ap.seq.seq6.response2, "seq6");
    if let Some(s) = s1 {
        seq_vec.push(s);
    }
    if let Some(s) = s2 {
        seq_vec.push(s);
    }
    if let Some(s) = s3 {
        seq_vec.push(s);
    }
    if let Some(s) = s4 {
        seq_vec.push(s);
    }
    if let Some(s) = s5 {
        seq_vec.push(s);
    }
    if let Some(s) = s6 {
        seq_vec.push(s);
    }

    let diff = get_diffs(&seq_vec, false);

    if diff.len() > 0 {
        let mut sum = 0.0;
        for &d in &diff {
            let f = d as f64;
            sum += f;
        }

        let t = ap.seq.st6 - ap.seq.st1;
        let isr = sum / t.as_secs_f64();
        isr
    } else {
        warn!("tcp sequence number diff is empty, return default value for ISR");
        -1.0
    }
}

/// A guess at the original value of the IPv6 Hop Limit field.
fn ipv6_hlim(eth_response: &[u8], probe_name: &str) -> f64 {
    match build_ipv6_packet(eth_response, probe_name) {
        Some(ipv6_packet) => {
            let hlim = ipv6_packet.get_hop_limit() as f64;
            let regual_hlim_vec = vec![32.0, 64.0, 128.0, 255.0];
            let mut guess = 255.0;

            for r_hlim in regual_hlim_vec {
                if hlim <= r_hlim {
                    guess = r_hlim;
                    break;
                }
            }
            guess
        }
        None => {
            warn!(
                "build ipv6 packet failed for probe {}, return default value for hlim",
                probe_name
            );
            // default value of machine learning alg
            -1.0
        }
    }
}

/// TCP window size.
fn tcp_window(eth_response: &[u8], probe_name: &str) -> f64 {
    match build_tcp_packet(eth_response, probe_name) {
        Some(tcp_packet) => tcp_packet.get_window() as f64,
        None => {
            warn!(
                "build tcp packet failed for probe {}, return default value for window size",
                probe_name
            );
            // default value of machine learning alg
            -1.0
        }
    }
}

/// TCP flags. Each flag becomes a feature with the value 0 or 1.
/// TCP_FLAG_F, TCP_FLAG_S, TCP_FLAG_R, TCP_FLAG_P, TCP_FLAG_A, TCP_FLAG_U, TCP_FLAG_E, TCP_FLAG_C.
fn tcp_flags(eth_response: &[u8], probe_name: &str) -> Vec<f64> {
    match build_tcp_packet(eth_response, probe_name) {
        Some(tcp_packet) => {
            let flags = tcp_packet.get_flags();
            let cwr = ((flags & CWR_MASK) >> 7) as f64;
            let ece = ((flags & ECE_MASK) >> 6) as f64;
            let urg = ((flags & URG_MASK) >> 5) as f64;
            let ack = ((flags & ACK_MASK) >> 4) as f64;
            let psh = ((flags & PSH_MASK) >> 3) as f64;
            let rst = ((flags & RST_MASK) >> 2) as f64;
            let syn = ((flags & SYN_MASK) >> 1) as f64;
            let fin = ((flags & FIN_MASK) >> 0) as f64;
            vec![fin, syn, rst, psh, ack, urg, ece, cwr]
        }
        None => {
            warn!(
                "build tcp packet failed for probe {}, return default value for tcp flags",
                probe_name
            );
            // default value of machine learning alg
            vec![-1.0; 8]
        }
    }
}

/// These are the four bits of the reserved part of the TCP header.
/// RFC 3540 defines TCP_FLAG_RES8 as the nonce sum (NS) bit.
/// TCP_FLAG_RES8, TCP_FLAG_RES9, TCP_FLAG_RES10, TCP_FLAG_RES11.
fn tcp_reserved(eth_response: &[u8], probe_name: &str) -> Vec<f64> {
    match build_tcp_packet(eth_response, probe_name) {
        Some(tcp_packet) => {
            let reserved = tcp_packet.get_reserved();
            let mask_1: u8 = 0b1000;
            let mask_2: u8 = 0b0100;
            let mask_3: u8 = 0b0010;
            let mask_4: u8 = 0b0001;
            let v1 = ((reserved & mask_1) >> 3) as f64;
            let v2 = ((reserved & mask_2) >> 2) as f64;
            let v3 = ((reserved & mask_3) >> 1) as f64;
            let v4 = ((reserved & mask_4) >> 0) as f64;
            vec![v4, v3, v2, v1]
        }
        None => {
            warn!(
                "build tcp packet failed for probe {}, return default value for tcp reserved bits",
                probe_name
            );
            // default value of machine learning alg
            vec![-1.0; 4]
        }
    }
}

/// Type codes for the first 16 TCP options.
fn tcp_option_code(eth_response: &[u8], probe_name: &str) -> Vec<f64> {
    match build_tcp_packet(eth_response, probe_name) {
        Some(tcp_packet) => {
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
            ret
        }
        None => {
            warn!(
                "build tcp packet failed for probe {}, return default value for tcp option codes",
                probe_name
            );
            // default value of machine learning alg
            vec![-1.0; 16]
        }
    }
}

/// Lengths of the first 16 TCP options.
fn tcp_option_len(eth_response: &[u8], probe_name: &str) -> Vec<f64> {
    match build_tcp_packet(eth_response, probe_name) {
        Some(tcp_packet) => {
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
            return ret;
        }
        None => {
            warn!(
                "build tcp packet failed for probe {}, return default value for tcp option lengths",
                probe_name
            );
            // default value of machine learning alg
            vec![-1.0; 16]
        }
    }
}

/// Value of the first MSS option, if present.
fn tcp_option_mss(eth_response: &[u8], probe_name: &str) -> f64 {
    match build_tcp_packet(eth_response, probe_name) {
        Some(tcp_packet) => {
            let options = tcp_packet.get_options();
            for option in options {
                match option.number {
                    TcpOptionNumbers::MSS => {
                        let data = if option.data.len() > 4 {
                            &option.data[0..4]
                        } else {
                            &option.data
                        };
                        let mss = v4u8_to_u32(data);
                        return mss as f64;
                    }
                    _ => (),
                }
            }
            -1.0
        }
        None => {
            warn!(
                "build tcp packet failed for probe {}, return default value for tcp option mss",
                probe_name
            );
            // default value of machine learning alg
            -1.0
        }
    }
}

/// 1 if the SACK-permitted option is present, 0 otherwise.
fn tcp_option_sackok(eth_response: &[u8], probe_name: &str) -> f64 {
    match build_tcp_packet(eth_response, probe_name) {
        Some(tcp_packet) => {
            let options = tcp_packet.get_options();
            for option in options {
                match option.number {
                    TcpOptionNumbers::SACK_PERMITTED => {
                        return 1.0;
                    }
                    _ => (),
                }
            }
            -1.0
        }
        None => {
            warn!(
                "build tcp packet failed for probe {}, return default value for tcp option sackok",
                probe_name
            );
            // default value of machine learning alg
            -1.0
        }
    }
}

fn tcp_option_wscale(eth_response: &[u8], probe_name: &str) -> f64 {
    match build_tcp_packet(eth_response, probe_name) {
        Some(tcp_packet) => {
            let options = tcp_packet.get_options();
            for option in options {
                match option.number {
                    TcpOptionNumbers::WSCALE => {
                        if option.data.len() > 0 {
                            return option.data[0] as f64;
                        }
                    }
                    _ => (),
                }
            }
            -1.0
        }
        None => {
            warn!(
                "build tcp packet failed for probe {}, return default value for tcp option wscale",
                probe_name
            );
            // default value of machine learning alg
            -1.0
        }
    }
}

fn icmpv6_type_code(eth_response: &[u8], probe_name: &str) -> (f64, f64) {
    match build_icmpv6_packet(eth_response, probe_name) {
        Some(icmpv6_packet) => {
            let icmpv6_type = icmpv6_packet.get_icmpv6_type().0 as f64;
            let icmpv6_code = icmpv6_packet.get_icmpv6_code().0 as f64;
            return (icmpv6_type, icmpv6_code);
        }
        None => {
            warn!(
                "build icmpv6 packet failed for probe {}, return default value for icmpv6 type and code",
                probe_name
            );
            // default value of machine learning alg
            return (-1.0, -1.0);
        }
    }
}

pub(crate) fn vectorize(ap: &AllPacketRR6) -> Vec<f64> {
    // 17 * 3 + 1 => 51 + 1 => 52 features
    let ipv6_probe_names: Vec<&str> = vec![
        "s1", "s2", "s3", "s4", "s5", "s6", "ie1", "ie2", "ns", "u1", "tecn", "t2", "t3", "t4",
        "t5", "t6", "t7",
    ];
    // 637 features
    let tcp_probe_names: Vec<&str> = vec![
        "s1", "s2", "s3", "s4", "s5", "s6", "tecn", "t2", "t3", "t4", "t5", "t6", "t7",
    ];
    // 6 features
    let icmpv6_probe_names: Vec<&str> = vec!["ie1", "ie2", "ns"];

    let mut features: Vec<f64> = Vec::new();
    for probe_name in ipv6_probe_names {
        let eth_response = get_eth_response_by_name(ap, probe_name);
        let (plen, tc) = ipv6_plen_tc(&eth_response, &probe_name.to_lowercase());
        features.push(plen);
        features.push(tc);
        let hlim = ipv6_hlim(&eth_response, &probe_name.to_lowercase());
        features.push(hlim);
        debug!(
            "probe name: {}, plen: {}, tc: {}, hlim: {}",
            probe_name, plen, tc, hlim
        );
    }
    let isr = tcp_isr(ap);
    debug!("ISR: {}", isr);
    features.push(isr);

    for name in tcp_probe_names {
        // Each round will add 49 features.
        let eth_response = get_eth_response_by_name(ap, name);
        let window = tcp_window(&eth_response, &name.to_lowercase());
        features.push(window);

        let flags = tcp_flags(&eth_response, &name.to_lowercase());
        assert_eq!(flags.len(), 8);

        features.extend(flags);

        let reserved = tcp_reserved(&eth_response, &name.to_lowercase());
        assert_eq!(reserved.len(), 4);
        features.extend(reserved);

        let opt_code = tcp_option_code(&eth_response, &name.to_lowercase());
        assert_eq!(opt_code.len(), 16);
        // println!("{:?}", opt_code);
        features.extend(opt_code);

        let opt_len = tcp_option_len(&eth_response, &name.to_lowercase());
        assert_eq!(opt_len.len(), 16);
        // println!("{:?}", opt_len);
        features.extend(opt_len);

        let mss = tcp_option_mss(&eth_response, &name.to_lowercase());
        features.push(mss);

        let sackok = tcp_option_sackok(&eth_response, &name.to_lowercase());
        features.push(sackok);

        let wscale = tcp_option_wscale(&eth_response, &name.to_lowercase());
        features.push(wscale);

        if mss != 0.0 && mss != -1.0 {
            features.push(window / mss);
        } else {
            features.push(-1.0);
        }
    }

    for name in icmpv6_probe_names {
        let ipv6_response = get_eth_response_by_name(ap, name);
        let (t, c) = icmpv6_type_code(&ipv6_response, &name.to_lowercase());
        features.push(t);
        features.push(c);
    }

    if features.len() != 695 {
        panic!("features length is {}, expected 695", features.len());
    }
    assert_eq!(features.len(), 695);
    features
}

pub(crate) fn apply_scale(features: &[f64], scale: &[Vec<f64>]) -> Vec<f64> {
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
