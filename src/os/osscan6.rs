use anyhow::Result;
use std::iter::zip;
use std::net::Ipv6Addr;
use std::sync::mpsc::channel;
use std::thread::sleep;
use std::time::Duration;
use std::time::SystemTime;

use crate::errors::{CanNotFoundInterface, CanNotFoundMacAddress};
use crate::layers::layer3_ipv6_send;
use crate::layers::{Layer3Match, Layer4MatchIcmpv6, Layer4MatchTcpUdp, LayersMatch};

use crate::utils::find_interface_by_ipv6;
use crate::utils::get_threads_pool;
use crate::utils::random_port;
use crate::utils::random_port_multi;

use super::operator6::{apply_scale, vectorize};
use super::osscan::get_scan_line;
use super::packet6;
use super::rr::NXRR;
use super::rr::TECNRR;
use super::rr::TXRR;
use super::rr::U1RR;
use super::rr::{AllPacketRR6, RequestAndResponse, IERR, SEQRR};
use super::Linear;
use super::NmapOsDetectRet6;

#[derive(Debug, Clone)]
pub struct PistolFingerprint6 {
    pub scan: String,
    pub novelty: f64,
    pub status: bool,
    pub predict: Vec<NmapOsDetectRet6>,
}

fn send_seq_probes(
    src_ipv6: Ipv6Addr,
    src_port: Option<u16>,
    dst_ipv6: Ipv6Addr,
    dst_open_port: u16,
    timeout: Duration,
) -> Result<SEQRR> {
    let pool = get_threads_pool(6);
    let (tx, rx) = channel();

    let src_ports = match src_port {
        Some(s) => vec![s; 6],
        None => random_port_multi(6),
    };

    let buff_1 = packet6::seq_packet_1_layer3(src_ipv6, src_ports[0], dst_ipv6, dst_open_port)?;
    let buff_2 = packet6::seq_packet_2_layer3(src_ipv6, src_ports[1], dst_ipv6, dst_open_port)?;
    let buff_3 = packet6::seq_packet_3_layer3(src_ipv6, src_ports[2], dst_ipv6, dst_open_port)?;
    let buff_4 = packet6::seq_packet_4_layer3(src_ipv6, src_ports[3], dst_ipv6, dst_open_port)?;
    let buff_5 = packet6::seq_packet_5_layer3(src_ipv6, src_ports[4], dst_ipv6, dst_open_port)?;
    let buff_6 = packet6::seq_packet_6_layer3(src_ipv6, src_ports[5], dst_ipv6, dst_open_port)?;
    let buffs = vec![buff_1, buff_2, buff_3, buff_4, buff_5, buff_6];

    let start = SystemTime::now();
    let mut i = 0;
    for buff in buffs {
        let src_port = src_ports[i];
        let layer3 = Layer3Match {
            layer2: None,
            src_addr: Some(dst_ipv6.into()),
            dst_addr: Some(src_ipv6.into()),
        };
        let layer4_tcp_udp = Layer4MatchTcpUdp {
            layer3: Some(layer3),
            src_port: Some(dst_open_port),
            dst_port: Some(src_port),
        };
        let layers_match = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp);

        let tx = tx.clone();
        pool.execute(move || {
            let ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![layers_match], timeout);
            match tx.send((i, buff.to_vec(), ret)) {
                _ => (),
            }
        });
        // the probes are sent exactly 100 milliseconds apart so the total time taken is 500 ms
        sleep(Duration::from_millis(100));
        i += 1;
    }

    let mut seq1 = None;
    let mut seq2 = None;
    let mut seq3 = None;
    let mut seq4 = None;
    let mut seq5 = None;
    let mut seq6 = None;

    let iter = rx.into_iter().take(6);
    for (i, request, ret) in iter {
        let response = match ret? {
            Some(r) => r,
            None => vec![],
        };
        let rr = Some(RequestAndResponse { request, response });
        match i {
            0 => seq1 = rr,
            1 => seq2 = rr,
            2 => seq3 = rr,
            3 => seq4 = rr,
            4 => seq5 = rr,
            5 => seq6 = rr,
            _ => (),
        }
    }
    let elapsed = start.elapsed()?.as_secs_f64();

    let seqrr = SEQRR {
        seq1: seq1.unwrap(),
        seq2: seq2.unwrap(),
        seq3: seq3.unwrap(),
        seq4: seq4.unwrap(),
        seq5: seq5.unwrap(),
        seq6: seq6.unwrap(),
        elapsed,
    };

    Ok(seqrr)
}

fn send_ie_probes(src_ipv6: Ipv6Addr, dst_ipv6: Ipv6Addr, timeout: Duration) -> Result<IERR> {
    let (tx, rx) = channel();

    let buff_1 = packet6::ie_packet_1_layer3(src_ipv6, dst_ipv6).unwrap();
    let buff_2 = packet6::ie_packet_2_layer3(src_ipv6, dst_ipv6).unwrap();
    let buffs = vec![buff_1, buff_2];
    // let match_object = MatchObject::new_layer4_icmpv6_specific(Icmpv6Types::EchoReply, Icmpv6Code(0));
    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        layer3: Some(layer3),
        types: None,
        codes: None,
    };
    let layers_match = LayersMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    let mut i = 0;
    for buff in buffs {
        i += 1;
        let tx = tx.clone();
        // For those that do not require time, process them in order.
        // Prevent the previous request from receiving response from the later request.
        // ICMPV6 is a stateless protocol, we cannot accurately know the response for each request.
        let ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![layers_match], timeout);
        match tx.send((i, buff.to_vec(), ret)) {
            _ => (),
        }
    }

    let mut ie1 = None;
    let mut ie2 = None;

    let iter = rx.into_iter().take(2);
    for (i, request, ret) in iter {
        let response = match ret? {
            Some(r) => r,
            None => vec![],
        };
        let rr = Some(RequestAndResponse { request, response });
        match i {
            1 => {
                ie1 = rr;
            }
            2 => {
                ie2 = rr;
            }
            _ => (),
        }
    }

    let ie = IERR {
        ie1: ie1.unwrap(),
        ie2: ie2.unwrap(),
    };
    Ok(ie)
}

fn send_nx_probes(src_ipv6: Ipv6Addr, dst_ipv6: Ipv6Addr, timeout: Duration) -> Result<NXRR> {
    let (tx, rx) = channel();

    let buff_1 = packet6::ni_packet_layer3(src_ipv6, dst_ipv6).unwrap();
    let buff_2 = packet6::ns_packet_layer3(src_ipv6, dst_ipv6).unwrap();
    let buffs = vec![buff_1, buff_2];
    // let buffs = vec![buff_1];
    // let buffs = vec![buff_2];
    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        layer3: Some(layer3),
        types: None,
        codes: None,
    };
    let layers_match = LayersMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    let mut i = 0;
    for buff in buffs {
        i += 1;
        let tx = tx.clone();
        // For those that do not require time, process them in order.
        // Prevent the previous request from receiving response from the later request.
        // ICMPV6 is a stateless protocol, we cannot accurately know the response for each request.
        let ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![layers_match], timeout);
        match tx.send((i, buff.to_vec(), ret)) {
            _ => (),
        }
    }

    let mut ni = None;
    let mut ns = None;

    let iter = rx.into_iter().take(2);
    for (i, request, ret) in iter {
        let response = match ret? {
            Some(r) => r,
            None => vec![],
        };
        let rr = Some(RequestAndResponse { request, response });
        match i {
            1 => {
                ni = rr;
            }
            2 => {
                ns = rr;
            }
            _ => (),
        }
    }

    let ns = NXRR {
        ni: ni.unwrap(),
        ns: ns.unwrap(),
    };
    Ok(ns)
}

fn send_u1_probe(
    src_ipv6: Ipv6Addr,
    src_port: Option<u16>,
    dst_ipv6: Ipv6Addr,
    dst_closed_port: u16, //should be an closed udp port
    timeout: Duration,
) -> Result<U1RR> {
    let src_port = match src_port {
        Some(s) => s,
        None => random_port(),
    };

    let buff = packet6::udp_packet_layer3(src_ipv6, src_port, dst_ipv6, dst_closed_port)?;
    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        layer3: Some(layer3),
        types: None,
        codes: None,
    };
    let layers_match = LayersMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    // For those that do not require time, process them in order.
    // Prevent the previous request from receiving response from the later request.
    // ICMPV6 is a stateless protocol, we cannot accurately know the response for each request.
    let ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![layers_match], timeout)?;

    let response = match ret {
        Some(r) => r,
        None => vec![],
    };
    let rr = RequestAndResponse {
        request: buff,
        response,
    };

    let u1 = U1RR { u1: rr };
    Ok(u1)
}

fn send_tecn_probe(
    src_ipv6: Ipv6Addr,
    src_port: Option<u16>,
    dst_ipv6: Ipv6Addr,
    dst_open_port: u16,
    timeout: Duration,
) -> Result<TECNRR> {
    let src_port = match src_port {
        Some(s) => s,
        None => random_port(),
    };

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_open_port),
        dst_port: Some(src_port),
    };
    let layers_match = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp);

    let buff = packet6::tecn_packet_layer3(src_ipv6, src_port, dst_ipv6, dst_open_port)?;
    // For those that do not require time, process them in order.
    // Prevent the previous request from receiving response from the later request.
    // ICMPV6 is a stateless protocol, we cannot accurately know the response for each request.
    let ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![layers_match], timeout)?;

    let response = match ret {
        Some(r) => r,
        None => vec![],
    };
    let rr = RequestAndResponse {
        request: buff,
        response,
    };

    let tecn = TECNRR { tecn: rr };
    Ok(tecn)
}

fn send_tx_probes(
    src_ipv6: Ipv6Addr,
    src_port: Option<u16>,
    dst_ipv6: Ipv6Addr,
    dst_open_port: u16,
    dst_closed_port: u16,
    timeout: Duration,
) -> Result<TXRR> {
    let pool = get_threads_pool(6);
    let (tx, rx) = channel();

    let src_ports = match src_port {
        Some(s) => vec![s; 6],
        None => random_port_multi(6),
    };

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp_1 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_open_port),
        dst_port: Some(src_ports[0]),
    };
    let layer4_tcp_udp_2 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_open_port),
        dst_port: Some(src_ports[1]),
    };
    let layer4_tcp_udp_3 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_open_port),
        dst_port: Some(src_ports[2]),
    };
    let layer4_tcp_udp_4 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_closed_port),
        dst_port: Some(src_ports[3]),
    };
    let layer4_tcp_udp_5 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_closed_port),
        dst_port: Some(src_ports[4]),
    };
    let layer4_tcp_udp_6 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_closed_port),
        dst_port: Some(src_ports[5]),
    };
    let layers_match_1 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_1);
    let layers_match_2 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_2);
    let layers_match_3 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_3);
    let layers_match_4 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_4);
    let layers_match_5 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_5);
    let layers_match_6 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_6);
    let ms = vec![
        layers_match_1,
        layers_match_2,
        layers_match_3,
        layers_match_4,
        layers_match_5,
        layers_match_6,
    ];

    let buff_2 = packet6::t2_packet_layer3(src_ipv6, src_ports[0], dst_ipv6, dst_open_port)?;
    let buff_3 = packet6::t3_packet_layer3(src_ipv6, src_ports[1], dst_ipv6, dst_open_port)?;
    let buff_4 = packet6::t4_packet_layer3(src_ipv6, src_ports[2], dst_ipv6, dst_open_port)?;
    let buff_5 = packet6::t5_packet_layer3(src_ipv6, src_ports[3], dst_ipv6, dst_closed_port)?;
    let buff_6 = packet6::t6_packet_layer3(src_ipv6, src_ports[4], dst_ipv6, dst_closed_port)?;
    let buff_7 = packet6::t7_packet_layer3(src_ipv6, src_ports[5], dst_ipv6, dst_closed_port)?;
    let buffs = vec![buff_2, buff_3, buff_4, buff_5, buff_6, buff_7];

    let mut i = 0;
    for buff in buffs {
        let tx = tx.clone();
        let m = ms[i];
        pool.execute(move || {
            let ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![m], timeout);
            match tx.send((i, buff.to_vec(), ret)) {
                _ => (),
            }
        });
        sleep(Duration::from_millis(100));
        i += 1;
    }

    let mut t2 = None;
    let mut t3 = None;
    let mut t4 = None;
    let mut t5 = None;
    let mut t6 = None;
    let mut t7 = None;

    let iter = rx.into_iter().take(6);
    for (i, request, ret) in iter {
        let response = match ret? {
            Some(r) => r,
            None => vec![],
        };
        let rr = Some(RequestAndResponse { request, response });
        match i {
            0 => t2 = rr,
            1 => t3 = rr,
            2 => t4 = rr,
            3 => t5 = rr,
            4 => t6 = rr,
            5 => t7 = rr,
            _ => (),
        }
    }

    let txrr = TXRR {
        t2: t2.unwrap(),
        t3: t3.unwrap(),
        t4: t4.unwrap(),
        t5: t5.unwrap(),
        t6: t6.unwrap(),
        t7: t7.unwrap(),
    };

    Ok(txrr)
}

fn send_all_probes(
    src_ipv6: Ipv6Addr,
    src_port: Option<u16>,
    dst_ipv6: Ipv6Addr,
    dst_open_tcp_port: u16,
    dst_closed_tcp_port: u16,
    dst_closed_udp_port: u16,
    timeout: Duration,
) -> Result<AllPacketRR6> {
    let seq = send_seq_probes(src_ipv6, src_port, dst_ipv6, dst_open_tcp_port, timeout)?;
    let ie = send_ie_probes(src_ipv6, dst_ipv6, timeout)?;
    let nx = send_nx_probes(src_ipv6, dst_ipv6, timeout)?;
    let u1 = send_u1_probe(src_ipv6, src_port, dst_ipv6, dst_closed_udp_port, timeout)?;
    let tecn = send_tecn_probe(src_ipv6, src_port, dst_ipv6, dst_open_tcp_port, timeout)?;
    let tx = send_tx_probes(
        src_ipv6,
        src_port,
        dst_ipv6,
        dst_open_tcp_port,
        dst_closed_tcp_port,
        timeout,
    )?;

    let ap = AllPacketRR6 {
        seq,
        ie,
        nx,
        u1,
        tecn,
        tx,
    };

    Ok(ap)
}

fn predict_value(features: &[f64], wvec: &[Vec<f64>]) -> Vec<f64> {
    /*
       features [695]
       wvec [92, 695]

    */
    let vec_time = |x: &[f64], y: &[f64]| -> f64 {
        assert_eq!(x.len(), y.len());
        let mut sum = 0.0;
        for (a, b) in zip(x, y) {
            sum += a * b;
        }
        sum
    };

    let mut dec_value = [0f64; 92];
    for (idx, w) in wvec.iter().enumerate() {
        dec_value[idx] = vec_time(features, w);
    }

    let dec_value = dec_value.map(|x| 1.0 / (1.0 + (-x as f64).exp()));
    dec_value.to_vec()
}

fn novelty_of(features: &[f64], mean: &[f64], variance: &[f64]) -> f64 {
    assert_eq!(features.len(), 695);
    assert_eq!(mean.len(), 695);
    assert_eq!(variance.len(), 695);

    let mut sum = 0.0;
    for i in 0..695 {
        let d = features[i] - mean[i];
        // print!("{:.3}, ", d);
        let mut v = variance[i];
        if v == 0.0 {
            v = 0.01;
        }
        sum += (d * d) / v;
    }

    sum.sqrt()
}

fn isort(input: &[NmapOsDetectRet6]) -> Vec<NmapOsDetectRet6> {
    let find_max_prob = |x: &[NmapOsDetectRet6]| -> usize {
        let mut max_value = 0.0;
        for a in x {
            if a.score > max_value {
                max_value = a.score;
            }
        }
        for (i, a) in x.iter().enumerate() {
            if a.score == max_value {
                return i;
            }
        }
        0
    };

    let mut input_sort = Vec::new();
    let mut input_clone = input.to_vec();
    loop {
        if input_clone.len() <= 0 {
            break;
        }
        let max_value_index = find_max_prob(&input_clone);
        input_sort.push(input_clone[max_value_index].clone());
        input_clone.remove(max_value_index);
    }
    input_sort
}

pub fn os_probe6(
    src_ipv6: Ipv6Addr,
    src_port: Option<u16>,
    dst_ipv6: Ipv6Addr,
    dst_open_tcp_port: u16,
    dst_closed_tcp_port: u16,
    dst_closed_udp_port: u16,
    top_k: usize,
    timeout: Duration,
    linear: Linear,
) -> Result<PistolFingerprint6> {
    // Check target.
    let dst_mac = match find_interface_by_ipv6(src_ipv6) {
        Some(interface) => match interface.mac {
            Some(m) => m,
            None => return Err(CanNotFoundMacAddress::new().into()),
        },
        None => return Err(CanNotFoundInterface::new().into()),
    };

    let ap = send_all_probes(
        src_ipv6,
        src_port,
        dst_ipv6,
        dst_open_tcp_port,
        dst_closed_tcp_port,
        dst_closed_udp_port,
        timeout,
    )?;

    let hops = None;
    let good_results = true;
    let scan = get_scan_line(
        Some(dst_mac),
        dst_open_tcp_port,
        dst_closed_tcp_port,
        dst_closed_udp_port,
        dst_ipv6.into(),
        hops,
        good_results,
    );

    let features = vectorize(&ap)?;
    // println!("{:?}", features);
    let features = apply_scale(&features, &linear.scale);
    // println!("{:?}", features[0..5].to_vec());
    // println!("{:?}", features_scale[0..5].to_vec());
    let predict = predict_value(&features, &linear.w);
    // println!("{:?}", predict);

    let mut detect_rets: Vec<NmapOsDetectRet6> = Vec::new();
    for (i, (name, score)) in zip(&linear.namelist, &predict).into_iter().enumerate() {
        let dr = NmapOsDetectRet6 {
            name: name.to_string(),
            osclass: linear.cpe[i].osclass.to_vec(),
            cpe: linear.cpe[i].cpe.to_vec(),
            score: *score,
            label: i,
        };
        detect_rets.push(dr);
    }

    let detect_rets_sort = isort(&detect_rets);
    let mut perfect_match = 1;
    for i in 1..36 {
        if detect_rets_sort[i].score >= 0.9 * detect_rets_sort[0].score {
            perfect_match += 1;
        }
    }

    // println!("{}", perfect_match);
    let label = detect_rets_sort[0].label;
    let novelty = novelty_of(&features, &linear.mean[label], &linear.variance[label]);

    let match_status = if perfect_match == 1 {
        const FP_NOVELTY_THRESHOLD: f64 = 15.0;
        // println!("{}", novelty);
        if novelty < FP_NOVELTY_THRESHOLD {
            true
        } else {
            false
        }
    } else {
        false
    };

    let ret = if match_status {
        PistolFingerprint6 {
            scan,
            novelty,
            status: match_status,
            predict: detect_rets_sort[0..top_k].to_vec(),
        }
    } else {
        PistolFingerprint6 {
            scan,
            novelty,
            status: match_status,
            predict: vec![],
        }
    };
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::{icmpv6::Icmpv6Packet, ipv6::Ipv6Packet, Packet};
    #[test]
    fn test_seq_probes() {
        let src_ipv6 = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let src_port = None;
        let dst_open_port = 22;
        let timeout = Duration::new(3, 0);
        let seqrr = send_seq_probes(src_ipv6, src_port, dst_ipv6, dst_open_port, timeout).unwrap();
        println!("{}", seqrr.seq1.response.len());
        println!("{}", seqrr.seq2.response.len());
        println!("{}", seqrr.seq3.response.len());
        println!("{}", seqrr.seq4.response.len());
        println!("{}", seqrr.seq5.response.len());
        println!("{}", seqrr.seq6.response.len());
    }
    #[test]
    fn test_ie_probe() {
        let src_ipv6 = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let timeout = Duration::new(3, 0);
        let ret = send_ie_probes(src_ipv6, dst_ipv6, timeout).unwrap();
        println!("{}", ret.ie1.response.len());
        println!("{}", ret.ie2.response.len());
    }
    #[test]
    fn test_nx_probe() {
        let src_ipv6 = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let timeout = Duration::new(3, 0);
        let ret = send_nx_probes(src_ipv6, dst_ipv6, timeout).unwrap();
        // println!("{}", ret.ni.response.len());
        // println!("{}", ret.ns.response.len());
        let ipv6_packet = Ipv6Packet::new(&ret.ns.response).unwrap();
        println!("{}", ipv6_packet.get_payload_length());
        let icmpv6_packet = Icmpv6Packet::new(ipv6_packet.payload()).unwrap();
        println!("{:?}", icmpv6_packet.get_icmpv6_type());
        println!("{}", icmpv6_packet.get_checksum());
    }
    #[test]
    fn test_u1_probes() {
        let src_ipv6 = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let src_port = None;
        let dst_closed_port = 12345;
        let timeout = Duration::new(3, 0);
        let ret = send_u1_probe(src_ipv6, src_port, dst_ipv6, dst_closed_port, timeout).unwrap();
        println!("{}", ret.u1.response.len());
    }
    #[test]
    fn test_tecn_probes() {
        let src_ipv6 = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let src_port = None;
        let dst_closed_port = 22;
        let timeout = Duration::new(3, 0);
        let ret = send_tecn_probe(src_ipv6, src_port, dst_ipv6, dst_closed_port, timeout).unwrap();
        println!("{}", ret.tecn.response.len());
    }
    #[test]
    fn test_tx_probes() {
        let src_ipv6 = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let src_port = None;
        let dst_open_port = 22;
        let dst_closed_port = 9999;
        let timeout = Duration::new(3, 0);
        let txrr = send_tx_probes(
            src_ipv6,
            src_port,
            dst_ipv6,
            dst_open_port,
            dst_closed_port,
            timeout,
        )
        .unwrap();
        println!("{}", txrr.t2.response.len());
        println!("{}", txrr.t3.response.len());
        println!("{}", txrr.t4.response.len());
        println!("{}", txrr.t5.response.len());
        println!("{}", txrr.t6.response.len());
        println!("{}", txrr.t7.response.len());
    }
}
