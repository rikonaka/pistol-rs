use anyhow::Result;
use std::net::Ipv6Addr;
use std::sync::mpsc::channel;
use std::thread::sleep;
use std::time::Duration;

use crate::utils::get_threads_pool;
use crate::utils::random_port;
use crate::utils::random_port_multi;

use crate::layers::{layer3_ipv6_send, MatchResp};

use super::packet6;
use super::rr::NXRR;
use super::rr::TECNRR;
use super::rr::TXRR;
use super::rr::U1RR;
use super::rr::{RequestAndResponse, IERR, SEQRR};

fn send_seq_probes(
    src_ipv6: Ipv6Addr,
    src_port: Option<u16>,
    dst_ipv6: Ipv6Addr,
    dst_open_port: u16,
    max_loop: usize,
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

    let mut i = 0;
    for buff in buffs {
        let src_port = src_ports[i];
        let match_tcp = MatchResp::new_layer4_tcp_udp(src_port, dst_open_port, false);
        i += 1;
        let tx = tx.clone();
        pool.execute(move || {
            let ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![match_tcp], max_loop);
            match tx.send((i, buff.to_vec(), ret)) {
                _ => (),
            }
        });
        // the probes are sent exactly 100 milliseconds apart so the total time taken is 500 ms
        sleep(Duration::from_millis(100));
    }

    let mut seq1 = None;
    let mut seq2 = None;
    let mut seq3 = None;
    let mut seq4 = None;
    let mut seq5 = None;
    let mut seq6 = None;

    let iter = rx.into_iter().take(6);
    for (i, request, ret) in iter {
        let name = format!("seq{}", i);
        let response = match ret? {
            Some(r) => r,
            None => vec![],
        };
        let rr = Some(RequestAndResponse {
            name: name.clone(),
            request,
            response,
        });
        match i {
            1 => seq1 = rr,
            2 => seq2 = rr,
            3 => seq3 = rr,
            4 => seq4 = rr,
            5 => seq5 = rr,
            6 => seq6 = rr,
            _ => (),
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

fn send_ie_probes(src_ipv6: Ipv6Addr, dst_ipv6: Ipv6Addr, max_loop: usize) -> Result<IERR> {
    let (tx, rx) = channel();

    let buff_1 = packet6::ie_packet_1_layer3(src_ipv6, dst_ipv6).unwrap();
    let buff_2 = packet6::ie_packet_2_layer3(src_ipv6, dst_ipv6).unwrap();
    let buffs = vec![buff_1, buff_2];
    // let match_object = MatchObject::new_layer4_icmpv6_specific(Icmpv6Types::EchoReply, Icmpv6Code(0));
    let match_icmpv6 = MatchResp::new_layer4_icmpv6(src_ipv6, dst_ipv6, false);

    let mut i = 0;
    for buff in buffs {
        i += 1;
        let tx = tx.clone();
        // For those that do not require time, process them in order.
        // Prevent the previous request from receiving response from the later request.
        // ICMPV6 is a stateless protocol, we cannot accurately know the response for each request.
        let ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![match_icmpv6], max_loop);
        match tx.send((i, buff.to_vec(), ret)) {
            _ => (),
        }
    }

    let mut ie1 = None;
    let mut ie2 = None;

    let iter = rx.into_iter().take(2);
    for (i, request, ret) in iter {
        let name = format!("ie{}", i);
        let response = match ret? {
            Some(r) => r,
            None => vec![],
        };
        let rr = Some(RequestAndResponse {
            name,
            request,
            response,
        });
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

fn send_nx_probes(src_ipv6: Ipv6Addr, dst_ipv6: Ipv6Addr, max_loop: usize) -> Result<NXRR> {
    let (tx, rx) = channel();

    let buff_1 = packet6::ni_packet_layer3(src_ipv6, dst_ipv6).unwrap();
    let buff_2 = packet6::ns_packet_layer3(src_ipv6, dst_ipv6).unwrap();
    let buffs = vec![buff_1, buff_2];
    // let buffs = vec![buff_1];
    let match_icmpv6 = MatchResp::new_layer4_icmpv6(src_ipv6, dst_ipv6, false);

    let mut i = 0;
    for buff in buffs {
        i += 1;
        let tx = tx.clone();
        // For those that do not require time, process them in order.
        // Prevent the previous request from receiving response from the later request.
        // ICMPV6 is a stateless protocol, we cannot accurately know the response for each request.
        let ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![match_icmpv6], max_loop);
        match tx.send((i, buff.to_vec(), ret)) {
            _ => (),
        }
    }

    let mut ni = None;
    let mut ns = None;

    let iter = rx.into_iter().take(2);
    for (i, request, ret) in iter {
        let name = if i == 0 {
            String::from("ni")
        } else {
            String::from("ns")
        };
        let response = match ret? {
            Some(r) => r,
            None => vec![],
        };
        let rr = Some(RequestAndResponse {
            name,
            request,
            response,
        });
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
    max_loop: usize,
) -> Result<U1RR> {
    let src_port = match src_port {
        Some(s) => s,
        None => random_port(),
    };

    let buff = packet6::udp_packet_layer3(src_ipv6, src_port, dst_ipv6, dst_closed_port)?;
    let match_icmpv6 = MatchResp::new_layer4_icmpv6(src_ipv6, dst_ipv6, false);

    // For those that do not require time, process them in order.
    // Prevent the previous request from receiving response from the later request.
    // ICMPV6 is a stateless protocol, we cannot accurately know the response for each request.
    let ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![match_icmpv6], max_loop)?;

    let name = String::from("u1");
    let response = match ret {
        Some(r) => r,
        None => vec![],
    };
    let rr = RequestAndResponse {
        name,
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
    max_loop: usize,
) -> Result<TECNRR> {
    let src_port = match src_port {
        Some(s) => s,
        None => random_port(),
    };

    let buff = packet6::tecn_packet_layer3(src_ipv6, src_port, dst_ipv6, dst_open_port)?;
    let match_tcp = MatchResp::new_layer4_tcp_udp(src_port, dst_open_port, false);

    // For those that do not require time, process them in order.
    // Prevent the previous request from receiving response from the later request.
    // ICMPV6 is a stateless protocol, we cannot accurately know the response for each request.
    let ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![match_tcp], max_loop)?;

    let name = String::from("tecn");
    let response = match ret {
        Some(r) => r,
        None => vec![],
    };
    let rr = RequestAndResponse {
        name,
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
    max_loop: usize,
) -> Result<TXRR> {
    let pool = get_threads_pool(6);
    let (tx, rx) = channel();

    let src_ports = match src_port {
        Some(s) => vec![s; 6],
        None => random_port_multi(6),
    };

    let buff_1 = packet6::t2_packet_layer3(src_ipv6, src_ports[0], dst_ipv6, dst_open_port)?;
    let buff_2 = packet6::t3_packet_layer3(src_ipv6, src_ports[1], dst_ipv6, dst_open_port)?;
    let buff_3 = packet6::t4_packet_layer3(src_ipv6, src_ports[2], dst_ipv6, dst_open_port)?;
    let buff_4 = packet6::t5_packet_layer3(src_ipv6, src_ports[3], dst_ipv6, dst_open_port)?;
    let buff_5 = packet6::t6_packet_layer3(src_ipv6, src_ports[4], dst_ipv6, dst_open_port)?;
    let buff_6 = packet6::t7_packet_layer3(src_ipv6, src_ports[5], dst_ipv6, dst_open_port)?;
    let buffs = vec![buff_1, buff_2, buff_3, buff_4, buff_5, buff_6];

    let mut i = 0;
    for buff in buffs {
        let src_port = src_ports[i];
        let match_tcp = MatchResp::new_layer4_tcp_udp(src_port, dst_open_port, false);
        i += 1;
        let tx = tx.clone();
        pool.execute(move || {
            let ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![match_tcp], max_loop);
            match tx.send((i, buff.to_vec(), ret)) {
                _ => (),
            }
        });
    }

    let mut t2 = None;
    let mut t3 = None;
    let mut t4 = None;
    let mut t5 = None;
    let mut t6 = None;
    let mut t7 = None;

    let iter = rx.into_iter().take(6);
    for (i, request, ret) in iter {
        let name = format!("t{}", i);
        let response = match ret? {
            Some(r) => r,
            None => vec![],
        };
        let rr = Some(RequestAndResponse {
            name: name.clone(),
            request,
            response,
        });
        match i + 1 {
            2 => t2 = rr,
            3 => t3 = rr,
            4 => t4 = rr,
            5 => t5 = rr,
            6 => t6 = rr,
            7 => t7 = rr,
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_seq_probes() {
        let src_ipv6 = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let src_port = None;
        let dst_open_port = 22;
        let max_loop = 32;
        let seqrr = send_seq_probes(src_ipv6, src_port, dst_ipv6, dst_open_port, max_loop).unwrap();
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
        let max_loop = 32;
        let ret = send_ie_probes(src_ipv6, dst_ipv6, max_loop).unwrap();
        println!("{}", ret.ie1.response.len());
        println!("{}", ret.ie2.response.len());
    }
    #[test]
    fn test_nx_probe() {
        let src_ipv6 = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let max_loop = 32;
        let ret = send_nx_probes(src_ipv6, dst_ipv6, max_loop).unwrap();
        println!("{}", ret.ni.response.len());
        println!("{}", ret.ns.response.len());
    }
    #[test]
    fn test_u1_probes() {
        let src_ipv6 = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let src_port = None;
        let dst_closed_port = 12345;
        let max_loop = 32;
        let ret = send_u1_probe(src_ipv6, src_port, dst_ipv6, dst_closed_port, max_loop).unwrap();
        println!("{}", ret.u1.response.len());
    }
    #[test]
    fn test_tecn_probes() {
        let src_ipv6 = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let src_port = None;
        let dst_closed_port = 22;
        let max_loop = 32;
        let ret = send_tecn_probe(src_ipv6, src_port, dst_ipv6, dst_closed_port, max_loop).unwrap();
        println!("{}", ret.tecn.response.len());
    }
    #[test]
    fn test_tx_probes() {
        let src_ipv6 = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        let src_port = None;
        let dst_open_port = 22;
        let max_loop = 32;
        let txrr = send_tx_probes(src_ipv6, src_port, dst_ipv6, dst_open_port, max_loop).unwrap();
        println!("{}", txrr.t2.response.len());
        println!("{}", txrr.t3.response.len());
        println!("{}", txrr.t4.response.len());
        println!("{}", txrr.t5.response.len());
        println!("{}", txrr.t6.response.len());
        println!("{}", txrr.t7.response.len());
    }
}
