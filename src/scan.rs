use anyhow::Result;
use pnet::datalink::MacAddr;
use pnet::packet::ip::IpNextHeaderProtocol;
use std::collections::HashMap;
use std::iter::zip;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::mpsc::channel;
use std::time::Duration;

pub mod arp;
pub mod ip;
pub mod tcp;
pub mod tcp6;
pub mod udp;
pub mod udp6;

use crate::utils::{self, get_ips_from_host, get_ips_from_host6};
use crate::TargetType;

use super::errors::{NotSupportIpTypeForArpScan, WrongTargetType};
use super::ArpScanResults;
use super::IpScanResults;
use super::Target;
use super::TargetScanStatus;
use super::TcpUdpScanResults;

#[derive(Debug, Clone, Copy)]
pub enum ScanMethod {
    Connect,
    Syn,
    Fin,
    Ack,
    Null,
    Xmas,
    Window,
    Maimon,
    Idle, // need ipv4 ip id
    Udp,
    IpProcotol,
}

#[derive(Debug, Clone, Copy)]
pub enum ScanMethod6 {
    Connect,
    Syn,
    Fin,
    Ack,
    Null,
    Xmas,
    Window,
    Maimon,
    Udp,
}

fn _ip_print_result(ip: IpAddr, protocol: IpNextHeaderProtocol, ret: TargetScanStatus) {
    let str = match ret {
        TargetScanStatus::Open => format!("{ip} {protocol} open"),
        TargetScanStatus::OpenOrFiltered => format!("{ip} {protocol} open|filtered"),
        TargetScanStatus::Filtered => format!("{ip} {protocol} filtered"),
        TargetScanStatus::Unfiltered => format!("{ip} {protocol} unfiltered"),
        TargetScanStatus::Closed => format!("{ip} {protocol} closed"),
        TargetScanStatus::Unreachable => format!("{ip} {protocol} unreachable"),
        TargetScanStatus::ClosedOrFiltered => format!("{ip} {protocol} closed|filtered"),
    };
    println!("{str}");
}

fn _arp_print_result(ip: IpAddr, mac: Option<MacAddr>) {
    match mac {
        Some(mac) => println!("{ip} ({mac})"),
        _ => println!("{ip} (null)"),
    }
}

fn _tcp_udp_print_result(ip: IpAddr, port: u16, ret: TargetScanStatus) {
    let str = match ret {
        TargetScanStatus::Open => format!("{ip} {port} open"),
        TargetScanStatus::OpenOrFiltered => format!("{ip} {port} open|filtered"),
        TargetScanStatus::Filtered => format!("{ip} {port} filtered"),
        TargetScanStatus::Unfiltered => format!("{ip} {port} unfiltered"),
        TargetScanStatus::Closed => format!("{ip} {port} closed"),
        TargetScanStatus::Unreachable => format!("{ip} {port} unreachable"),
        TargetScanStatus::ClosedOrFiltered => format!("{ip} {port} closed|filtered"),
    };
    println!("{str}");
}

fn _no_interface_found(ip: Ipv4Addr) {
    println!(
        "IP {} cannot obtain the corresponding interface, ignore it",
        ip
    );
}

fn arp_scan_with_interface(
    target: Target,
    dst_mac: Option<&str>,
    interface: &str,
    threads_num: usize,
    print_result: bool,
    max_loop: Option<usize>,
) -> Result<ArpScanResults> {
    let (interface, src_ipv4, src_mac) = utils::parse_interface_from_str(interface)?;
    let dst_mac = match dst_mac {
        Some(v) => match MacAddr::from_str(v) {
            Ok(m) => m,
            Err(e) => return Err(e.into()),
        },
        _ => MacAddr::broadcast(),
    };
    let (tx, rx) = channel();
    let pool = utils::get_threads_pool(threads_num);
    let mut recv_size = 0;
    let max_loop = utils::get_max_loop(max_loop);

    for h in &target.hosts {
        let dst_ipv4 = h.addr;
        recv_size += 1;
        let tx = tx.clone();
        let i = interface.clone();
        pool.execute(move || {
            let scan_ret =
                arp::send_arp_scan_packet(dst_ipv4, dst_mac, src_ipv4, src_mac, i, max_loop);
            if print_result {
                _arp_print_result(dst_ipv4.into(), scan_ret)
            }
            match tx.send((dst_ipv4, scan_ret)) {
                _ => (),
            }
        });
    }
    let iter = rx.into_iter().take(recv_size);
    let mut ret = ArpScanResults {
        alive_hosts_num: 0,
        alive_hosts: HashMap::new(),
    };
    for (target_ipv4, target_mac) in iter {
        match target_mac {
            Some(m) => {
                ret.alive_hosts_num += 1;
                ret.alive_hosts.insert(target_ipv4, m);
            }
            None => (),
        }
    }
    return Ok(ret);
}

fn arp_scan_no_interface(
    target: Target,
    dst_mac: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_loop: Option<usize>,
) -> Result<ArpScanResults> {
    let mut ret = ArpScanResults {
        alive_hosts_num: 0,
        alive_hosts: HashMap::new(),
    };

    let target_ips = get_ips_from_host(&target.hosts);
    let bi_vec = utils::bind_interface(&target_ips);
    // println!("{:?}", bi_vec);

    let pool = utils::get_threads_pool(threads_num);
    let max_loop = utils::get_max_loop(max_loop);
    let dst_mac = match dst_mac {
        Some(v) => match MacAddr::from_str(v) {
            Ok(m) => m,
            Err(e) => return Err(e.into()),
        },
        _ => MacAddr::broadcast(),
    };
    let (tx, rx) = channel();
    let mut recv_size = 0;

    for bi in bi_vec {
        let tx = tx.clone();
        recv_size += 1;
        match bi.interface {
            Some(interface) => {
                let (src_ipv4, src_mac) = utils::parse_interface(&interface).unwrap();
                let dst_ipv4 = bi.ipv4;
                let tx = tx.clone();
                let i = interface.clone();
                pool.execute(move || {
                    let scan_ret = arp::send_arp_scan_packet(
                        dst_ipv4, dst_mac, src_ipv4, src_mac, i, max_loop,
                    );
                    if print_result {
                        _arp_print_result(dst_ipv4.into(), scan_ret)
                    }
                    match tx.send(Some((dst_ipv4, scan_ret))) {
                        _ => (),
                    }
                });
            }
            None => {
                _no_interface_found(bi.ipv4);
                match tx.send(None) {
                    _ => (),
                }
            }
        }
    }
    let iter = rx.into_iter().take(recv_size);
    for v in iter {
        match v {
            Some((target_ipv4, target_mac)) => match target_mac {
                Some(m) => {
                    ret.alive_hosts_num += 1;
                    ret.alive_hosts.insert(target_ipv4, m);
                }
                None => (),
            },
            None => (),
        }
    }
    return Ok(ret);
}

pub fn arp_scan(
    target: Target,
    dst_mac: Option<&str>,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_loop: Option<usize>,
) -> Result<ArpScanResults> {
    match target.target_type {
        TargetType::Ipv4 => {
            match interface {
                Some(interface) => {
                    // If the user provides an interface, all packets will be tried to be sent from this interface.
                    arp_scan_with_interface(
                        target,
                        dst_mac,
                        interface,
                        threads_num,
                        print_result,
                        max_loop,
                    )
                }
                None => arp_scan_no_interface(target, dst_mac, threads_num, print_result, max_loop),
            }
        }
        _ => return Err(NotSupportIpTypeForArpScan::new(target.target_type).into()),
    }
}

fn run_scan(
    method: ScanMethod,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    protocol: Option<IpNextHeaderProtocol>,
    print_result: bool,
    timeout: Duration,
    max_loop: usize,
) -> Result<(
    Ipv4Addr,
    u16,
    Option<IpNextHeaderProtocol>,
    TargetScanStatus,
)> {
    let scan_ret = match method {
        ScanMethod::Connect => tcp::send_connect_scan_packet(
            src_ipv4, src_port, dst_ipv4, dst_port, timeout, max_loop,
        )?,
        ScanMethod::Syn => {
            tcp::send_syn_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout, max_loop)?
        }
        ScanMethod::Fin => {
            tcp::send_fin_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout, max_loop)?
        }
        ScanMethod::Ack => {
            tcp::send_ack_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout, max_loop)?
        }
        ScanMethod::Null => {
            tcp::send_null_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout, max_loop)?
        }
        ScanMethod::Xmas => {
            tcp::send_xmas_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout, max_loop)?
        }
        ScanMethod::Window => {
            tcp::send_window_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout, max_loop)?
        }
        ScanMethod::Maimon => {
            tcp::send_maimon_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout, max_loop)?
        }
        ScanMethod::Idle => {
            let zombie_ipv4 = zombie_ipv4.unwrap();
            let zombie_port = zombie_port.unwrap();
            match tcp::send_idle_scan_packet(
                src_ipv4,
                src_port,
                dst_ipv4,
                dst_port,
                zombie_ipv4,
                zombie_port,
                timeout,
                max_loop,
            ) {
                Ok((status, idel_rets)) => {
                    if print_result {
                        if idel_rets.is_some() {
                            let v = idel_rets.unwrap();
                            println!(
                                "zombie ip id 1: {}, zombie ip id 2: {}",
                                v.zombie_ip_id_1, v.zombie_ip_id_2
                            );
                        }
                    }
                    status
                }
                Err(e) => return Err(e.into()),
            }
        }
        ScanMethod::Udp => {
            udp::send_udp_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout, max_loop)?
        }
        ScanMethod::IpProcotol => ip::send_ip_procotol_scan_packet(
            src_ipv4,
            dst_ipv4,
            protocol.unwrap(),
            timeout,
            max_loop,
        )?,
    };

    if print_result {
        _tcp_udp_print_result(dst_ipv4.into(), dst_port, scan_ret);
    }
    Ok((dst_ipv4, dst_port, protocol, scan_ret))
}

fn run_scan6(
    method: ScanMethod6,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    print_result: bool,
    timeout: Duration,
    max_loop: usize,
) -> Result<(Ipv6Addr, u16, TargetScanStatus)> {
    let scan_ret = match method {
        ScanMethod6::Connect => tcp6::send_connect_scan_packet(
            src_ipv6, src_port, dst_ipv6, dst_port, timeout, max_loop,
        )?,
        ScanMethod6::Syn => {
            tcp6::send_syn_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout, max_loop)?
        }
        ScanMethod6::Fin => {
            tcp6::send_fin_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout, max_loop)?
        }
        ScanMethod6::Ack => {
            tcp6::send_ack_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout, max_loop)?
        }
        ScanMethod6::Null => {
            tcp6::send_null_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout, max_loop)?
        }
        ScanMethod6::Xmas => {
            tcp6::send_xmas_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout, max_loop)?
        }
        ScanMethod6::Window => tcp6::send_window_scan_packet(
            src_ipv6, src_port, dst_ipv6, dst_port, timeout, max_loop,
        )?,
        ScanMethod6::Maimon => tcp6::send_maimon_scan_packet(
            src_ipv6, src_port, dst_ipv6, dst_port, timeout, max_loop,
        )?,
        ScanMethod6::Udp => {
            udp6::send_udp_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout, max_loop)?
        }
    };

    if print_result {
        _tcp_udp_print_result(dst_ipv6.into(), dst_port, scan_ret);
    }
    Ok((dst_ipv6, dst_port, scan_ret))
}

fn scan_with_interface(
    target: Target,
    method: ScanMethod,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    protocol: Option<IpNextHeaderProtocol>,
    interface: &str,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<(
    HashMap<IpAddr, TcpUdpScanResults>,
    HashMap<IpAddr, IpScanResults>,
)> {
    let (interface, src_ipv4_interface, _) = utils::parse_interface_from_str(interface)?;
    let (tx, rx) = channel();
    let pool = utils::get_threads_pool(threads_num);
    let mut recv_size = 0;
    let max_loop = utils::get_max_loop(max_loop);
    let timeout = utils::get_timeout(timeout);

    let src_ipv4 = match src_ipv4 {
        Some(s) => s,
        None => src_ipv4_interface,
    };
    let src_port = match src_port {
        Some(s) => s,
        None => utils::random_port(),
    };

    for h in &target.hosts {
        let dst_ipv4 = h.addr;
        for dst_port in &h.ports {
            let tx = tx.clone();
            recv_size += 1;
            let dst_port = dst_port.clone();
            pool.execute(move || {
                let scan_ret = run_scan(
                    method,
                    src_ipv4,
                    src_port,
                    dst_ipv4,
                    dst_port,
                    zombie_ipv4,
                    zombie_port,
                    protocol,
                    print_result,
                    timeout,
                    max_loop,
                );
                match tx.send(scan_ret) {
                    _ => (),
                }
            });
        }
    }

    let iter = rx.into_iter().take(recv_size);
    let mut ret: HashMap<IpAddr, TcpUdpScanResults> = HashMap::new();
    let mut ret_procotol: HashMap<IpAddr, IpScanResults> = HashMap::new();

    for v in iter {
        match v {
            Ok((dst_ipv4, dst_port, procotol, scan_rets)) => match procotol {
                Some(p) => {
                    if ret_procotol.contains_key(&dst_ipv4.into()) {
                        ret_procotol
                            .get_mut(&dst_ipv4.into())
                            .unwrap()
                            .results
                            .insert(p, scan_rets);
                    } else {
                        let mut v = IpScanResults::new(dst_ipv4.into());
                        v.results.insert(p, scan_rets);
                        ret_procotol.insert(dst_ipv4.into(), v);
                    }
                }
                _ => {
                    if ret.contains_key(&dst_ipv4.into()) {
                        ret.get_mut(&dst_ipv4.into())
                            .unwrap()
                            .results
                            .insert(dst_port, scan_rets);
                    } else {
                        let mut v = TcpUdpScanResults::new(dst_ipv4.into());
                        v.results.insert(dst_port, scan_rets);
                        ret.insert(dst_ipv4.into(), v);
                    }
                }
            },
            Err(e) => return Err(e),
        }
    }
    Ok((ret, ret_procotol))
}

fn scan_with_interface6(
    target: Target,
    method: ScanMethod6,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    interface: &str,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (interface, src_ipv6_interface, _) = utils::parse_interface_from_str6(interface)?;
    let (tx, rx) = channel();
    let pool = utils::get_threads_pool(threads_num);
    let mut recv_size = 0;
    let max_loop = utils::get_max_loop(max_loop);
    let timeout = utils::get_timeout(timeout);

    let src_ipv6 = match src_ipv6 {
        Some(s) => s,
        None => src_ipv6_interface,
    };
    let src_port = match src_port {
        Some(s) => s,
        None => utils::random_port(),
    };

    for h in &target.hosts6 {
        let dst_ipv6 = h.addr;
        for dst_port in &h.ports {
            let tx = tx.clone();
            recv_size += 1;
            let dst_port = dst_port.clone();
            pool.execute(move || {
                let scan_ret = run_scan6(
                    method,
                    src_ipv6,
                    src_port,
                    dst_ipv6,
                    dst_port,
                    print_result,
                    timeout,
                    max_loop,
                );
                match tx.send(scan_ret) {
                    _ => (),
                }
            });
        }
    }

    let iter = rx.into_iter().take(recv_size);
    let mut ret: HashMap<IpAddr, TcpUdpScanResults> = HashMap::new();

    for v in iter {
        match v {
            Ok((dst_ipv6, dst_port, scan_rets)) => {
                if ret.contains_key(&dst_ipv6.into()) {
                    ret.get_mut(&dst_ipv6.into())
                        .unwrap()
                        .results
                        .insert(dst_port, scan_rets);
                } else {
                    let mut v = TcpUdpScanResults::new(dst_ipv6.into());
                    v.results.insert(dst_port, scan_rets);
                    ret.insert(dst_ipv6.into(), v);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(ret)
}

fn scan_no_interface(
    target: Target,
    method: ScanMethod,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    protocol: Option<IpNextHeaderProtocol>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<(
    HashMap<IpAddr, TcpUdpScanResults>,
    HashMap<IpAddr, IpScanResults>,
)> {
    let target_ips = get_ips_from_host(&target.hosts);
    let bi_vec = utils::bind_interface(&target_ips);

    let pool = utils::get_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut recv_size = 0;
    let max_loop = utils::get_max_loop(max_loop);
    let timeout = utils::get_timeout(timeout);

    for (bi, host) in zip(bi_vec, target.hosts) {
        match bi.interface {
            Some(interface) => {
                let src_ipv4 = match src_ipv4 {
                    Some(s) => s,
                    None => {
                        let (src_ipv4, _) = utils::parse_interface(&interface).unwrap();
                        src_ipv4
                    }
                };
                let src_port = match src_port {
                    Some(s) => s,
                    None => utils::random_port(),
                };
                let dst_ipv4 = bi.ipv4;
                for dst_port in host.ports {
                    let tx = tx.clone();
                    recv_size += 1;
                    pool.execute(move || {
                        let scan_ret = run_scan(
                            method,
                            src_ipv4,
                            src_port,
                            dst_ipv4,
                            dst_port,
                            zombie_ipv4,
                            zombie_port,
                            protocol,
                            print_result,
                            timeout,
                            max_loop,
                        );
                        match tx.send(scan_ret) {
                            _ => (),
                        }
                    });
                }
            }
            None => (),
        }
    }

    let iter = rx.into_iter().take(recv_size);
    let mut ret: HashMap<IpAddr, TcpUdpScanResults> = HashMap::new();
    let mut ret_procotol: HashMap<IpAddr, IpScanResults> = HashMap::new();

    for v in iter {
        match v {
            Ok((dst_ipv4, dst_port, procotol, scan_rets)) => match procotol {
                Some(p) => {
                    if ret_procotol.contains_key(&dst_ipv4.into()) {
                        ret_procotol
                            .get_mut(&dst_ipv4.into())
                            .unwrap()
                            .results
                            .insert(p, scan_rets);
                    } else {
                        let mut v = IpScanResults::new(dst_ipv4.into());
                        v.results.insert(p, scan_rets);
                        ret_procotol.insert(dst_ipv4.into(), v);
                    }
                }
                _ => {
                    if ret.contains_key(&dst_ipv4.into()) {
                        ret.get_mut(&dst_ipv4.into())
                            .unwrap()
                            .results
                            .insert(dst_port, scan_rets);
                    } else {
                        let mut v = TcpUdpScanResults::new(dst_ipv4.into());
                        v.results.insert(dst_port, scan_rets);
                        ret.insert(dst_ipv4.into(), v);
                    }
                }
            },
            Err(e) => return Err(e),
        }
    }
    Ok((ret, ret_procotol))
}

fn scan_no_interface6(
    target: Target,
    method: ScanMethod6,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let target_ips = get_ips_from_host6(&target.hosts6);
    let bi_vec = utils::bind_interface6(&target_ips);

    let pool = utils::get_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut recv_size = 0;
    let max_loop = utils::get_max_loop(max_loop);
    let timeout = utils::get_timeout(timeout);

    for (bi, host) in zip(bi_vec, target.hosts) {
        match bi.interface {
            Some(interface) => {
                let src_ipv6 = match src_ipv6 {
                    Some(s) => s,
                    None => {
                        let (src_ipv6, _) = utils::parse_interface6(&interface).unwrap();
                        src_ipv6
                    }
                };
                let src_port = match src_port {
                    Some(s) => s,
                    None => utils::random_port(),
                };
                let dst_ipv6 = bi.ipv6;
                for dst_port in host.ports {
                    let tx = tx.clone();
                    recv_size += 1;
                    pool.execute(move || {
                        let scan_ret = run_scan6(
                            method,
                            src_ipv6,
                            src_port,
                            dst_ipv6,
                            dst_port,
                            print_result,
                            timeout,
                            max_loop,
                        );
                        match tx.send(scan_ret) {
                            _ => (),
                        }
                    });
                }
            }
            None => (),
        }
    }

    let iter = rx.into_iter().take(recv_size);
    let mut ret: HashMap<IpAddr, TcpUdpScanResults> = HashMap::new();

    for v in iter {
        match v {
            Ok((dst_ipv4, dst_port, scan_rets)) => {
                if ret.contains_key(&dst_ipv4.into()) {
                    ret.get_mut(&dst_ipv4.into())
                        .unwrap()
                        .results
                        .insert(dst_port, scan_rets);
                } else {
                    let mut v = TcpUdpScanResults::new(dst_ipv4.into());
                    v.results.insert(dst_port, scan_rets);
                    ret.insert(dst_ipv4.into(), v);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(ret)
}

pub fn scan(
    target: Target,
    method: ScanMethod,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    protocol: Option<IpNextHeaderProtocol>,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<(
    HashMap<IpAddr, TcpUdpScanResults>,
    HashMap<IpAddr, IpScanResults>,
)> {
    match interface {
        Some(interface) => scan_with_interface(
            target,
            method,
            src_ipv4,
            src_port,
            zombie_ipv4,
            zombie_port,
            protocol,
            interface,
            threads_num,
            print_result,
            timeout,
            max_loop,
        ),
        None => scan_no_interface(
            target,
            method,
            src_ipv4,
            src_port,
            zombie_ipv4,
            zombie_port,
            protocol,
            threads_num,
            print_result,
            timeout,
            max_loop,
        ),
    }
}

pub fn scan6(
    target: Target,
    method: ScanMethod6,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    match interface {
        Some(interface) => scan_with_interface6(
            target,
            method,
            src_ipv6,
            src_port,
            interface,
            threads_num,
            print_result,
            timeout,
            max_loop,
        ),
        None => scan_no_interface6(
            target,
            method,
            src_ipv6,
            src_port,
            threads_num,
            print_result,
            timeout,
            max_loop,
        ),
    }
}

pub fn tcp_connect_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Connect,
        src_ipv4,
        src_port,
        None,
        None,
        None,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )?;
    Ok(ret)
}

pub fn tcp_connect_scan6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    scan6(
        target,
        ScanMethod6::Connect,
        src_ipv6,
        src_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn tcp_syn_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Syn,
        src_ipv4,
        src_port,
        None,
        None,
        None,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )?;
    Ok(ret)
}

pub fn tcp_syn_scan6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    scan6(
        target,
        ScanMethod6::Syn,
        src_ipv6,
        src_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn tcp_fin_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Fin,
        src_ipv4,
        src_port,
        None,
        None,
        None,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )?;
    Ok(ret)
}

pub fn tcp_fin_scan6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    scan6(
        target,
        ScanMethod6::Fin,
        src_ipv6,
        src_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn tcp_ack_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Ack,
        src_ipv4,
        src_port,
        None,
        None,
        None,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )?;
    Ok(ret)
}

pub fn tcp_ack_scan6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    scan6(
        target,
        ScanMethod6::Ack,
        src_ipv6,
        src_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn tcp_null_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Null,
        src_ipv4,
        src_port,
        None,
        None,
        None,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )?;
    Ok(ret)
}

pub fn tcp_null_scan6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    scan6(
        target,
        ScanMethod6::Null,
        src_ipv6,
        src_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn tcp_xmas_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Xmas,
        src_ipv4,
        src_port,
        None,
        None,
        None,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )?;
    Ok(ret)
}

pub fn tcp_xmas_scan6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    scan6(
        target,
        ScanMethod6::Xmas,
        src_ipv6,
        src_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn tcp_window_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Window,
        src_ipv4,
        src_port,
        None,
        None,
        None,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )?;
    Ok(ret)
}

pub fn tcp_window_scan6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    scan6(
        target,
        ScanMethod6::Window,
        src_ipv6,
        src_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn tcp_maimon_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Maimon,
        src_ipv4,
        src_port,
        None,
        None,
        None,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )?;
    Ok(ret)
}

pub fn tcp_maimon_scan6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    scan6(
        target,
        ScanMethod6::Maimon,
        src_ipv6,
        src_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn tcp_idle_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Idle,
        src_ipv4,
        src_port,
        zombie_ipv4,
        zombie_port,
        None,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )?;
    Ok(ret)
}

pub fn udp_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Udp,
        src_ipv4,
        src_port,
        None,
        None,
        None,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )?;
    Ok(ret)
}

pub fn udp_scan6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    scan6(
        target,
        ScanMethod6::Udp,
        src_ipv6,
        src_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn ip_procotol_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    protocol: Option<IpNextHeaderProtocol>,
    interface: Option<&str>,
    print_result: bool,
    threads_num: usize,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, IpScanResults>> {
    let (_, ret) = scan(
        target,
        ScanMethod::IpProcotol,
        src_ipv4,
        src_port,
        None,
        None,
        protocol,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )?;
    Ok(ret)
}
