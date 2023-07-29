use anyhow::Result;
use pnet::datalink::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::mpsc::channel;
use subnetwork::Ipv4Pool;

use crate::utils;

pub mod arp;
pub mod tcp;

const CONNECT_SCAN: &str = "connect";
const SYN_SCAN: &str = "syn";
const FIN_SCAN: &str = "fin";

#[derive(Debug)]
pub struct HostInfo {
    pub host_ip: Ipv4Addr,
    pub host_mac: Option<MacAddr>,
}

#[derive(Debug)]
pub struct ArpScanResults {
    pub alive_hosts_num: usize,
    pub alive_hosts_vec: Vec<HostInfo>,
}

#[derive(Debug, Clone)]
pub struct TcpScanResults {
    pub alive_port_num: usize,
    pub alive_port_vec: Vec<u16>,
}

fn _arp_print_result(ip: Ipv4Addr, mac: Option<MacAddr>) {
    match mac {
        Some(mac) => println!("{ip} ({mac})"),
        _ => println!("{ip} (null)"),
    }
}

fn _tcp_print_result(ip: Ipv4Addr, port: u16, ret: bool) {
    match ret {
        true => println!("{ip} {port} OPEN"),
        _ => println!("{ip} {port} CLOSED"),
    }
}

pub fn run_arp_scan_subnet(
    subnet: Ipv4Pool,
    dst_mac: Option<&str>,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
) -> Result<ArpScanResults> {
    let (i, src_ip, src_mac) = utils::parse_interface(interface)?;
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

    for target_ip in subnet {
        recv_size += 1;
        let tx = tx.clone();
        let i = i.clone();
        pool.execute(move || {
            match arp::send_arp_scan_packet(&i, &dst_mac, src_ip, src_mac, target_ip) {
                Some(target_mac) => {
                    // println!("alive host {}, mac {}", &target_ip, &target_mac);
                    let host_info = HostInfo {
                        host_ip: target_ip,
                        host_mac: Some(target_mac),
                    };
                    if print_result {
                        _arp_print_result(target_ip, Some(target_mac));
                    }
                    tx.send(host_info)
                        .expect("channel will be there waiting for the pool");
                }
                _ => {
                    if print_result {
                        _arp_print_result(target_ip, None);
                    }
                    let host_info = HostInfo {
                        host_ip: target_ip,
                        host_mac: None,
                    };
                    match tx.send(host_info) {
                        _ => (),
                    }
                }
            }
        });
    }
    let iter = rx.into_iter().take(recv_size);
    let mut alive_hosts_info = Vec::new();
    let mut alive_hosts = 0;
    for host_info in iter {
        if host_info.host_mac.is_some() {
            alive_hosts_info.push(host_info);
            alive_hosts += 1;
        }
    }
    Ok(ArpScanResults {
        alive_hosts_num: alive_hosts,
        alive_hosts_vec: alive_hosts_info,
    })
}

fn _run_tcp_scan_single_port(
    scan_type: &str,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    interface: Option<&str>,
    print_result: bool,
    max_wait_time: Option<usize>,
) -> Result<bool> {
    let src_port: u16 = utils::random_port();
    let (_, src_ipv4, _) = utils::parse_interface(interface)?;
    let max_wait = utils::get_max_wait(max_wait_time);
    let scan_ret = match scan_type {
        CONNECT_SCAN => tcp::tcp_handshake(src_ipv4, dst_ipv4, src_port, dst_port, max_wait),
        SYN_SCAN => {
            match tcp::send_syn_scan_packet(src_ipv4, dst_ipv4, src_port, dst_port, max_wait) {
                Some(_) => true,
                _ => false,
            }
        }
        FIN_SCAN => {
            match tcp::send_fin_scan_packet(src_ipv4, dst_ipv4, src_port, dst_port, max_wait) {
                Some(_) => true,
                _ => false,
            }
        }
        _ => false,
    };

    if print_result {
        _tcp_print_result(dst_ipv4, dst_port, scan_ret);
    }
    if scan_ret {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn _run_tcp_scan_range_port(
    scan_type: &str,
    dst_ipv4: Ipv4Addr,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_wait_time: Option<usize>,
) -> Result<TcpScanResults> {
    let pool = utils::get_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut recv_size = 0;
    let src_port: u16 = utils::random_port();
    let (_, src_ipv4, _) = utils::parse_interface(interface)?;
    let max_wait = utils::get_max_wait(max_wait_time);

    for dst_port in start_port..=end_port {
        recv_size += 1;
        let tx = tx.clone();
        let scan_type = scan_type.to_string();
        pool.execute(move || {
            let scan_ret = match scan_type.as_str() {
                CONNECT_SCAN => {
                    tcp::tcp_handshake(src_ipv4, dst_ipv4, src_port, dst_port, max_wait)
                }
                SYN_SCAN => {
                    match tcp::send_syn_scan_packet(
                        src_ipv4, dst_ipv4, src_port, dst_port, max_wait,
                    ) {
                        Some(_) => true,
                        _ => false,
                    }
                }
                FIN_SCAN => {
                    match tcp::send_fin_scan_packet(
                        src_ipv4, dst_ipv4, src_port, dst_port, max_wait,
                    ) {
                        Some(_) => true,
                        _ => false,
                    }
                }
                _ => false,
            };
            if print_result {
                _tcp_print_result(dst_ipv4, dst_port, scan_ret);
            }
            match tx.send((dst_port, scan_ret)) {
                _ => (),
            }
        })
    }
    let iter = rx.into_iter().take(recv_size);
    let mut ret = TcpScanResults {
        alive_port_num: 0,
        alive_port_vec: vec![],
    };
    for (dst_port, dst_port_ret) in iter {
        if dst_port_ret {
            ret.alive_port_num += 1;
            ret.alive_port_vec.push(dst_port);
        }
    }

    Ok(ret)
}

fn _run_tcp_scan_subnet(
    scan_type: &str,
    subnet: Ipv4Pool,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_wait_time: Option<usize>,
) -> Result<HashMap<Ipv4Addr, TcpScanResults>> {
    // scan with arp first
    if print_result {
        println!("arp scan start...")
    }
    let arp_scan_result =
        match run_arp_scan_subnet(subnet, None, interface, threads_num, print_result) {
            Ok(r) => r,
            Err(e) => return Err(e.into()),
        };

    let (_, src_ipv4, _) = utils::parse_interface(interface)?;
    let pool = utils::get_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut recv_size = 0;
    let src_port = utils::random_port();
    let max_wait = utils::get_max_wait(max_wait_time);

    for host_info in arp_scan_result.alive_hosts_vec {
        let dst_ipv4 = host_info.host_ip;
        if dst_ipv4 != src_ipv4 {
            for dst_port in start_port..=end_port {
                recv_size += 1;
                let tx = tx.clone();
                let scan_type = scan_type.to_string();
                pool.execute(move || {
                    let scan_ret = match scan_type.as_str() {
                        CONNECT_SCAN => {
                            tcp::tcp_handshake(src_ipv4, dst_ipv4, src_port, dst_port, max_wait)
                        }
                        SYN_SCAN => {
                            match tcp::send_syn_scan_packet(
                                src_ipv4, dst_ipv4, src_port, dst_port, max_wait,
                            ) {
                                Some(_) => true,
                                _ => false,
                            }
                        }
                        FIN_SCAN => {
                            match tcp::send_fin_scan_packet(
                                src_ipv4, dst_ipv4, src_port, dst_port, max_wait,
                            ) {
                                Some(_) => true,
                                _ => false,
                            }
                        }
                        _ => false,
                    };
                    if print_result {
                        _tcp_print_result(dst_ipv4, dst_port, scan_ret);
                    }
                    match tx.send((dst_ipv4, dst_port, scan_ret)) {
                        _ => (),
                    }
                })
            }
        }
    }
    let iter = rx.into_iter().take(recv_size);
    let mut ret: HashMap<Ipv4Addr, TcpScanResults> = HashMap::new();

    for (dst_ipv4, dst_port, dst_port_ret) in iter {
        if dst_port_ret {
            if ret.contains_key(&dst_ipv4) {
                ret.get_mut(&dst_ipv4).unwrap().alive_port_num += 1;
                ret.get_mut(&dst_ipv4)
                    .unwrap()
                    .alive_port_vec
                    .push(dst_port);
            } else {
                ret.insert(
                    dst_ipv4,
                    TcpScanResults {
                        alive_port_num: 1,
                        alive_port_vec: vec![dst_port],
                    },
                );
            }
        }
    }
    Ok(ret)
}

pub fn run_tcp_connect_scan_single_port(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    interface: Option<&str>,
    print_result: bool,
    max_wait_time: Option<usize>,
) -> Result<bool> {
    _run_tcp_scan_single_port(
        CONNECT_SCAN,
        dst_ipv4,
        dst_port,
        interface,
        print_result,
        max_wait_time,
    )
}

pub fn run_tcp_connect_scan_range_port(
    dst_ipv4: Ipv4Addr,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_wait_time: Option<usize>,
) -> Result<TcpScanResults> {
    _run_tcp_scan_range_port(
        CONNECT_SCAN,
        dst_ipv4,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
        max_wait_time,
    )
}

pub fn run_tcp_connect_scan_subnet(
    subnet: Ipv4Pool,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_wait_time: Option<usize>,
) -> Result<HashMap<Ipv4Addr, TcpScanResults>> {
    _run_tcp_scan_subnet(
        CONNECT_SCAN,
        subnet,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
        max_wait_time,
    )
}

pub fn run_tcp_syn_scan_single_port(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    interface: Option<&str>,
    print_result: bool,
    max_wait_time: Option<usize>,
) -> Result<bool> {
    _run_tcp_scan_single_port(
        SYN_SCAN,
        dst_ipv4,
        dst_port,
        interface,
        print_result,
        max_wait_time,
    )
}

pub fn run_tcp_syn_scan_range_port(
    dst_ipv4: Ipv4Addr,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_wait_time: Option<usize>,
) -> Result<TcpScanResults> {
    _run_tcp_scan_range_port(
        SYN_SCAN,
        dst_ipv4,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
        max_wait_time,
    )
}

pub fn run_tcp_syn_scan_subnet(
    subnet: Ipv4Pool,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_wait_time: Option<usize>,
) -> Result<HashMap<Ipv4Addr, TcpScanResults>> {
    _run_tcp_scan_subnet(
        SYN_SCAN,
        subnet,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
        max_wait_time,
    )
}

pub fn run_tcp_fin_scan_single_port(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    interface: Option<&str>,
    print_result: bool,
    max_wait_time: Option<usize>,
) -> Result<bool> {
    _run_tcp_scan_single_port(
        FIN_SCAN,
        dst_ipv4,
        dst_port,
        interface,
        print_result,
        max_wait_time,
    )
}

pub fn run_tcp_fin_scan_range_port(
    dst_ipv4: Ipv4Addr,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_wait_time: Option<usize>,
) -> Result<TcpScanResults> {
    _run_tcp_scan_range_port(
        FIN_SCAN,
        dst_ipv4,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
        max_wait_time,
    )
}

pub fn run_tcp_fin_scan_subnet(
    subnet: Ipv4Pool,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_wait_time: Option<usize>,
) -> Result<HashMap<Ipv4Addr, TcpScanResults>> {
    _run_tcp_scan_subnet(
        FIN_SCAN,
        subnet,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
        max_wait_time,
    )
}
