use anyhow::Result;
use pnet::datalink::MacAddr;
use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::mpsc::channel;
use std::time::Duration;
use subnetwork::Ipv4Pool;

use crate::utils;

pub mod arp;
pub mod tcp;
pub mod udp;

use tcp::TcpScanStatus;
use udp::UdpScanStatus;

#[derive(Debug, Clone, Copy)]
enum TcpScanMethod {
    Connect,
    Syn,
    Fin,
    Ack,
    Null,
    Xmas,
}

#[derive(Debug, Clone)]
pub struct ArpScanResults {
    pub alive_hosts_num: usize,
    pub alive_hosts: HashMap<Ipv4Addr, Option<MacAddr>>,
}

#[derive(Debug, Clone)]
pub struct TcpScanResults {
    addr: Ipv4Addr,
    // port: TcpScanStatus
    results: HashMap<u16, TcpScanStatus>,
}

impl TcpScanResults {
    pub fn new(addr: Ipv4Addr) -> TcpScanResults {
        let results = HashMap::new();
        TcpScanResults { addr, results }
    }
}

impl fmt::Display for TcpScanResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ip = self.addr;
        let mut result_str = String::new();
        for port in self.results.keys() {
            let str = match self.results.get(port).unwrap() {
                TcpScanStatus::Open => format!("{ip} {port} open"),
                TcpScanStatus::OpenOrFiltered => format!("{ip} {port} open|filtered"),
                TcpScanStatus::Filtered => format!("{ip} {port} filtered"),
                TcpScanStatus::Unfiltered => format!("{ip} {port} unfiltered"),
                TcpScanStatus::Closed => format!("{ip} {port} closed"),
            };
            result_str += &str;
            result_str += "\n";
        }
        write!(f, "can not found interface {}", result_str)
    }
}

#[derive(Debug, Clone)]
pub struct UdpScanResults {
    addr: Ipv4Addr,
    // port: TcpScanStatus
    results: HashMap<u16, UdpScanStatus>,
}

impl UdpScanResults {
    pub fn new(addr: Ipv4Addr) -> UdpScanResults {
        let results = HashMap::new();
        UdpScanResults { addr, results }
    }
}

impl fmt::Display for UdpScanResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ip = self.addr;
        let mut result_str = String::new();
        for port in self.results.keys() {
            let str = match self.results.get(port).unwrap() {
                UdpScanStatus::Open => format!("{ip} {port} open"),
                UdpScanStatus::OpenOrFiltered => format!("{ip} {port} open|filtered"),
                UdpScanStatus::Filtered => format!("{ip} {port} filtered"),
                UdpScanStatus::Closed => format!("{ip} {port} closed"),
            };
            result_str += &str;
            result_str += "\n";
        }
        write!(f, "can not found interface {}", result_str)
    }
}

fn _arp_print_result(ip: Ipv4Addr, mac: Option<MacAddr>) {
    match mac {
        Some(mac) => println!("{ip} ({mac})"),
        _ => println!("{ip} (null)"),
    }
}

fn _tcp_print_result(ip: Ipv4Addr, port: u16, ret: TcpScanStatus) {
    match ret {
        TcpScanStatus::Open => println!("{ip} {port} open"),
        TcpScanStatus::OpenOrFiltered => println!("{ip} {port} open|filtered"),
        TcpScanStatus::Filtered => println!("{ip} {port} filtered"),
        TcpScanStatus::Unfiltered => println!("{ip} {port} unfiltered"),
        TcpScanStatus::Closed => println!("{ip} {port} closed"),
    }
}

fn _udp_print_result(ip: Ipv4Addr, port: u16, ret: UdpScanStatus) {
    match ret {
        UdpScanStatus::Open => println!("{ip} {port} open"),
        UdpScanStatus::OpenOrFiltered => println!("{ip} {port} open|filtered"),
        UdpScanStatus::Filtered => println!("{ip} {port} filtered"),
        UdpScanStatus::Closed => println!("{ip} {port} closed"),
    }
}

pub fn run_arp_scan_subnet(
    subnet: Ipv4Pool,
    dst_mac: Option<&str>,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
) -> Result<ArpScanResults> {
    let (i, src_ip, src_mac, dst_mac) = if interface.is_some() {
        let (i, src_ip, src_mac) = utils::parse_interface(interface)?;
        let dst_mac = match dst_mac {
            Some(v) => match MacAddr::from_str(v) {
                Ok(m) => m,
                Err(e) => return Err(e.into()),
            },
            _ => MacAddr::broadcast(),
        };
        (i, src_ip, src_mac, dst_mac)
    } else {
        let (i, src_ip, src_mac) = utils::parse_interface_by_subnet(subnet)?;
        let dst_mac = match dst_mac {
            Some(v) => match MacAddr::from_str(v) {
                Ok(m) => m,
                Err(e) => return Err(e.into()),
            },
            _ => MacAddr::broadcast(),
        };
        (i, src_ip, src_mac, dst_mac)
    };

    let (tx, rx) = channel();
    let pool = utils::get_threads_pool(threads_num);
    let mut recv_size = 0;

    for target_ip in subnet {
        recv_size += 1;
        let tx = tx.clone();
        let i = i.clone();
        pool.execute(move || {
            let scan_ret = arp::send_arp_scan_packet(&i, &dst_mac, src_ip, src_mac, target_ip);
            if print_result {
                _arp_print_result(target_ip, scan_ret)
            }
            match tx.send((target_ip, scan_ret)) {
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
        if target_mac.is_some() {
            ret.alive_hosts_num += 1;
        }
        ret.alive_hosts.insert(target_ipv4, target_mac);
    }
    Ok(ret)
}

fn _run_tcp_scan_single_port(
    method: TcpScanMethod,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<TcpScanResults> {
    let src_ipv4 = if src_ipv4.is_none() {
        let (_, src_ipv4, _) = utils::parse_interface(interface)?;
        src_ipv4
    } else {
        src_ipv4.unwrap()
    };
    let src_port = if src_port.is_none() {
        let src_port: u16 = utils::random_port();
        src_port
    } else {
        src_port.unwrap()
    };

    let max_loop = utils::get_max_loop(max_loop);
    let timeout = utils::get_timeout(timeout);
    let scan_ret = match method {
        TcpScanMethod::Connect => {
            match tcp::send_connect_scan_packet(
                src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
            ) {
                Ok(t) => t,
                Err(e) => return Err(e.into()),
            }
        }
        TcpScanMethod::Syn => {
            match tcp::send_syn_scan_packet(
                src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
            ) {
                Ok(t) => t,
                Err(e) => return Err(e.into()),
            }
        }
        TcpScanMethod::Fin => {
            match tcp::send_fin_scan_packet(
                src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
            ) {
                Ok(t) => t,
                Err(e) => return Err(e.into()),
            }
        }
        TcpScanMethod::Ack => {
            match tcp::send_ack_scan_packet(
                src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
            ) {
                Ok(t) => t,
                Err(e) => return Err(e.into()),
            }
        }
        TcpScanMethod::Null => {
            match tcp::send_null_scan_packet(
                src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
            ) {
                Ok(t) => t,
                Err(e) => return Err(e.into()),
            }
        }
        TcpScanMethod::Xmas => {
            match tcp::send_xmas_scan_packet(
                src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
            ) {
                Ok(t) => t,
                Err(e) => return Err(e.into()),
            }
        }
    };

    if print_result {
        _tcp_print_result(dst_ipv4, dst_port, scan_ret);
    }
    let mut results = HashMap::new();
    results.insert(dst_port, scan_ret);
    Ok(TcpScanResults {
        results,
        addr: dst_ipv4,
    })
}

fn _run_tcp_scan_range_port(
    method: TcpScanMethod,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<TcpScanResults> {
    let src_ipv4 = if src_ipv4.is_none() {
        let (_, src_ipv4, _) = utils::parse_interface(interface)?;
        src_ipv4
    } else {
        src_ipv4.unwrap()
    };
    let src_port = if src_port.is_none() {
        let src_port: u16 = utils::random_port();
        src_port
    } else {
        src_port.unwrap()
    };

    let pool = utils::get_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut recv_size = 0;
    let max_loop = utils::get_max_loop(max_loop);
    let timeout = utils::get_timeout(timeout);

    for dst_port in start_port..=end_port {
        recv_size += 1;
        let tx = tx.clone();
        pool.execute(move || {
            let scan_ret_with_error = match method {
                TcpScanMethod::Connect => tcp::send_connect_scan_packet(
                    src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                ),
                TcpScanMethod::Syn => tcp::send_syn_scan_packet(
                    src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                ),
                TcpScanMethod::Fin => tcp::send_fin_scan_packet(
                    src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                ),
                TcpScanMethod::Ack => tcp::send_ack_scan_packet(
                    src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                ),
                TcpScanMethod::Null => tcp::send_null_scan_packet(
                    src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                ),
                TcpScanMethod::Xmas => tcp::send_xmas_scan_packet(
                    src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                ),
            };
            if print_result {
                match scan_ret_with_error {
                    Ok(s) => _tcp_print_result(dst_ipv4, dst_port, s),
                    _ => (),
                }
            }
            match tx.send((dst_port, scan_ret_with_error)) {
                _ => (),
            }
        })
    }
    let iter = rx.into_iter().take(recv_size);
    let mut ret = TcpScanResults::new(dst_ipv4);

    for (dst_port, dst_port_ret) in iter {
        match dst_port_ret {
            Ok(s) => ret.results.insert(dst_port, s),
            Err(e) => return Err(e),
        };
    }
    Ok(ret)
}

fn _run_tcp_scan_subnet(
    method: TcpScanMethod,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    subnet: Ipv4Pool,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, TcpScanResults>> {
    let src_ipv4 = if src_ipv4.is_none() {
        let (_, src_ipv4, _) = utils::parse_interface(interface)?;
        src_ipv4
    } else {
        src_ipv4.unwrap()
    };
    let src_port = if src_port.is_none() {
        let src_port: u16 = utils::random_port();
        src_port
    } else {
        src_port.unwrap()
    };

    let pool = utils::get_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut recv_size = 0;
    let max_loop = utils::get_max_loop(max_loop);
    let timeout = utils::get_timeout(timeout);

    for dst_ipv4 in subnet {
        if dst_ipv4 != src_ipv4 {
            for dst_port in start_port..=end_port {
                recv_size += 1;
                let tx = tx.clone();
                pool.execute(move || {
                    let scan_ret_with_error = match method {
                        TcpScanMethod::Connect => tcp::send_connect_scan_packet(
                            src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                        ),
                        TcpScanMethod::Syn => tcp::send_syn_scan_packet(
                            src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                        ),
                        TcpScanMethod::Fin => tcp::send_fin_scan_packet(
                            src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                        ),
                        TcpScanMethod::Ack => tcp::send_ack_scan_packet(
                            src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                        ),
                        TcpScanMethod::Null => tcp::send_null_scan_packet(
                            src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                        ),
                        TcpScanMethod::Xmas => tcp::send_xmas_scan_packet(
                            src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                        ),
                    };
                    if print_result {
                        match scan_ret_with_error {
                            Ok(s) => _tcp_print_result(dst_ipv4, dst_port, s),
                            _ => (),
                        }
                    }
                    match tx.send((dst_ipv4, dst_port, scan_ret_with_error)) {
                        _ => (),
                    }
                })
            }
        }
    }
    let iter = rx.into_iter().take(recv_size);
    let mut ret: HashMap<Ipv4Addr, TcpScanResults> = HashMap::new();

    for (dst_ipv4, dst_port, dst_port_ret) in iter {
        match dst_port_ret {
            Ok(s) => {
                if ret.contains_key(&dst_ipv4) {
                    ret.get_mut(&dst_ipv4).unwrap().results.insert(dst_port, s);
                } else {
                    let mut v = TcpScanResults::new(dst_ipv4);
                    v.results.insert(dst_port, s);
                    ret.insert(dst_ipv4, v);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(ret)
}

pub fn run_tcp_connect_scan_single_port(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<TcpScanResults> {
    _run_tcp_scan_single_port(
        TcpScanMethod::Connect,
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_port,
        interface,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_tcp_connect_scan_range_port(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<TcpScanResults> {
    _run_tcp_scan_range_port(
        TcpScanMethod::Connect,
        src_ipv4,
        src_port,
        dst_ipv4,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_tcp_connect_scan_subnet(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    subnet: Ipv4Pool,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, TcpScanResults>> {
    _run_tcp_scan_subnet(
        TcpScanMethod::Connect,
        src_ipv4,
        src_port,
        subnet,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_tcp_syn_scan_single_port(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<TcpScanResults> {
    _run_tcp_scan_single_port(
        TcpScanMethod::Syn,
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_port,
        interface,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_tcp_syn_scan_range_port(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<TcpScanResults> {
    _run_tcp_scan_range_port(
        TcpScanMethod::Syn,
        src_ipv4,
        src_port,
        dst_ipv4,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_tcp_syn_scan_subnet(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    subnet: Ipv4Pool,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, TcpScanResults>> {
    _run_tcp_scan_subnet(
        TcpScanMethod::Syn,
        src_ipv4,
        src_port,
        subnet,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_tcp_fin_scan_single_port(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<TcpScanResults> {
    _run_tcp_scan_single_port(
        TcpScanMethod::Fin,
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_port,
        interface,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_tcp_fin_scan_range_port(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<TcpScanResults> {
    _run_tcp_scan_range_port(
        TcpScanMethod::Fin,
        src_ipv4,
        src_port,
        dst_ipv4,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_tcp_fin_scan_subnet(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    subnet: Ipv4Pool,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, TcpScanResults>> {
    _run_tcp_scan_subnet(
        TcpScanMethod::Fin,
        src_ipv4,
        src_port,
        subnet,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_tcp_ack_scan_single_port(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<TcpScanResults> {
    _run_tcp_scan_single_port(
        TcpScanMethod::Ack,
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_port,
        interface,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_tcp_ack_scan_range_port(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<TcpScanResults> {
    _run_tcp_scan_range_port(
        TcpScanMethod::Ack,
        src_ipv4,
        src_port,
        dst_ipv4,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_tcp_ack_scan_subnet(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    subnet: Ipv4Pool,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, TcpScanResults>> {
    _run_tcp_scan_subnet(
        TcpScanMethod::Ack,
        src_ipv4,
        src_port,
        subnet,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_tcp_null_scan_single_port(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<TcpScanResults> {
    _run_tcp_scan_single_port(
        TcpScanMethod::Null,
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_port,
        interface,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_tcp_null_scan_range_port(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<TcpScanResults> {
    _run_tcp_scan_range_port(
        TcpScanMethod::Null,
        src_ipv4,
        src_port,
        dst_ipv4,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_tcp_null_scan_subnet(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    subnet: Ipv4Pool,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, TcpScanResults>> {
    _run_tcp_scan_subnet(
        TcpScanMethod::Null,
        src_ipv4,
        src_port,
        subnet,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_tcp_xmas_scan_single_port(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<TcpScanResults> {
    _run_tcp_scan_single_port(
        TcpScanMethod::Xmas,
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_port,
        interface,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_tcp_xmas_scan_range_port(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<TcpScanResults> {
    _run_tcp_scan_range_port(
        TcpScanMethod::Xmas,
        src_ipv4,
        src_port,
        dst_ipv4,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_tcp_xmas_scan_subnet(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    subnet: Ipv4Pool,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, TcpScanResults>> {
    _run_tcp_scan_subnet(
        TcpScanMethod::Xmas,
        src_ipv4,
        src_port,
        subnet,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_udp_scan_single_port(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<UdpScanResults> {
    let src_ipv4 = if src_ipv4.is_none() {
        let (_, src_ipv4, _) = utils::parse_interface(interface)?;
        src_ipv4
    } else {
        src_ipv4.unwrap()
    };
    let src_port = if src_port.is_none() {
        let src_port: u16 = utils::random_port();
        src_port
    } else {
        src_port.unwrap()
    };

    let max_loop = utils::get_max_loop(max_loop);
    let timeout = utils::get_timeout(timeout);
    let scan_ret = match udp::send_udp_scan_packet(
        src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
    ) {
        Ok(s) => s,
        Err(e) => return Err(e.into()),
    };

    if print_result {
        _udp_print_result(dst_ipv4, dst_port, scan_ret);
    }
    let mut results = HashMap::new();
    results.insert(dst_port, scan_ret);
    Ok(UdpScanResults {
        results,
        addr: dst_ipv4,
    })
}

pub fn run_udp_scan_range_port(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<UdpScanResults> {
    let src_ipv4 = if src_ipv4.is_none() {
        let (_, src_ipv4, _) = utils::parse_interface(interface)?;
        src_ipv4
    } else {
        src_ipv4.unwrap()
    };
    let src_port = if src_port.is_none() {
        let src_port: u16 = utils::random_port();
        src_port
    } else {
        src_port.unwrap()
    };

    let pool = utils::get_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut recv_size = 0;
    let max_loop = utils::get_max_loop(max_loop);
    let timeout = utils::get_timeout(timeout);

    for dst_port in start_port..=end_port {
        recv_size += 1;
        let tx = tx.clone();
        pool.execute(move || {
            let scan_ret_with_error = udp::send_udp_scan_packet(
                src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
            );
            if print_result {
                match scan_ret_with_error {
                    Ok(s) => _udp_print_result(dst_ipv4, dst_port, s),
                    _ => (),
                }
            }
            match tx.send((dst_port, scan_ret_with_error)) {
                _ => (),
            }
        })
    }
    let iter = rx.into_iter().take(recv_size);
    let mut ret = UdpScanResults::new(dst_ipv4);

    for (dst_port, dst_port_ret) in iter {
        match dst_port_ret {
            Ok(s) => ret.results.insert(dst_port, s),
            Err(e) => return Err(e),
        };
    }
    Ok(ret)
}

pub fn run_udp_scan_subnet(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    subnet: Ipv4Pool,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, UdpScanResults>> {
    let src_ipv4 = if src_ipv4.is_none() {
        let (_, src_ipv4, _) = utils::parse_interface(interface)?;
        src_ipv4
    } else {
        src_ipv4.unwrap()
    };
    let src_port = if src_port.is_none() {
        let src_port: u16 = utils::random_port();
        src_port
    } else {
        src_port.unwrap()
    };

    let pool = utils::get_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut recv_size = 0;
    let max_loop = utils::get_max_loop(max_loop);
    let timeout = utils::get_timeout(timeout);

    for dst_ipv4 in subnet {
        if dst_ipv4 != src_ipv4 {
            for dst_port in start_port..=end_port {
                recv_size += 1;
                let tx = tx.clone();
                pool.execute(move || {
                    let scan_ret_with_error = udp::send_udp_scan_packet(
                        src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                    );
                    if print_result {
                        match scan_ret_with_error {
                            Ok(s) => _udp_print_result(dst_ipv4, dst_port, s),
                            _ => (),
                        }
                    }
                    match tx.send((dst_ipv4, dst_port, scan_ret_with_error)) {
                        _ => (),
                    }
                })
            }
        }
    }
    let iter = rx.into_iter().take(recv_size);
    let mut ret: HashMap<Ipv4Addr, UdpScanResults> = HashMap::new();

    for (dst_ipv4, dst_port, dst_port_ret) in iter {
        match dst_port_ret {
            Ok(s) => {
                if ret.contains_key(&dst_ipv4) {
                    ret.get_mut(&dst_ipv4).unwrap().results.insert(dst_port, s);
                } else {
                    let mut v = UdpScanResults::new(dst_ipv4);
                    v.results.insert(dst_port, s);
                    ret.insert(dst_ipv4, v);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(ret)
}
