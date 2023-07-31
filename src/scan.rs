use anyhow::Result;
use pnet::datalink::MacAddr;
use std::collections::HashMap;
use std::error::Error;
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

const CONNECT_SCAN: &str = "connect";
const SYN_SCAN: &str = "syn";
const FIN_SCAN: &str = "fin";
const ACK_SCAN: &str = "ack";

/* NoSuchMethodError*/
#[derive(Debug, Clone)]
pub struct NoSuchMethodError {
    method: String,
}

impl fmt::Display for NoSuchMethodError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "can not found interface {}", self.method)
    }
}

impl NoSuchMethodError {
    pub fn new(method: &str) -> NoSuchMethodError {
        let method = method.to_string();
        NoSuchMethodError { method }
    }
}

impl Error for NoSuchMethodError {}

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
    method: &str,
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
        CONNECT_SCAN => {
            match tcp::tcp_handshake(src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop) {
                Ok(t) => t,
                Err(e) => return Err(e.into()),
            }
        }
        SYN_SCAN => {
            match tcp::send_syn_scan_packet(
                src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
            ) {
                Ok(t) => t,
                Err(e) => return Err(e.into()),
            }
        }
        FIN_SCAN => {
            match tcp::send_fin_scan_packet(
                src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
            ) {
                Ok(t) => t,
                Err(e) => return Err(e.into()),
            }
        }
        ACK_SCAN => {
            match tcp::send_ack_scan_packet(
                src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
            ) {
                Ok(t) => t,
                Err(e) => return Err(e.into()),
            }
        }
        _ => return Err(NoSuchMethodError::new(method).into()),
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
    method: &str,
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
        let method = method.to_string();
        pool.execute(move || {
            let scan_ret_with_error = match method.as_str() {
                CONNECT_SCAN => {
                    tcp::tcp_handshake(src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop)
                }
                SYN_SCAN => tcp::send_syn_scan_packet(
                    src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                ),
                FIN_SCAN => tcp::send_fin_scan_packet(
                    src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                ),
                ACK_SCAN => tcp::send_ack_scan_packet(
                    src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                ),
                _ => Err(NoSuchMethodError::new(&method).into()),
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
    pool.join();
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
    method: &str,
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
                let method = method.to_string();
                pool.execute(move || {
                    let scan_ret_with_error = match method.as_str() {
                        CONNECT_SCAN => tcp::tcp_handshake(
                            src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                        ),
                        SYN_SCAN => tcp::send_syn_scan_packet(
                            src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                        ),
                        FIN_SCAN => tcp::send_fin_scan_packet(
                            src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                        ),
                        ACK_SCAN => tcp::send_ack_scan_packet(
                            src_ipv4, dst_ipv4, src_port, dst_port, timeout, max_loop,
                        ),
                        _ => Err(NoSuchMethodError::new(&method).into()),
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
        CONNECT_SCAN,
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
        CONNECT_SCAN,
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
        CONNECT_SCAN,
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
        SYN_SCAN,
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
        SYN_SCAN,
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
        SYN_SCAN,
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
        FIN_SCAN,
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
        FIN_SCAN,
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
        FIN_SCAN,
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
        ACK_SCAN,
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
        ACK_SCAN,
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
        ACK_SCAN,
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
