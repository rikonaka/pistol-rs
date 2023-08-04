use anyhow::Result;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use subnetwork::Ipv4Pool;

pub mod icmp;

use crate::scan;
use crate::utils;
use crate::PingResults;
use crate::PingStatus;
use crate::TcpScanStatus;
use crate::UdpScanStatus;

const SYN_PING_DEFAULT_PORT: u16 = 80;
const ACK_PING_DEFAULT_PORT: u16 = 80;
const UDP_PING_DEFAULT_PORT: u16 = 125;
const ICMP_BUFF_SIZE: usize = 4096;
const IPV4_HEADER_LEN: usize = 20;
const ICMP_HEADER_LEN: usize = 8;
const ICMP_DATA_LEN: usize = 0;

enum TcpPingMethods {
    Syn,
    Ack,
    Udp,
    Icmp,
}

fn _print_icmp_result(addr: Ipv4Addr, status: PingStatus) {
    let str = match status {
        PingStatus::Up => format!("{addr} up"),
        PingStatus::Down => format!("{addr} down"),
    };
    println!("{str}");
}

fn _run_icmp_ping_host(
    src_ipv4: Option<Ipv4Addr>,
    dst_ipv4: Ipv4Addr,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<PingStatus> {
    let src_ipv4 = if src_ipv4.is_none() {
        let (_, src_ipv4, _) = utils::parse_interface(interface)?;
        src_ipv4
    } else {
        src_ipv4.unwrap()
    };

    let max_loop = utils::get_max_loop(max_loop);
    let timeout = utils::get_timeout(timeout);
    let status = icmp::send_icmp_ping_packet(src_ipv4, dst_ipv4, timeout, max_loop)?;
    if print_result {
        _print_icmp_result(dst_ipv4, status);
    }
    Ok(status)
}

fn _run_icmp_ping_subnet(
    src_ipv4: Option<Ipv4Addr>,
    subnet: Ipv4Pool,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, PingResults>> {
    let src_ipv4 = if src_ipv4.is_none() {
        let (_, src_ipv4, _) = utils::parse_interface(interface)?;
        src_ipv4
    } else {
        src_ipv4.unwrap()
    };

    let max_loop = utils::get_max_loop(max_loop);
    let timeout = utils::get_timeout(timeout);

    let mut hm = HashMap::new();
    for dst_ipv4 in subnet {
        let status = icmp::send_icmp_ping_packet(src_ipv4, dst_ipv4, timeout, max_loop)?;
        let results = PingResults {
            addr: dst_ipv4,
            status,
        };
        if print_result {
            _print_icmp_result(dst_ipv4, status);
        }
        hm.insert(dst_ipv4, results);
    }
    Ok(hm)
}

fn _run_tcp_ping_host(
    method: TcpPingMethods,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<PingResults> {
    let ping_status = match method {
        TcpPingMethods::Syn => {
            let dst_port = if dst_port.is_none() {
                SYN_PING_DEFAULT_PORT
            } else {
                dst_port.unwrap()
            };
            let scan_ret = scan::run_tcp_syn_scan_single_port(
                src_ipv4,
                src_port,
                dst_ipv4,
                dst_port,
                interface,
                print_result,
                timeout,
                max_loop,
            )?;
            match scan_ret.results.get(&dst_port).unwrap() {
                TcpScanStatus::Open => PingStatus::Up,
                _ => PingStatus::Down,
            }
        }
        TcpPingMethods::Ack => {
            let dst_port = if dst_port.is_none() {
                ACK_PING_DEFAULT_PORT
            } else {
                dst_port.unwrap()
            };
            let scan_ret = scan::run_tcp_ack_scan_single_port(
                src_ipv4,
                src_port,
                dst_ipv4,
                dst_port,
                interface,
                print_result,
                timeout,
                max_loop,
            )?;
            match scan_ret.results.get(&dst_port).unwrap() {
                TcpScanStatus::Unfiltered => PingStatus::Up,
                _ => PingStatus::Down,
            }
        }
        TcpPingMethods::Udp => {
            let dst_port = if dst_port.is_none() {
                UDP_PING_DEFAULT_PORT
            } else {
                dst_port.unwrap()
            };
            let scan_ret = scan::run_udp_scan_single_port(
                src_ipv4,
                src_port,
                dst_ipv4,
                dst_port,
                interface,
                print_result,
                timeout,
                max_loop,
            )?;
            match scan_ret.results.get(&dst_port).unwrap() {
                UdpScanStatus::Open => PingStatus::Up,
                UdpScanStatus::OpenOrFiltered => PingStatus::Up,
                _ => PingStatus::Down,
            }
        }
        TcpPingMethods::Icmp => _run_icmp_ping_host(
            src_ipv4,
            dst_ipv4,
            interface,
            print_result,
            timeout,
            max_loop,
        )?,
    };
    Ok(PingResults {
        addr: dst_ipv4,
        status: ping_status,
    })
}

fn _run_tcp_ping_subnet(
    method: TcpPingMethods,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    subnet: Ipv4Pool,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, PingResults>> {
    let ret = match method {
        TcpPingMethods::Syn => {
            let dst_port = if dst_port.is_none() {
                SYN_PING_DEFAULT_PORT
            } else {
                dst_port.unwrap()
            };
            let start_port = dst_port;
            let end_port = dst_port;
            let scan_ret = scan::run_tcp_syn_scan_subnet(
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
            )?;
            let mut hm = HashMap::new();
            for k in scan_ret.keys() {
                let v = scan_ret.get(k).unwrap();
                let ping_status = match v.results.get(&dst_port).unwrap() {
                    TcpScanStatus::Open => PingStatus::Up,
                    _ => PingStatus::Down,
                };
                hm.insert(
                    k.clone(),
                    PingResults {
                        addr: k.clone(),
                        status: ping_status,
                    },
                );
            }
            hm
        }
        TcpPingMethods::Ack => {
            let dst_port = if dst_port.is_none() {
                ACK_PING_DEFAULT_PORT
            } else {
                dst_port.unwrap()
            };
            let start_port = dst_port;
            let end_port = dst_port;
            let scan_ret = scan::run_tcp_ack_scan_subnet(
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
            )?;
            let mut hm = HashMap::new();
            for k in scan_ret.keys() {
                let v = scan_ret.get(k).unwrap();
                let ping_status = match v.results.get(&dst_port).unwrap() {
                    TcpScanStatus::Open => PingStatus::Up,
                    _ => PingStatus::Down,
                };
                hm.insert(
                    k.clone(),
                    PingResults {
                        addr: k.clone(),
                        status: ping_status,
                    },
                );
            }
            hm
        }
        TcpPingMethods::Udp => {
            let dst_port = if dst_port.is_none() {
                UDP_PING_DEFAULT_PORT
            } else {
                dst_port.unwrap()
            };
            let start_port = dst_port;
            let end_port = dst_port;
            let scan_ret = scan::run_udp_scan_subnet(
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
            )?;
            let mut hm = HashMap::new();
            for k in scan_ret.keys() {
                let v = scan_ret.get(k).unwrap();
                let ping_status = match v.results.get(&dst_port).unwrap() {
                    UdpScanStatus::Open => PingStatus::Up,
                    _ => PingStatus::Down,
                };
                hm.insert(
                    k.clone(),
                    PingResults {
                        addr: k.clone(),
                        status: ping_status,
                    },
                );
            }
            hm
        }
        TcpPingMethods::Icmp => {
            _run_icmp_ping_subnet(src_ipv4, subnet, interface, print_result, timeout, max_loop)?
        }
    };
    Ok(ret)
}

pub fn run_tcp_syn_ping_host(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<PingResults> {
    _run_tcp_ping_host(
        TcpPingMethods::Syn,
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

pub fn run_tcp_syn_ping_subnet(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    subnet: Ipv4Pool,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, PingResults>> {
    _run_tcp_ping_subnet(
        TcpPingMethods::Syn,
        src_ipv4,
        src_port,
        dst_port,
        subnet,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_tcp_ack_ping_host(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<PingResults> {
    _run_tcp_ping_host(
        TcpPingMethods::Ack,
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

pub fn run_tcp_ack_ping_subnet(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    subnet: Ipv4Pool,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, PingResults>> {
    _run_tcp_ping_subnet(
        TcpPingMethods::Ack,
        src_ipv4,
        src_port,
        dst_port,
        subnet,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_udp_ping_host(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<PingResults> {
    _run_tcp_ping_host(
        TcpPingMethods::Udp,
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

pub fn run_udp_ping_subnet(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    subnet: Ipv4Pool,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, PingResults>> {
    _run_tcp_ping_subnet(
        TcpPingMethods::Udp,
        src_ipv4,
        src_port,
        dst_port,
        subnet,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn run_icmp_ping_host(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<PingResults> {
    _run_tcp_ping_host(
        TcpPingMethods::Icmp,
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

pub fn run_icmp_ping_subnet(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    subnet: Ipv4Pool,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, PingResults>> {
    _run_tcp_ping_subnet(
        TcpPingMethods::Icmp,
        src_ipv4,
        src_port,
        dst_port,
        subnet,
        interface,
        threads_num,
        print_result,
        timeout,
        max_loop,
    )
}
