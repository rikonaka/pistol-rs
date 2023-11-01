use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use subnetwork::{Ipv4Pool, Ipv6Pool};

pub mod icmp;
pub mod icmp6;

use crate::utils;
use crate::PingResults;
use crate::PingStatus;
use crate::TargetScanStatus;
use crate::{scan, Target};

const SYN_PING_DEFAULT_PORT: u16 = 80;
const ACK_PING_DEFAULT_PORT: u16 = 80;
const UDP_PING_DEFAULT_PORT: u16 = 125;

enum TcpPingMethods {
    Syn,
    Ack,
    Udp,
    Icmp,
}

fn _print_icmp_result(addr: IpAddr, status: PingStatus) {
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
        let (_, src_ipv4, _) = utils::parse_interface_from_str(interface.unwrap())?;
        src_ipv4
    } else {
        src_ipv4.unwrap()
    };

    let max_loop = utils::get_max_loop(max_loop);
    let timeout = utils::get_timeout(timeout);
    let status = icmp::send_icmp_ping_packet(src_ipv4, dst_ipv4, timeout, max_loop)?;
    if print_result {
        _print_icmp_result(dst_ipv4.into(), status);
    }
    Ok(status)
}

fn _run_icmp_ping_host6(
    src_ipv6: Option<Ipv6Addr>,
    dst_ipv6: Ipv6Addr,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<PingStatus> {
    let src_ipv6 = if src_ipv6.is_none() {
        let (_, src_ipv6, _) = utils::parse_interface_from_str6(interface.unwrap())?;
        src_ipv6
    } else {
        src_ipv6.unwrap()
    };

    let max_loop = utils::get_max_loop(max_loop);
    let timeout = utils::get_timeout(timeout);
    let status = icmp6::send_icmp_ping_packet(src_ipv6, dst_ipv6, timeout, max_loop)?;
    if print_result {
        _print_icmp_result(dst_ipv6.into(), status);
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
) -> Result<HashMap<IpAddr, PingResults>> {
    let src_ipv4 = if src_ipv4.is_none() {
        let (_, src_ipv4, _) = utils::parse_interface_from_str(interface.unwrap())?;
        src_ipv4
    } else {
        src_ipv4.unwrap()
    };

    let max_loop = utils::get_max_loop(max_loop);
    let timeout = utils::get_timeout(timeout);

    let mut hm: HashMap<IpAddr, PingResults> = HashMap::new();
    for dst_ipv4 in subnet {
        let status = icmp::send_icmp_ping_packet(src_ipv4, dst_ipv4, timeout, max_loop)?;
        let results = PingResults {
            addr: dst_ipv4.into(),
            status,
        };
        if print_result {
            _print_icmp_result(dst_ipv4.into(), status);
        }
        hm.insert(dst_ipv4.into(), results);
    }
    Ok(hm)
}

fn _run_icmp_ping_subnet6(
    src_ipv6: Option<Ipv6Addr>,
    subnet: Ipv6Pool,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, PingResults>> {
    let src_ipv6 = if src_ipv6.is_none() {
        let (_, src_ipv6, _) = utils::parse_interface_from_str6(interface.unwrap())?;
        src_ipv6
    } else {
        src_ipv6.unwrap()
    };

    let max_loop = utils::get_max_loop(max_loop);
    let timeout = utils::get_timeout(timeout);

    let mut hm: HashMap<IpAddr, PingResults> = HashMap::new();
    for dst_ipv4 in subnet {
        let status = icmp6::send_icmp_ping_packet(src_ipv6, dst_ipv4, timeout, max_loop)?;
        let results = PingResults {
            addr: dst_ipv4.into(),
            status,
        };
        if print_result {
            _print_icmp_result(dst_ipv4.into(), status);
        }
        hm.insert(dst_ipv4.into(), results);
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
            let target = Target::new_static_port(&vec![dst_ipv4], &vec![dst_port]);
            let ret = scan::tcp_syn_scan(
                target,
                src_ipv4,
                src_port,
                interface,
                print_result,
                8,
                timeout,
                max_loop,
            )?;
            let scan_rets = ret.get(&dst_ipv4.into()).unwrap();
            let status = scan_rets.results.get(&dst_port).unwrap();
            match status {
                TargetScanStatus::Open => PingStatus::Up,
                _ => PingStatus::Down,
            }
        }
        TcpPingMethods::Ack => {
            let dst_port = if dst_port.is_none() {
                ACK_PING_DEFAULT_PORT
            } else {
                dst_port.unwrap()
            };
            let target = Target::new_static_port(&vec![dst_ipv4], &vec![dst_port]);
            let ret = scan::tcp_ack_scan(
                target,
                src_ipv4,
                src_port,
                interface,
                print_result,
                8,
                timeout,
                max_loop,
            )?;
            let scan_rets = ret.get(&dst_ipv4.into()).unwrap();
            let status = scan_rets.results.get(&dst_port).unwrap();
            match status {
                TargetScanStatus::Unfiltered => PingStatus::Up,
                _ => PingStatus::Down,
            }
        }
        TcpPingMethods::Udp => {
            let dst_port = if dst_port.is_none() {
                UDP_PING_DEFAULT_PORT
            } else {
                dst_port.unwrap()
            };
            let target = Target::new_static_port(&vec![dst_ipv4], &vec![dst_port]);
            let ret = scan::udp_scan(
                target,
                src_ipv4,
                src_port,
                interface,
                print_result,
                8,
                timeout,
                max_loop,
            )?;
            let scan_rets = ret.get(&dst_ipv4.into()).unwrap();
            let status = scan_rets.results.get(&dst_port).unwrap();
            match status {
                TargetScanStatus::Open => PingStatus::Up,
                TargetScanStatus::OpenOrFiltered => PingStatus::Up,
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
        addr: dst_ipv4.into(),
        status: ping_status,
    })
}

fn _run_tcp_ping_host6(
    method: TcpPingMethods,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    dst_ipv6: Ipv6Addr,
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
            let target = Target::new_static_port6(&vec![dst_ipv6], &vec![dst_port]);
            let ret = scan::tcp_syn_scan6(
                target,
                src_ipv6,
                src_port,
                interface,
                print_result,
                8,
                timeout,
                max_loop,
            )?;
            let scan_rets = ret.get(&dst_ipv6.into()).unwrap();
            let status = scan_rets.results.get(&dst_port).unwrap();
            match status {
                TargetScanStatus::Open => PingStatus::Up,
                _ => PingStatus::Down,
            }
        }
        TcpPingMethods::Ack => {
            let dst_port = if dst_port.is_none() {
                ACK_PING_DEFAULT_PORT
            } else {
                dst_port.unwrap()
            };
            let target = Target::new_static_port6(&vec![dst_ipv6], &vec![dst_port]);
            let ret = scan::tcp_ack_scan6(
                target,
                src_ipv6,
                src_port,
                interface,
                print_result,
                8,
                timeout,
                max_loop,
            )?;
            let scan_rets = ret.get(&dst_ipv6.into()).unwrap();
            let status = scan_rets.results.get(&dst_port).unwrap();
            match status {
                TargetScanStatus::Unfiltered => PingStatus::Up,
                _ => PingStatus::Down,
            }
        }
        TcpPingMethods::Udp => {
            let dst_port = if dst_port.is_none() {
                UDP_PING_DEFAULT_PORT
            } else {
                dst_port.unwrap()
            };
            let target = Target::new_static_port6(&vec![dst_ipv6], &vec![dst_port]);
            let ret = scan::udp_scan6(
                target,
                src_ipv6,
                src_port,
                interface,
                print_result,
                8,
                timeout,
                max_loop,
            )?;
            let scan_rets = ret.get(&dst_ipv6.into()).unwrap();
            let status = scan_rets.results.get(&dst_port).unwrap();
            match status {
                TargetScanStatus::Open => PingStatus::Up,
                TargetScanStatus::OpenOrFiltered => PingStatus::Up,
                _ => PingStatus::Down,
            }
        }
        TcpPingMethods::Icmp => _run_icmp_ping_host6(
            src_ipv6,
            dst_ipv6,
            interface,
            print_result,
            timeout,
            max_loop,
        )?,
    };
    Ok(PingResults {
        addr: dst_ipv6.into(),
        status: ping_status,
    })
}

pub fn tcp_syn_ping_host(
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

pub fn tcp_syn_ping_host6(
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    dst_ipv6: Ipv6Addr,
    dst_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<PingResults> {
    _run_tcp_ping_host6(
        TcpPingMethods::Syn,
        src_ipv6,
        src_port,
        dst_ipv6,
        dst_port,
        interface,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn tcp_ack_ping_host(
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

pub fn tcp_ack_ping_host6(
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    dst_ipv6: Ipv6Addr,
    dst_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<PingResults> {
    _run_tcp_ping_host6(
        TcpPingMethods::Ack,
        src_ipv6,
        src_port,
        dst_ipv6,
        dst_port,
        interface,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn udp_ping_host(
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

pub fn udp_ping_host6(
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    dst_ipv6: Ipv6Addr,
    dst_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<PingResults> {
    _run_tcp_ping_host6(
        TcpPingMethods::Udp,
        src_ipv6,
        src_port,
        dst_ipv6,
        dst_port,
        interface,
        print_result,
        timeout,
        max_loop,
    )
}

pub fn icmp_ping_host(
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

pub fn icmp_ping_host6(
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    dst_ipv6: Ipv6Addr,
    dst_port: Option<u16>,
    interface: Option<&str>,
    print_result: bool,
    timeout: Option<Duration>,
    max_loop: Option<usize>,
) -> Result<PingResults> {
    _run_tcp_ping_host6(
        TcpPingMethods::Icmp,
        src_ipv6,
        src_port,
        dst_ipv6,
        dst_port,
        interface,
        print_result,
        timeout,
        max_loop,
    )
}
