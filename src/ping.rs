use anyhow::Result;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::mpsc::channel;
use std::time::Duration;

pub mod icmp;
pub mod icmpv6;

use crate::errors::CanNotFoundSourceAddress;
use crate::scan::tcp;
use crate::scan::tcp6;
use crate::scan::udp;
use crate::scan::udp6;
use crate::scan::TargetScanStatus;
use crate::utils::find_source_ipv4;
use crate::utils::find_source_ipv6;
use crate::utils::get_default_timeout;
use crate::utils::get_threads_pool;
use crate::utils::random_port;
use crate::Target;

const SYN_PING_DEFAULT_PORT: u16 = 80;
const ACK_PING_DEFAULT_PORT: u16 = 80;
const UDP_PING_DEFAULT_PORT: u16 = 125;

#[derive(Debug, Clone, PartialEq)]
pub enum PingStatus {
    Up,
    Down,
}

#[derive(Debug, Clone)]
pub struct PingRet {
    pub status: PingStatus,
    pub rtt: Option<Duration>,
}

impl PingRet {
    pub fn new(status: PingStatus, rtt: Option<Duration>) -> PingRet {
        PingRet { status, rtt }
    }
}

#[derive(Debug, Clone)]
pub struct PingResults {
    pub results: HashMap<IpAddr, PingRet>,
}

impl PingResults {
    pub fn new() -> PingResults {
        PingResults {
            results: HashMap::new(),
        }
    }
    pub fn get(&self, k: &IpAddr) -> Option<&PingRet> {
        self.results.get(k)
    }
}

impl fmt::Display for PingResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut result_str = String::new();
        for (ip, ping_ret) in &self.results {
            let str = match ping_ret.status {
                PingStatus::Up => format!("{ip} up"),
                PingStatus::Down => format!("{ip} down"),
            };
            result_str += &str;
        }
        write!(f, "{}", result_str)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PingMethods {
    Syn,
    Ack,
    Udp,
    Icmp,
}

fn run_ping(
    method: PingMethods,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: Option<u16>,
    timeout: Duration,
) -> Result<(PingStatus, Option<Duration>)> {
    let (ping_status, rtt) = match method {
        PingMethods::Syn => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => SYN_PING_DEFAULT_PORT,
            };

            let (ret, rtt) =
                tcp::send_syn_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?;
            match ret {
                TargetScanStatus::Open => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, rtt),
            }
        }
        PingMethods::Ack => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => ACK_PING_DEFAULT_PORT,
            };

            let (ret, rtt) =
                tcp::send_ack_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?;
            match ret {
                TargetScanStatus::Unfiltered => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, rtt),
            }
        }
        PingMethods::Udp => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => UDP_PING_DEFAULT_PORT,
            };

            let (ret, rtt) =
                udp::send_udp_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?;
            match ret {
                TargetScanStatus::Open => (PingStatus::Up, rtt),
                TargetScanStatus::OpenOrFiltered => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, rtt),
            }
        }
        PingMethods::Icmp => icmp::send_icmp_ping_packet(src_ipv4, dst_ipv4, timeout)?,
    };
    Ok((ping_status, rtt))
}

fn run_ping6(
    method: PingMethods,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: Option<u16>,
    timeout: Duration,
) -> Result<(PingStatus, Option<Duration>)> {
    let (ping_status, rtt) = match method {
        PingMethods::Syn => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => SYN_PING_DEFAULT_PORT,
            };

            let (ret, rtt) =
                tcp6::send_syn_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?;
            match ret {
                TargetScanStatus::Open => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, rtt),
            }
        }
        PingMethods::Ack => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => ACK_PING_DEFAULT_PORT,
            };

            let (ret, rtt) =
                tcp6::send_ack_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?;
            match ret {
                TargetScanStatus::Unfiltered => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, rtt),
            }
        }
        PingMethods::Udp => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => UDP_PING_DEFAULT_PORT,
            };

            let (ret, rtt) =
                udp6::send_udp_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?;
            match ret {
                TargetScanStatus::Open => (PingStatus::Up, rtt),
                TargetScanStatus::OpenOrFiltered => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, rtt),
            }
        }
        PingMethods::Icmp => icmpv6::send_icmpv6_ping_packet(src_ipv6, dst_ipv6, timeout)?,
    };
    Ok((ping_status, rtt))
}

pub fn ping(
    target: Target,
    method: PingMethods,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
) -> Result<PingResults> {
    let src_port = match src_port {
        Some(p) => p,
        None => random_port(),
    };

    let pool = get_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut recv_size = 0;
    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };

    for host in target.hosts {
        let dst_ipv4 = host.addr;
        let src_ipv4 = match find_source_ipv4(src_ipv4, dst_ipv4)? {
            Some(s) => s,
            None => return Err(CanNotFoundSourceAddress::new().into()),
        };
        if host.ports.len() > 0 && method != PingMethods::Icmp {
            for dst_port in host.ports {
                let tx = tx.clone();
                recv_size += 1;
                pool.execute(move || {
                    let ret = run_ping(
                        method,
                        src_ipv4,
                        src_port,
                        dst_ipv4,
                        Some(dst_port),
                        timeout,
                    );
                    match tx.send((dst_ipv4, ret)) {
                        _ => (),
                    }
                });
            }
        } else {
            let tx = tx.clone();
            recv_size += 1;
            pool.execute(move || {
                let ret = run_ping(method, src_ipv4, src_port, dst_ipv4, None, timeout);
                match tx.send((dst_ipv4, ret)) {
                    _ => (),
                }
            });
        }
    }

    let iter = rx.into_iter().take(recv_size);
    let mut ping_results = PingResults::new();

    for (dst_ipv4, pr) in iter {
        match pr {
            Ok((p, rtt)) => {
                let pr = PingRet::new(p, rtt);
                ping_results.results.insert(dst_ipv4.into(), pr);
            }
            _ => (),
        }
    }
    Ok(ping_results)
}

pub fn ping6(
    target: Target,
    method: PingMethods,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
) -> Result<PingResults> {
    let src_port = match src_port {
        Some(p) => p,
        None => random_port(),
    };
    let pool = get_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut recv_size = 0;
    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };

    for host in target.hosts6 {
        let dst_ipv6 = host.addr;
        let src_ipv6 = match find_source_ipv6(src_ipv6, dst_ipv6)? {
            Some(s) => s,
            None => return Err(CanNotFoundSourceAddress::new().into()),
        };
        if host.ports.len() > 0 && method != PingMethods::Icmp {
            for dst_port in host.ports {
                let tx = tx.clone();
                recv_size += 1;
                pool.execute(move || {
                    let ret = run_ping6(
                        method,
                        src_ipv6,
                        src_port,
                        dst_ipv6,
                        Some(dst_port),
                        timeout,
                    );
                    match tx.send((dst_ipv6, ret)) {
                        _ => (),
                    }
                });
            }
        } else {
            let tx = tx.clone();
            recv_size += 1;
            pool.execute(move || {
                let ret = run_ping6(method, src_ipv6, src_port, dst_ipv6, None, timeout);
                match tx.send((dst_ipv6, ret)) {
                    _ => (),
                }
            });
        }
    }

    let iter = rx.into_iter().take(recv_size);
    let mut ping_results = PingResults::new();

    for (dst_ipv6, pr) in iter {
        match pr {
            Ok((p, rtt)) => {
                let pr = PingRet::new(p, rtt);
                ping_results.results.insert(dst_ipv6.into(), pr);
            }
            _ => (),
        }
    }
    Ok(ping_results)
}

/// TCP SYN Ping.
/// This ping probe stays away from being similar to a SYN port scan,
/// and to keep the probe stealthy,
/// we chose to have the user manually provide a port number that is open on the target machine instead of traversing all ports.
pub fn tcp_syn_ping(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
) -> Result<PingResults> {
    ping(
        target,
        PingMethods::Syn,
        src_ipv4,
        src_port,
        threads_num,
        timeout,
    )
}

pub fn tcp_syn_ping6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
) -> Result<PingResults> {
    ping6(
        target,
        PingMethods::Syn,
        src_ipv6,
        src_port,
        threads_num,
        timeout,
    )
}

/// TCP ACK Ping.
/// This ping probe stays away from being similar to a ACK port scan,
/// and to keep the probe stealthy,
/// we chose to have the user manually provide a port number that is open on the target machine instead of traversing all ports.
pub fn tcp_ack_ping(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
) -> Result<PingResults> {
    ping(
        target,
        PingMethods::Ack,
        src_ipv4,
        src_port,
        threads_num,
        timeout,
    )
}

pub fn tcp_ack_ping6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
) -> Result<PingResults> {
    ping6(
        target,
        PingMethods::Ack,
        src_ipv6,
        src_port,
        threads_num,
        timeout,
    )
}

/// UDP Ping.
/// This ping probe stays away from being similar to a UDP port scan,
/// and to keep the probe stealthy,
/// we chose to have the user manually provide a port number that is open on the target machine instead of traversing all ports.
pub fn udp_ping(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
) -> Result<PingResults> {
    ping(
        target,
        PingMethods::Udp,
        src_ipv4,
        src_port,
        threads_num,
        timeout,
    )
}

pub fn udp_ping6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
) -> Result<PingResults> {
    ping6(
        target,
        PingMethods::Udp,
        src_ipv6,
        src_port,
        threads_num,
        timeout,
    )
}

/// Traditional Ping.
pub fn icmp_ping(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
) -> Result<PingResults> {
    ping(
        target,
        PingMethods::Icmp,
        src_ipv4,
        src_port,
        threads_num,
        timeout,
    )
}

pub fn icmpv6_ping(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
) -> Result<PingResults> {
    ping6(
        target,
        PingMethods::Icmp,
        src_ipv6,
        src_port,
        threads_num,
        timeout,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Host, Host6, Target};
    #[test]
    fn test_tcp_syn_ping() -> Result<()> {
        let src_ipv4 = None;
        let src_port = None;
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 51);
        let threads_num: usize = 8;
        let timeout = Some(Duration::new(3, 0));
        let host = Host::new(dst_ipv4, Some(vec![22]))?;
        let target: Target = Target::new(vec![host]);
        let ret = tcp_syn_ping(target, src_ipv4, src_port, threads_num, timeout).unwrap();
        println!("{}", ret);
        Ok(())
    }
    #[test]
    fn test_icmp_ping() -> Result<()> {
        // let src_ipv4: Option<Ipv4Addr> = Some(Ipv4Addr::new(192, 168, 72, 128));
        let src_ipv4 = None;
        let src_port: Option<u16> = None;
        let dst_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 5, 1);
        // let dst_ipv4: Ipv4Addr = Ipv4Addr::new(39, 156, 66, 10);
        // let dst_ipv4: Ipv4Addr = Ipv4Addr::new(114, 114, 114, 114);
        let threads_num: usize = 8;
        let timeout = Some(Duration::new(3, 0));
        let host = Host::new(dst_ipv4, Some(vec![]))?;
        let target: Target = Target::new(vec![host]);
        let ret = icmp_ping(target, src_ipv4, src_port, threads_num, timeout).unwrap();
        println!("{}", ret);
        Ok(())
    }
    #[test]
    fn test_icmpv6_ping() -> Result<()> {
        let src_port: Option<u16> = None;
        // let src_ipv6: Option<Ipv6Addr> = Some("fe80::20c:29ff:fe43:9c82".parse().unwrap());
        // let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        // let dst_ipv6: Ipv6Addr = "fe80::47c:7f4a:10a8:7f4a".parse().unwrap();
        // let dst_ipv6: Ipv6Addr = "fe80::cc6c:3960:8be6:579".parse().unwrap();
        // let src_ipv6: Option<Ipv6Addr> = Some("240e:34c:85:e4d0:20c:29ff:fe43:9c8c".parse().unwrap());
        let src_ipv6 = None;
        let dst_ipv6: Ipv6Addr = "fe80::6445:b9f8:cc82:3015".parse().unwrap();
        let host1 = Host6::new(dst_ipv6, Some(vec![]))?;
        let dst_ipv6: Ipv6Addr = "2001:da8:8000:1::80".parse().unwrap();
        let host2 = Host6::new(dst_ipv6, Some(vec![]))?;
        let target: Target = Target::new6(vec![host1, host2]);
        let threads_num: usize = 8;
        let timeout = Some(Duration::new(3, 0));
        let ret = icmpv6_ping(target, src_ipv6, src_port, threads_num, timeout).unwrap();
        println!("{}", ret);
        Ok(())
    }
}
