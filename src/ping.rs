use anyhow::Result;
use log::debug;
use log::warn;
use prettytable::row;
use prettytable::Cell;
use prettytable::Row;
use prettytable::Table;
use std::collections::BTreeMap;
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
use crate::scan::PortStatus;
use crate::utils::find_source_addr;
use crate::utils::find_source_addr6;
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
    Error,
}

#[derive(Debug, Clone)]
pub struct PingResults {
    pub pings: HashMap<IpAddr, Vec<PingStatus>>,
    pub rtts: HashMap<IpAddr, Vec<Duration>>,
    pub avg_rtt: Option<Duration>,
    pub alive_hosts: usize,
}

impl PingResults {
    pub fn new() -> PingResults {
        PingResults {
            pings: HashMap::new(),
            rtts: HashMap::new(),
            avg_rtt: None,
            alive_hosts: 0,
        }
    }
    pub fn get_ping_status(&self, k: &IpAddr) -> Option<&Vec<PingStatus>> {
        self.pings.get(k)
    }
    pub fn get_rtts(&self, k: &IpAddr) -> Option<&Vec<Duration>> {
        self.rtts.get(k)
    }
    pub fn enrichment(&mut self) {
        // avg rtt
        let mut total_rtt = 0.0;
        let mut total_num = 0;
        for (_ip, rtts) in &self.rtts {
            for r in rtts {
                total_rtt += r.as_secs_f64();
                total_num += 1;
            }
        }
        let avg_rtt = if total_num != 0 {
            let avg_rtt = total_rtt / total_num as f64;
            let avg_rtt = Duration::from_secs_f64(avg_rtt);
            Some(avg_rtt)
        } else {
            None
        };
        self.avg_rtt = avg_rtt;

        // alive hosts
        let mut alive_hosts = 0;
        for (_ip, ps) in &self.pings {
            for p in ps {
                match p {
                    PingStatus::Up => {
                        alive_hosts += 1;
                        break;
                    }
                    _ => (),
                }
            }
        }
        self.alive_hosts = alive_hosts;
    }
    fn insert(&mut self, dst_addr: IpAddr, ping_status: PingStatus, rtt: Option<Duration>) {
        match self.pings.get_mut(&dst_addr.into()) {
            Some(p) => {
                p.push(ping_status);
            }
            None => {
                let v = vec![ping_status];
                self.pings.insert(dst_addr.into(), v);
            }
        }
        match rtt {
            Some(rtt) => match self.rtts.get_mut(&dst_addr.into()) {
                Some(r) => {
                    r.push(rtt);
                }
                None => {
                    let v = vec![rtt];
                    self.rtts.insert(dst_addr.into(), v);
                }
            },
            None => (),
        }
    }
}

impl fmt::Display for PingResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![Cell::new("Ping Results")
            .style_spec("c")
            .with_hspan(2)]));

        let pings = &self.pings;
        let pings: BTreeMap<IpAddr, &Vec<PingStatus>> =
            pings.into_iter().map(|(i, p)| (*i, p)).collect();
        for (ip, status) in pings {
            let mut status_str_vec = Vec::new();
            for s in status {
                let s_str = match s {
                    PingStatus::Up => String::from("up"),
                    PingStatus::Down => String::from("down"),
                    PingStatus::Error => String::from("error"),
                };
                status_str_vec.push(s_str);
            }
            let status_str = status_str_vec.join("|");
            table.add_row(row![c -> ip, c -> status_str]);
        }
        let avg_rtt = match self.avg_rtt {
            Some(avg_rtt) => avg_rtt,
            None => Duration::new(0, 0),
        };
        let summary = format!(
            "avg rtt: {:.1}ms\nalive hosts: {}",
            avg_rtt.as_secs_f64() * 1000.0,
            self.alive_hosts
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(2)]));
        write!(f, "{}", table)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PingMethods {
    Syn,
    Ack,
    Udp,
    Icmp,
}

fn threads_ping(
    method: PingMethods,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: Option<u16>,
    timeout: Duration,
) -> Result<(PingStatus, Option<Duration>)> {
    match dst_port {
        None => debug!("can not found dst port on method: {:?}", method),
        _ => (),
    }
    let (ping_status, rtt) = match method {
        PingMethods::Syn => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => SYN_PING_DEFAULT_PORT,
            };

            let (ret, rtt) =
                tcp::send_syn_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?;
            debug!("syn ret: {:?}", ret);
            match ret {
                PortStatus::Open => (PingStatus::Up, rtt),
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
            debug!("ack ret: {:?}", ret);
            match ret {
                PortStatus::Unfiltered => (PingStatus::Up, rtt),
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
            debug!("udp ret: {:?}", ret);
            match ret {
                PortStatus::Open => (PingStatus::Up, rtt),
                // PortStatus::OpenOrFiltered => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, rtt),
            }
        }
        PingMethods::Icmp => {
            let (ret, rtt) = icmp::send_icmp_ping_packet(src_ipv4, dst_ipv4, timeout)?;
            debug!("icmp ret: {:?}", ret);
            (ret, rtt)
        }
    };
    Ok((ping_status, rtt))
}

fn threads_ping6(
    method: PingMethods,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: Option<u16>,
    timeout: Duration,
) -> Result<(PingStatus, Option<Duration>)> {
    match dst_port {
        None => debug!("can not found dst port on method: {:?}", method),
        _ => (),
    }
    let (ping_status, rtt) = match method {
        PingMethods::Syn => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => SYN_PING_DEFAULT_PORT,
            };

            let (ret, rtt) =
                tcp6::send_syn_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?;
            match ret {
                PortStatus::Open => (PingStatus::Up, rtt),
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
                PortStatus::Unfiltered => (PingStatus::Up, rtt),
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
                PortStatus::Open => (PingStatus::Up, rtt),
                PortStatus::OpenOrFiltered => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, rtt),
            }
        }
        PingMethods::Icmp => icmpv6::send_icmpv6_ping_packet(src_ipv6, dst_ipv6, timeout)?,
    };
    Ok((ping_status, rtt))
}

fn ipv4_ping(
    method: PingMethods,
    src_addr: Option<IpAddr>,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: Option<u16>,
    timeout: Duration,
) -> Result<(PingStatus, Option<Duration>)> {
    let src_ipv4 = match find_source_addr(src_addr, dst_ipv4)? {
        Some(s) => s,
        None => return Err(CanNotFoundSourceAddress::new().into()),
    };

    let dst_port = if method != PingMethods::Icmp {
        dst_port
    } else {
        None
    };

    let ret = threads_ping(method, src_ipv4, src_port, dst_ipv4, dst_port, timeout);
    ret
}

fn ipv6_ping(
    method: PingMethods,
    src_addr: Option<IpAddr>,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: Option<u16>,
    timeout: Duration,
) -> Result<(PingStatus, Option<Duration>)> {
    let src_ipv6 = match find_source_addr6(src_addr, dst_ipv6)? {
        Some(s) => s,
        None => return Err(CanNotFoundSourceAddress::new().into()),
    };

    let dst_port = if method != PingMethods::Icmp {
        dst_port
    } else {
        None
    };

    let ret = threads_ping6(method, src_ipv6, src_port, dst_ipv6, dst_port, timeout);
    ret
}

pub fn ping(
    target: Target,
    method: PingMethods,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
    tests: usize,
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
        let dst_addr = host.addr;
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                for _ in 0..tests {
                    let tx = tx.clone();
                    recv_size += 1;
                    let dst_port = if host.ports.len() > 0 {
                        Some(host.ports[0])
                    } else {
                        None
                    };
                    pool.execute(move || {
                        let ret =
                            ipv4_ping(method, src_addr, src_port, dst_ipv4, dst_port, timeout);
                        match tx.send((dst_addr, ret)) {
                            _ => (),
                        }
                    });
                }
            }
            IpAddr::V6(dst_ipv6) => {
                for _ in 0..tests {
                    let tx = tx.clone();
                    recv_size += 1;
                    let dst_port = if host.ports.len() > 0 {
                        Some(host.ports[0])
                    } else {
                        None
                    };
                    pool.execute(move || {
                        let ret =
                            ipv6_ping(method, src_addr, src_port, dst_ipv6, dst_port, timeout);
                        match tx.send((dst_addr, ret)) {
                            _ => (),
                        }
                    });
                }
            }
        }
    }

    debug!("recv_size: {}", recv_size);
    let iter = rx.into_iter().take(recv_size);
    let mut ping_results = PingResults::new();

    for (dst_ipv4, pr) in iter {
        match pr {
            Ok((ping_status, rtt)) => {
                debug!(
                    "ip: {}, port status: {:?}, rtt: {:?}",
                    dst_ipv4, ping_status, rtt
                );
                ping_results.insert(dst_ipv4, ping_status, rtt);
            }
            Err(e) => {
                warn!("ping error: {}", e);
                ping_results.insert(dst_ipv4, PingStatus::Error, None);
            }
        }
    }

    ping_results.enrichment();
    Ok(ping_results)
}

/// TCP SYN Ping.
/// This ping probe stays away from being similar to a SYN port scan, and to keep the probe stealthy,
/// we chose to have the user manually provide a port number that is open on the target machine instead of traversing all ports.
pub fn tcp_syn_ping(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PingResults> {
    ping(
        target,
        PingMethods::Syn,
        src_addr,
        src_port,
        threads_num,
        timeout,
        tests,
    )
}

/// TCP ACK Ping.
/// This ping probe stays away from being similar to a ACK port scan, and to keep the probe stealthy,
/// we chose to have the user manually provide a port number that is open on the target machine instead of traversing all ports.
pub fn tcp_ack_ping(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PingResults> {
    ping(
        target,
        PingMethods::Ack,
        src_addr,
        src_port,
        threads_num,
        timeout,
        tests,
    )
}

/// UDP Ping.
/// This ping probe stays away from being similar to a UDP port scan, and to keep the probe stealthy,
/// we chose to have the user manually provide a port number that is open on the target machine instead of traversing all ports.
pub fn udp_ping(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PingResults> {
    ping(
        target,
        PingMethods::Udp,
        src_addr,
        src_port,
        threads_num,
        timeout,
        tests,
    )
}

/// ICMP Ping.
/// In addition to the unusual TCP and UDP host discovery types discussed previously,
/// we can send the standard packets sent by the ubiquitous ping program.
/// We sends an ICMP type 8 (echo request) packet to the target IP addresses, expecting a type 0 (echo reply) in return from available hosts.
/// As noted at the beginning of this chapter, many hosts and firewalls now block these packets, rather than responding as required by RFC 1122.
/// For this reason, ICMP-only scans are rarely reliable enough against unknown targets over the Internet.
/// But for system administrators monitoring an internal network, this can be a practical and efficient approach.
/// Sends an ICMPv6 type 128 (echo request) packet (IPv6).
pub fn icmp_ping(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PingResults> {
    ping(
        target,
        PingMethods::Icmp,
        src_addr,
        src_port,
        threads_num,
        timeout,
        tests,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Host;
    use crate::Logger;
    use crate::Target;
    // use crate::TEST_IPV4_LOCAL;
    use crate::TEST_IPV4_REMOTE;
    use crate::TEST_IPV6_LOCAL;
    #[test]
    fn test_tcp_syn_ping() -> Result<()> {
        Logger::init_debug_logging()?;
        let src_ipv4 = None;
        let src_port = None;
        let threads_num: usize = 8;
        let timeout = Some(Duration::new(3, 0));
        let host_1 = Host::new(TEST_IPV4_REMOTE.into(), Some(vec![80]));
        // let host_2 = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22]));
        // let target: Target = Target::new(vec![host_1, host_2]);
        let target: Target = Target::new(vec![host_1]);
        let tests = 3;
        let ret = tcp_syn_ping(target, src_ipv4, src_port, threads_num, timeout, tests)?;
        println!("{}", ret);
        Ok(())
    }
    #[test]
    fn test_tcp_syn_ping6() -> Result<()> {
        // Logger::init_debug_logging()?;
        let src_ipv4 = None;
        let src_port = None;
        let threads_num: usize = 8;
        let timeout = Some(Duration::new(1, 0));
        let host = Host::new(TEST_IPV6_LOCAL.into(), Some(vec![22]));
        let target: Target = Target::new(vec![host]);
        let tests = 4;
        let ret = tcp_syn_ping(target, src_ipv4, src_port, threads_num, timeout, tests)?;
        println!("{}", ret);
        Ok(())
    }
    #[test]
    fn test_icmp_ping() -> Result<()> {
        // Logger::init_debug_logging()?;
        let src_ipv4 = None;
        let src_port: Option<u16> = None;
        let threads_num: usize = 8;
        let timeout = Some(Duration::new(1, 0));
        let host = Host::new(TEST_IPV4_REMOTE.into(), Some(vec![]));
        let target: Target = Target::new(vec![host]);
        let tests = 4;
        let ret = icmp_ping(target, src_ipv4, src_port, threads_num, timeout, tests)?;
        println!("{}", ret);
        Ok(())
    }
    #[test]
    fn test_icmpv6_ping() -> Result<()> {
        // Logger::init_debug_logging()?;
        let src_port: Option<u16> = None;
        let src_ipv6: Ipv6Addr = "fe80::20c:29ff:fe99:57c6".parse()?;
        let src_ipv6 = Some(src_ipv6.into());
        let host = Host::new(TEST_IPV6_LOCAL.into(), Some(vec![]));
        let target: Target = Target::new(vec![host]);
        let threads_num: usize = 8;
        let tests = 4;
        let timeout = Some(Duration::new(3, 0));
        let ret = icmp_ping(target, src_ipv6, src_port, threads_num, timeout, tests)?;
        println!("{}", ret);
        Ok(())
    }
}
