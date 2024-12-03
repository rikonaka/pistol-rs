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
use std::time::Instant;

pub mod icmp;
pub mod icmpv6;

use crate::errors::PistolErrors;
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
use crate::utils::threads_num_check;
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
pub struct HostPingResults {
    pub ping_status: PingStatus,
    pub ping_time_cost: Duration,
}

#[derive(Debug, Clone)]
pub struct PingResults {
    pub pings: HashMap<IpAddr, Vec<HostPingResults>>,
    pub avg_time_cost: f64,
    pub total_time_cost: f64,
    pub alive_hosts: usize,
    start_time: Instant,
    tests: usize,
}

impl PingResults {
    pub fn new() -> PingResults {
        PingResults {
            pings: HashMap::new(),
            avg_time_cost: 0.0,
            alive_hosts: 0,
            start_time: Instant::now(),
            total_time_cost: 0.0,
            tests: 0,
        }
    }
    pub fn get_ping_status(&self, k: &IpAddr) -> Option<Vec<PingStatus>> {
        match self.pings.get(k) {
            Some(host_ping_status) => {
                let mut ping_status = Vec::new();
                for hps in host_ping_status {
                    ping_status.push(hps.ping_status.clone());
                }
                Some(ping_status)
            }
            None => None,
        }
    }
    pub fn get_rtts(&self, k: &IpAddr) -> Option<Vec<Duration>> {
        match self.pings.get(k) {
            Some(host_ping_status) => {
                let mut ping_rtts = Vec::new();
                for hpr in host_ping_status {
                    ping_rtts.push(hpr.ping_time_cost);
                }
                Some(ping_rtts)
            }
            None => None,
        }
    }
    pub fn enrichment(&mut self) {
        // avg time cost
        let mut total_cost = 0.0;
        let mut total_num = 0;
        // alive hosts
        let mut alive_hosts = 0;
        for (_ip, ps) in &self.pings {
            self.tests = ps.len();
            for p in ps {
                match p.ping_status {
                    PingStatus::Up => {
                        alive_hosts += 1;
                        break;
                    }
                    _ => (),
                }
                total_cost += p.ping_time_cost.as_secs_f64();
                if p.ping_time_cost != Duration::new(0, 0) {
                    total_num += 1;
                }
            }
        }

        self.avg_time_cost = total_cost / total_num as f64;
        self.alive_hosts = alive_hosts;
        self.total_time_cost = self.start_time.elapsed().as_secs_f64();
    }
    fn insert(&mut self, dst_addr: IpAddr, ping_status: PingStatus, ping_time_cost: Duration) {
        let hpr = HostPingResults {
            ping_status,
            ping_time_cost,
        };

        match self.pings.get_mut(&dst_addr.into()) {
            Some(p) => {
                p.push(hpr);
            }
            None => {
                let v = vec![hpr];
                self.pings.insert(dst_addr.into(), v);
            }
        }
    }
}

impl fmt::Display for PingResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![Cell::new(&format!(
            "Ping Results (tests:{})",
            self.tests
        ))
        .style_spec("c")
        .with_hspan(4)]));

        table.add_row(row![
            c -> "id",
            c -> "addr",
            c -> "status",
            c -> "avg cost"
        ]);

        let pings = &self.pings;
        let pings: BTreeMap<IpAddr, &Vec<HostPingResults>> =
            pings.into_iter().map(|(i, p)| (*i, p)).collect();
        for (i, (ip, hpr)) in pings.into_iter().enumerate() {
            let mut host_avg_time_cost = 0.0;
            let mut host_up_num = 0;
            // let mut host_down_num = 0;
            // let mut host_error_num = 0;
            for h in hpr {
                match h.ping_status {
                    PingStatus::Up => host_up_num += 1,
                    PingStatus::Down => (),  // host_down_num += 1,
                    PingStatus::Error => (), //host_error_num += 1,
                };
                host_avg_time_cost += h.ping_time_cost.as_secs_f64();
            }

            let status_str = if host_up_num > 0 {
                String::from("up")
            } else {
                String::from("down")
            };

            let rtt_str = format!("{:.2}ms", host_avg_time_cost * 1000.0 / self.tests as f64);
            table.add_row(row![c -> (i + 1), c -> ip, c -> status_str, c -> rtt_str]);
        }

        let help_info = "NOTE:\nThe target host is considered alive\nas long as one of the packets returns\na result that is considered to be alive.";
        table.add_row(Row::new(vec![Cell::new(&help_info).with_hspan(4)]));

        let summary = format!(
            "total used time: {:.2}ms\navg time cost: {:.1}ms\nalive hosts: {}",
            self.total_time_cost * 1000.0,
            self.avg_time_cost * 1000.0,
            self.alive_hosts
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(4)]));
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
) -> Result<(PingStatus, Duration), PistolErrors> {
    let (ping_status, rtt) = match method {
        PingMethods::Syn => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => SYN_PING_DEFAULT_PORT,
            };

            let (ret, rtt) =
                tcp::send_syn_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?;
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
            match ret {
                PortStatus::Open => (PingStatus::Up, rtt),
                // PortStatus::OpenOrFiltered => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, rtt),
            }
        }
        PingMethods::Icmp => {
            let (ret, rtt) = icmp::send_icmp_ping_packet(src_ipv4, dst_ipv4, timeout)?;
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
) -> Result<(PingStatus, Duration), PistolErrors> {
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

pub fn ping(
    target: Target,
    method: PingMethods,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PingResults, PistolErrors> {
    let mut ping_results = PingResults::new();
    let threads_num = target.hosts.len() * tests;
    let threads_num = threads_num_check(threads_num);

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
                    let src_ipv4 = match find_source_addr(src_addr, dst_ipv4)? {
                        Some(s) => s,
                        None => return Err(PistolErrors::CanNotFoundSourceAddress),
                    };
                    let dst_port = if host.ports.len() > 0 {
                        Some(host.ports[0])
                    } else {
                        None
                    };
                    let dst_port = if method != PingMethods::Icmp {
                        dst_port
                    } else {
                        None
                    };
                    pool.execute(move || {
                        let cost = Instant::now(); // for error situation
                        let ret =
                            threads_ping(method, src_ipv4, src_port, dst_ipv4, dst_port, timeout);
                        match tx.send((dst_addr, ret, cost)) {
                            _ => (),
                        }
                    });
                }
            }
            IpAddr::V6(dst_ipv6) => {
                for _ in 0..tests {
                    let tx = tx.clone();
                    recv_size += 1;
                    let src_ipv6 = match find_source_addr6(src_addr, dst_ipv6)? {
                        Some(s) => s,
                        None => return Err(PistolErrors::CanNotFoundSourceAddress),
                    };
                    let dst_port = if host.ports.len() > 0 {
                        Some(host.ports[0])
                    } else {
                        None
                    };
                    let dst_port = if method != PingMethods::Icmp {
                        dst_port
                    } else {
                        None
                    };
                    pool.execute(move || {
                        let cost = Instant::now(); // for error situation
                        let ret =
                            threads_ping6(method, src_ipv6, src_port, dst_ipv6, dst_port, timeout);
                        match tx.send((dst_addr, ret, cost)) {
                            _ => (),
                        }
                    });
                }
            }
        }
    }

    let iter = rx.into_iter().take(recv_size);

    for (dst_ipv4, pr, cost) in iter {
        let tc = cost.elapsed();
        match pr {
            Ok((ping_status, rtt)) => {
                ping_results.insert(dst_ipv4, ping_status, rtt);
            }
            Err(e) => match e {
                PistolErrors::CanNotFoundMacAddress => {
                    ping_results.insert(dst_ipv4, PingStatus::Down, tc)
                }
                _ => {
                    warn!("ping error: {}", e);
                    ping_results.insert(dst_ipv4, PingStatus::Error, tc);
                }
            },
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
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PingResults, PistolErrors> {
    ping(target, PingMethods::Syn, src_addr, src_port, timeout, tests)
}

/// TCP SYN Ping, raw version.
pub fn tcp_syn_ping_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolErrors> {
    let src_port = match src_port {
        Some(p) => p,
        None => random_port(),
    };
    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };
    match dst_addr {
        IpAddr::V4(dst_ipv4) => match find_source_addr(src_addr, dst_ipv4)? {
            Some(src_ipv4) => {
                let (ret, rtt) =
                    tcp::send_syn_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?;
                let (s, rtt) = match ret {
                    PortStatus::Open => (PingStatus::Up, rtt),
                    _ => (PingStatus::Down, rtt),
                };
                Ok((s, rtt))
            }
            None => Err(PistolErrors::CanNotFoundSourceAddress),
        },
        IpAddr::V6(dst_ipv6) => match find_source_addr6(src_addr, dst_ipv6)? {
            Some(src_ipv6) => {
                let (ret, rtt) =
                    tcp6::send_syn_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?;
                let (s, rtt) = match ret {
                    PortStatus::Open => (PingStatus::Up, rtt),
                    _ => (PingStatus::Down, rtt),
                };
                Ok((s, rtt))
            }
            None => Err(PistolErrors::CanNotFoundSourceAddress),
        },
    }
}

/// TCP ACK Ping.
/// This ping probe stays away from being similar to a ACK port scan, and to keep the probe stealthy,
/// we chose to have the user manually provide a port number that is open on the target machine instead of traversing all ports.
pub fn tcp_ack_ping(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PingResults, PistolErrors> {
    ping(target, PingMethods::Ack, src_addr, src_port, timeout, tests)
}

/// TCP ACK Ping, raw version.
pub fn tcp_ack_ping_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolErrors> {
    let src_port = match src_port {
        Some(p) => p,
        None => random_port(),
    };
    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };
    match dst_addr {
        IpAddr::V4(dst_ipv4) => match find_source_addr(src_addr, dst_ipv4)? {
            Some(src_ipv4) => {
                let (ret, rtt) =
                    tcp::send_ack_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?;
                let (s, rtt) = match ret {
                    PortStatus::Unfiltered => (PingStatus::Up, rtt),
                    _ => (PingStatus::Down, rtt),
                };
                Ok((s, rtt))
            }
            None => Err(PistolErrors::CanNotFoundSourceAddress),
        },
        IpAddr::V6(dst_ipv6) => match find_source_addr6(src_addr, dst_ipv6)? {
            Some(src_ipv6) => {
                let (ret, rtt) =
                    tcp6::send_ack_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?;
                let (s, rtt) = match ret {
                    PortStatus::Unfiltered => (PingStatus::Up, rtt),
                    _ => (PingStatus::Down, rtt),
                };
                Ok((s, rtt))
            }
            None => Err(PistolErrors::CanNotFoundSourceAddress),
        },
    }
}

/// UDP Ping.
/// This ping probe stays away from being similar to a UDP port scan, and to keep the probe stealthy,
/// we chose to have the user manually provide a port number that is open on the target machine instead of traversing all ports.
pub fn udp_ping(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PingResults, PistolErrors> {
    ping(target, PingMethods::Udp, src_addr, src_port, timeout, tests)
}

/// UDP Ping, raw version.
pub fn udp_ping_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolErrors> {
    let src_port = match src_port {
        Some(p) => p,
        None => random_port(),
    };
    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };
    match dst_addr {
        IpAddr::V4(dst_ipv4) => match find_source_addr(src_addr, dst_ipv4)? {
            Some(src_ipv4) => {
                let (ret, rtt) =
                    udp::send_udp_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?;
                let (s, rtt) = match ret {
                    PortStatus::Open => (PingStatus::Up, rtt),
                    // PortStatus::OpenOrFiltered => (PingStatus::Up, rtt),
                    _ => (PingStatus::Down, rtt),
                };
                Ok((s, rtt))
            }
            None => Err(PistolErrors::CanNotFoundSourceAddress),
        },
        IpAddr::V6(dst_ipv6) => match find_source_addr6(src_addr, dst_ipv6)? {
            Some(src_ipv6) => {
                let (ret, rtt) =
                    udp6::send_udp_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?;
                let (s, rtt) = match ret {
                    PortStatus::Open => (PingStatus::Up, rtt),
                    // PortStatus::OpenOrFiltered => (PingStatus::Up, rtt),
                    _ => (PingStatus::Down, rtt),
                };
                Ok((s, rtt))
            }
            None => Err(PistolErrors::CanNotFoundSourceAddress),
        },
    }
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
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PingResults, PistolErrors> {
    ping(
        target,
        PingMethods::Icmp,
        src_addr,
        src_port,
        timeout,
        tests,
    )
}

/// ICMP ping, raw version.
pub fn icmp_ping_raw(
    dst_addr: IpAddr,
    src_addr: Option<IpAddr>,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolErrors> {
    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };
    match dst_addr {
        IpAddr::V4(dst_ipv4) => match find_source_addr(src_addr, dst_ipv4)? {
            Some(src_ipv4) => {
                let (ret, rtt) = icmp::send_icmp_ping_packet(src_ipv4, dst_ipv4, timeout)?;
                Ok((ret, rtt))
            }
            None => Err(PistolErrors::CanNotFoundSourceAddress),
        },
        IpAddr::V6(dst_ipv6) => match find_source_addr6(src_addr, dst_ipv6)? {
            Some(src_ipv6) => {
                let (ret, rtt) = icmpv6::send_icmpv6_ping_packet(src_ipv6, dst_ipv6, timeout)?;
                Ok((ret, rtt))
            }
            None => Err(PistolErrors::CanNotFoundSourceAddress),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Host;
    use crate::Target;
    use crate::TEST_IPV4_LOCAL;
    // use crate::TEST_IPV4_REMOTE;
    use crate::TEST_IPV6_LOCAL;
    use subnetwork::CrossIpv4Pool;
    #[test]
    fn test_tcp_syn_ping() {
        // use crate::Logger;
        // Logger::init_debug_logging().unwrap();
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(3, 0));
        let host_1 = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![80]));
        // let host_2 = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22]));
        // let target: Target = Target::new(vec![host_1, host_2]);
        let target: Target = Target::new(vec![host_1]);
        let tests = 3;
        let ret = tcp_syn_ping(target, src_ipv4, src_port, timeout, tests).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_tcp_syn_ping_raw() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(3, 0));
        let (ret, _rtt) =
            tcp_syn_ping_raw(TEST_IPV4_LOCAL.into(), 80, src_ipv4, src_port, timeout).unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_syn_ping6() {
        // Logger::init_debug_logging()?;
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
        let host = Host::new(TEST_IPV6_LOCAL.into(), Some(vec![22]));
        let target: Target = Target::new(vec![host]);
        let tests = 4;
        let ret = tcp_syn_ping(target, src_ipv4, src_port, timeout, tests).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_icmp_ping() {
        // Logger::init_debug_logging()?;
        let src_ipv4 = None;
        let src_port: Option<u16> = None;
        let timeout = Some(Duration::new(1, 0));
        let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![]));
        let target: Target = Target::new(vec![host]);
        let tests = 4;
        let ret = icmp_ping(target, src_ipv4, src_port, timeout, tests).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_icmpv6_ping() {
        // Logger::init_debug_logging()?;
        let src_port: Option<u16> = None;
        let src_ipv6: Ipv6Addr = "fe80::20c:29ff:fe99:57c6".parse().unwrap();
        let src_ipv6 = Some(src_ipv6.into());
        let host = Host::new(TEST_IPV6_LOCAL.into(), Some(vec![]));
        let target: Target = Target::new(vec![host]);
        let tests = 4;
        let timeout = Some(Duration::new(3, 0));
        let ret = icmp_ping(target, src_ipv6, src_port, timeout, tests).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_ping_timeout2() {
        let src_ipv4: Option<IpAddr> = None;
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
        let start_ip = Ipv4Addr::new(192, 168, 5, 1);
        let end_ip = Ipv4Addr::new(192, 168, 5, 10);
        let pool = CrossIpv4Pool::new(start_ip, end_ip).unwrap();
        let mut hosts = vec![];
        for ip in pool {
            hosts.push(Host::new(ip.into(), None));
        }
        let target: Target = Target::new(hosts);
        let tests = 2;
        let start = Instant::now();
        let ret = icmp_ping(target, src_ipv4, src_port, timeout, tests).unwrap();
        println!("{} - {:.2}s", ret, start.elapsed().as_secs_f64());
    }
    #[test]
    fn test_github_issues_14() {
        use std::process::Command;
        let pid = std::process::id();

        for i in 0..10_000 {
            let c2 = Command::new("bash")
                .arg("-c")
                .arg(&format!("lsof -p {} | wc -l", pid))
                .output()
                .unwrap();
            println!(
                "pid: {}, lsof output: {}",
                &pid,
                String::from_utf8_lossy(&c2.stdout)
            );

            let host = Host::new(TEST_IPV4_LOCAL.into(), None);
            let target = Target::new(vec![host]);
            let _ret = icmp_ping(target, None, None, Some(Duration::new(1, 0)), 1).unwrap();
            // println!("{}\n{:?}", i, ret);
            println!("id: {}", i);
            // std::thread::sleep(Duration::new(1, 0));
        }
    }
}
