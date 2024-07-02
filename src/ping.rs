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
}

#[derive(Debug, Clone)]
pub struct HostPingStatus {
    pub status: PingStatus,
    pub rtt: Option<Duration>,
}

impl HostPingStatus {
    pub fn new(status: PingStatus, rtt: Option<Duration>) -> HostPingStatus {
        HostPingStatus { status, rtt }
    }
}

#[derive(Debug, Clone)]
pub struct PingResults {
    pub results: HashMap<IpAddr, HostPingStatus>,
    pub avg_rtt: Option<Duration>,
    pub alive_host_num: usize,
}

impl PingResults {
    pub fn new() -> PingResults {
        PingResults {
            results: HashMap::new(),
            avg_rtt: None,
            alive_host_num: 0,
        }
    }
    pub fn get(&self, k: &IpAddr) -> Option<&HostPingStatus> {
        self.results.get(k)
    }
    pub fn enrichment(&mut self) {
        // avg rtt
        let mut total_rtt = 0.0;
        let mut total_num = 0;
        for (_ip, ping_status) in &self.results {
            let rtt = ping_status.rtt;
            match rtt {
                Some(r) => {
                    total_rtt += r.as_secs_f64();
                    total_num += 1;
                }
                None => (),
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
        self.alive_host_num = self.results.len();
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
    Icmpv6,
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
                PortStatus::OpenOrFiltered => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, rtt),
            }
        }
        PingMethods::Icmpv6 => icmp::send_icmp_ping_packet(src_ipv4, dst_ipv4, timeout)?,
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
        PingMethods::Icmpv6 => icmpv6::send_icmpv6_ping_packet(src_ipv6, dst_ipv6, timeout)?,
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
        let src_ipv4 = match find_source_addr(src_ipv4, dst_ipv4)? {
            Some(s) => s,
            None => return Err(CanNotFoundSourceAddress::new().into()),
        };
        if host.ports.len() > 0 && method != PingMethods::Icmpv6 {
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
                let pr = HostPingStatus::new(p, rtt);
                ping_results.results.insert(dst_ipv4.into(), pr);
            }
            _ => (),
        }
    }
    ping_results.enrichment();
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
        let src_ipv6 = match find_source_addr6(src_ipv6, dst_ipv6)? {
            Some(s) => s,
            None => return Err(CanNotFoundSourceAddress::new().into()),
        };
        if host.ports.len() > 0 && method != PingMethods::Icmpv6 {
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
                let pr = HostPingStatus::new(p, rtt);
                ping_results.results.insert(dst_ipv6.into(), pr);
            }
            _ => (),
        }
    }
    ping_results.enrichment();
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

/// ICMP Ping.
/// In addition to the unusual TCP and UDP host discovery types discussed previously, we can send the standard packets sent by the ubiquitous ping program.
/// We sends an ICMP type 8 (echo request) packet to the target IP addresses, expecting a type 0 (echo reply) in return from available hosts.
/// As noted at the beginning of this chapter, many hosts and firewalls now block these packets, rather than responding as required by RFC 1122.
/// For this reason, ICMP-only scans are rarely reliable enough against unknown targets over the Internet.
/// But for system administrators monitoring an internal network, this can be a practical and efficient approach.
pub fn icmp_ping(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
) -> Result<PingResults> {
    ping(
        target,
        PingMethods::Icmpv6,
        src_ipv4,
        src_port,
        threads_num,
        timeout,
    )
}

/// Sends an ICMPv6 type 128 (echo request) packet .
pub fn icmpv6_ping(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
) -> Result<PingResults> {
    ping6(
        target,
        PingMethods::Icmpv6,
        src_ipv6,
        src_port,
        threads_num,
        timeout,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Host;
    use crate::Host6;
    use crate::Logger;
    use crate::Target;
    use crate::DST_IPV4;
    use crate::DST_IPV6;
    #[test]
    fn test_tcp_syn_ping() -> Result<()> {
        Logger::init_debug_logging()?;
        let src_ipv4 = None;
        let src_port = None;
        let threads_num: usize = 8;
        let timeout = Some(Duration::new(3, 0));
        let host = Host::new(DST_IPV4, Some(vec![22]));
        let target: Target = Target::new(vec![host]);
        let ret = tcp_syn_ping(target, src_ipv4, src_port, threads_num, timeout)?;
        println!("{}", ret);
        Ok(())
    }
    #[test]
    fn test_tcp_syn_ping6() -> Result<()> {
        Logger::init_debug_logging()?;
        let src_ipv4 = None;
        let src_port = None;
        let threads_num: usize = 8;
        let timeout = Some(Duration::new(3, 0));
        let host = Host6::new(DST_IPV6, Some(vec![22]));
        let target: Target = Target::new6(vec![host]);
        let ret = tcp_syn_ping6(target, src_ipv4, src_port, threads_num, timeout)?;
        println!("{}", ret);
        Ok(())
    }
    #[test]
    fn test_icmp_ping() -> Result<()> {
        Logger::init_debug_logging()?;
        let src_ipv4 = None;
        let src_port: Option<u16> = None;
        let threads_num: usize = 8;
        let timeout = Some(Duration::new(1, 0));
        let host = Host::new(DST_IPV4, Some(vec![]));
        let target: Target = Target::new(vec![host]);
        let ret = icmp_ping(target, src_ipv4, src_port, threads_num, timeout)?;
        println!("{}", ret);
        Ok(())
    }
    #[test]
    fn test_icmpv6_ping() -> Result<()> {
        Logger::init_debug_logging()?;
        let src_port: Option<u16> = None;
        let src_ipv6 = None;
        let host = Host6::new(DST_IPV6, Some(vec![]));
        let target: Target = Target::new6(vec![host]);
        let threads_num: usize = 8;
        let timeout = Some(Duration::new(3, 0));
        let ret = icmpv6_ping(target, src_ipv6, src_port, threads_num, timeout)?;
        println!("{}", ret);
        Ok(())
    }
}
