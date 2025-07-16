#[cfg(feature = "ping")]
use chrono::DateTime;
#[cfg(feature = "ping")]
use chrono::Local;
#[cfg(feature = "ping")]
use tracing::debug;
#[cfg(feature = "ping")]
use tracing::warn;
#[cfg(feature = "ping")]
use prettytable::Cell;
#[cfg(feature = "ping")]
use prettytable::Row;
#[cfg(feature = "ping")]
use prettytable::Table;
#[cfg(feature = "ping")]
use prettytable::row;
#[cfg(feature = "ping")]
use std::collections::BTreeMap;
#[cfg(feature = "ping")]
use std::collections::HashMap;
#[cfg(feature = "ping")]
use std::fmt;
#[cfg(feature = "ping")]
use std::net::IpAddr;
#[cfg(feature = "ping")]
use std::net::Ipv4Addr;
#[cfg(feature = "ping")]
use std::net::Ipv6Addr;
#[cfg(feature = "ping")]
use std::panic::Location;
#[cfg(feature = "ping")]
use std::sync::mpsc::channel;
#[cfg(feature = "ping")]
use std::time::Duration;

#[cfg(feature = "ping")]
pub mod icmp;
#[cfg(feature = "ping")]
pub mod icmpv6;

#[cfg(feature = "ping")]
use crate::Target;
#[cfg(feature = "ping")]
use crate::error::PistolError;
#[cfg(feature = "ping")]
use crate::scan::PortStatus;
#[cfg(feature = "ping")]
use crate::scan::tcp;
#[cfg(feature = "ping")]
use crate::scan::tcp6;
#[cfg(feature = "ping")]
use crate::scan::udp;
#[cfg(feature = "ping")]
use crate::scan::udp6;
#[cfg(feature = "ping")]
use crate::utils::infer_source_addr;
#[cfg(feature = "ping")]
use crate::utils::infer_source_addr6;
#[cfg(feature = "ping")]
use crate::utils::get_threads_pool;
#[cfg(feature = "ping")]
use crate::utils::random_port;
#[cfg(feature = "ping")]
use crate::utils::threads_num_check;

#[cfg(feature = "ping")]
const SYN_PING_DEFAULT_PORT: u16 = 80;
#[cfg(feature = "ping")]
const ACK_PING_DEFAULT_PORT: u16 = 80;
#[cfg(feature = "ping")]
const UDP_PING_DEFAULT_PORT: u16 = 125;

#[cfg(feature = "ping")]
#[derive(Debug, Clone, PartialEq)]
pub enum PingStatus {
    Up,
    Down,
    Error,
}

#[cfg(feature = "ping")]
#[derive(Debug, Clone)]
pub struct HostPings {
    pub status: PingStatus,
    pub rtt: Duration,
    pub stime: DateTime<Local>,
    pub etime: DateTime<Local>,
}

#[cfg(feature = "ping")]
#[derive(Debug, Clone)]
pub struct Pings {
    pub pings: HashMap<IpAddr, Vec<HostPings>>,
    pub avg_cost: f64,
    pub total_cost: i64,
    pub alives_num: usize,
    pub stime: DateTime<Local>,
    pub etime: DateTime<Local>,
    tests: usize,
}

#[cfg(feature = "ping")]
impl Pings {
    pub fn new() -> Pings {
        Pings {
            pings: HashMap::new(),
            avg_cost: 0.0,
            total_cost: 0,
            alives_num: 0,
            stime: Local::now(),
            etime: Local::now(),
            tests: 0,
        }
    }
    pub fn get(&self, k: &IpAddr) -> Option<&Vec<HostPings>> {
        self.pings.get(k)
    }
    pub fn enrichment(&mut self) {
        self.etime = Local::now();
        // avg time cost
        let mut total_cost = 0;
        let mut total_num = 0;
        // alive hosts
        let mut alive_hosts = 0;
        for (_ip, ps) in &self.pings {
            self.tests = ps.len();
            for p in ps {
                match p.status {
                    PingStatus::Up => {
                        alive_hosts += 1;
                        break;
                    }
                    _ => (),
                }
                let time_cost = p.etime.signed_duration_since(self.stime).num_milliseconds();
                if time_cost != 0 {
                    total_cost += time_cost;
                    total_num += 1;
                }
            }
        }

        debug!("ping total num: {}", total_num);
        debug!("ping total cost: {}", total_cost);
        self.avg_cost = total_cost as f64 / total_num as f64;
        self.alives_num = alive_hosts;
        self.total_cost = self
            .etime
            .signed_duration_since(self.stime)
            .num_milliseconds();
    }
    fn insert(
        &mut self,
        dst_addr: IpAddr,
        ping_status: PingStatus,
        rtt: Duration,
        stime: DateTime<Local>,
        etime: DateTime<Local>,
    ) {
        let hpr = HostPings {
            status: ping_status,
            rtt,
            stime,
            etime,
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

#[cfg(feature = "ping")]
impl fmt::Display for Pings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new(&format!("Ping Results (tests:{})", self.tests))
                .style_spec("c")
                .with_hspan(4),
        ]));

        table.add_row(row![
            c -> "id",
            c -> "addr",
            c -> "status",
            c -> "avg cost"
        ]);

        let pings = &self.pings;
        let pings: BTreeMap<IpAddr, &Vec<HostPings>> =
            pings.into_iter().map(|(i, p)| (*i, p)).collect();
        for (i, (ip, hpr)) in pings.into_iter().enumerate() {
            let mut host_total_time_cost = 0;
            let mut host_up_num = 0;
            // let mut host_down_num = 0;
            // let mut host_error_num = 0;
            for h in hpr {
                match h.status {
                    PingStatus::Up => host_up_num += 1,
                    PingStatus::Down => (),  // host_down_num += 1,
                    PingStatus::Error => (), //host_error_num += 1,
                };
                let time_cost = h.etime.signed_duration_since(self.stime).num_milliseconds();
                host_total_time_cost += time_cost;
            }

            let status_str = if host_up_num > 0 {
                String::from("up")
            } else {
                String::from("down")
            };

            let rtt_str = format!("{:.3}s", host_total_time_cost as f64 / self.tests as f64);
            table.add_row(row![c -> (i + 1), c -> ip, c -> status_str, c -> rtt_str]);
        }

        let help_info = "NOTE:\nThe target host is considered alive\nas long as one of the packets returns\na result that is considered to be alive.";
        table.add_row(Row::new(vec![Cell::new(&help_info).with_hspan(4)]));

        let summary = format!(
            "total cost: {:.3}s\navg cost: {:.3}s\nalive hosts: {}",
            self.total_cost, self.avg_cost, self.alives_num
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(4)]));
        write!(f, "{}", table)
    }
}

#[cfg(feature = "ping")]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PingMethods {
    Syn,
    Ack,
    Udp,
    Icmp,
}

#[cfg(feature = "ping")]
fn threads_ping(
    method: PingMethods,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolError> {
    let (ping_status, rtt) = match method {
        PingMethods::Syn => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => SYN_PING_DEFAULT_PORT,
            };

            let (ret, rtt) =
                tcp::send_syn_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?;
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
                tcp::send_ack_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?;
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
                udp::send_udp_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?;
            match ret {
                PortStatus::Open => (PingStatus::Up, rtt),
                // PortStatus::OpenOrFiltered => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, rtt),
            }
        }
        PingMethods::Icmp => {
            let (ret, rtt) = icmp::send_icmp_ping_packet(dst_ipv4, src_ipv4, timeout)?;
            (ret, rtt)
        }
    };
    Ok((ping_status, rtt))
}

#[cfg(feature = "ping")]
fn threads_ping6(
    method: PingMethods,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolError> {
    let (ping_status, rtt) = match method {
        PingMethods::Syn => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => SYN_PING_DEFAULT_PORT,
            };

            let (ret, rtt) =
                tcp6::send_syn_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?;
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
                tcp6::send_ack_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?;
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
                udp6::send_udp_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?;
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

#[cfg(feature = "ping")]
fn ping(
    targets: &[Target],
    threads_num: Option<usize>,
    method: PingMethods,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<Pings, PistolError> {
    let mut ping_results = Pings::new();

    let threads_num = match threads_num {
        Some(t) => t,
        None => {
            let threads_num = targets.len() * tests;
            let threads_num = threads_num_check(threads_num);
            threads_num
        }
    };

    let src_port = match src_port {
        Some(p) => p,
        None => random_port(),
    };

    let pool = get_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut recv_size = 0;

    for target in targets {
        let dst_addr = target.addr;
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                for _ in 0..tests {
                    let tx = tx.clone();
                    recv_size += 1;
                    let src_ipv4 = match infer_source_addr(src_addr, dst_ipv4)? {
                        Some(s) => s,
                        None => return Err(PistolError::CanNotFoundSourceAddress),
                    };
                    let dst_port = if target.ports.len() > 0 {
                        Some(target.ports[0])
                    } else {
                        None
                    };
                    let dst_port = if method != PingMethods::Icmp {
                        dst_port
                    } else {
                        None
                    };
                    pool.execute(move || {
                        let stime = Local::now();
                        let ret =
                            threads_ping(method, dst_ipv4, dst_port, src_ipv4, src_port, timeout);
                        tx.send((dst_addr, ret, stime))
                            .expect(&format!("tx send failed at {}", Location::caller()));
                    });
                }
            }
            IpAddr::V6(dst_ipv6) => {
                for _ in 0..tests {
                    let tx = tx.clone();
                    recv_size += 1;
                    let src_ipv6 = match find_source_addr6(src_addr, dst_ipv6)? {
                        Some(s) => s,
                        None => return Err(PistolError::CanNotFoundSourceAddress),
                    };
                    let dst_port = if target.ports.len() > 0 {
                        Some(target.ports[0])
                    } else {
                        None
                    };
                    let dst_port = if method != PingMethods::Icmp {
                        dst_port
                    } else {
                        None
                    };
                    pool.execute(move || {
                        let stime = Local::now();
                        let ret =
                            threads_ping6(method, dst_ipv6, dst_port, src_ipv6, src_port, timeout);
                        tx.send((dst_addr, ret, stime))
                            .expect(&format!("tx send failed at {}", Location::caller()));
                    });
                }
            }
        }
    }

    let iter = rx.into_iter().take(recv_size);

    for (dst_ipv4, pr, stime) in iter {
        let etime = Local::now();
        match pr {
            Ok((ping_status, rtt)) => {
                ping_results.insert(dst_ipv4, ping_status, rtt, stime, etime);
            }
            Err(e) => {
                let rtt = Duration::new(0, 0);
                match e {
                    PistolError::CanNotFoundMacAddress => {
                        ping_results.insert(dst_ipv4, PingStatus::Down, rtt, stime, etime)
                    }
                    _ => {
                        warn!("ping error: {}", e);
                        ping_results.insert(dst_ipv4, PingStatus::Error, rtt, stime, etime);
                    }
                }
            }
        }
    }

    ping_results.enrichment();
    Ok(ping_results)
}

/// TCP SYN Ping.
/// This ping probe stays away from being similar to a SYN port scan, and to keep the probe stealthy,
/// we chose to have the user manually provide a port number that is open on the target machine instead of traversing all ports.
#[cfg(feature = "ping")]
pub fn tcp_syn_ping(
    targets: &[Target],
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<Pings, PistolError> {
    ping(
        targets,
        threads_num,
        PingMethods::Syn,
        src_addr,
        src_port,
        timeout,
        tests,
    )
}

/// TCP SYN Ping, raw version.
#[cfg(feature = "ping")]
pub fn tcp_syn_ping_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolError> {
    let src_port = match src_port {
        Some(p) => p,
        None => random_port(),
    };
    match dst_addr {
        IpAddr::V4(dst_ipv4) => match infer_source_addr(src_addr, dst_ipv4)? {
            Some(src_ipv4) => {
                let (ret, rtt) =
                    tcp::send_syn_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?;
                let (s, rtt) = match ret {
                    PortStatus::Open => (PingStatus::Up, rtt),
                    _ => (PingStatus::Down, rtt),
                };
                Ok((s, rtt))
            }
            None => Err(PistolError::CanNotFoundSourceAddress),
        },
        IpAddr::V6(dst_ipv6) => match find_source_addr6(src_addr, dst_ipv6)? {
            Some(src_ipv6) => {
                let (ret, rtt) =
                    tcp6::send_syn_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?;
                let (s, rtt) = match ret {
                    PortStatus::Open => (PingStatus::Up, rtt),
                    _ => (PingStatus::Down, rtt),
                };
                Ok((s, rtt))
            }
            None => Err(PistolError::CanNotFoundSourceAddress),
        },
    }
}

/// TCP ACK Ping.
/// This ping probe stays away from being similar to a ACK port scan, and to keep the probe stealthy,
/// we chose to have the user manually provide a port number that is open on the target machine instead of traversing all ports.
#[cfg(feature = "ping")]
pub fn tcp_ack_ping(
    targets: &[Target],
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<Pings, PistolError> {
    ping(
        targets,
        threads_num,
        PingMethods::Ack,
        src_addr,
        src_port,
        timeout,
        tests,
    )
}

/// TCP ACK Ping, raw version.
#[cfg(feature = "ping")]
pub fn tcp_ack_ping_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolError> {
    let src_port = match src_port {
        Some(p) => p,
        None => random_port(),
    };
    match dst_addr {
        IpAddr::V4(dst_ipv4) => match infer_source_addr(src_addr, dst_ipv4)? {
            Some(src_ipv4) => {
                let (ret, rtt) =
                    tcp::send_ack_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?;
                let (s, rtt) = match ret {
                    PortStatus::Unfiltered => (PingStatus::Up, rtt),
                    _ => (PingStatus::Down, rtt),
                };
                Ok((s, rtt))
            }
            None => Err(PistolError::CanNotFoundSourceAddress),
        },
        IpAddr::V6(dst_ipv6) => match find_source_addr6(src_addr, dst_ipv6)? {
            Some(src_ipv6) => {
                let (ret, rtt) =
                    tcp6::send_ack_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?;
                let (s, rtt) = match ret {
                    PortStatus::Unfiltered => (PingStatus::Up, rtt),
                    _ => (PingStatus::Down, rtt),
                };
                Ok((s, rtt))
            }
            None => Err(PistolError::CanNotFoundSourceAddress),
        },
    }
}

/// UDP Ping.
/// This ping probe stays away from being similar to a UDP port scan, and to keep the probe stealthy,
/// we chose to have the user manually provide a port number that is open on the target machine instead of traversing all ports.
#[cfg(feature = "ping")]
pub fn udp_ping(
    targets: &[Target],
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<Pings, PistolError> {
    ping(
        targets,
        threads_num,
        PingMethods::Udp,
        src_addr,
        src_port,
        timeout,
        tests,
    )
}

/// UDP Ping, raw version.
#[cfg(feature = "ping")]
pub fn udp_ping_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolError> {
    let src_port = match src_port {
        Some(p) => p,
        None => random_port(),
    };
    match dst_addr {
        IpAddr::V4(dst_ipv4) => match infer_source_addr(src_addr, dst_ipv4)? {
            Some(src_ipv4) => {
                let (ret, rtt) =
                    udp::send_udp_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?;
                let (s, rtt) = match ret {
                    PortStatus::Open => (PingStatus::Up, rtt),
                    // PortStatus::OpenOrFiltered => (PingStatus::Up, rtt),
                    _ => (PingStatus::Down, rtt),
                };
                Ok((s, rtt))
            }
            None => Err(PistolError::CanNotFoundSourceAddress),
        },
        IpAddr::V6(dst_ipv6) => match find_source_addr6(src_addr, dst_ipv6)? {
            Some(src_ipv6) => {
                let (ret, rtt) =
                    udp6::send_udp_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?;
                let (s, rtt) = match ret {
                    PortStatus::Open => (PingStatus::Up, rtt),
                    // PortStatus::OpenOrFiltered => (PingStatus::Up, rtt),
                    _ => (PingStatus::Down, rtt),
                };
                Ok((s, rtt))
            }
            None => Err(PistolError::CanNotFoundSourceAddress),
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
#[cfg(feature = "ping")]
pub fn icmp_ping(
    targets: &[Target],
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<Pings, PistolError> {
    ping(
        targets,
        threads_num,
        PingMethods::Icmp,
        src_addr,
        src_port,
        timeout,
        tests,
    )
}

/// ICMP ping, raw version.
#[cfg(feature = "ping")]
pub fn icmp_ping_raw(
    dst_addr: IpAddr,
    src_addr: Option<IpAddr>,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolError> {
    match dst_addr {
        IpAddr::V4(dst_ipv4) => match infer_source_addr(src_addr, dst_ipv4)? {
            Some(src_ipv4) => {
                let (ret, rtt) = icmp::send_icmp_ping_packet(dst_ipv4, src_ipv4, timeout)?;
                Ok((ret, rtt))
            }
            None => Err(PistolError::CanNotFoundSourceAddress),
        },
        IpAddr::V6(dst_ipv6) => match find_source_addr6(src_addr, dst_ipv6)? {
            Some(src_ipv6) => {
                let (ret, rtt) = icmpv6::send_icmpv6_ping_packet(src_ipv6, dst_ipv6, timeout)?;
                Ok((ret, rtt))
            }
            None => Err(PistolError::CanNotFoundSourceAddress),
        },
    }
}

#[cfg(feature = "ping")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Target;
    use std::time::Instant;
    use subnetwork::CrossIpv4Pool;
    #[test]
    fn test_tcp_syn_ping() {
        // use crate::Logger;
        // Logger::init_debug_logging().unwrap();
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(3, 0));

        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let target1 = Target::new(addr1, Some(vec![80]));
        // let host_2 = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22]));
        // let target: Target = Target::new(vec![host_1, host_2]);
        let tests = 3;
        let threads_num = Some(8);
        let ret =
            tcp_syn_ping(&[target1], threads_num, src_ipv4, src_port, timeout, tests).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_tcp_syn_ping_raw() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(3, 0));
        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let (ret, _rtt) = tcp_syn_ping_raw(addr1, 80, src_ipv4, src_port, timeout).unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_syn_ping6() {
        // Logger::init_debug_logging()?;
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
        let addr1 = IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0x0020c, 0x29ff, 0xfe2c, 0x09e4,
        ));
        let target = Target::new(addr1, Some(vec![22]));
        let tests = 4;
        let threads_num = Some(8);
        let ret = tcp_syn_ping(&[target], threads_num, src_ipv4, src_port, timeout, tests).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_icmp_ping() {
        // let _ = Logger::init_debug_logging();
        let src_ipv4 = None;
        let src_port: Option<u16> = None;
        let timeout = Some(Duration::new(1, 0));
        let dst_ipv4 = Ipv4Addr::new(139, 180, 156, 169);
        // let dst_ipv4 = Ipv4Addr::new(192, 168, 31, 1);
        // let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![]));
        let target = Target::new(dst_ipv4.into(), Some(vec![]));
        let tests = 4;
        let threads_num = Some(8);
        let ret = icmp_ping(&[target], threads_num, src_ipv4, src_port, timeout, tests).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_icmpv6_ping() {
        // Logger::init_debug_logging()?;
        let src_port: Option<u16> = None;
        let src_ipv6: Ipv6Addr = "fe80::20c:29ff:fe99:57c6".parse().unwrap();
        let src_ipv6 = Some(src_ipv6.into());
        let addr1 = IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0x0020c, 0x29ff, 0xfe2c, 0x09e4,
        ));
        let target = Target::new(addr1, Some(vec![]));
        let tests = 4;
        let threads_num = Some(8);
        let timeout = Some(Duration::new(3, 0));
        let ret = icmp_ping(&[target], threads_num, src_ipv6, src_port, timeout, tests).unwrap();
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
        let mut targets = vec![];
        for ip in pool {
            targets.push(Target::new(ip.into(), None));
        }
        let tests = 2;
        let start = Instant::now();
        let threads_num = Some(8);
        let ret = icmp_ping(&targets, threads_num, src_ipv4, src_port, timeout, tests).unwrap();
        println!("{} - {:.3}s", ret, start.elapsed().as_secs_f64());
    }
    #[test]
    #[ignore]
    fn test_github_issues_14() {
        use std::process::Command;
        let pid = std::process::id();
        let threads_num = Some(8);

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
            let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
            let target = Target::new(addr1, None);
            let _ret = icmp_ping(
                &[target],
                threads_num,
                None,
                None,
                Some(Duration::new(1, 0)),
                1,
            )
            .unwrap();
            // println!("{}\n{:?}", i, ret);
            println!("id: {}", i);
            // std::thread::sleep(Duration::new(1, 0));
        }
    }
}
