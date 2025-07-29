#[cfg(feature = "ping")]
use chrono::DateTime;
#[cfg(feature = "ping")]
use chrono::Local;
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
use std::fmt;
#[cfg(feature = "ping")]
use std::net::IpAddr;
#[cfg(feature = "ping")]
use std::net::Ipv4Addr;
#[cfg(feature = "ping")]
use std::net::Ipv6Addr;
#[cfg(feature = "ping")]
use std::sync::mpsc::channel;
#[cfg(feature = "ping")]
use std::time::Duration;
#[cfg(feature = "ping")]
use std::time::Instant;
#[cfg(feature = "ping")]
use tracing::error;

#[cfg(feature = "ping")]
pub mod icmp;
#[cfg(feature = "ping")]
pub mod icmpv6;

#[cfg(feature = "ping")]
use crate::Target;
#[cfg(feature = "ping")]
use crate::error::PistolError;
#[cfg(feature = "ping")]
use crate::layer::infer_addr;
#[cfg(feature = "ping")]
use crate::scan::DataRecvStatus;
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
use crate::utils::get_threads_pool;
#[cfg(feature = "ping")]
use crate::utils::num_threads_check;
#[cfg(feature = "ping")]
use crate::utils::random_port;
#[cfg(feature = "ping")]
use crate::utils::time_sec_to_string;

#[cfg(feature = "ping")]
const SYN_PING_DEFAULT_PORT: u16 = 80;
#[cfg(feature = "ping")]
const ACK_PING_DEFAULT_PORT: u16 = 80;
#[cfg(feature = "ping")]
const UDP_PING_DEFAULT_PORT: u16 = 125;

#[cfg(feature = "ping")]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PingStatus {
    Up,
    Down,
    Error,
}

#[cfg(feature = "ping")]
impl fmt::Display for PingStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            PingStatus::Up => "up",
            PingStatus::Down => "down",
            PingStatus::Error => "error",
        };
        write!(f, "{}", s)
    }
}

#[cfg(feature = "ping")]
#[derive(Debug, Clone)]
pub struct PingReport {
    pub addr: IpAddr,
    pub status: PingStatus,
    pub cost: Duration,
}

#[cfg(feature = "ping")]
#[derive(Debug, Clone)]
pub struct PistolPings {
    pub ping_reports: Vec<PingReport>,
    pub start_time: DateTime<Local>,
    pub end_time: DateTime<Local>,
    max_attempts: usize,
}

#[cfg(feature = "ping")]
impl PistolPings {
    pub fn new(max_attempts: usize) -> PistolPings {
        PistolPings {
            ping_reports: Vec::new(),
            start_time: Local::now(),
            end_time: Local::now(),
            max_attempts,
        }
    }
    pub fn value(&self) -> Vec<PingReport> {
        self.ping_reports.clone()
    }
    pub fn finish(&mut self, ping_reports: Vec<PingReport>) {
        self.end_time = Local::now();
        self.ping_reports = ping_reports;
    }
}

#[cfg(feature = "ping")]
impl fmt::Display for PistolPings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let total_cost = self.end_time - self.start_time;

        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new(&format!(
                "Ping Results (max_attempts:{})",
                self.max_attempts
            ))
            .style_spec("c")
            .with_hspan(4),
        ]));

        table.add_row(row![
            c -> "id",
            c -> "addr",
            c -> "status",
            c -> "time cost"
        ]);

        // sorted
        let mut btm_addr: BTreeMap<IpAddr, PingReport> = BTreeMap::new();
        for report in &self.ping_reports {
            btm_addr.insert(report.addr, report.clone());
        }

        let mut alive_hosts = 0;
        let mut i = 1;
        for (_addr, report) in btm_addr {
            match report.status {
                PingStatus::Up => alive_hosts += 1,
                _ => (),
            }
            let status_str = format!("{}", report.status);
            let rtt_str = time_sec_to_string(report.cost);
            table.add_row(row![c -> i, c -> report.addr, c -> status_str, c -> rtt_str]);
            i += 1;
        }

        // let help_info = "NOTE:\nThe target host is considered alive\nas long as one of the packets returns\na result that is considered to be alive.";
        // table.add_row(Row::new(vec![Cell::new(&help_info).with_hspan(4)]));

        let avg_cost = total_cost.as_seconds_f64() / self.ping_reports.len() as f64;
        let summary = format!(
            "total cost: {:.3}s\navg cost: {:.3}s\nalive hosts: {}",
            total_cost.as_seconds_f64(),
            avg_cost,
            alive_hosts,
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
    Icmpv6,
}

#[cfg(feature = "ping")]
fn ping_thread(
    method: PingMethods,
    dst_ipv4: Ipv4Addr,
    dst_port: Option<u16>,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    timeout: Option<Duration>,
) -> Result<(PingStatus, DataRecvStatus, Duration), PistolError> {
    let (ping_status, data_return, rtt) = match method {
        PingMethods::Syn => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => SYN_PING_DEFAULT_PORT,
            };

            let (port_status, data_return, rtt) =
                tcp::send_syn_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?;
            match port_status {
                PortStatus::Open => (PingStatus::Up, data_return, rtt),
                _ => (PingStatus::Down, data_return, rtt),
            }
        }
        PingMethods::Ack => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => ACK_PING_DEFAULT_PORT,
            };

            let (ret, data_return, rtt) =
                tcp::send_ack_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?;
            match ret {
                PortStatus::Unfiltered => (PingStatus::Up, data_return, rtt),
                _ => (PingStatus::Down, data_return, rtt),
            }
        }
        PingMethods::Udp => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => UDP_PING_DEFAULT_PORT,
            };

            let (ret, data_return, rtt) =
                udp::send_udp_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?;
            match ret {
                PortStatus::Open => (PingStatus::Up, data_return, rtt),
                // PortStatus::OpenOrFiltered => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, data_return, rtt),
            }
        }
        PingMethods::Icmp => {
            let (ret, data_return, rtt) = icmp::send_icmp_ping_packet(dst_ipv4, src_ipv4, timeout)?;
            (ret, data_return, rtt)
        }
        PingMethods::Icmpv6 => {
            return Err(PistolError::PingDetectionMethodError {
                target: dst_ipv4.into(),
                method: String::from("icmpv6"),
            });
        }
    };
    Ok((ping_status, data_return, rtt))
}

#[cfg(feature = "ping")]
fn ping_thread6(
    method: PingMethods,
    dst_ipv6: Ipv6Addr,
    dst_port: Option<u16>,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    timeout: Option<Duration>,
) -> Result<(PingStatus, DataRecvStatus, Duration), PistolError> {
    let (ping_status, data_return, rtt) = match method {
        PingMethods::Syn => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => SYN_PING_DEFAULT_PORT,
            };

            let (ret, data_return, rtt) =
                tcp6::send_syn_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?;
            match ret {
                PortStatus::Open => (PingStatus::Up, data_return, rtt),
                _ => (PingStatus::Down, data_return, rtt),
            }
        }
        PingMethods::Ack => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => ACK_PING_DEFAULT_PORT,
            };

            let (ret, data_return, rtt) =
                tcp6::send_ack_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?;
            match ret {
                PortStatus::Unfiltered => (PingStatus::Up, data_return, rtt),
                _ => (PingStatus::Down, data_return, rtt),
            }
        }
        PingMethods::Udp => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => UDP_PING_DEFAULT_PORT,
            };

            let (ret, data_return, rtt) =
                udp6::send_udp_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?;
            match ret {
                PortStatus::Open => (PingStatus::Up, data_return, rtt),
                PortStatus::OpenOrFiltered => (PingStatus::Up, data_return, rtt),
                _ => (PingStatus::Down, data_return, rtt),
            }
        }
        PingMethods::Icmp => {
            return Err(PistolError::PingDetectionMethodError {
                target: dst_ipv6.into(),
                method: String::from("icmp"),
            });
        }
        PingMethods::Icmpv6 => icmpv6::send_icmpv6_ping_packet(dst_ipv6, src_ipv6, timeout)?,
    };
    Ok((ping_status, data_return, rtt))
}

#[cfg(feature = "ping")]
fn ping(
    targets: &[Target],
    num_threads: Option<usize>,
    method: PingMethods,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    max_attempts: usize,
) -> Result<PistolPings, PistolError> {
    let mut pistol_pings = PistolPings::new(max_attempts);

    let num_threads = match num_threads {
        Some(t) => t,
        None => {
            let num_threads = targets.len();
            let num_threads = num_threads_check(num_threads);
            num_threads
        }
    };

    let pool = get_threads_pool(num_threads);
    let (tx, rx) = channel();
    let mut recv_size = 0;

    for target in targets {
        let dst_addr = target.addr;
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                let src_port = match src_port {
                    Some(p) => p,
                    None => random_port(),
                };
                let tx = tx.clone();
                recv_size += 1;
                let (dst_ipv4, src_ipv4) = match infer_addr(src_addr, dst_ipv4.into())? {
                    Some(ia) => ia.ipv4_addr()?,
                    None => return Err(PistolError::CanNotFoundSourceAddress),
                };
                let dst_port = if target.ports.len() > 0 {
                    Some(target.ports[0])
                } else {
                    None
                };
                let dst_port = if method != PingMethods::Icmp && method != PingMethods::Icmpv6 {
                    dst_port
                } else {
                    None
                };
                pool.execute(move || {
                    for ind in 0..max_attempts {
                        let start_time = Instant::now();
                        let ping_ret =
                            ping_thread(method, dst_ipv4, dst_port, src_ipv4, src_port, timeout);
                        if ind == max_attempts - 1 {
                            // last attempt
                            let _ = tx.send((dst_addr, ping_ret, start_time.elapsed()));
                        } else {
                            match ping_ret {
                                Ok((_port_status, data_return, _)) => {
                                    match data_return {
                                        DataRecvStatus::Yes => {
                                            // conclusions drawn from the returned data
                                            let _ =
                                                tx.send((dst_addr, ping_ret, start_time.elapsed()));
                                            break; // quit loop now
                                        }
                                        // conclusions from the default policy
                                        DataRecvStatus::No => (), // continue probing
                                    }
                                }
                                Err(_) => {
                                    // stop probe immediately if an error occurs
                                    let _ = tx.send((dst_addr, ping_ret, start_time.elapsed()));
                                }
                            }
                        }
                    }
                });
            }
            IpAddr::V6(dst_ipv6) => {
                let src_port = match src_port {
                    Some(p) => p,
                    None => random_port(),
                };
                let tx = tx.clone();
                recv_size += 1;
                let (dst_ipv6, src_ipv6) = match infer_addr(src_addr, dst_ipv6.into())? {
                    Some(ia) => ia.ipv6_addr()?,
                    None => return Err(PistolError::CanNotFoundSourceAddress),
                };
                let dst_port = if target.ports.len() > 0 {
                    Some(target.ports[0])
                } else {
                    None
                };
                let dst_port = if method != PingMethods::Icmp && method != PingMethods::Icmpv6 {
                    dst_port
                } else {
                    None
                };
                pool.execute(move || {
                    for ind in 0..max_attempts {
                        let start_time = Instant::now();
                        let ping_ret =
                            ping_thread6(method, dst_ipv6, dst_port, src_ipv6, src_port, timeout);
                        if ind == max_attempts - 1 {
                            // last attempt
                            let _ = tx.send((dst_addr, ping_ret, start_time.elapsed()));
                        } else {
                            match ping_ret {
                                Ok((_port_status, data_return, _)) => {
                                    match data_return {
                                        DataRecvStatus::Yes => {
                                            // conclusions drawn from the returned data
                                            let _ =
                                                tx.send((dst_addr, ping_ret, start_time.elapsed()));
                                            break; // quit loop now
                                        }
                                        // conclusions from the default policy
                                        DataRecvStatus::No => (), // continue probing
                                    }
                                }
                                Err(_) => {
                                    // stop probe immediately if an error occurs
                                    let _ = tx.send((dst_addr, ping_ret, start_time.elapsed()));
                                }
                            }
                        }
                    }
                });
            }
        }
    }

    let iter = rx.into_iter().take(recv_size);
    let mut reports = Vec::new();
    for (dst_addr, v, elapsed) in iter {
        match v {
            Ok((status, _data_return, rtt)) => {
                let ping_report = PingReport {
                    addr: dst_addr,
                    status,
                    cost: rtt,
                };
                reports.push(ping_report);
            }
            Err(e) => match e {
                PistolError::CanNotFoundMacAddress => {
                    let scan_report = PingReport {
                        addr: dst_addr,
                        status: PingStatus::Down,
                        cost: elapsed,
                    };
                    reports.push(scan_report);
                }
                _ => {
                    error!("ping error: {}", e);
                    let scan_report = PingReport {
                        addr: dst_addr,
                        status: PingStatus::Error,
                        cost: elapsed,
                    };
                    reports.push(scan_report);
                }
            },
        }
    }
    pistol_pings.finish(reports);
    Ok(pistol_pings)
}

/// TCP SYN Ping.
/// This ping probe stays away from being similar to a SYN port scan, and to keep the probe stealthy,
/// we chose to have the user manually provide a port number that is open on the target machine instead of traversing all ports.
#[cfg(feature = "ping")]
pub fn tcp_syn_ping(
    targets: &[Target],
    num_threads: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    max_attempts: usize,
) -> Result<PistolPings, PistolError> {
    ping(
        targets,
        num_threads,
        PingMethods::Syn,
        src_addr,
        src_port,
        timeout,
        max_attempts,
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
    let ia = match infer_addr(src_addr, dst_addr)? {
        Some(ia) => ia,
        None => return Err(PistolError::CanNotFoundSourceAddress),
    };
    match dst_addr {
        IpAddr::V4(_) => {
            let (dst_ipv4, src_ipv4) = ia.ipv4_addr()?;
            let (ret, _data_return, rtt) =
                tcp::send_syn_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?;
            let (s, rtt) = match ret {
                PortStatus::Open => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, rtt),
            };
            Ok((s, rtt))
        }
        IpAddr::V6(_) => {
            let (dst_ipv6, src_ipv6) = ia.ipv6_addr()?;
            let (ret, _data_return, rtt) =
                tcp6::send_syn_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?;
            let (s, rtt) = match ret {
                PortStatus::Open => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, rtt),
            };
            Ok((s, rtt))
        }
    }
}

/// TCP ACK Ping.
/// This ping probe stays away from being similar to a ACK port scan, and to keep the probe stealthy,
/// we chose to have the user manually provide a port number that is open on the target machine instead of traversing all ports.
#[cfg(feature = "ping")]
pub fn tcp_ack_ping(
    targets: &[Target],
    num_threads: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    max_attempts: usize,
) -> Result<PistolPings, PistolError> {
    ping(
        targets,
        num_threads,
        PingMethods::Ack,
        src_addr,
        src_port,
        timeout,
        max_attempts,
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
    let ia = match infer_addr(src_addr, dst_addr)? {
        Some(ia) => ia,
        None => return Err(PistolError::CanNotFoundSourceAddress),
    };
    match dst_addr {
        IpAddr::V4(_) => {
            let (dst_ipv4, src_ipv4) = ia.ipv4_addr()?;
            let (ret, _data_return, rtt) =
                tcp::send_ack_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?;
            let (s, rtt) = match ret {
                PortStatus::Unfiltered => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, rtt),
            };
            Ok((s, rtt))
        }
        IpAddr::V6(_) => {
            let (dst_ipv6, src_ipv6) = ia.ipv6_addr()?;
            let (ret, _data_return, rtt) =
                tcp6::send_ack_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?;
            let (s, rtt) = match ret {
                PortStatus::Unfiltered => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, rtt),
            };
            Ok((s, rtt))
        }
    }
}

/// UDP Ping.
/// This ping probe stays away from being similar to a UDP port scan, and to keep the probe stealthy,
/// we chose to have the user manually provide a port number that is open on the target machine instead of traversing all ports.
#[cfg(feature = "ping")]
pub fn udp_ping(
    targets: &[Target],
    num_threads: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    max_attempts: usize,
) -> Result<PistolPings, PistolError> {
    ping(
        targets,
        num_threads,
        PingMethods::Udp,
        src_addr,
        src_port,
        timeout,
        max_attempts,
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
    let ia = match infer_addr(src_addr, dst_addr)? {
        Some(ia) => ia,
        None => return Err(PistolError::CanNotFoundSourceAddress),
    };
    match dst_addr {
        IpAddr::V4(_) => {
            let (dst_ipv4, src_ipv4) = ia.ipv4_addr()?;
            let (ret, _data_return, rtt) =
                udp::send_udp_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?;
            let (s, rtt) = match ret {
                PortStatus::Open => (PingStatus::Up, rtt),
                // PortStatus::OpenOrFiltered => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, rtt),
            };
            Ok((s, rtt))
        }
        IpAddr::V6(_) => {
            let (dst_ipv6, src_ipv6) = ia.ipv6_addr()?;
            let (ret, _data_return, rtt) =
                udp6::send_udp_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?;
            let (s, rtt) = match ret {
                PortStatus::Open => (PingStatus::Up, rtt),
                // PortStatus::OpenOrFiltered => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, rtt),
            };
            Ok((s, rtt))
        }
    }
}

/// ICMP Ping.
/// In addition to the unusual TCP and UDP host discovery types discussed previously,
/// we can send the standard packets sent by the ubiquitous ping program.
/// We sends an ICMP type 8 (echo request) packet to the target IP addresses, expecting a type 0 (echo reply) in return from available hosts.
/// As noted at the beginning of this chapter, many hosts and firewalls now block these packets, rather than responding as required by RFC 1122.
/// For this reason, ICMP-only scans are rarely reliable enough against unknown targets over the Internet.
/// But for system administrators monitoring an internal network, this can be a practical and efficient approach.
#[cfg(feature = "ping")]
pub fn icmp_ping(
    targets: &[Target],
    num_threads: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    max_attempts: usize,
) -> Result<PistolPings, PistolError> {
    ping(
        targets,
        num_threads,
        PingMethods::Icmp,
        src_addr,
        src_port,
        timeout,
        max_attempts,
    )
}

/// Sends an ICMPv6 type 128 (echo request) packet (IPv6).
#[cfg(feature = "ping")]
pub fn icmpv6_ping(
    targets: &[Target],
    num_threads: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    max_attempts: usize,
) -> Result<PistolPings, PistolError> {
    ping(
        targets,
        num_threads,
        PingMethods::Icmpv6,
        src_addr,
        src_port,
        timeout,
        max_attempts,
    )
}

/// ICMP ping, raw version.
#[cfg(feature = "ping")]
pub fn icmp_ping_raw(
    dst_addr: IpAddr,
    src_addr: Option<IpAddr>,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolError> {
    let ia = match infer_addr(src_addr, dst_addr)? {
        Some(ia) => ia,
        None => return Err(PistolError::CanNotFoundSourceAddress),
    };
    match dst_addr {
        IpAddr::V4(_) => {
            let (dst_ipv4, src_ipv4) = ia.ipv4_addr()?;
            let (ret, _data_return, rtt) =
                icmp::send_icmp_ping_packet(dst_ipv4, src_ipv4, timeout)?;
            Ok((ret, rtt))
        }
        IpAddr::V6(_) => {
            let (dst_ipv6, src_ipv6) = ia.ipv6_addr()?;
            let (ret, _data_return, rtt) =
                icmpv6::send_icmpv6_ping_packet(dst_ipv6, src_ipv6, timeout)?;
            Ok((ret, rtt))
        }
    }
}

#[cfg(feature = "ping")]
#[cfg(test)]
mod max_attempts {
    use super::*;
    use crate::PistolLogger;
    use crate::PistolRunner;
    use crate::Target;
    use std::str::FromStr;
    #[test]
    fn test_tcp_syn_ping() {
        let _pr = PistolRunner::init(
            PistolLogger::None,
            Some(String::from("tcp_syn_ping.pcapng")),
            None, // use default value
        )
        .unwrap();
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 2));
        let addr2 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5));
        let addr3 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 10));
        let target1 = Target::new(addr1, Some(vec![80]));
        let target2 = Target::new(addr2, Some(vec![80]));
        let target3 = Target::new(addr3, Some(vec![80]));
        let max_attempts = 2;
        let num_threads = Some(8);
        let ret = tcp_syn_ping(
            &[target1, target2, target3],
            // &[target1, target2, target3],
            num_threads,
            src_ipv4,
            src_port,
            timeout,
            max_attempts,
        )
        .unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_tcp_syn_ping_raw() {
        let _pr = PistolRunner::init(
            PistolLogger::None,
            Some(String::from("tcp_syn_ping_raw.pcapng")),
            None, // use default value
        )
        .unwrap();
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(3, 0));
        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5));
        let dst_port = 80;
        let (ret, _rtt) = tcp_syn_ping_raw(addr1, dst_port, src_ipv4, src_port, timeout).unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_syn_ping6() {
        let _pr = PistolRunner::init(
            PistolLogger::None,
            Some(String::from("tcp_syn_ping6.pcapng")),
            None, // use default value
        )
        .unwrap();
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
        let addr1 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e4").unwrap();
        let addr2 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e5").unwrap();
        let addr3 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e6").unwrap();
        let target1 = Target::new(addr1.into(), Some(vec![80]));
        let target2 = Target::new(addr2.into(), Some(vec![80]));
        let target3 = Target::new(addr3.into(), Some(vec![80]));
        let max_attempts = 4;
        let num_threads = Some(8);
        let ret = tcp_syn_ping(
            &[target1, target2, target3],
            num_threads,
            src_ipv4,
            src_port,
            timeout,
            max_attempts,
        )
        .unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_icmp_ping() {
        let _pr = PistolRunner::init(
            PistolLogger::None,
            Some(String::from("icmp_ping.pcapng")),
            None, // use default value
        )
        .unwrap();
        let src_ipv4 = None;
        let src_port: Option<u16> = None;
        let timeout = Some(Duration::new(1, 0));
        let addr1 = Ipv4Addr::new(192, 168, 5, 5);
        let addr2 = Ipv4Addr::new(192, 168, 5, 1);
        let addr3 = Ipv4Addr::new(192, 168, 5, 100);
        let addr4 = Ipv4Addr::new(192, 168, 1, 4);
        let target1 = Target::new(addr1.into(), Some(vec![]));
        let target2 = Target::new(addr2.into(), Some(vec![]));
        let target3 = Target::new(addr3.into(), Some(vec![]));
        let target4 = Target::new(addr4.into(), Some(vec![]));
        let max_attempts = 4;
        let num_threads = Some(8);
        let ret = icmp_ping(
            &[target1, target2, target3, target4],
            num_threads,
            src_ipv4,
            src_port,
            timeout,
            max_attempts,
        )
        .unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_icmp_ping_debug() {
        let _pr = PistolRunner::init(
            PistolLogger::None,
            Some(String::from("icmp_ping_debug.pcapng")),
            None, // use default value
        )
        .unwrap();
        let src_ipv4 = None;
        let src_port: Option<u16> = None;
        let timeout = Some(Duration::new(1, 0));
        let addr1 = Ipv4Addr::new(192, 168, 1, 2);
        let target1 = Target::new(addr1.into(), Some(vec![]));
        let max_attempts = 4;
        let num_threads = Some(8);
        let ret = icmp_ping(
            &[target1],
            num_threads,
            src_ipv4,
            src_port,
            timeout,
            max_attempts,
        )
        .unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_icmpv6_ping() {
        let _pr = PistolRunner::init(
            PistolLogger::None,
            Some(String::from("icmpv6_ping.pcapng")),
            None, // use default value
        )
        .unwrap();
        let src_port: Option<u16> = None;
        let src_addr = None;
        let addr1 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e4").unwrap();
        let addr2 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e5").unwrap();
        let addr3 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e6").unwrap();
        let target1 = Target::new(addr1.into(), Some(vec![80]));
        let target2 = Target::new(addr2.into(), Some(vec![80]));
        let target3 = Target::new(addr3.into(), Some(vec![80]));
        let max_attempts = 4;
        let num_threads = Some(8);
        let timeout = Some(Duration::new(1, 0));
        let ret = icmpv6_ping(
            &[target1, target2, target3],
            num_threads,
            src_addr,
            src_port,
            timeout,
            max_attempts,
        )
        .unwrap();
        println!("{}", ret);
    }
    #[test]
    #[ignore]
    fn test_github_issues_14() {
        use std::process::Command;
        let pid = std::process::id();
        let num_threads = Some(8);

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
                num_threads,
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
