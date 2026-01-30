#[cfg(feature = "ping")]
use chrono::DateTime;
#[cfg(feature = "ping")]
use chrono::Local;
#[cfg(feature = "ping")]
use pnet::datalink::MacAddr;
#[cfg(feature = "ping")]
use pnet::datalink::NetworkInterface;
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
use tracing::warn;

#[cfg(feature = "ping")]
pub mod icmp;
#[cfg(feature = "ping")]
pub mod icmpv6;

#[cfg(feature = "ping")]
use crate::NetInfo;
#[cfg(feature = "ping")]
use crate::error::PistolError;
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
use crate::utils;

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
    pub origin: IpAddr,
    pub status: PingStatus,
    pub cost: Duration,
}

#[cfg(feature = "ping")]
#[derive(Debug, Clone)]
pub struct PistolPings {
    pub ping_reports: Vec<PingReport>,
    pub start_time: DateTime<Local>,
    pub end_time: DateTime<Local>,
    attempts: usize,
}

#[cfg(feature = "ping")]
impl PistolPings {
    pub fn new(attempts: usize) -> PistolPings {
        PistolPings {
            ping_reports: Vec::new(),
            start_time: Local::now(),
            end_time: Local::now(),
            attempts,
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
            Cell::new(&format!("Ping Results (attempts:{})", self.attempts))
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
            let addr_str = if report.origin != report.addr {
                format!("{}({})", report.origin, report.addr)
            } else {
                format!("{}", report.addr)
            };
            let status_str = format!("{}", report.status);
            let rtt_str = utils::time_sec_to_string(report.cost);
            table.add_row(row![c -> i, c -> addr_str, c -> status_str, c -> rtt_str]);
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
    IcmpEcho,
    IcmpTimeStamp,
    IcmpAddressMask,
    Icmpv6Echo,
}

#[cfg(feature = "ping")]
fn ping_thread(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    dst_port: Option<u16>,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    interface: &NetworkInterface,
    method: PingMethods,
    timeout: Option<Duration>,
) -> Result<(PingStatus, DataRecvStatus, Duration), PistolError> {
    let timeout = match timeout {
        Some(t) => t,
        None => utils::get_attack_default_timeout(),
    };
    let (ping_status, data_return, rtt) = match method {
        PingMethods::Syn => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => SYN_PING_DEFAULT_PORT,
            };

            let (port_status, data_return, rtt) = tcp::send_syn_scan_packet(
                dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface, timeout,
            )?;
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

            let (ret, data_return, rtt) = tcp::send_ack_scan_packet(
                dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface, timeout,
            )?;
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

            let (ret, data_return, rtt) = udp::send_udp_scan_packet(
                dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface, timeout,
            )?;
            match ret {
                PortStatus::Open => (PingStatus::Up, data_return, rtt),
                // PortStatus::OpenOrFiltered => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, data_return, rtt),
            }
        }
        PingMethods::IcmpEcho => {
            let (ret, data_return, rtt) = icmp::send_icmp_echo_packet(
                dst_mac, dst_ipv4, src_mac, src_ipv4, interface, timeout,
            )?;
            (ret, data_return, rtt)
        }
        PingMethods::IcmpTimeStamp => {
            let (ret, data_return, rtt) = icmp::send_icmp_timestamp_packet(
                dst_mac, dst_ipv4, src_mac, src_ipv4, interface, timeout,
            )?;
            (ret, data_return, rtt)
        }
        PingMethods::IcmpAddressMask => {
            let (ret, data_return, rtt) = icmp::send_icmp_address_mask_packet(
                dst_mac, dst_ipv4, src_mac, src_ipv4, interface, timeout,
            )?;
            (ret, data_return, rtt)
        }
        PingMethods::Icmpv6Echo => {
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
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_port: Option<u16>,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    interface: &NetworkInterface,
    method: PingMethods,
    timeout: Option<Duration>,
) -> Result<(PingStatus, DataRecvStatus, Duration), PistolError> {
    let timeout = match timeout {
        Some(t) => t,
        None => utils::get_attack_default_timeout(),
    };
    let (ping_status, data_return, rtt) = match method {
        PingMethods::Syn => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => SYN_PING_DEFAULT_PORT,
            };

            let (ret, data_return, rtt) = tcp6::send_syn_scan_packet(
                dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, interface, timeout,
            )?;
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

            let (ret, data_return, rtt) = tcp6::send_ack_scan_packet(
                dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, interface, timeout,
            )?;
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

            let (ret, data_return, rtt) = udp6::send_udp_scan_packet(
                dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, interface, timeout,
            )?;
            match ret {
                PortStatus::Open => (PingStatus::Up, data_return, rtt),
                PortStatus::OpenOrFiltered => (PingStatus::Up, data_return, rtt),
                _ => (PingStatus::Down, data_return, rtt),
            }
        }
        PingMethods::IcmpEcho | PingMethods::IcmpTimeStamp | PingMethods::IcmpAddressMask => {
            return Err(PistolError::PingDetectionMethodError {
                target: dst_ipv6.into(),
                method: String::from("icmp"),
            });
        }
        PingMethods::Icmpv6Echo => icmpv6::send_icmpv6_ping_packet(
            dst_mac, dst_ipv6, src_mac, src_ipv6, interface, timeout,
        )?,
    };
    Ok((ping_status, data_return, rtt))
}

#[cfg(feature = "ping")]
fn ping(
    net_infos: &[NetInfo],
    method: PingMethods,
    threads: Option<usize>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPings, PistolError> {
    let mut pistol_pings = PistolPings::new(attempts);

    let threads = match threads {
        Some(t) => t,
        None => {
            let threads = net_infos.len();
            let threads = utils::num_threads_check(threads);
            threads
        }
    };

    let pool = utils::get_threads_pool(threads);
    let (tx, rx) = channel();
    let mut recv_size = 0;

    for ni in net_infos {
        let dst_mac = ni.dst_mac;
        let dst_addr = ni.dst_addr;
        let ori_dst_addr = ni.ori_dst_addr;
        let src_mac = ni.src_mac;
        let src_port = ni.src_port;
        let interface = ni.interface.clone();
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                let tx = tx.clone();
                let src_port = match src_port {
                    Some(p) => p,
                    None => utils::random_port(),
                };
                let dst_port = if ni.dst_ports.len() > 0 {
                    Some(ni.dst_ports[0])
                } else {
                    None
                };
                let src_ipv4 = match ni.src_addr {
                    IpAddr::V4(src) => src,
                    _ => return Err(PistolError::AttackAddressNotMatch { addr: ni.src_addr }),
                };

                let no_port_vec = vec![
                    PingMethods::IcmpEcho,
                    PingMethods::IcmpTimeStamp,
                    PingMethods::Icmpv6Echo,
                ];

                let dst_port = if !no_port_vec.contains(&method) {
                    dst_port
                } else {
                    None
                };
                recv_size += 1;
                pool.execute(move || {
                    for ind in 0..attempts {
                        let start_time = Instant::now();
                        let ping_ret = ping_thread(
                            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, &interface,
                            method, timeout,
                        );
                        if ind == attempts - 1 {
                            // last attempt
                            let _ =
                                tx.send((dst_addr, ori_dst_addr, ping_ret, start_time.elapsed()));
                        } else {
                            match ping_ret {
                                Ok((_port_status, data_return, _)) => {
                                    match data_return {
                                        DataRecvStatus::Yes => {
                                            // conclusions drawn from the returned data
                                            let _ = tx.send((
                                                dst_addr,
                                                ori_dst_addr,
                                                ping_ret,
                                                start_time.elapsed(),
                                            ));
                                            break; // quit loop now
                                        }
                                        // conclusions from the default policy
                                        DataRecvStatus::No => (), // continue probing
                                    }
                                }
                                Err(_) => {
                                    // stop probe immediately if an error occurs
                                    let _ = tx.send((
                                        dst_addr,
                                        ori_dst_addr,
                                        ping_ret,
                                        start_time.elapsed(),
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                });
            }
            IpAddr::V6(dst_ipv6) => {
                let src_ipv6 = match ni.src_addr {
                    IpAddr::V6(src) => src,
                    _ => return Err(PistolError::AttackAddressNotMatch { addr: ni.src_addr }),
                };
                let src_port = match src_port {
                    Some(p) => p,
                    None => utils::random_port(),
                };
                let tx = tx.clone();
                let dst_port = if ni.dst_ports.len() > 0 {
                    Some(ni.dst_ports[0])
                } else {
                    None
                };
                let dst_port =
                    if method != PingMethods::IcmpEcho && method != PingMethods::Icmpv6Echo {
                        dst_port
                    } else {
                        None
                    };
                recv_size += 1;
                pool.execute(move || {
                    for ind in 0..attempts {
                        let start_time = Instant::now();
                        let ping_ret = ping_thread6(
                            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, &interface,
                            method, timeout,
                        );
                        if ind == attempts - 1 {
                            // last attempt
                            let _ = tx.send((
                                dst_addr,
                                ori_dst_addr.clone(),
                                ping_ret,
                                start_time.elapsed(),
                            ));
                        } else {
                            match ping_ret {
                                Ok((_port_status, data_return, _)) => {
                                    match data_return {
                                        DataRecvStatus::Yes => {
                                            // conclusions drawn from the returned data
                                            let _ = tx.send((
                                                dst_addr,
                                                ori_dst_addr.clone(),
                                                ping_ret,
                                                start_time.elapsed(),
                                            ));
                                            break; // quit loop now
                                        }
                                        // conclusions from the default policy
                                        DataRecvStatus::No => (), // continue probing
                                    }
                                }
                                Err(_) => {
                                    // stop probe immediately if an error occurs
                                    let _ = tx.send((
                                        dst_addr,
                                        ori_dst_addr.clone(),
                                        ping_ret,
                                        start_time.elapsed(),
                                    ));
                                    break;
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
    for (dst_addr, origin, v, elapsed) in iter {
        match v {
            Ok((status, _data_return, rtt)) => {
                let ping_report = PingReport {
                    addr: dst_addr,
                    origin,
                    status,
                    cost: rtt,
                };
                reports.push(ping_report);
            }
            Err(e) => match e {
                PistolError::CanNotFoundMacAddress => {
                    let scan_report = PingReport {
                        addr: dst_addr,
                        origin,
                        status: PingStatus::Down,
                        cost: elapsed,
                    };
                    reports.push(scan_report);
                }
                _ => {
                    error!("ping error: {}", e);
                    let scan_report = PingReport {
                        addr: dst_addr,
                        origin,
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

#[cfg(feature = "ping")]
pub fn tcp_syn_ping(
    net_infos: &[NetInfo],
    threads: Option<usize>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPings, PistolError> {
    ping(net_infos, PingMethods::Syn, threads, timeout, attempts)
}

#[cfg(feature = "ping")]
pub fn ping_raw(
    net_info: &NetInfo,
    method: PingMethods,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolError> {
    let dst_mac = net_info.dst_mac;
    let dst_port = if net_info.dst_ports.len() > 0 {
        net_info.dst_ports[0]
    } else {
        match method {
            PingMethods::Syn => SYN_PING_DEFAULT_PORT,
            PingMethods::Ack => ACK_PING_DEFAULT_PORT,
            PingMethods::Udp => UDP_PING_DEFAULT_PORT,
            _ => 0,
        }
    };
    let src_mac = net_info.src_mac;
    let src_port = match net_info.src_port {
        Some(p) => p,
        None => utils::random_port(),
    };
    let timeout = match timeout {
        Some(t) => t,
        None => utils::get_attack_default_timeout(),
    };
    let interface = &net_info.interface;

    match net_info.dst_addr {
        IpAddr::V4(dst_ipv4) => {
            let src_ipv4 = match net_info.src_addr {
                IpAddr::V4(src) => src,
                _ => return Err(PistolError::AttackAddressNotMatch { addr: ni.src_addr }),
            };

            let (s, rtt) = match method {
                PingMethods::Syn => {
                    let (ret, _data_return, rtt) = tcp::send_syn_scan_packet(
                        dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface,
                        timeout,
                    )?;
                    match ret {
                        PortStatus::Open => (PingStatus::Up, rtt),
                        _ => (PingStatus::Down, rtt),
                    }
                }
                PingMethods::Ack => {
                    let (ret, _data_return, rtt) = tcp::send_ack_scan_packet(
                        dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface,
                        timeout,
                    )?;
                    match ret {
                        PortStatus::Unfiltered => (PingStatus::Up, rtt),
                        _ => (PingStatus::Down, rtt),
                    }
                }
                PingMethods::Udp => {
                    let (ret, _data_return, rtt) = udp::send_udp_scan_packet(
                        dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface,
                        timeout,
                    )?;
                    match ret {
                        PortStatus::Open => (PingStatus::Up, rtt),
                        // PortStatus::OpenOrFiltered => (PingStatus::Up, rtt),
                        _ => (PingStatus::Down, rtt),
                    }
                }
                PingMethods::IcmpEcho => {
                    let (ret, _data_return, rtt) = icmp::send_icmp_echo_packet(
                        dst_mac, dst_ipv4, src_mac, src_ipv4, interface, timeout,
                    )?;
                    (ret, rtt)
                }
                PingMethods::IcmpTimeStamp => {
                    let (ret, _data_return, rtt) = icmp::send_icmp_timestamp_packet(
                        dst_mac, dst_ipv4, src_mac, src_ipv4, interface, timeout,
                    )?;
                    (ret, rtt)
                }
                PingMethods::IcmpAddressMask => {
                    let (ret, _data_return, rtt) = icmp::send_icmp_address_mask_packet(
                        dst_mac, dst_ipv4, src_mac, src_ipv4, interface, timeout,
                    )?;
                    (ret, rtt)
                }
                PingMethods::Icmpv6Echo => {
                    warn!("icmpv6 ping method called on ipv4 target");
                    return Err(PistolError::PingDetectionMethodError {
                        target: dst_ipv4.into(),
                        method: String::from("Icmpv6Echo"),
                    });
                }
            };

            Ok((s, rtt))
        }
        IpAddr::V6(dst_ipv6) => {
            let src_ipv6 = match net_info.src_addr {
                IpAddr::V6(src) => src,
                _ => return Err(PistolError::AttackAddressNotMatch { addr: ni.src_addr }),
            };
            let (s, rtt) = match method {
                PingMethods::Syn => {
                    let (ret, _data_return, rtt) = tcp6::send_syn_scan_packet(
                        dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, &interface,
                        timeout,
                    )?;
                    match ret {
                        PortStatus::Open => (PingStatus::Up, rtt),
                        _ => (PingStatus::Down, rtt),
                    }
                }
                PingMethods::Ack => {
                    let (ret, _data_return, rtt) = tcp6::send_ack_scan_packet(
                        dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, &interface,
                        timeout,
                    )?;
                    match ret {
                        PortStatus::Unfiltered => (PingStatus::Up, rtt),
                        _ => (PingStatus::Down, rtt),
                    }
                }
                PingMethods::Udp => {
                    let (ret, _data_return, rtt) = udp6::send_udp_scan_packet(
                        dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, &interface,
                        timeout,
                    )?;
                    match ret {
                        PortStatus::Open => (PingStatus::Up, rtt),
                        // PortStatus::OpenOrFiltered => (PingStatus::Up, rtt),
                        _ => (PingStatus::Down, rtt),
                    }
                }
                PingMethods::IcmpEcho => {
                    warn!("icmp ping method called on ipv6 target");
                    return Err(PistolError::PingDetectionMethodError {
                        target: dst_ipv6.into(),
                        method: String::from("IcmpEcho"),
                    });
                }
                _ => {
                    let (ret, _data_return, rtt) = icmpv6::send_icmpv6_ping_packet(
                        dst_mac, dst_ipv6, src_mac, src_ipv6, &interface, timeout,
                    )?;
                    (ret, rtt)
                }
            };

            Ok((s, rtt))
        }
    }
}

/// TCP SYN Ping, raw version.
/// Only for one target and one port.
#[cfg(feature = "ping")]
pub fn tcp_syn_ping_raw(
    net_info: &NetInfo,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolError> {
    ping_raw(net_info, PingMethods::Syn, timeout)
}

#[cfg(feature = "ping")]
pub fn tcp_ack_ping(
    net_infos: &[NetInfo],
    threads: Option<usize>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPings, PistolError> {
    ping(net_infos, PingMethods::Ack, threads, timeout, attempts)
}

/// TCP ACK Ping, raw version.
/// Only for one target and one port.
#[cfg(feature = "ping")]
pub fn tcp_ack_ping_raw(
    net_info: &NetInfo,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolError> {
    ping_raw(net_info, PingMethods::Ack, timeout)
}

#[cfg(feature = "ping")]
pub fn udp_ping(
    net_infos: &[NetInfo],
    threads: Option<usize>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPings, PistolError> {
    ping(net_infos, PingMethods::Udp, threads, timeout, attempts)
}

/// UDP Ping, raw version.
#[cfg(feature = "ping")]
pub fn udp_ping_raw(
    net_info: &NetInfo,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolError> {
    ping_raw(net_info, PingMethods::Udp, timeout)
}

#[cfg(feature = "ping")]
pub fn icmp_echo_ping(
    net_infos: &[NetInfo],
    threads: Option<usize>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPings, PistolError> {
    ping(net_infos, PingMethods::IcmpEcho, threads, timeout, attempts)
}

#[cfg(feature = "ping")]
pub fn icmp_echo_ping_raw(
    net_info: &NetInfo,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolError> {
    ping_raw(net_info, PingMethods::IcmpEcho, timeout)
}

#[cfg(feature = "ping")]
pub fn icmp_timestamp_ping(
    net_infos: &[NetInfo],
    threads: Option<usize>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPings, PistolError> {
    ping(
        net_infos,
        PingMethods::IcmpTimeStamp,
        threads,
        timeout,
        attempts,
    )
}

#[cfg(feature = "ping")]
pub fn icmp_timestamp_ping_raw(
    net_info: &NetInfo,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolError> {
    ping_raw(net_info, PingMethods::IcmpTimeStamp, timeout)
}

#[cfg(feature = "ping")]
pub fn icmp_address_mask_ping(
    net_infos: &[NetInfo],
    threads: Option<usize>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPings, PistolError> {
    ping(
        net_infos,
        PingMethods::IcmpAddressMask,
        threads,
        timeout,
        attempts,
    )
}

#[cfg(feature = "ping")]
pub fn icmp_address_mask_ping_raw(
    net_info: &NetInfo,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolError> {
    ping_raw(net_info, PingMethods::IcmpAddressMask, timeout)
}

#[cfg(feature = "ping")]
pub fn icmpv6_ping(
    net_infos: &[NetInfo],
    threads: Option<usize>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPings, PistolError> {
    ping(
        net_infos,
        PingMethods::Icmpv6Echo,
        threads,
        timeout,
        attempts,
    )
}

#[cfg(feature = "ping")]
pub fn icmp_ping_raw(
    net_info: &NetInfo,
    timeout: Option<Duration>,
) -> Result<(PingStatus, Duration), PistolError> {
    ping_raw(net_info, PingMethods::IcmpEcho, timeout)
}

/*
#[cfg(feature = "ping")]
#[cfg(test)]
mod attempts {
    use super::*;
    use crate::Target;
    use std::str::FromStr;
    #[test]
    fn test_tcp_syn_ping() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 2));
        let addr2 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5));
        let addr3 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 10));
        let target1 = Target::new(addr1, Some(vec![80]));
        let target2 = Target::new(addr2, Some(vec![80]));
        let target3 = Target::new(addr3, Some(vec![80]));
        let attempts = 2;
        let threads = Some(8);
        let ret = tcp_syn_ping(
            &[target1, target2, target3],
            // &[target1, target2, target3],
            threads,
            src_ipv4,
            src_port,
            timeout,
            attempts,
        )
        .unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_tcp_syn_ping_raw() {
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
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
        let addr1 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e4").unwrap();
        let addr2 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e5").unwrap();
        let addr3 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e6").unwrap();
        let target1 = Target::new(addr1.into(), Some(vec![80]));
        let target2 = Target::new(addr2.into(), Some(vec![80]));
        let target3 = Target::new(addr3.into(), Some(vec![80]));
        let attempts = 4;
        let threads = Some(8);
        let ret = tcp_syn_ping(
            &[target1, target2, target3],
            threads,
            src_ipv4,
            src_port,
            timeout,
            attempts,
        )
        .unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_icmp_echo_ping() {
        let src_ipv4 = None;
        let src_port: Option<u16> = None;
        let timeout = Some(Duration::new(1, 0));
        let addr1 = Ipv4Addr::new(192, 168, 5, 5);
        // let addr2 = Ipv4Addr::new(192, 168, 5, 1);
        // let addr3 = Ipv4Addr::new(192, 168, 5, 100);
        // let addr4 = Ipv4Addr::new(192, 168, 1, 4);
        let target1 = Target::new(addr1.into(), Some(vec![]));
        // let target2 = Target::new(addr2.into(), Some(vec![]));
        // let target3 = Target::new(addr3.into(), Some(vec![]));
        // let target4 = Target::new(addr4.into(), Some(vec![]));
        let attempts = 4;
        let threads = Some(8);
        let ret = icmp_echo_ping(
            // &[target1, target2, target3, target4],
            &[target1],
            threads,
            src_ipv4,
            src_port,
            timeout,
            attempts,
        )
        .unwrap();

        println!("{}", ret);
    }
    #[test]
    fn test_icmp_timestamp_ping() {
        let src_ipv4 = None;
        let src_port: Option<u16> = None;
        let timeout = Some(Duration::new(1, 0));
        let addr1 = Ipv4Addr::new(192, 168, 5, 5);
        // let addr2 = Ipv4Addr::new(192, 168, 5, 1);
        // let addr3 = Ipv4Addr::new(192, 168, 5, 100);
        // let addr4 = Ipv4Addr::new(192, 168, 1, 4);
        let target1 = Target::new(addr1.into(), Some(vec![]));
        // let target2 = Target::new(addr2.into(), Some(vec![]));
        // let target3 = Target::new(addr3.into(), Some(vec![]));
        // let target4 = Target::new(addr4.into(), Some(vec![]));
        let attempts = 4;
        let threads = Some(8);
        let ret = icmp_timestamp_ping(
            // &[target1, target2, target3, target4],
            &[target1],
            threads,
            src_ipv4,
            src_port,
            timeout,
            attempts,
        )
        .unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_icmp_ping_debug() {
        let src_ipv4 = None;
        let src_port: Option<u16> = None;
        let timeout = Some(Duration::new(1, 0));
        let targets = Target::from_domain("scanme.nmap.org", None).unwrap();

        let attempts = 4;
        let threads = Some(8);
        let ret = icmp_echo_ping(&targets, threads, src_ipv4, src_port, timeout, attempts).unwrap();
        println!("{}", ret.ping_reports.len());
        println!("{}", ret);
    }
    #[test]
    fn test_icmpv6_ping() {
        let src_port: Option<u16> = None;
        let src_addr = None;
        let addr1 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e4").unwrap();
        let addr2 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e5").unwrap();
        let addr3 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e6").unwrap();
        let target1 = Target::new(addr1.into(), Some(vec![80]));
        let target2 = Target::new(addr2.into(), Some(vec![80]));
        let target3 = Target::new(addr3.into(), Some(vec![80]));
        let attempts = 4;
        let threads = Some(8);
        let timeout = Some(Duration::new(1, 0));
        let ret = icmpv6_ping(
            &[target1, target2, target3],
            threads,
            src_addr,
            src_port,
            timeout,
            attempts,
        )
        .unwrap();
        println!("{}", ret);
    }
    #[test]
    #[ignore]
    fn test_github_issues_14() {
        use std::process::Command;
        let pid = std::process::id();
        let threads = Some(8);

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
            let _ret = icmp_echo_ping(&[target], threads, None, None, Some(Duration::new(1, 0)), 1)
                .unwrap();
            // println!("{}\n{:?}", i, ret);
            println!("id: {}", i);
            // std::thread::sleep(Duration::new(1, 0));
        }
    }
}
*/
