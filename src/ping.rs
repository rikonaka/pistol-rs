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
#[derive(Debug, Clone, Copy)]
pub struct PingReport {
    pub addr: IpAddr,
    pub status: PingStatus,
    pub cost: Duration,
}

#[cfg(feature = "ping")]
#[derive(Debug, Clone, Copy)]
pub struct HostPing {
    pub layer2_cost: Duration,
    pub ping_report: Option<PingReport>,
    pub start_time: DateTime<Local>,
    pub end_time: DateTime<Local>,
    pub max_attempts: usize,
}

#[cfg(feature = "ping")]
impl HostPing {
    pub(crate) fn new(max_attempts: usize) -> Self {
        Self {
            layer2_cost: Duration::ZERO,
            ping_report: None,
            start_time: Local::now(),
            end_time: Local::now(),
            max_attempts,
        }
    }
    pub(crate) fn finish(&mut self, ping_report: Option<PingReport>) {
        self.end_time = Local::now();
        self.ping_report = ping_report;
    }
    pub fn report(&self) -> Option<PingReport> {
        self.ping_report.clone()
    }
}

#[cfg(feature = "ping")]
#[derive(Debug, Clone)]
pub struct HostPings {
    /// Searching ip on arp cache or send arp (or ndp_ns) packet will cost some time,
    /// so we record the cost seconds of layer2 here.
    pub layer2_cost: Duration,
    pub ping_reports: Vec<PingReport>,
    pub start_time: DateTime<Local>,
    pub end_time: DateTime<Local>,
    pub max_attempts: usize,
}

#[cfg(feature = "ping")]
impl HostPings {
    pub(crate) fn new(max_attempts: usize) -> HostPings {
        HostPings {
            layer2_cost: Duration::ZERO,
            ping_reports: Vec::new(),
            start_time: Local::now(),
            end_time: Local::now(),
            max_attempts,
        }
    }
    pub(crate) fn finish(&mut self, ping_reports: Vec<PingReport>) {
        self.end_time = Local::now();
        self.ping_reports = ping_reports;
    }
}

#[cfg(feature = "ping")]
impl fmt::Display for HostPings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let total_cost = self.end_time - self.start_time;

        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new(&format!("Pings (max_attempts:{})", self.max_attempts))
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
            let addr_str = format!("{}", report.addr);
            let status_str = format!("{}", report.status);
            let rtt_str = utils::time_sec_to_string(report.cost);
            table.add_row(row![c -> i, c -> addr_str, c -> status_str, c -> rtt_str]);
            i += 1;
        }

        // let help_info = "NOTE:\nThe target host is considered alive\nas long as one of the packets returns\na result that is considered to be alive.";
        // table.add_row(Row::new(vec![Cell::new(&help_info).with_hspan(4)]));

        let summary1 = format!(
            "start: {}, end: {}, max_attempts: {}",
            self.start_time.format("%Y-%m-%d %H:%M:%S"),
            self.end_time.format("%Y-%m-%d %H:%M:%S"),
            self.max_attempts,
        );
        let layer2_cost = self.layer2_cost.as_secs_f32();
        let avg_cost = total_cost.as_seconds_f64() / self.ping_reports.len() as f64;
        let summary2 = format!(
            "layer2 cost: {:.3}s, total cost: {:.3}s, avg cost: {:.3}s, alive hosts: {}",
            layer2_cost,
            total_cost.as_seconds_f64(),
            avg_cost,
            alive_hosts,
        );
        let summary = format!("{}\n{}", summary1, summary2);
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
    timeout: Duration,
) -> Result<(PingStatus, DataRecvStatus, Duration), PistolError> {
    let (ping_status, data_recv_status, rtt) = match method {
        PingMethods::Syn => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => SYN_PING_DEFAULT_PORT,
            };

            let (port_status, data_recv_status, rtt) = tcp::send_syn_scan_packet(
                dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface, timeout,
            )?;
            match port_status {
                PortStatus::Open => (PingStatus::Up, data_recv_status, rtt),
                _ => (PingStatus::Down, data_recv_status, rtt),
            }
        }
        PingMethods::Ack => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => ACK_PING_DEFAULT_PORT,
            };

            let (ret, data_recv_status, rtt) = tcp::send_ack_scan_packet(
                dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface, timeout,
            )?;
            match ret {
                PortStatus::Unfiltered => (PingStatus::Up, data_recv_status, rtt),
                _ => (PingStatus::Down, data_recv_status, rtt),
            }
        }
        PingMethods::Udp => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => UDP_PING_DEFAULT_PORT,
            };

            let (ret, data_recv_status, rtt) = udp::send_udp_scan_packet(
                dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface, timeout,
            )?;
            match ret {
                PortStatus::Open => (PingStatus::Up, data_recv_status, rtt),
                // PortStatus::OpenOrFiltered => (PingStatus::Up, rtt),
                _ => (PingStatus::Down, data_recv_status, rtt),
            }
        }
        PingMethods::IcmpEcho => {
            let (ret, data_recv_status, rtt) = icmp::send_icmp_echo_packet(
                dst_mac, dst_ipv4, src_mac, src_ipv4, interface, timeout,
            )?;
            (ret, data_recv_status, rtt)
        }
        PingMethods::IcmpTimeStamp => {
            let (ret, data_recv_status, rtt) = icmp::send_icmp_timestamp_packet(
                dst_mac, dst_ipv4, src_mac, src_ipv4, interface, timeout,
            )?;
            (ret, data_recv_status, rtt)
        }
        PingMethods::IcmpAddressMask => {
            let (ret, data_recv_status, rtt) = icmp::send_icmp_address_mask_packet(
                dst_mac, dst_ipv4, src_mac, src_ipv4, interface, timeout,
            )?;
            (ret, data_recv_status, rtt)
        }
        PingMethods::Icmpv6Echo => {
            return Err(PistolError::PingDetectionMethodError {
                target: dst_ipv4.into(),
                method: String::from("icmpv6"),
            });
        }
    };
    Ok((ping_status, data_recv_status, rtt))
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
    timeout: Duration,
) -> Result<(PingStatus, DataRecvStatus, Duration), PistolError> {
    let (ping_status, data_recv_status, rtt) = match method {
        PingMethods::Syn => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => SYN_PING_DEFAULT_PORT,
            };

            let (ret, data_recv_status, rtt) = tcp6::send_syn_scan_packet(
                dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, interface, timeout,
            )?;
            match ret {
                PortStatus::Open => (PingStatus::Up, data_recv_status, rtt),
                _ => (PingStatus::Down, data_recv_status, rtt),
            }
        }
        PingMethods::Ack => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => ACK_PING_DEFAULT_PORT,
            };

            let (ret, data_recv_status, rtt) = tcp6::send_ack_scan_packet(
                dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, interface, timeout,
            )?;
            match ret {
                PortStatus::Unfiltered => (PingStatus::Up, data_recv_status, rtt),
                _ => (PingStatus::Down, data_recv_status, rtt),
            }
        }
        PingMethods::Udp => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => UDP_PING_DEFAULT_PORT,
            };

            let (ret, data_recv_status, rtt) = udp6::send_udp_scan_packet(
                dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, interface, timeout,
            )?;
            match ret {
                PortStatus::Open => (PingStatus::Up, data_recv_status, rtt),
                PortStatus::OpenOrFiltered => (PingStatus::Up, data_recv_status, rtt),
                _ => (PingStatus::Down, data_recv_status, rtt),
            }
        }
        PingMethods::IcmpEcho | PingMethods::IcmpTimeStamp | PingMethods::IcmpAddressMask => {
            warn!(
                "run IcmpEcho/IcmpTimeStamp/IcmpAddressMask as Icmpv6Echo ping method on ipv6 target"
            );
            return Err(PistolError::PingDetectionMethodError {
                target: dst_ipv6.into(),
                method: String::from("icmp"),
            });
        }
        PingMethods::Icmpv6Echo => icmpv6::send_icmpv6_ping_packet(
            dst_mac, dst_ipv6, src_mac, src_ipv6, interface, timeout,
        )?,
    };
    Ok((ping_status, data_recv_status, rtt))
}

#[cfg(feature = "ping")]
fn ping(
    net_infos: Vec<NetInfo>,
    method: PingMethods,
    threads: usize,
    timeout: Duration,
    max_attempts: usize,
) -> Result<HostPings, PistolError> {
    let mut pistol_pings = HostPings::new(max_attempts);
    let pool = utils::get_threads_pool(threads);
    let (tx, rx) = channel();
    let mut recv_size = 0;

    for ni in net_infos {
        let dst_mac = ni.dst_mac;
        let dst_addr = ni.dst_addr;
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
                    for ind in 0..max_attempts {
                        let start_time = Instant::now();
                        let ping_ret = ping_thread(
                            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, &interface,
                            method, timeout,
                        );
                        if ind == max_attempts - 1 {
                            // last attempt
                            if let Err(e) = tx.send((dst_addr, ping_ret, start_time.elapsed())) {
                                error!("failed to send to tx on func ping: {}", e);
                            }
                        } else {
                            match ping_ret {
                                Ok((_port_status, data_recv_status, _)) => {
                                    match data_recv_status {
                                        DataRecvStatus::Yes => {
                                            // conclusions drawn from the returned data
                                            if let Err(e) =
                                                tx.send((dst_addr, ping_ret, start_time.elapsed()))
                                            {
                                                error!("failed to send to tx on func ping: {}", e);
                                            }
                                            break; // quit loop now
                                        }
                                        // conclusions from the default policy
                                        DataRecvStatus::No => (), // continue probing
                                    }
                                }
                                Err(_) => {
                                    // stop probe immediately if an error occurs
                                    if let Err(e) =
                                        tx.send((dst_addr, ping_ret, start_time.elapsed()))
                                    {
                                        error!("failed to send to tx on func ping: {}", e);
                                    }
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
                    for ind in 0..max_attempts {
                        let start_time = Instant::now();
                        let ping_ret = ping_thread6(
                            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, &interface,
                            method, timeout,
                        );
                        if ind == max_attempts - 1 {
                            // last attempt
                            if let Err(e) = tx.send((dst_addr, ping_ret, start_time.elapsed())) {
                                error!("failed to send to tx on func ping: {}", e);
                            }
                        } else {
                            match ping_ret {
                                Ok((_port_status, data_recv_status, _)) => {
                                    match data_recv_status {
                                        DataRecvStatus::Yes => {
                                            // conclusions drawn from the returned data
                                            if let Err(e) =
                                                tx.send((dst_addr, ping_ret, start_time.elapsed()))
                                            {
                                                error!("failed to send to tx on func ping: {}", e);
                                            }
                                            break; // quit loop now
                                        }
                                        // conclusions from the default policy
                                        DataRecvStatus::No => (), // continue probing
                                    }
                                }
                                Err(_) => {
                                    // stop probe immediately if an error occurs
                                    if let Err(e) =
                                        tx.send((dst_addr, ping_ret, start_time.elapsed()))
                                    {
                                        error!("failed to send to tx on func ping: {}", e);
                                    }
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
    for (dst_addr, ret, elapsed) in iter {
        match ret {
            Ok((status, _data_recv_status, rtt)) => {
                let ping_report = PingReport {
                    addr: dst_addr,
                    status,
                    cost: rtt,
                };
                reports.push(ping_report);
            }
            Err(e) => match e {
                PistolError::CanNotFoundDstMacAddress => {
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

#[cfg(feature = "ping")]
pub fn tcp_syn_ping(
    net_infos: Vec<NetInfo>,
    threads: usize,
    timeout: Duration,
    max_attempts: usize,
) -> Result<HostPings, PistolError> {
    ping(net_infos, PingMethods::Syn, threads, timeout, max_attempts)
}

#[cfg(feature = "ping")]
pub fn ping_raw(
    net_info: NetInfo,
    method: PingMethods,
    timeout: Duration,
    max_attempts: usize,
) -> Result<HostPing, PistolError> {
    let mut host_ping = HostPing::new(max_attempts);
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
    let interface = &net_info.interface;

    match net_info.dst_addr {
        IpAddr::V4(dst_ipv4) => {
            let src_ipv4 = match net_info.src_addr {
                IpAddr::V4(src) => src,
                _ => {
                    return Err(PistolError::AttackAddressNotMatch {
                        addr: net_info.src_addr,
                    });
                }
            };
            let mut status_x = PingStatus::Down;
            let mut rtt_x = Duration::ZERO;
            for i in 0..max_attempts {
                let (status, rtt) = match method {
                    PingMethods::Syn => {
                        let (ret, _data_recv_status, rtt) = tcp::send_syn_scan_packet(
                            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface,
                            timeout,
                        )?;
                        match ret {
                            PortStatus::Open => (PingStatus::Up, rtt),
                            _ => (PingStatus::Down, rtt),
                        }
                    }
                    PingMethods::Ack => {
                        let (ret, _data_recv_status, rtt) = tcp::send_ack_scan_packet(
                            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface,
                            timeout,
                        )?;
                        match ret {
                            PortStatus::Unfiltered => (PingStatus::Up, rtt),
                            _ => (PingStatus::Down, rtt),
                        }
                    }
                    PingMethods::Udp => {
                        let (ret, _data_recv_status, rtt) = udp::send_udp_scan_packet(
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
                        let (ret, _data_recv_status, rtt) = icmp::send_icmp_echo_packet(
                            dst_mac, dst_ipv4, src_mac, src_ipv4, interface, timeout,
                        )?;
                        (ret, rtt)
                    }
                    PingMethods::IcmpTimeStamp => {
                        let (ret, _data_recv_status, rtt) = icmp::send_icmp_timestamp_packet(
                            dst_mac, dst_ipv4, src_mac, src_ipv4, interface, timeout,
                        )?;
                        (ret, rtt)
                    }
                    PingMethods::IcmpAddressMask => {
                        let (ret, _data_recv_status, rtt) = icmp::send_icmp_address_mask_packet(
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
                match status {
                    PingStatus::Up => {
                        status_x = status;
                        rtt_x = rtt;
                        break;
                    }
                    _ => (),
                }

                if i == max_attempts - 1 {
                    // last attempt
                    status_x = status;
                    rtt_x = rtt;
                }
            }

            let ping_report = PingReport {
                addr: net_info.dst_addr,
                status: status_x,
                cost: rtt_x,
            };
            host_ping.finish(Some(ping_report));
            Ok(host_ping)
        }
        IpAddr::V6(dst_ipv6) => {
            let src_ipv6 = match net_info.src_addr {
                IpAddr::V6(src) => src,
                _ => {
                    return Err(PistolError::AttackAddressNotMatch {
                        addr: net_info.src_addr,
                    });
                }
            };
            let mut status_x = PingStatus::Down;
            let mut rtt_x = Duration::ZERO;
            for i in 0..max_attempts {
                let (status, rtt) = match method {
                    PingMethods::Syn => {
                        let (ret, _data_recv_status, rtt) = tcp6::send_syn_scan_packet(
                            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, &interface,
                            timeout,
                        )?;
                        match ret {
                            PortStatus::Open => (PingStatus::Up, rtt),
                            _ => (PingStatus::Down, rtt),
                        }
                    }
                    PingMethods::Ack => {
                        let (ret, _data_recv_status, rtt) = tcp6::send_ack_scan_packet(
                            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, &interface,
                            timeout,
                        )?;
                        match ret {
                            PortStatus::Unfiltered => (PingStatus::Up, rtt),
                            _ => (PingStatus::Down, rtt),
                        }
                    }
                    PingMethods::Udp => {
                        let (ret, _data_recv_status, rtt) = udp6::send_udp_scan_packet(
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
                        let (ret, _data_recv_status, rtt) = icmpv6::send_icmpv6_ping_packet(
                            dst_mac, dst_ipv6, src_mac, src_ipv6, &interface, timeout,
                        )?;
                        (ret, rtt)
                    }
                };
                match status {
                    PingStatus::Up => {
                        status_x = status;
                        rtt_x = rtt;
                        break;
                    }
                    _ => (),
                }

                if i == max_attempts - 1 {
                    // last attempt
                    status_x = status;
                    rtt_x = rtt;
                }
            }

            let ping_report = PingReport {
                addr: net_info.dst_addr,
                status: status_x,
                cost: rtt_x,
            };
            host_ping.finish(Some(ping_report));
            Ok(host_ping)
        }
    }
}

/// TCP SYN Ping, raw version.
/// Only for one target and one port.
#[cfg(feature = "ping")]
pub fn tcp_syn_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_attempts: usize,
) -> Result<HostPing, PistolError> {
    ping_raw(net_info, PingMethods::Syn, timeout, max_attempts)
}

#[cfg(feature = "ping")]
pub fn tcp_ack_ping(
    net_infos: Vec<NetInfo>,
    threads: usize,
    timeout: Duration,
    max_attempts: usize,
) -> Result<HostPings, PistolError> {
    ping(net_infos, PingMethods::Ack, threads, timeout, max_attempts)
}

/// TCP ACK Ping, raw version.
/// Only for one target and one port.
#[cfg(feature = "ping")]
pub fn tcp_ack_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_attempts: usize,
) -> Result<HostPing, PistolError> {
    ping_raw(net_info, PingMethods::Ack, timeout, max_attempts)
}

#[cfg(feature = "ping")]
pub fn udp_ping(
    net_infos: Vec<NetInfo>,
    threads: usize,
    timeout: Duration,
    max_attempts: usize,
) -> Result<HostPings, PistolError> {
    ping(net_infos, PingMethods::Udp, threads, timeout, max_attempts)
}

/// UDP Ping, raw version.
#[cfg(feature = "ping")]
pub fn udp_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_attempts: usize,
) -> Result<HostPing, PistolError> {
    ping_raw(net_info, PingMethods::Udp, timeout, max_attempts)
}

#[cfg(feature = "ping")]
pub fn icmp_echo_ping(
    net_infos: Vec<NetInfo>,
    threads: usize,
    timeout: Duration,
    max_attempts: usize,
) -> Result<HostPings, PistolError> {
    ping(
        net_infos,
        PingMethods::IcmpEcho,
        threads,
        timeout,
        max_attempts,
    )
}

#[cfg(feature = "ping")]
pub fn icmp_echo_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_attempts: usize,
) -> Result<HostPing, PistolError> {
    ping_raw(net_info, PingMethods::IcmpEcho, timeout, max_attempts)
}

#[cfg(feature = "ping")]
pub fn icmp_timestamp_ping(
    net_infos: Vec<NetInfo>,
    threads: usize,
    timeout: Duration,
    max_attempts: usize,
) -> Result<HostPings, PistolError> {
    ping(
        net_infos,
        PingMethods::IcmpTimeStamp,
        threads,
        timeout,
        max_attempts,
    )
}

#[cfg(feature = "ping")]
pub fn icmp_timestamp_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_attempts: usize,
) -> Result<HostPing, PistolError> {
    ping_raw(net_info, PingMethods::IcmpTimeStamp, timeout, max_attempts)
}

#[cfg(feature = "ping")]
pub fn icmp_address_mask_ping(
    net_infos: Vec<NetInfo>,
    threads: usize,
    timeout: Duration,
    max_attempts: usize,
) -> Result<HostPings, PistolError> {
    ping(
        net_infos,
        PingMethods::IcmpAddressMask,
        threads,
        timeout,
        max_attempts,
    )
}

#[cfg(feature = "ping")]
pub fn icmp_address_mask_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_attempts: usize,
) -> Result<HostPing, PistolError> {
    ping_raw(
        net_info,
        PingMethods::IcmpAddressMask,
        timeout,
        max_attempts,
    )
}

#[cfg(feature = "ping")]
pub fn icmpv6_ping(
    net_infos: Vec<NetInfo>,
    threads: usize,
    timeout: Duration,
    max_attempts: usize,
) -> Result<HostPings, PistolError> {
    ping(
        net_infos,
        PingMethods::Icmpv6Echo,
        threads,
        timeout,
        max_attempts,
    )
}

#[cfg(feature = "ping")]
pub fn icmp_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_attempts: usize,
) -> Result<HostPing, PistolError> {
    ping_raw(net_info, PingMethods::IcmpEcho, timeout, max_attempts)
}

#[cfg(feature = "ping")]
#[cfg(test)]
mod max_attempts {
    use super::*;
    use crate::Pistol;
    use crate::Target;
    use std::process::Command;
    use std::str::FromStr;
    #[test]
    fn test_tcp_syn_ping() {
        let src_addr = None;
        let src_port = None;
        let timeout = Duration::new(1, 0);
        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 2));
        let addr2 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5));
        let addr3 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 10));
        let target1 = Target::new(addr1, Some(vec![80]));
        let target2 = Target::new(addr2, Some(vec![80]));
        let target3 = Target::new(addr3, Some(vec![80]));
        let targets = vec![target1, target2, target3];
        let max_attempts = 2;
        let threads = 8;

        let mut pistol = Pistol::new();
        let (net_infos, dur) = pistol.init_recver(&targets, src_addr, src_port).unwrap();
        let ret = tcp_syn_ping(net_infos, threads, timeout, max_attempts).unwrap();
        println!("layer2: {:.3}s, {}", dur.as_secs_f32(), ret);
    }
    #[test]
    fn test_tcp_syn_ping_raw() {
        let src_addr = None;
        let src_port = None;
        let timeout = Duration::new(3, 0);
        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5));
        let dst_ports = vec![80];
        let max_attempts = 2;

        let mut pistol = Pistol::new();
        let (net_info, dur) = pistol
            .init_recver_raw(addr1, dst_ports, src_addr, src_port)
            .unwrap();
        let ret = tcp_syn_ping_raw(net_info, timeout, max_attempts).unwrap();
        println!("layer2: {:.3}s, {:?}", dur.as_secs_f32(), ret);
    }
    #[test]
    fn test_tcp_syn_ping6() {
        let src_addr = None;
        let src_port = None;
        let timeout = Duration::new(1, 0);
        let addr1 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e4").unwrap();
        let addr2 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e5").unwrap();
        let addr3 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e6").unwrap();
        let target1 = Target::new(addr1.into(), Some(vec![80]));
        let target2 = Target::new(addr2.into(), Some(vec![80]));
        let target3 = Target::new(addr3.into(), Some(vec![80]));
        let targets = vec![target1, target2, target3];
        let max_attempts = 4;
        let threads = 8;

        let mut pistol = Pistol::new();
        let (net_infos, dur) = pistol.init_recver(&targets, src_addr, src_port).unwrap();
        let ret = tcp_syn_ping(net_infos, threads, timeout, max_attempts).unwrap();
        println!("layer2: {:.3}s, {}", dur.as_secs_f32(), ret);
    }
    #[test]
    fn test_icmp_echo_ping() {
        let src_addr = None;
        let src_port: Option<u16> = None;
        let timeout = Duration::new(1, 0);
        let addr1 = Ipv4Addr::new(192, 168, 5, 5);
        // let addr2 = Ipv4Addr::new(192, 168, 5, 1);
        // let addr3 = Ipv4Addr::new(192, 168, 5, 100);
        // let addr4 = Ipv4Addr::new(192, 168, 1, 4);
        let target1 = Target::new(addr1.into(), Some(vec![]));
        // let target2 = Target::new(addr2.into(), Some(vec![]));
        // let target3 = Target::new(addr3.into(), Some(vec![]));
        // let target4 = Target::new(addr4.into(), Some(vec![]));
        let targets = vec![target1];
        let max_attempts = 4;
        let threads = 8;

        let mut pistol = Pistol::new();
        let (net_infos, dur) = pistol.init_recver(&targets, src_addr, src_port).unwrap();
        let ret = icmp_echo_ping(net_infos, threads, timeout, max_attempts).unwrap();
        println!("layer2: {:.3}s, {}", dur.as_secs_f32(), ret);
    }
    #[test]
    fn test_icmp_timestamp_ping() {
        let src_addr = None;
        let src_port: Option<u16> = None;
        let timeout = Duration::new(1, 0);
        let addr1 = Ipv4Addr::new(192, 168, 5, 5);
        // let addr2 = Ipv4Addr::new(192, 168, 5, 1);
        // let addr3 = Ipv4Addr::new(192, 168, 5, 100);
        // let addr4 = Ipv4Addr::new(192, 168, 1, 4);
        let target1 = Target::new(addr1.into(), Some(vec![]));
        // let target2 = Target::new(addr2.into(), Some(vec![]));
        // let target3 = Target::new(addr3.into(), Some(vec![]));
        // let target4 = Target::new(addr4.into(), Some(vec![]));
        let targets = vec![target1];
        let max_attempts = 4;
        let threads = 8;

        let mut pistol = Pistol::new();
        let (net_infos, dur) = pistol.init_recver(&targets, src_addr, src_port).unwrap();
        let ret = icmp_timestamp_ping(net_infos, threads, timeout, max_attempts).unwrap();
        println!("layer2: {:.3}s, {}", dur.as_secs_f32(), ret);
    }
    #[test]
    fn test_icmp_ping_debug() {
        let src_addr = None;
        let src_port: Option<u16> = None;
        let timeout = Duration::new(1, 0);
        let targets = Target::from_domain("scanme.nmap.org", None).unwrap();
        let max_attempts = 4;
        let threads = 8;

        let mut pistol = Pistol::new();
        let (net_infos, dur) = pistol.init_recver(&targets, src_addr, src_port).unwrap();
        let ret = icmp_echo_ping(net_infos, threads, timeout, max_attempts).unwrap();
        println!("layer2: {:.3}s, {}", dur.as_secs_f32(), ret);
    }
    #[test]
    fn test_icmpv6_ping() {
        let src_port = None;
        let src_addr = None;
        let addr1 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e4").unwrap();
        let addr2 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e5").unwrap();
        let addr3 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e6").unwrap();
        let target1 = Target::new(addr1.into(), Some(vec![80]));
        let target2 = Target::new(addr2.into(), Some(vec![80]));
        let target3 = Target::new(addr3.into(), Some(vec![80]));
        let targets = vec![target1, target2, target3];
        let max_attempts = 4;
        let threads = 8;
        let timeout = Duration::new(1, 0);

        let mut pistol = Pistol::new();
        let (net_infos, dur) = pistol.init_recver(&targets, src_addr, src_port).unwrap();
        let ret = icmpv6_ping(net_infos, threads, timeout, max_attempts).unwrap();
        println!("layer2: {:.3}s, {}", dur.as_secs_f32(), ret);
    }
    #[test]
    #[ignore]
    fn test_github_issues_14() {
        let pid = std::process::id();

        let threads = 8;
        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 2));
        let target = Target::new(addr1, None);
        let targets = vec![target];
        let timeout = Duration::new(1, 0);
        let max_attempts = 1;

        let mut pistol = Pistol::new();
        let (net_infos, _dur) = pistol.init_recver(&targets, None, None).unwrap();
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

            let _ret = icmp_echo_ping(net_infos.clone(), threads, timeout, max_attempts).unwrap();
            println!("id: {}", i);
            // std::thread::sleep(Duration::new(1, 0));
        }
    }
}
