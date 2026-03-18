#[cfg(feature = "ping")]
use chrono::DateTime;
#[cfg(feature = "ping")]
use chrono::Local;
#[cfg(feature = "ping")]
use crossbeam::channel::Receiver;
#[cfg(feature = "ping")]
use crossbeam::channel::Sender;
#[cfg(feature = "ping")]
use pnet::packet::Packet;
#[cfg(feature = "ping")]
use pnet::packet::ethernet::EtherTypes;
#[cfg(feature = "ping")]
use pnet::packet::ethernet::EthernetPacket;
#[cfg(feature = "ping")]
use pnet::packet::ipv4::Ipv4Packet;
#[cfg(feature = "ping")]
use pnet::packet::ipv6::Ipv6Packet;
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
use std::sync::Arc;
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
use crate::RRequest;
#[cfg(feature = "ping")]
use crate::RResponse;
#[cfg(feature = "ping")]
use crate::SRequest;
#[cfg(feature = "ping")]
use crate::error::PistolError;
#[cfg(feature = "ping")]
use crate::layer::PacketFilter;
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
use crate::utils::random_port;
#[cfg(feature = "ping")]
use crate::utils::random_recv_msg_id;
#[cfg(feature = "ping")]
use crate::utils::time_to_string;

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
    cached: bool,
}

impl PingReport {
    pub fn is_up(&self) -> bool {
        self.status == PingStatus::Up
    }
}

#[cfg(feature = "ping")]
#[derive(Debug, Clone, Copy)]
pub struct HostPing {
    pub layer2_cost: Duration,
    pub ping_report: Option<PingReport>,
    pub start_time: DateTime<Local>,
    pub finish_time: DateTime<Local>,
    pub max_retries: usize,
}

#[cfg(feature = "ping")]
impl fmt::Display for HostPing {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let total_cost = self.finish_time - self.start_time;

        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Pings").style_spec("c").with_hspan(3),
        ]));

        table.add_row(row![
            c -> "addr",
            c -> "status",
            c -> "time cost"
        ]);

        match self.ping_report {
            Some(report) => {
                let addr_str = format!("{}", report.addr);
                let status_str = format!("{}", report.status);
                let time_cost_str = if report.cached {
                    time_to_string(report.cost)
                } else {
                    let time_cost_str = time_to_string(report.cost);
                    format!("{}(cached)", time_cost_str)
                };
                table.add_row(row![c -> addr_str, c -> status_str, c -> time_cost_str]);
            }
            None => (),
        }

        // let help_info = "NOTE:\nThe target host is considered alive\nas long as one of the packets returns\na result that is considered to be alive.";
        // table.add_row(Row::new(vec![Cell::new(&help_info).with_hspan(4)]));

        let summary1 = format!(
            "start at: {}, finish at: {}, max_retries: {}",
            self.start_time.format("%Y-%m-%d %H:%M:%S"),
            self.finish_time.format("%Y-%m-%d %H:%M:%S"),
            self.max_retries,
        );
        let layer2_cost = self.layer2_cost.as_secs_f32();
        let summary2 = format!(
            "layer2 cost: {:.2}s, total cost: {:.2}s",
            layer2_cost,
            total_cost.as_seconds_f64(),
        );
        let summary = format!("{}\n{}", summary1, summary2);
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(3)]));
        write!(f, "{}", table)
    }
}

#[cfg(feature = "ping")]
impl HostPing {
    pub(crate) fn new(max_retries: usize) -> Self {
        Self {
            layer2_cost: Duration::ZERO,
            ping_report: None,
            start_time: Local::now(),
            finish_time: Local::now(),
            max_retries,
        }
    }
    pub(crate) fn finish(&mut self, ping_report: Option<PingReport>) {
        self.finish_time = Local::now();
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
    pub finish_time: DateTime<Local>,
    pub max_retries: usize,
}

#[cfg(feature = "ping")]
impl fmt::Display for HostPings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let total_cost = self.finish_time - self.start_time;

        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Pings").style_spec("c").with_hspan(4),
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
            let time_cost_str = if report.cached {
                time_to_string(report.cost)
            } else {
                let time_cost_str = time_to_string(report.cost);
                format!("{}(cached)", time_cost_str)
            };
            table.add_row(row![c -> i, c -> addr_str, c -> status_str, c -> time_cost_str]);
            i += 1;
        }

        // let help_info = "NOTE:\nThe target host is considered alive\nas long as one of the packets returns\na result that is considered to be alive.";
        // table.add_row(Row::new(vec![Cell::new(&help_info).with_hspan(4)]));

        let summary1 = format!(
            "start at: {}, finish at: {}, max_retries: {}",
            self.start_time.format("%Y-%m-%d %H:%M:%S"),
            self.finish_time.format("%Y-%m-%d %H:%M:%S"),
            self.max_retries,
        );
        let layer2_cost = self.layer2_cost.as_secs_f32();
        let avg_cost = total_cost.as_seconds_f64() / self.ping_reports.len() as f64;
        let summary2 = format!(
            "layer2 cost: {:.2}s, total cost: {:.2}s, avg cost: {:.2}s, alive hosts: {}",
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
impl HostPings {
    pub(crate) fn new(max_retries: usize) -> HostPings {
        HostPings {
            layer2_cost: Duration::ZERO,
            ping_reports: Vec::new(),
            start_time: Local::now(),
            finish_time: Local::now(),
            max_retries,
        }
    }
    pub(crate) fn finish(&mut self, ping_reports: Vec<PingReport>) {
        self.finish_time = Local::now();
        self.ping_reports = ping_reports;
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
fn build_ping_buff(
    dst_ipv4: Ipv4Addr,
    dst_port: Option<u16>,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    method: PingMethods,
) -> Result<(Arc<[u8]>, Vec<Arc<PacketFilter>>), PistolError> {
    match method {
        PingMethods::Syn => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => SYN_PING_DEFAULT_PORT,
            };
            let (buff, filters) =
                tcp::build_syn_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port)?;
            Ok((buff, filters))
        }
        PingMethods::Ack => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => ACK_PING_DEFAULT_PORT,
            };
            let (buff, filters) =
                tcp::build_ack_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port)?;
            Ok((buff, filters))
        }
        PingMethods::Udp => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => UDP_PING_DEFAULT_PORT,
            };
            let (buff, filters) =
                udp::build_udp_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port)?;
            Ok((buff, filters))
        }
        PingMethods::IcmpEcho => {
            let (buff, filters) = icmp::build_icmp_echo_packet(dst_ipv4, src_ipv4)?;
            Ok((buff, filters))
        }
        PingMethods::IcmpTimeStamp => {
            let (buff, filters) = icmp::build_icmp_timestamp_packet(dst_ipv4, src_ipv4)?;
            Ok((buff, filters))
        }
        PingMethods::IcmpAddressMask => {
            let (buff, filters) = icmp::build_icmp_address_mask_packet(dst_ipv4, src_ipv4)?;
            Ok((buff, filters))
        }
        PingMethods::Icmpv6Echo => {
            return Err(PistolError::PingDetectionMethodError {
                target: dst_ipv4.into(),
                method: String::from("icmpv6"),
            });
        }
    }
}

#[cfg(feature = "ping")]
fn build_ping_buff6(
    dst_ipv6: Ipv6Addr,
    dst_port: Option<u16>,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    method: PingMethods,
) -> Result<(Arc<[u8]>, Vec<Arc<PacketFilter>>), PistolError> {
    match method {
        PingMethods::Syn => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => SYN_PING_DEFAULT_PORT,
            };
            let (buff, filters) =
                tcp6::build_syn_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port)?;
            Ok((buff, filters))
        }
        PingMethods::Ack => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => ACK_PING_DEFAULT_PORT,
            };
            let (buff, filters) =
                tcp6::build_ack_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port)?;
            Ok((buff, filters))
        }
        PingMethods::Udp => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => UDP_PING_DEFAULT_PORT,
            };
            let (buff, filters) =
                udp6::send_udp_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port)?;
            Ok((buff, filters))
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
        PingMethods::Icmpv6Echo => {
            let (buff, filters) = icmpv6::send_icmpv6_ping_packet(dst_ipv6, src_ipv6)?;
            Ok((buff, filters))
        }
    }
}

#[cfg(feature = "ping")]
fn parse_response(method: PingMethods, eth_response: Arc<[u8]>) -> Result<PingStatus, PistolError> {
    let parse_ipv4 = |dst_ipv4: Ipv4Addr| -> Result<PingStatus, PistolError> {
        let eth_response_clone = eth_response.clone();
        match method {
            PingMethods::Syn => {
                let port_status = tcp::parse_syn_scan_response(eth_response_clone)?;
                let ping_status = match port_status {
                    PortStatus::Open => PingStatus::Up,
                    _ => PingStatus::Down,
                };
                Ok(ping_status)
            }
            PingMethods::Ack => {
                let port_status = tcp::parse_ack_scan_response(eth_response_clone)?;
                let ping_status = match port_status {
                    PortStatus::Unfiltered => PingStatus::Up,
                    _ => PingStatus::Down,
                };
                Ok(ping_status)
            }
            PingMethods::Udp => {
                let port_status = udp::parse_udp_scan_response(eth_response_clone)?;
                let ping_status = match port_status {
                    PortStatus::Open => PingStatus::Up,
                    // PortStatus::OpenOrFiltered => PingStatus::Up,
                    _ => PingStatus::Down,
                };
                Ok(ping_status)
            }
            PingMethods::IcmpEcho => {
                let ping_status = icmp::parse_icmp_echo_response(eth_response_clone)?;
                Ok(ping_status)
            }
            PingMethods::IcmpTimeStamp => {
                let ping_status = icmp::parse_icmp_timestamp_response(eth_response_clone)?;
                Ok(ping_status)
            }
            PingMethods::IcmpAddressMask => {
                let ping_status = icmp::parse_icmp_address_mask_response(eth_response_clone)?;
                Ok(ping_status)
            }
            PingMethods::Icmpv6Echo => Err(PistolError::PingDetectionMethodError {
                target: dst_ipv4.into(),
                method: String::from("icmpv6"),
            }),
        }
    };
    let parse_ipv6 = |dst_ipv6: Ipv6Addr| -> Result<PingStatus, PistolError> {
        let eth_response_clone = eth_response.clone();
        match method {
            PingMethods::Syn => {
                let port_status = tcp6::parse_syn_scan_response(eth_response_clone)?;
                let ping_status = match port_status {
                    PortStatus::Open => PingStatus::Up,
                    _ => PingStatus::Down,
                };
                Ok(ping_status)
            }
            PingMethods::Ack => {
                let port_status = tcp6::parse_ack_scan_response(eth_response_clone)?;
                let ping_status = match port_status {
                    PortStatus::Unfiltered => PingStatus::Up,
                    _ => PingStatus::Down,
                };
                Ok(ping_status)
            }
            PingMethods::Udp => {
                let port_status = udp6::parse_udp_scan_response(eth_response_clone)?;
                let ping_status = match port_status {
                    PortStatus::Open => PingStatus::Up,
                    PortStatus::OpenOrFiltered => PingStatus::Up,
                    _ => PingStatus::Down,
                };
                Ok(ping_status)
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
            PingMethods::Icmpv6Echo => {
                let ping_status = icmpv6::parse_icmpv6_ping_response(eth_response_clone)?;
                Ok(ping_status)
            }
        }
    };

    match EthernetPacket::new(&eth_response) {
        Some(eth_packet) => match eth_packet.get_ethertype() {
            EtherTypes::Ipv4 => match Ipv4Packet::new(eth_packet.payload()) {
                Some(ip_packet) => {
                    let dst_ipv4 = ip_packet.get_destination();
                    return parse_ipv4(dst_ipv4);
                }
                None => (),
            },
            EtherTypes::Ipv6 => match Ipv6Packet::new(eth_packet.payload()) {
                Some(ip_packet) => {
                    let dst_ipv6 = ip_packet.get_destination();
                    return parse_ipv6(dst_ipv6);
                }
                None => (),
            },
            _ => (),
        },
        None => (),
    }

    Err(PistolError::PingParseResponseError)
}

#[derive(Debug, Clone)]
struct ScanStatus {
    retried: usize,
    data_recved: bool,
}

#[cfg(feature = "ping")]
fn ping(
    net_infos: Vec<NetInfo>,
    method: PingMethods,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<HostPings, PistolError> {
    let mut pistol_pings = HostPings::new(max_retries);
    let mut reports = Vec::new();

    let mut scan_status = HashMap::new();
    for ni in net_infos {
        // (0, false, None, start) => (retiries, has data recved?, receiver, send probe time)
        if ni.valid {
            let status = ScanStatus {
                retried: 0,
                data_recved: false,
            };
            scan_status.insert(ni, status);
        }
    }

    let mut recv_msg_ids = HashMap::new();
    let mut scan_status_clone = scan_status.clone();
    loop {
        let mut all_done = true;
        for (ni, status) in scan_status {
            let dst_mac = ni.inferred_dst_mac;
            let dst_addr = ni.inferred_dst_addr;
            let src_mac = ni.inferred_src_mac;
            let src_port = ni.src_port;
            match dst_addr {
                IpAddr::V4(dst_ipv4) => {
                    let src_port = match src_port {
                        Some(p) => p,
                        None => random_port(),
                    };
                    let dst_port = if ni.dst_ports.len() > 0 {
                        Some(ni.dst_ports[0])
                    } else {
                        None
                    };
                    let src_ipv4 = match ni.inferred_src_addr {
                        IpAddr::V4(src) => src,
                        _ => {
                            return Err(PistolError::AttackAddressNotMatch {
                                addr: ni.inferred_src_addr,
                            });
                        }
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

                    let retried = status.retried;
                    let data_recved = status.data_recved;
                    if retried < max_retries && !data_recved {
                        let (buff, filters) =
                            build_ping_buff(dst_ipv4, dst_port, src_ipv4, src_port, method)?;

                        let interface_name = ni.interface_name.clone();
                        let rrq_id = random_recv_msg_id();
                        let rrq = RRequest {
                            interface_name: interface_name.clone(),
                            id: rrq_id,
                            filters,
                            created: Instant::now(),
                            elapsed: timeout,
                        };
                        let srq = SRequest {
                            interface_name: interface_name.clone(),
                            dst_mac,
                            src_mac,
                            eth_payload: buff,
                            eth_type: EtherTypes::Ipv4,
                            retransmit: 1,
                        };
                        if let Err(e) = push_rd.send(rrq) {
                            error!("ipv4 send ping recv msg error: {}", e);
                        }
                        if let Err(e) = push_sd.send(srq) {
                            error!("ipv4 send ping send msg error: {}", e);
                        }

                        recv_msg_ids.insert(rrq_id, dst_addr);

                        let mut status_clone = status.clone();
                        status_clone.retried = retried + 1;
                        scan_status_clone.insert(ni.clone(), status_clone);

                        all_done = false;
                    }
                }
                IpAddr::V6(dst_ipv6) => {
                    let src_ipv6 = match ni.inferred_src_addr {
                        IpAddr::V6(src) => src,
                        _ => {
                            return Err(PistolError::AttackAddressNotMatch {
                                addr: ni.inferred_src_addr,
                            });
                        }
                    };
                    let src_port = match src_port {
                        Some(p) => p,
                        None => random_port(),
                    };
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

                    let retried = status.retried;
                    let data_recved = status.data_recved;
                    if retried < max_retries && !data_recved {
                        let (buff, filters) =
                            build_ping_buff6(dst_ipv6, dst_port, src_ipv6, src_port, method)?;

                        let interface_name = ni.interface_name.clone();
                        let rrq_id = random_recv_msg_id();
                        let rrq = RRequest {
                            interface_name: interface_name.clone(),
                            id: rrq_id,
                            filters,
                            created: Instant::now(),
                            elapsed: timeout,
                        };
                        let srq = SRequest {
                            interface_name: interface_name.clone(),
                            dst_mac,
                            src_mac,
                            eth_payload: buff,
                            eth_type: EtherTypes::Ipv6,
                            retransmit: 1,
                        };
                        if let Err(e) = push_rd.send(rrq) {
                            error!("ipv4 send ping recv msg error: {}", e);
                        }
                        if let Err(e) = push_sd.send(srq) {
                            error!("ipv4 send ping send msg error: {}", e);
                        }

                        recv_msg_ids.insert(rrq_id, dst_addr);

                        let mut status_clone = status.clone();
                        status_clone.retried = retried + 1;
                        scan_status_clone.insert(ni.clone(), status_clone);

                        all_done = false;
                    }
                }
            }
        }

        if all_done {
            break;
        }
        scan_status = scan_status_clone.clone();

        let timeout_10ms = Duration::from_millis(10);
        let recv_start = Instant::now();
        loop {
            if recv_start.elapsed() > timeout {
                break;
            }

            let recv_response = match get_response.recv_timeout(timeout_10ms) {
                Ok(r) => {
                    if recv_msg_ids.contains_key(&r.id) {
                        r
                    } else {
                        continue;
                    }
                }
                Err(_e) => continue,
            };

            match parse_response(method, recv_response.data) {
                Ok(ps) => {
                    let dst_addr = recv_msg_ids[&recv_response.id];
                    let rtt = recv_response.rtt;
                    let mut cached = false;
                    for (ni, _status) in &scan_status {
                        if ni.inferred_dst_addr == dst_addr {
                            cached = ni.cached;
                        }
                    }
                    let ping_report = PingReport {
                        addr: dst_addr,
                        status: ps,
                        cost: rtt,
                        cached,
                    };
                    reports.push(ping_report);

                    for (ni, status) in &scan_status {
                        if ni.inferred_dst_addr == dst_addr {
                            let mut status_clone = status.clone();
                            status_clone.data_recved = true;
                            scan_status_clone.insert(ni.clone(), status_clone);
                        }
                    }
                }
                Err(e) => {
                    error!("parse ping response error: {}", e);
                    continue;
                }
            }
        }
        scan_status = scan_status_clone.clone();
    }
    pistol_pings.finish(reports);
    Ok(pistol_pings)
}

#[cfg(feature = "ping")]
pub fn ping_raw(
    net_info: NetInfo,
    method: PingMethods,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<HostPing, PistolError> {
    let mut host_ping = HostPing::new(max_retries);
    if !net_info.valid {
        host_ping.finish(None);
        return Ok(host_ping);
    }

    let dst_mac = net_info.inferred_dst_mac;
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
    let src_mac = net_info.inferred_src_mac;
    let src_port = match net_info.src_port {
        Some(p) => p,
        None => random_port(),
    };

    match net_info.inferred_dst_addr {
        IpAddr::V4(dst_ipv4) => {
            let src_ipv4 = match net_info.inferred_src_addr {
                IpAddr::V4(src) => src,
                _ => {
                    return Err(PistolError::AttackAddressNotMatch {
                        addr: net_info.inferred_src_addr,
                    });
                }
            };
            for i in 0..max_retries {
                let (buff, filters) =
                    build_ping_buff(dst_ipv4, Some(dst_port), src_ipv4, src_port, method)?;

                let interface_name = net_info.interface_name.clone();
                let rrq_id = random_recv_msg_id();
                let rrq = RRequest {
                    interface_name: interface_name.clone(),
                    id: rrq_id,
                    filters,
                    created: Instant::now(),
                    elapsed: timeout,
                };
                let srq = SRequest {
                    interface_name: interface_name.clone(),
                    dst_mac,
                    src_mac,
                    eth_payload: buff,
                    eth_type: EtherTypes::Ipv4,
                    retransmit: 1,
                };
                if let Err(e) = push_rd.send(rrq) {
                    error!("ipv4 send ping recv msg error: {}", e);
                }
                if let Err(e) = push_sd.send(srq) {
                    error!("ipv4 send ping send msg error: {}", e);
                }

                let recv_response = match get_response.recv_timeout(timeout) {
                    Ok(r) => {
                        if r.id == rrq_id {
                            r
                        } else {
                            continue;
                        }
                    }
                    Err(_e) => {
                        continue;
                    }
                };

                let status = parse_response(method, recv_response.data)?;
                if status == PingStatus::Up || i == max_retries - 1 {
                    let rtt = recv_response.rtt;
                    let ping_report = PingReport {
                        addr: net_info.inferred_dst_addr,
                        status,
                        cost: rtt,
                        cached: net_info.cached,
                    };
                    host_ping.finish(Some(ping_report));
                    return Ok(host_ping);
                }
            }

            // never reached here in normal case
            let ping_report = PingReport {
                addr: net_info.inferred_dst_addr,
                status: PingStatus::Error,
                cost: Duration::ZERO,
                cached: net_info.cached,
            };
            host_ping.finish(Some(ping_report));
            Ok(host_ping)
        }
        IpAddr::V6(dst_ipv6) => {
            let src_ipv6 = match net_info.inferred_src_addr {
                IpAddr::V6(src) => src,
                _ => {
                    return Err(PistolError::AttackAddressNotMatch {
                        addr: net_info.inferred_src_addr,
                    });
                }
            };

            for i in 0..max_retries {
                let (buff, filters) =
                    build_ping_buff6(dst_ipv6, Some(dst_port), src_ipv6, src_port, method)?;

                let interface_name = net_info.interface_name.clone();
                let rrq_id = random_recv_msg_id();
                let rrq = RRequest {
                    interface_name: interface_name.clone(),
                    id: rrq_id,
                    filters,
                    created: Instant::now(),
                    elapsed: timeout,
                };
                let srq = SRequest {
                    interface_name: interface_name.clone(),
                    dst_mac,
                    src_mac,
                    eth_payload: buff,
                    eth_type: EtherTypes::Ipv4,
                    retransmit: 1,
                };
                if let Err(e) = push_rd.send(rrq) {
                    error!("ipv4 send ping recv msg error: {}", e);
                }
                if let Err(e) = push_sd.send(srq) {
                    error!("ipv4 send ping send msg error: {}", e);
                }

                let recv_response = match get_response.recv_timeout(timeout) {
                    Ok(r) => {
                        if r.id == rrq_id {
                            r
                        } else {
                            continue;
                        }
                    }
                    Err(_e) => {
                        continue;
                    }
                };
                let status = parse_response(method, recv_response.data)?;
                if status == PingStatus::Up || i == max_retries - 1 {
                    let rtt = recv_response.rtt;
                    let ping_report = PingReport {
                        addr: net_info.inferred_dst_addr,
                        status,
                        cost: rtt,
                        cached: net_info.cached,
                    };
                    host_ping.finish(Some(ping_report));
                    return Ok(host_ping);
                }
            }

            // never reached here in normal case
            let ping_report = PingReport {
                addr: net_info.inferred_dst_addr,
                status: PingStatus::Error,
                cost: Duration::ZERO,
                cached: net_info.cached,
            };
            host_ping.finish(Some(ping_report));
            Ok(host_ping)
        }
    }
}

#[cfg(feature = "ping")]
pub fn tcp_syn_ping(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<HostPings, PistolError> {
    ping(
        net_infos,
        PingMethods::Syn,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

/// TCP SYN Ping, raw version.
/// Only for one target and one port.
#[cfg(feature = "ping")]
pub fn tcp_syn_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<HostPing, PistolError> {
    ping_raw(
        net_info,
        PingMethods::Syn,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

#[cfg(feature = "ping")]
pub fn tcp_ack_ping(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<HostPings, PistolError> {
    ping(
        net_infos,
        PingMethods::Ack,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

/// TCP ACK Ping, raw version.
/// Only for one target and one port.
#[cfg(feature = "ping")]
pub fn tcp_ack_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<HostPing, PistolError> {
    ping_raw(
        net_info,
        PingMethods::Ack,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

#[cfg(feature = "ping")]
pub fn udp_ping(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<HostPings, PistolError> {
    ping(
        net_infos,
        PingMethods::Udp,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

/// UDP Ping, raw version.
#[cfg(feature = "ping")]
pub fn udp_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<HostPing, PistolError> {
    ping_raw(
        net_info,
        PingMethods::Udp,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

#[cfg(feature = "ping")]
pub fn icmp_echo_ping(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<HostPings, PistolError> {
    ping(
        net_infos,
        PingMethods::IcmpEcho,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

#[cfg(feature = "ping")]
pub fn icmp_echo_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<HostPing, PistolError> {
    ping_raw(
        net_info,
        PingMethods::IcmpEcho,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

#[cfg(feature = "ping")]
pub fn icmp_timestamp_ping(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<HostPings, PistolError> {
    ping(
        net_infos,
        PingMethods::IcmpTimeStamp,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

#[cfg(feature = "ping")]
pub fn icmp_timestamp_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<HostPing, PistolError> {
    ping_raw(
        net_info,
        PingMethods::IcmpTimeStamp,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

#[cfg(feature = "ping")]
pub fn icmp_address_mask_ping(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<HostPings, PistolError> {
    ping(
        net_infos,
        PingMethods::IcmpAddressMask,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

#[cfg(feature = "ping")]
pub fn icmp_address_mask_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<HostPing, PistolError> {
    ping_raw(
        net_info,
        PingMethods::IcmpAddressMask,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

#[cfg(feature = "ping")]
pub fn icmpv6_ping(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<HostPings, PistolError> {
    ping(
        net_infos,
        PingMethods::Icmpv6Echo,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

#[cfg(feature = "ping")]
pub fn icmp_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<HostPing, PistolError> {
    ping_raw(
        net_info,
        PingMethods::IcmpEcho,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}
