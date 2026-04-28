use chrono::DateTime;
use chrono::Local;
use pnet::datalink::MacAddr;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use prettytable::Cell;
use prettytable::Row;
use prettytable::Table;
use prettytable::row;
use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;
use tracing::error;
use tracing::warn;

pub mod icmp;
pub mod icmpv6;

use crate::LoopStates;
use crate::NetInfo;
use crate::PistolStream;
use crate::SendPacketInput;
use crate::error::PistolError;
use crate::layer::PacketFilter;
use crate::scan::PortStatus;
use crate::scan::tcp;
use crate::scan::tcp6;
use crate::scan::udp;
use crate::scan::udp6;
use crate::utils::random_port;
use crate::utils::time_to_string;

const SYN_PING_DEFAULT_PORT: u16 = 80;
const ACK_PING_DEFAULT_PORT: u16 = 80;
const UDP_PING_DEFAULT_PORT: u16 = 125;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PingStatus {
    Up,
    Down,
    Error,
}

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

#[derive(Debug, Clone, Copy)]
pub struct PingReport {
    pub addr: IpAddr,
    pub status: PingStatus,
    pub retries: usize,
    cached: bool,
}

impl PingReport {
    pub fn is_up(&self) -> bool {
        self.status == PingStatus::Up
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HostPing {
    pub layer2_cost: Duration,
    pub ping_report: Option<PingReport>,
    pub start_time: DateTime<Local>,
    pub finish_time: DateTime<Local>,
    pub max_retries: usize,
}

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
            c -> "retries",
        ]);

        match self.ping_report {
            Some(report) => {
                let addr_str = format!("{}", report.addr);
                let status_str = format!("{}", report.status);
                let retries_str = format!("{}", report.retries);
                table.add_row(row![c -> addr_str, c -> status_str, c -> retries_str]);
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
            c -> "retries",
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
            let retries_str = format!("{}", report.retries);
            table.add_row(row![c -> i, c -> addr_str, c -> status_str, c -> retries_str]);
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
        let layer2_cost_str = time_to_string(self.layer2_cost);
        let total_cost_str = time_to_string(total_cost.to_std().unwrap_or(Duration::ZERO));
        let summary2 = format!(
            "layer2 cost: {}, total cost: {}, alive hosts: {}",
            layer2_cost_str, total_cost_str, alive_hosts,
        );
        let summary = format!("{}\n{}", summary1, summary2);
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(4)]));
        write!(f, "{}", table)
    }
}

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

fn build_ping_buff(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    dst_port: Option<u16>,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    if_name: String,
    method: PingMethods,
) -> Result<(SendPacketInput, Vec<Arc<PacketFilter>>), PistolError> {
    let build_now = || -> Result<(Arc<[u8]>, Vec<Arc<PacketFilter>>), PistolError> {
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
    };

    let (buff, filters) = build_now()?;

    let send_packet_input = SendPacketInput {
        dst_mac,
        src_mac,
        l3_payload: buff,
        eth_type: EtherTypes::Ipv4,
        if_name,
        retransmit: 1,
    };

    Ok((send_packet_input, filters))
}

fn build_ping_buff6(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_port: Option<u16>,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    if_name: String,
    method: PingMethods,
) -> Result<(SendPacketInput, Vec<Arc<PacketFilter>>), PistolError> {
    let build_now = || -> Result<(Arc<[u8]>, Vec<Arc<PacketFilter>>), PistolError> {
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
    };

    let (buff, filters) = build_now()?;

    let send_packet_input = SendPacketInput {
        dst_mac,
        src_mac,
        l3_payload: buff,
        eth_type: EtherTypes::Ipv4,
        if_name,
        retransmit: 1,
    };

    Ok((send_packet_input, filters))
}

fn parse_response(eth_response: &[u8], method: PingMethods) -> Result<PingStatus, PistolError> {
    let parse_ipv4 = |src_ipv4: Ipv4Addr| -> Result<PingStatus, PistolError> {
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
                target: src_ipv4.into(),
                method: String::from("icmpv6"),
            }),
        }
    };
    let parse_ipv6 = |src_ipv6: Ipv6Addr| -> Result<PingStatus, PistolError> {
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
                    target: src_ipv6.into(),
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
                    let src_ipv4 = ip_packet.get_source();
                    return parse_ipv4(src_ipv4);
                }
                None => (),
            },
            EtherTypes::Ipv6 => match Ipv6Packet::new(eth_packet.payload()) {
                Some(ip_packet) => {
                    let src_ipv6 = ip_packet.get_source();
                    return parse_ipv6(src_ipv6);
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
struct PingState {
    retries: usize,
    data_recved: bool,
    net_info: NetInfo,
}

fn ping(
    net_infos: Vec<NetInfo>,
    method: PingMethods,
    timeout: Duration,
    max_retries: usize,
) -> Result<HostPings, PistolError> {
    let mut stream = PistolStream::new();
    stream.init(Some(String::from("tcp or udp or icmp or icmp6")))?;

    let mut pistol_pings = HostPings::new(max_retries);
    let mut reports = Vec::new();

    let mut loop_states = LoopStates::default();
    for ni in net_infos {
        if ni.valid {
            let dst_addr = ni.dst_addr;
            let state = PingState {
                retries: 0,
                data_recved: false,
                net_info: ni.clone(),
            };
            loop_states.insert_ip(dst_addr, state);
        }
    }

    loop {
        let mut all_done = true;
        let mut all_filters = Vec::new();
        for (_key, state) in &mut loop_states {
            let ni = state.net_info.clone();
            let dst_mac = ni.inferred_dst_mac;
            let dst_addr = ni.inferred_dst_addr;
            let src_mac = ni.inferred_src_mac;
            let src_port = ni.src_port;
            let if_name = ni.if_name.clone();
            match dst_addr {
                IpAddr::V4(dst_ipv4) => {
                    let src_port = match src_port {
                        Some(p) => p,
                        None => random_port(),
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
                        if ni.dst_ports.len() > 0 {
                            Some(ni.dst_ports[0])
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    if state.retries < max_retries && !state.data_recved {
                        let (spi, filters) = build_ping_buff(
                            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, if_name,
                            method,
                        )?;
                        all_filters.extend(filters);
                        stream.send_packet(spi)?;

                        state.retries += 1;
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

                    if state.retries < max_retries && !state.data_recved {
                        let (spi, filters) = build_ping_buff6(
                            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, if_name,
                            method,
                        )?;
                        all_filters.extend(filters);
                        stream.send_packet(spi)?;

                        state.retries += 1;
                        all_done = false;
                    }
                }
            }
        }

        if all_done {
            break;
        }

        let response = stream.recv_packet(timeout)?;

        for r in &response {
            for f in &all_filters {
                if f.check(&r) {
                    let addr = if let Some(addr) = f.icmp_ip() {
                        // icmp ping or icmpv6 ping
                        Some(addr)
                    } else if let Some((addr, _port)) = f.tcp_udp_ip_port() {
                        // tcp ping or udp ping
                        Some(addr)
                    } else {
                        None
                    };

                    if let Some(addr) = addr {
                        for (_key, state) in &mut loop_states {
                            if state.net_info.inferred_dst_addr == addr {
                                match parse_response(r, method) {
                                    Ok(ps) => {
                                        state.data_recved = true;
                                        let dst_addr = state.net_info.inferred_dst_addr;
                                        let cached = state.net_info.cached;
                                        let retries = state.retries;

                                        let ping_report = PingReport {
                                            addr: dst_addr,
                                            status: ps,
                                            retries,
                                            cached,
                                        };
                                        reports.push(ping_report);
                                    }
                                    Err(e) => {
                                        error!("parse ping response error: {}", e);
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    pistol_pings.finish(reports);
    Ok(pistol_pings)
}

pub fn ping_raw(
    net_info: NetInfo,
    method: PingMethods,
    timeout: Duration,
    max_retries: usize,
) -> Result<HostPing, PistolError> {
    let mut stream = PistolStream::new();
    stream.init(Some(String::from("tcp or udp or icmp or icmp6")))?;

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
    let if_name = net_info.if_name.clone();

    let (spi, filters) = match net_info.inferred_dst_addr {
        IpAddr::V4(dst_ipv4) => {
            let src_ipv4 = match net_info.inferred_src_addr {
                IpAddr::V4(src) => src,
                _ => {
                    return Err(PistolError::AttackAddressNotMatch {
                        addr: net_info.inferred_src_addr,
                    });
                }
            };
            let (spi, filters) = build_ping_buff(
                dst_mac,
                dst_ipv4,
                Some(dst_port),
                src_mac,
                src_ipv4,
                src_port,
                if_name,
                method,
            )?;
            (spi, filters)
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
            let (spi, filters) = build_ping_buff6(
                dst_mac,
                dst_ipv6,
                Some(dst_port),
                src_mac,
                src_ipv6,
                src_port,
                if_name,
                method,
            )?;
            (spi, filters)
        }
    };

    let dst_addr = net_info.inferred_dst_addr;

    for i in 0..max_retries {
        stream.send_packet(spi.clone())?;
        let response = stream.recv_packet(timeout)?;

        for r in &response {
            for f in &filters {
                if f.check(&r) {
                    let addr = if let Some(addr) = f.icmp_ip() {
                        // icmp ping or icmpv6 ping
                        Some(addr)
                    } else if let Some((addr, _port)) = f.tcp_udp_ip_port() {
                        // tcp ping or udp ping
                        Some(addr)
                    } else {
                        None
                    };

                    if let Some(addr) = addr {
                        if addr == dst_addr {
                            let status = parse_response(r, method)?;
                            let retries = i + 1;
                            let ping_report = PingReport {
                                addr: net_info.inferred_dst_addr,
                                status,
                                retries,
                                cached: net_info.cached,
                            };
                            host_ping.finish(Some(ping_report));
                            return Ok(host_ping);
                        }
                    }
                }
            }
        }
    }

    // never reached here in normal case
    let ping_report = PingReport {
        addr: net_info.inferred_dst_addr,
        status: PingStatus::Error,
        retries: max_retries,
        cached: net_info.cached,
    };
    host_ping.finish(Some(ping_report));
    Ok(host_ping)
}

pub fn tcp_syn_ping(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
) -> Result<HostPings, PistolError> {
    ping(net_infos, PingMethods::Syn, timeout, max_retries)
}

/// TCP SYN Ping, raw version.
/// Only for one target and one port.
pub fn tcp_syn_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<HostPing, PistolError> {
    ping_raw(net_info, PingMethods::Syn, timeout, max_retries)
}

pub fn tcp_ack_ping(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
) -> Result<HostPings, PistolError> {
    ping(net_infos, PingMethods::Ack, timeout, max_retries)
}

/// TCP ACK Ping, raw version.
/// Only for one target and one port.
pub fn tcp_ack_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<HostPing, PistolError> {
    ping_raw(net_info, PingMethods::Ack, timeout, max_retries)
}

pub fn udp_ping(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
) -> Result<HostPings, PistolError> {
    ping(net_infos, PingMethods::Udp, timeout, max_retries)
}

/// UDP Ping, raw version.
pub fn udp_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<HostPing, PistolError> {
    ping_raw(net_info, PingMethods::Udp, timeout, max_retries)
}

pub fn icmp_echo_ping(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
) -> Result<HostPings, PistolError> {
    ping(net_infos, PingMethods::IcmpEcho, timeout, max_retries)
}

pub fn icmp_echo_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<HostPing, PistolError> {
    ping_raw(net_info, PingMethods::IcmpEcho, timeout, max_retries)
}

pub fn icmp_timestamp_ping(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
) -> Result<HostPings, PistolError> {
    ping(net_infos, PingMethods::IcmpTimeStamp, timeout, max_retries)
}

pub fn icmp_timestamp_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<HostPing, PistolError> {
    ping_raw(net_info, PingMethods::IcmpTimeStamp, timeout, max_retries)
}

pub fn icmp_address_mask_ping(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
) -> Result<HostPings, PistolError> {
    ping(
        net_infos,
        PingMethods::IcmpAddressMask,
        timeout,
        max_retries,
    )
}

pub fn icmp_address_mask_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<HostPing, PistolError> {
    ping_raw(net_info, PingMethods::IcmpAddressMask, timeout, max_retries)
}

pub fn icmpv6_ping(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
) -> Result<HostPings, PistolError> {
    ping(net_infos, PingMethods::Icmpv6Echo, timeout, max_retries)
}

pub fn icmp_ping_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<HostPing, PistolError> {
    ping_raw(net_info, PingMethods::IcmpEcho, timeout, max_retries)
}
