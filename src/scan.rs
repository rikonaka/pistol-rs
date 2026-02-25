/* Scan */
#[cfg(any(feature = "scan", feature = "ping"))]
use chrono::DateTime;
#[cfg(any(feature = "scan", feature = "ping"))]
use chrono::Local;
#[cfg(feature = "scan")]
use pnet::datalink::MacAddr;
#[cfg(any(feature = "scan", feature = "ping"))]
use pnet::datalink::NetworkInterface;
#[cfg(any(feature = "scan", feature = "ping"))]
use prettytable::Cell;
#[cfg(any(feature = "scan", feature = "ping"))]
use prettytable::Row;
#[cfg(any(feature = "scan", feature = "ping"))]
use prettytable::Table;
#[cfg(any(feature = "scan", feature = "ping"))]
use prettytable::row;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::collections::BTreeMap;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::fmt;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::net::IpAddr;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::net::Ipv4Addr;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::net::Ipv6Addr;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::sync::mpsc::channel;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::time::Duration;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::time::Instant;
#[cfg(any(feature = "scan", feature = "ping"))]
use subnetwork::Ipv6AddrExt;
#[cfg(any(feature = "scan", feature = "ping"))]
use tracing::debug;
#[cfg(any(feature = "scan", feature = "ping"))]
use tracing::error;

pub mod arp;
pub mod ndp_ns;
#[cfg(any(feature = "scan", feature = "ping"))]
pub mod tcp;
#[cfg(any(feature = "scan", feature = "ping"))]
pub mod tcp6;
#[cfg(any(feature = "scan", feature = "ping"))]
pub mod udp;
#[cfg(any(feature = "scan", feature = "ping"))]
pub mod udp6;

#[cfg(feature = "scan")]
use crate::NetInfo;
#[cfg(feature = "scan")]
use crate::Target;
#[cfg(any(feature = "scan", feature = "ping"))]
use crate::error::PistolError;
#[cfg(feature = "scan")]
use crate::layer::find_interface_by_dst_ip;
#[cfg(any(feature = "scan", feature = "ping"))]
use crate::layer::multicast_mac;
#[cfg(any(feature = "scan", feature = "ping"))]
#[cfg(feature = "scan")]
use crate::scan::arp::send_arp_scan_packet;
#[cfg(feature = "scan")]
use crate::scan::ndp_ns::send_ndp_ns_scan_packet;
#[cfg(any(feature = "scan", feature = "ping"))]
use crate::utils;

/// This structure is used to indicate whether the program has data received or no data received.
/// For example, in UDP scan, if no data is received, the status returned is open_or_filtered.
/// So when UDP scan returns to the open_or_filtered state, DataRecvStatus should be set to No.
#[cfg(any(feature = "scan", feature = "ping"))]
#[derive(Debug, Clone, Copy)]
pub enum DataRecvStatus {
    Yes,
    No,
}

#[cfg(feature = "scan")]
#[derive(Debug, Clone)]
pub struct MacReport {
    pub addr: IpAddr,
    pub mac: Option<MacAddr>,
    pub ouis: String, // productions organization name
    pub rtt: Duration,
}

#[cfg(feature = "scan")]
#[derive(Debug, Clone)]
pub struct MacScans {
    pub mac_reports: Vec<MacReport>,
    pub start_time: DateTime<Local>,
    pub finish_time: DateTime<Local>,
    max_retries: usize,
}

#[cfg(feature = "scan")]
impl fmt::Display for MacScans {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new(&format!("Mac Scans (max_retries:{})", self.max_retries))
                .style_spec("c")
                .with_hspan(5),
        ]));

        table.add_row(row![c -> "seq", c -> "addr", c -> "mac", c -> "oui", c-> "rtt"]);

        // sorted the results
        let mut btm_addr: BTreeMap<IpAddr, MacReport> = BTreeMap::new();
        for report in &self.mac_reports {
            btm_addr.insert(report.addr, report.clone());
        }

        let mut alive_hosts = 0;
        let mut i = 1;
        for (_addr, report) in btm_addr {
            let time_cost_str = utils::time_to_string(report.rtt);
            match report.mac {
                Some(mac) => {
                    table.add_row(
                        row![c -> i, c -> report.addr, c -> mac, c -> report.ouis, c -> time_cost_str],
                    );
                    i += 1;
                    alive_hosts += 1;
                }
                None => (),
            }
        }

        let total_cost = self.finish_time - self.start_time;
        let total_cost_str =
            utils::time_to_string(Duration::from_secs_f32(total_cost.as_seconds_f32()));
        let avg_cost = total_cost.as_seconds_f32() / self.mac_reports.len() as f32;
        let avg_cost_str = utils::time_to_string(Duration::from_secs_f32(avg_cost));
        let summary = format!(
            "total cost: {}, avg cost: {}, alive hosts: {}",
            total_cost_str, avg_cost_str, alive_hosts
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(5)]));

        write!(f, "{}", table)
    }
}

#[cfg(feature = "scan")]
impl MacScans {
    pub fn new(max_retries: usize) -> MacScans {
        MacScans {
            mac_reports: Vec::new(),
            start_time: Local::now(),
            finish_time: Local::now(),
            max_retries,
        }
    }
    pub fn value(&self) -> Vec<MacReport> {
        self.mac_reports.clone()
    }
    pub fn finish(&mut self, mac_reports: Vec<MacReport>) {
        self.finish_time = Local::now();
        self.mac_reports = mac_reports;
    }
}

#[cfg(feature = "scan")]
#[derive(Debug, Clone)]
pub struct NmapMacPrefix {
    pub prefix: String,
    pub ouis: String,
}

#[cfg(feature = "scan")]
fn get_nmap_mac_prefixes() -> Vec<NmapMacPrefix> {
    let nmap_mac_prefixes_file = include_str!("./db/nmap-mac-prefixes");
    let mut nmap_mac_prefixes = Vec::new();
    for l in nmap_mac_prefixes_file.lines() {
        nmap_mac_prefixes.push(l.to_string());
    }

    let mut ret = Vec::new();
    for p in nmap_mac_prefixes {
        if !p.contains("#") {
            let p_split: Vec<String> = p.split(" ").map(|s| s.to_string()).collect();
            if p_split.len() >= 2 {
                let ouis_slice = p_split[1..].to_vec();
                let n = NmapMacPrefix {
                    prefix: p_split[0].to_string(),
                    ouis: ouis_slice.join(" "),
                };
                ret.push(n);
            }
        }
    }
    ret
}

#[cfg(feature = "scan")]
pub fn arp_scan_raw(
    dst_ipv4: Ipv4Addr,
    timeout: Duration,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    debug!("start arp scan to {}", dst_ipv4);

    // broadcast mac address
    let dst_mac = MacAddr::broadcast();
    let interface = match find_interface_by_dst_ip(dst_ipv4.into()) {
        Some(i) => i,
        None => {
            return Err(PistolError::CanNotFoundInterface {
                i: format!("arp to {}", dst_ipv4),
            });
        }
    };
    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(PistolError::CanNotFoundSrcMacAddress),
    };
    let mut src_ipv4 = None;
    for ipn in &interface.ips {
        match ipn.ip() {
            IpAddr::V4(src) => {
                if src.is_loopback() {
                    continue;
                } else {
                    src_ipv4 = Some(src);
                    break;
                }
            }
            _ => debug!("skip non-ipv4 address {}", ipn.ip()),
        }
    }

    match src_ipv4 {
        Some(src_ipv4) => {
            debug!("use interface {} and src ipv4 {}", interface.name, src_ipv4);
            send_arp_scan_packet(dst_mac, dst_ipv4, src_mac, src_ipv4, &interface, timeout)
        }
        None => Err(PistolError::CanNotFoundSrcAddress),
    }
}

#[cfg(feature = "scan")]
pub fn ndp_ns_scan_raw(
    dst_ipv6: Ipv6Addr,
    timeout: Duration,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    let interface = match find_interface_by_dst_ip(dst_ipv6.into()) {
        Some(i) => i,
        None => {
            return Err(PistolError::CanNotFoundInterface {
                i: format!("to {}", dst_ipv6),
            });
        }
    };
    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(PistolError::CanNotFoundSrcMacAddress),
    };

    let dst_ipv6_ext: Ipv6AddrExt = dst_ipv6.into();
    let dst_ipv6 = dst_ipv6_ext.link_multicast();
    let dst_mac = multicast_mac(dst_ipv6);

    let mut src_ipv6 = None;
    for ipn in &interface.ips {
        match ipn.ip() {
            IpAddr::V6(src) => {
                if src.is_loopback() {
                    continue;
                } else {
                    src_ipv6 = Some(src);
                }
            }
            _ => debug!("skip non-ipv6 address {}", ipn.ip()),
        }
    }

    match src_ipv6 {
        Some(src_ipv6) => {
            debug!("use interface {} and src ipv6 {}", interface.name, src_ipv6);
            send_ndp_ns_scan_packet(dst_mac, dst_ipv6, src_mac, src_ipv6, &interface, timeout)
        }
        None => Err(PistolError::CanNotFoundSrcAddress),
    }
}

#[cfg(feature = "scan")]
pub fn mac_scan(
    targets: &[Target],
    timeout: Duration,
    threads: usize,
    max_retries: usize,
) -> Result<MacScans, PistolError> {
    let nmap_mac_prefixes = get_nmap_mac_prefixes();
    let mut ret = MacScans::new(max_retries);
    let threads = utils::threads_check(threads);
    let pool = utils::get_threads_pool(threads);
    let (tx, rx) = channel();
    let mut recv_size = 0;
    for t in targets {
        let dst_addr = t.addr;
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                let tx = tx.clone();
                recv_size += 1;
                pool.execute(move || {
                    for i in 0..max_retries {
                        debug!("arp scan packets: #{}/{}", i + 1, max_retries);
                        let scan_ret = arp_scan_raw(dst_ipv4, timeout);
                        if i == max_retries - 1 {
                            if let Err(e) = tx.send((dst_addr, scan_ret)) {
                                error!("failed to send to tx on func mac_scan: {}", e);
                            }
                        } else {
                            match scan_ret {
                                Ok((value, _rtt)) => {
                                    if value.is_some() {
                                        if let Err(e) = tx.send((dst_addr, scan_ret)) {
                                            error!("failed to send to tx on func mac_scan: {}", e);
                                        }
                                        break;
                                    }
                                }
                                Err(_) => {
                                    // debug!(
                                    //     "arp scan error for {}: {}, stop probing",
                                    //     dst_ipv4,
                                    //     e.to_string()
                                    // );
                                    if let Err(e) = tx.send((dst_addr, scan_ret)) {
                                        error!("failed to send to tx on func mac_scan: {}", e);
                                    }
                                    break;
                                }
                            }
                        }
                    }
                });
            }
            IpAddr::V6(dst_ipv6) => {
                let tx = tx.clone();
                recv_size += 1;
                pool.execute(move || {
                    for i in 0..max_retries {
                        debug!("ndp_ns scan packets: #{}/{}", i + 1, max_retries);
                        let scan_ret = ndp_ns_scan_raw(dst_ipv6, timeout);
                        if i == max_retries - 1 {
                            if let Err(e) = tx.send((dst_addr, scan_ret)) {
                                error!("failed to send to tx on func mac_scan: {}", e);
                            }
                        } else {
                            match scan_ret {
                                Ok((value, _rtt)) => {
                                    if value.is_some() {
                                        if let Err(e) = tx.send((dst_addr, scan_ret)) {
                                            error!("failed to send to tx on func mac_scan: {}", e);
                                        }
                                        break;
                                    }
                                }
                                Err(_) => {
                                    // debug!(
                                    //     "ndp_ns scan error for {}: {}, stop probing",
                                    //     dst_ipv6,
                                    //     e.to_string()
                                    // );
                                    if let Err(e) = tx.send((dst_addr, scan_ret)) {
                                        error!("failed to send to tx on func mac_scan: {}", e);
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

    let mut mac_scan_reports = Vec::new();
    let iter = rx.into_iter().take(recv_size);
    for (target_addr, values) in iter {
        match values? {
            (Some(target_mac), rtt) => {
                let mut target_ouis = String::new();
                let mut mac_prefix = String::new();
                let m0 = format!("{:X}", target_mac.0);
                let m1 = format!("{:X}", target_mac.1);
                let m2 = format!("{:X}", target_mac.2);
                // m0
                let i = if m0.len() < 2 { 2 - m0.len() } else { 0 };
                if i > 0 {
                    for _ in 0..i {
                        mac_prefix += "0";
                    }
                }
                mac_prefix += &m0;
                // m1
                let i = if m1.len() < 2 { 2 - m1.len() } else { 0 };
                if i > 0 {
                    for _ in 0..i {
                        mac_prefix += "0";
                    }
                }
                mac_prefix += &m1;
                // m2
                let i = if m2.len() < 2 { 2 - m2.len() } else { 0 };
                if i > 0 {
                    for _ in 0..i {
                        mac_prefix += "0";
                    }
                }
                mac_prefix += &m2;
                // println!("{}", mac_prefix);
                for p in &nmap_mac_prefixes {
                    if mac_prefix == p.prefix {
                        target_ouis = p.ouis.to_string();
                    }
                }
                let mr = MacReport {
                    addr: target_addr,
                    mac: Some(target_mac),
                    ouis: target_ouis,
                    rtt,
                };
                mac_scan_reports.push(mr);
            }
            (None, rtt) => {
                let mr = MacReport {
                    addr: target_addr,
                    mac: None,
                    ouis: String::new(),
                    rtt,
                };
                mac_scan_reports.push(mr);
            }
        }
    }
    ret.finish(mac_scan_reports);
    Ok(ret)
}

#[cfg(any(feature = "scan", feature = "ping"))]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanMethod {
    Connect,
    Syn,
    Fin,
    Ack,
    Null,
    Xmas,
    Window,
    Maimon,
    Idle, // need ipv4 ip id and ipv4 only
    Udp,
}

#[cfg(any(feature = "scan", feature = "ping"))]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
    OpenOrFiltered,
    Unfiltered,
    Unreachable,
    ClosedOrFiltered,
    Error,
    // pistol new, for offline host
    Offline,
}

#[cfg(any(feature = "scan", feature = "ping"))]
impl fmt::Display for PortStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            PortStatus::Open => "open",
            PortStatus::Closed => "closed",
            PortStatus::Filtered => "filtered",
            PortStatus::OpenOrFiltered => "open_or_filtered",
            PortStatus::Unfiltered => "unfiltered",
            PortStatus::Unreachable => "unreachable",
            PortStatus::ClosedOrFiltered => "closed_or_filtered",
            PortStatus::Error => "error",
            PortStatus::Offline => "offline",
        };
        write!(f, "{}", s)
    }
}

#[cfg(any(feature = "scan", feature = "ping"))]
#[derive(Debug, Clone, Copy)]
pub struct PortReport {
    pub addr: IpAddr,
    pub port: u16,
    pub status: PortStatus,
    /// The cost of each target, not all.
    pub cost: Duration,
    cached: bool,
}

impl PortReport {
    pub fn is_open(&self) -> bool {
        self.status == PortStatus::Open
    }
}

#[cfg(any(feature = "scan", feature = "ping"))]
#[derive(Debug, Clone, Copy)]
pub struct PortScan {
    /// Searching ip on arp cache or send arp (or ndp_ns) packet will cost some time,
    /// so we record the time cost seconds of layer2 here.
    pub layer2_cost: Duration,
    pub port_report: Option<PortReport>,
    pub start_time: DateTime<Local>,
    pub finish_time: DateTime<Local>,
    pub max_retries: usize,
}

#[cfg(any(feature = "scan", feature = "ping"))]
impl fmt::Display for PortScan {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Port Scan").style_spec("c").with_hspan(4),
        ]));

        table.add_row(row![c -> "addr", c -> "port", c-> "status", c -> "time cost"]);

        match self.port_report {
            Some(report) => {
                let addr_str = format!("{}", report.addr);
                let status_str = format!("{}", report.status);
                let time_cost_str = if report.cached {
                    utils::time_to_string(report.cost)
                } else {
                    let time_cost_str = utils::time_to_string(report.cost);
                    format!("{}(cached)", time_cost_str)
                };

                table.add_row(
                    row![c -> addr_str, c -> report.port, c -> status_str, c -> time_cost_str],
                );
            }
            None => (),
        }

        let summary1 = format!(
            "start at: {}, finish at: {}, max_retries: {}",
            self.start_time.format("%Y-%m-%d %H:%M:%S"),
            self.finish_time.format("%Y-%m-%d %H:%M:%S"),
            self.max_retries,
        );
        let total_cost = self.finish_time - self.start_time;
        let total_cost = total_cost.as_seconds_f32();
        let layer2_cost = self.layer2_cost.as_secs_f32();
        let summary2 = format!(
            "layer2 cost: {:.2}s, total cost: {:.2}s",
            layer2_cost, total_cost
        );
        let summary = format!("{}\n{}", summary1, summary2);
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(4)]));
        write!(f, "{}", table)
    }
}

#[cfg(any(feature = "scan", feature = "ping"))]
impl PortScan {
    pub(crate) fn new(max_retries: usize) -> Self {
        let now = Local::now();
        Self {
            layer2_cost: Duration::ZERO,
            port_report: None,
            start_time: now,
            finish_time: now,
            max_retries,
        }
    }
    pub(crate) fn finish(&mut self, port_report: Option<PortReport>) {
        self.finish_time = Local::now();
        self.port_report = port_report;
    }
}

#[cfg(any(feature = "scan", feature = "ping"))]
#[derive(Debug, Clone)]
pub struct PortScans {
    /// Searching ip on arp cache or send arp (or ndp_ns) packet will cost some time,
    /// so we record the cost seconds of layer2 here.
    pub layer2_cost: Duration,
    /// The order of this Vec is the same as the order in which the data packets are received,
    /// the detection that receives the data first is in the front.
    pub port_reports: Vec<PortReport>,
    pub start_time: DateTime<Local>,
    pub finish_time: DateTime<Local>,
    pub max_retries: usize,
}

#[cfg(any(feature = "scan", feature = "ping"))]
impl fmt::Display for PortScans {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Port Scans").style_spec("c").with_hspan(5),
        ]));

        table.add_row(row![c -> "id", c -> "addr", c -> "port", c-> "status", c -> "time cost"]);

        // sorted the resutls
        let mut btm_addr: BTreeMap<IpAddr, BTreeMap<u16, PortReport>> = BTreeMap::new();
        for report in &self.port_reports {
            if let Some(btm_port) = btm_addr.get_mut(&report.addr) {
                btm_port.insert(report.port, report.clone());
            } else {
                let mut btm_port = BTreeMap::new();
                btm_port.insert(report.port, report.clone());
                btm_addr.insert(report.addr, btm_port);
            }
        }

        let mut open_ports_num = 0;
        let mut i = 1;
        for (_addr, bt_port) in btm_addr {
            for (_port, report) in bt_port {
                match report.status {
                    PortStatus::Open => open_ports_num += 1,
                    _ => (),
                }
                let addr_str = format!("{}", report.addr);
                let status_str = format!("{}", report.status);
                let time_cost_str = if report.cached {
                    let time_cost_str = utils::time_to_string(report.cost);
                    format!("{}(cached)", time_cost_str)
                } else {
                    utils::time_to_string(report.cost)
                };
                table.add_row(
                    row![c -> i, c -> addr_str, c -> report.port, c -> status_str, c -> time_cost_str],
                );
                i += 1;
            }
        }

        let summary1 = format!(
            "start at: {}, finish at: {}, max_retries: {}",
            self.start_time.format("%Y-%m-%d %H:%M:%S"),
            self.finish_time.format("%Y-%m-%d %H:%M:%S"),
            self.max_retries,
        );
        let total_cost = self.finish_time - self.start_time;
        let total_cost_str =
            utils::time_to_string(Duration::from_secs_f32(total_cost.as_seconds_f32()));
        let avg_cost = total_cost.as_seconds_f32() / self.port_reports.len() as f32;
        let avg_cost_str = utils::time_to_string(Duration::from_secs_f32(avg_cost));
        let layer2_cost_str = utils::time_to_string(self.layer2_cost);
        let summary2 = format!(
            "layer2 cost: {}, total cost: {}, avg cost: {}, open ports: {}",
            layer2_cost_str, total_cost_str, avg_cost_str, open_ports_num
        );
        let summary = format!("{}\n{}", summary1, summary2);
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(5)]));
        write!(f, "{}", table)
    }
}

#[cfg(any(feature = "scan", feature = "ping"))]
impl PortScans {
    pub(crate) fn new(max_retries: usize) -> Self {
        let now = Local::now();
        Self {
            layer2_cost: Duration::ZERO,
            port_reports: Vec::new(),
            start_time: now,
            finish_time: now,
            max_retries,
        }
    }
    pub(crate) fn finish(&mut self, port_reports: Vec<PortReport>) {
        self.finish_time = Local::now();
        self.port_reports = port_reports;
    }
    pub fn reports(&self) -> Vec<PortReport> {
        self.port_reports.clone()
    }
}

#[cfg(any(feature = "scan", feature = "ping"))]
fn scan_thread(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    zombie_mac: Option<MacAddr>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    interface: &NetworkInterface,
    method: ScanMethod,
    timeout: Duration,
) -> Result<(PortStatus, DataRecvStatus, Duration), PistolError> {
    let (port_status, data_recv_status, rtt) = match method {
        ScanMethod::Connect => tcp::send_connect_scan_packet(dst_ipv4.into(), dst_port, timeout)?,
        ScanMethod::Syn => tcp::send_syn_scan_packet(
            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface, timeout,
        )?,
        ScanMethod::Fin => tcp::send_fin_scan_packet(
            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface, timeout,
        )?,
        ScanMethod::Ack => tcp::send_ack_scan_packet(
            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface, timeout,
        )?,
        ScanMethod::Null => tcp::send_null_scan_packet(
            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface, timeout,
        )?,
        ScanMethod::Xmas => tcp::send_xmas_scan_packet(
            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface, timeout,
        )?,
        ScanMethod::Window => tcp::send_window_scan_packet(
            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface, timeout,
        )?,
        ScanMethod::Maimon => tcp::send_maimon_scan_packet(
            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface, timeout,
        )?,
        ScanMethod::Idle => {
            // this three parameters must be Some
            let zombie_mac = match zombie_mac {
                Some(zm) => zm,
                None => {
                    return Err(PistolError::IdleScanNoParamsError {
                        params: "zombie_mac".to_string(),
                    });
                }
            };
            let zombie_ipv4 = match zombie_ipv4 {
                Some(zi) => zi,
                None => {
                    return Err(PistolError::IdleScanNoParamsError {
                        params: "zombie_ipv4".to_string(),
                    });
                }
            };
            let zombie_port = match zombie_port {
                Some(zp) => zp,
                None => {
                    return Err(PistolError::IdleScanNoParamsError {
                        params: "zombie_port".to_string(),
                    });
                }
            };
            tcp::send_idle_scan_packet(
                dst_mac,
                dst_ipv4,
                dst_port,
                src_mac,
                src_ipv4,
                src_port,
                zombie_mac,
                zombie_ipv4,
                zombie_port,
                interface,
                timeout,
            )?
        }
        ScanMethod::Udp => udp::send_udp_scan_packet(
            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, interface, timeout,
        )?,
    };

    Ok((port_status, data_recv_status, rtt))
}

#[cfg(any(feature = "scan", feature = "ping"))]
fn scan_thread6(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    interface: &NetworkInterface,
    method: ScanMethod,
    timeout: Duration,
) -> Result<(PortStatus, DataRecvStatus, Duration), PistolError> {
    let (port_status, data_recv_status, rtt) = match method {
        ScanMethod::Connect => tcp::send_connect_scan_packet(dst_ipv6.into(), dst_port, timeout)?,
        ScanMethod::Syn => tcp6::send_syn_scan_packet(
            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, interface, timeout,
        )?,
        ScanMethod::Fin => tcp6::send_fin_scan_packet(
            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, interface, timeout,
        )?,
        ScanMethod::Ack => tcp6::send_ack_scan_packet(
            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, interface, timeout,
        )?,
        ScanMethod::Null => tcp6::send_null_scan_packet(
            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, interface, timeout,
        )?,
        ScanMethod::Xmas => tcp6::send_xmas_scan_packet(
            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, interface, timeout,
        )?,
        ScanMethod::Window => tcp6::send_window_scan_packet(
            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, interface, timeout,
        )?,
        ScanMethod::Maimon => tcp6::send_maimon_scan_packet(
            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, interface, timeout,
        )?,
        ScanMethod::Udp => udp6::send_udp_scan_packet(
            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, interface, timeout,
        )?,
        ScanMethod::Idle => return Err(PistolError::IpVersionNotMatch),
    };

    Ok((port_status, data_recv_status, rtt))
}

/// General scan function.
#[cfg(any(feature = "scan", feature = "ping"))]
fn scan(
    net_infos: Vec<NetInfo>,
    zombie_mac: Option<MacAddr>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    method: ScanMethod,
    threads: usize,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    let mut pistol_port_scans = PortScans::new(max_retries);
    debug!("scan will create {} threads to do the jobs", threads);
    let pool = utils::get_threads_pool(threads);
    let (tx, rx) = channel();
    let mut recv_size = 0;
    let mut reports = Vec::new();

    for ni in net_infos {
        if !ni.valid {
            continue;
        }
        let dst_mac = ni.dst_mac;
        let dst_addr = ni.dst_addr;
        let src_mac = ni.src_mac;
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                let src_ipv4 = match ni.src_addr {
                    IpAddr::V4(s) => s,
                    _ => return Err(PistolError::AttackAddressNotMatch { addr: ni.src_addr }),
                };
                for dst_port in ni.dst_ports {
                    let interface = ni.interface.clone();
                    let src_port = match ni.src_port {
                        Some(s) => s,
                        None => utils::random_port(),
                    };
                    let cached = ni.cached;
                    let tx = tx.clone();
                    recv_size += 1;

                    pool.execute(move || {
                        for ind in 0..max_retries {
                            let start_time = Instant::now();
                            debug!(
                                "sending scan packet to [{}] port [{}] try [{}]",
                                dst_ipv4, dst_port, ind
                            );
                            let scan_ret = scan_thread(
                                dst_mac,
                                dst_ipv4,
                                dst_port,
                                src_mac,
                                src_ipv4,
                                src_port,
                                zombie_mac,
                                zombie_ipv4,
                                zombie_port,
                                &interface,
                                method,
                                timeout,
                            );
                            if ind == max_retries - 1 {
                                // last attempt
                                if let Err(e) = tx.send((
                                    dst_addr,
                                    dst_port,
                                    scan_ret,
                                    start_time.elapsed(),
                                    cached,
                                )) {
                                    error!("failed to send to tx on func scan: {}", e);
                                }
                            } else {
                                match scan_ret {
                                    Ok((_port_status, data_recv_status, _rtt)) => {
                                        match data_recv_status {
                                            DataRecvStatus::Yes => {
                                                // conclusions drawn from the returned data
                                                if let Err(e) = tx.send((
                                                    dst_addr,
                                                    dst_port,
                                                    scan_ret,
                                                    start_time.elapsed(),
                                                    cached,
                                                )) {
                                                    error!(
                                                        "failed to send to tx on func scan: {}",
                                                        e
                                                    );
                                                }
                                                break; // quit loop now
                                            }
                                            // conclusions from the default policy
                                            DataRecvStatus::No => (), // continue probing
                                        }
                                    }
                                    Err(_) => {
                                        // stop probe immediately if an error occurs
                                        if let Err(e) = tx.send((
                                            dst_addr,
                                            dst_port,
                                            scan_ret,
                                            start_time.elapsed(),
                                            cached,
                                        )) {
                                            error!("failed to send to tx on func scan: {}", e);
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
            }
            IpAddr::V6(dst_ipv6) => {
                let src_ipv6 = match ni.src_addr {
                    IpAddr::V6(s) => s,
                    _ => return Err(PistolError::AttackAddressNotMatch { addr: ni.src_addr }),
                };
                for dst_port in ni.dst_ports {
                    let interface = ni.interface.clone();
                    let src_port = match ni.src_port {
                        Some(s) => s,
                        None => utils::random_port(),
                    };
                    let cached = ni.cached;
                    let tx = tx.clone();
                    recv_size += 1;

                    pool.execute(move || {
                        for ind in 0..max_retries {
                            let start_time = Instant::now();
                            let scan_ret = scan_thread6(
                                dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port,
                                &interface, method, timeout,
                            );
                            if ind == max_retries - 1 {
                                if let Err(e) = tx.send((
                                    dst_addr,
                                    dst_port,
                                    scan_ret,
                                    start_time.elapsed(),
                                    cached,
                                )) {
                                    error!("failed to send to tx on func scan: {}", e);
                                }
                            } else {
                                match scan_ret {
                                    Ok((_port_status, data_recv_status, _rtt)) => {
                                        match data_recv_status {
                                            DataRecvStatus::Yes => {
                                                // conclusions drawn from the returned data
                                                if let Err(e) = tx.send((
                                                    dst_addr,
                                                    dst_port,
                                                    scan_ret,
                                                    start_time.elapsed(),
                                                    cached,
                                                )) {
                                                    error!(
                                                        "failed to send to tx on func scan: {}",
                                                        e
                                                    );
                                                }
                                                break; // quit loop now
                                            }
                                            // conclusions from the default policy
                                            DataRecvStatus::No => (), // continue probing
                                        }
                                    }
                                    Err(_) => {
                                        // stop probe immediately if an error occurs
                                        // debug!(
                                        //     "scan error for {}: {}, stop probing",
                                        //     dst_ipv6,
                                        //     e.to_string()
                                        // );
                                        if let Err(e) = tx.send((
                                            dst_addr,
                                            dst_port,
                                            scan_ret,
                                            start_time.elapsed(),
                                            cached,
                                        )) {
                                            error!("failed to send to tx on func scan: {}", e);
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
    }

    let iter = rx.into_iter().take(recv_size);
    for (dst_addr, dst_port, ret, elapsed, cached) in iter {
        match ret {
            Ok((port_status, _data_recv_status, rtt)) => {
                // println!("rtt: {:.2}", rtt.as_secs_f64());
                let scan_report = PortReport {
                    addr: dst_addr,
                    port: dst_port,
                    status: port_status,
                    cost: rtt,
                    cached,
                };
                reports.push(scan_report);
            }
            Err(e) => match e {
                PistolError::CanNotFoundDstMacAddress => {
                    let scan_report = PortReport {
                        addr: dst_addr,
                        port: dst_port,
                        status: PortStatus::Offline,
                        cost: elapsed,
                        cached,
                    };
                    reports.push(scan_report);
                }
                _ => {
                    debug!("scan error: {}", e);
                    let scan_report = PortReport {
                        addr: dst_addr,
                        port: dst_port,
                        status: PortStatus::Error,
                        cost: elapsed,
                        cached,
                    };
                    reports.push(scan_report);
                }
            },
        }
    }
    pistol_port_scans.finish(reports);
    Ok(pistol_port_scans)
}

#[cfg(feature = "scan")]
pub fn tcp_connect_scan(
    net_infos: Vec<NetInfo>,
    threads: usize,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    scan(
        net_infos,
        None,
        None,
        None,
        ScanMethod::Connect,
        threads,
        timeout,
        max_retries,
    )
}

/// TCP connect() Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_connect_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(
        net_info,
        None,
        None,
        None,
        ScanMethod::Connect,
        timeout,
        max_retries,
    )
}

#[cfg(any(feature = "scan", feature = "ping"))]
pub fn tcp_syn_scan(
    net_infos: Vec<NetInfo>,
    threads: usize,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    scan(
        net_infos,
        None,
        None,
        None,
        ScanMethod::Syn,
        threads,
        timeout,
        max_retries,
    )
}

/// TCP SYN Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_syn_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(
        net_info,
        None,
        None,
        None,
        ScanMethod::Syn,
        timeout,
        max_retries,
    )
}

#[cfg(feature = "scan")]
pub fn tcp_fin_scan(
    net_infos: Vec<NetInfo>,
    threads: usize,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    scan(
        net_infos,
        None,
        None,
        None,
        ScanMethod::Fin,
        threads,
        timeout,
        max_retries,
    )
}

/// TCP FIN Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_fin_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(
        net_info,
        None,
        None,
        None,
        ScanMethod::Fin,
        timeout,
        max_retries,
    )
}

#[cfg(feature = "scan")]
pub fn tcp_ack_scan(
    net_infos: Vec<NetInfo>,
    threads: usize,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    scan(
        net_infos,
        None,
        None,
        None,
        ScanMethod::Ack,
        threads,
        timeout,
        max_retries,
    )
}

/// TCP ACK Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_ack_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(
        net_info,
        None,
        None,
        None,
        ScanMethod::Ack,
        timeout,
        max_retries,
    )
}

#[cfg(feature = "scan")]
pub fn tcp_null_scan(
    net_infos: Vec<NetInfo>,
    threads: usize,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    scan(
        net_infos,
        None,
        None,
        None,
        ScanMethod::Null,
        threads,
        timeout,
        max_retries,
    )
}

/// TCP Null Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_null_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(
        net_info,
        None,
        None,
        None,
        ScanMethod::Null,
        timeout,
        max_retries,
    )
}

#[cfg(feature = "scan")]
pub fn tcp_xmas_scan(
    net_infos: Vec<NetInfo>,
    threads: usize,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    scan(
        net_infos,
        None,
        None,
        None,
        ScanMethod::Xmas,
        threads,
        timeout,
        max_retries,
    )
}

/// TCP Xmas Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_xmas_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(
        net_info,
        None,
        None,
        None,
        ScanMethod::Xmas,
        timeout,
        max_retries,
    )
}

#[cfg(feature = "scan")]
pub fn tcp_window_scan(
    net_infos: Vec<NetInfo>,
    threads: usize,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    scan(
        net_infos,
        None,
        None,
        None,
        ScanMethod::Window,
        threads,
        timeout,
        max_retries,
    )
}

/// TCP Window Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_window_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(
        net_info,
        None,
        None,
        None,
        ScanMethod::Window,
        timeout,
        max_retries,
    )
}

#[cfg(feature = "scan")]
pub fn tcp_maimon_scan(
    net_infos: Vec<NetInfo>,
    threads: usize,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    scan(
        net_infos,
        None,
        None,
        None,
        ScanMethod::Maimon,
        threads,
        timeout,
        max_retries,
    )
}

/// TCP Maimon Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_maimon_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(
        net_info,
        None,
        None,
        None,
        ScanMethod::Maimon,
        timeout,
        max_retries,
    )
}

#[cfg(feature = "scan")]
pub fn tcp_idle_scan(
    net_infos: Vec<NetInfo>,
    zombie_mac: Option<MacAddr>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    threads: usize,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    scan(
        net_infos,
        zombie_mac,
        zombie_ipv4,
        zombie_port,
        ScanMethod::Idle,
        threads,
        timeout,
        max_retries,
    )
}

/// TCP Idle Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_idle_scan_raw(
    net_info: NetInfo,
    zombie_mac: Option<MacAddr>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(
        net_info,
        zombie_mac,
        zombie_ipv4,
        zombie_port,
        ScanMethod::Idle,
        timeout,
        max_retries,
    )
}

#[cfg(feature = "scan")]
pub fn udp_scan(
    net_infos: Vec<NetInfo>,
    threads: usize,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    scan(
        net_infos,
        None,
        None,
        None,
        ScanMethod::Udp,
        threads,
        timeout,
        max_retries,
    )
}

/// UDP Scan, raw version.
#[cfg(feature = "scan")]
pub fn udp_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(
        net_info,
        None,
        None,
        None,
        ScanMethod::Udp,
        timeout,
        max_retries,
    )
}

#[cfg(feature = "scan")]
fn scan_raw(
    net_info: NetInfo,
    zombie_mac: Option<MacAddr>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    method: ScanMethod,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    let mut ret = PortScan::new(max_retries);
    if !net_info.valid {
        ret.finish(None);
        return Ok(ret);
    }

    let dst_mac = net_info.dst_mac;
    let dst_addr = net_info.dst_addr;
    let src_mac = net_info.src_mac;
    let interface = &net_info.interface;
    let src_port = match net_info.src_port {
        Some(s) => s,
        None => utils::random_port(),
    };

    let dst_port = if net_info.dst_ports.len() > 0 {
        net_info.dst_ports[0]
    } else {
        return Err(PistolError::NoDstPortSpecified);
    };

    // dst_addr may change during the processing.
    // It is only used here to determine whether the target is ipv4 or ipv6.
    // The real dst_addr is inferred from infer_addr.
    let mut port_report = None;
    let cached = net_info.cached;
    match dst_addr {
        IpAddr::V4(dst_ipv4) => {
            let src_ipv4 = match net_info.src_addr {
                IpAddr::V4(s) => s,
                _ => {
                    return Err(PistolError::AttackAddressNotMatch {
                        addr: net_info.src_addr,
                    });
                }
            };
            for i in 0..max_retries {
                let (port_status, data_recv_status, rtt) = scan_thread(
                    dst_mac,
                    dst_ipv4,
                    dst_port,
                    src_mac,
                    src_ipv4,
                    src_port,
                    zombie_mac,
                    zombie_ipv4,
                    zombie_port,
                    interface,
                    method,
                    timeout,
                )?;
                if i == max_retries - 1 {
                    port_report = Some(PortReport {
                        addr: dst_addr,
                        port: dst_port,
                        status: port_status,
                        cost: rtt,
                        cached,
                    });
                } else {
                    match data_recv_status {
                        DataRecvStatus::Yes => {
                            port_report = Some(PortReport {
                                addr: dst_addr,
                                port: dst_port,
                                status: port_status,
                                cost: rtt,
                                cached,
                            });
                            break;
                        }
                        DataRecvStatus::No => (), // continue probing
                    }
                }
            }
        }
        IpAddr::V6(dst_ipv6) => {
            let src_ipv6 = match net_info.src_addr {
                IpAddr::V6(s) => s,
                _ => {
                    return Err(PistolError::AttackAddressNotMatch {
                        addr: net_info.src_addr,
                    });
                }
            };
            for i in 0..max_retries {
                let (port_status, data_recv_status, rtt) = scan_thread6(
                    dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, interface, method,
                    timeout,
                )?;
                if i == max_retries - 1 {
                    port_report = Some(PortReport {
                        addr: dst_addr,
                        port: dst_port,
                        status: port_status,
                        cost: rtt,
                        cached,
                    });
                } else {
                    match data_recv_status {
                        DataRecvStatus::Yes => {
                            port_report = Some(PortReport {
                                addr: dst_addr,
                                port: dst_port,
                                status: port_status,
                                cost: rtt,
                                cached,
                            });
                            break;
                        }
                        DataRecvStatus::No => (), // continue probing
                    }
                }
            }
        }
    };
    ret.finish(port_report);
    Ok(ret)
}

#[cfg(feature = "scan")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Pistol, Target};
    use std::{str::FromStr, vec};
    #[test]
    fn test_arp_scan_single() {
        let target = Target::new(IpAddr::V4(Ipv4Addr::new(192, 168, 5, 77)), None);
        let targets = vec![target];
        let timeout = Duration::from_secs_f32(10.0);
        let threads = 512;
        let max_retries = 2;

        let mut pistol = Pistol::new();
        pistol.set_log_level("debug");
        pistol.init_runners_without_net_infos().unwrap();
        let ret = mac_scan(&targets, timeout, threads, max_retries).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_arp_scan_subnet() {
        let targets = Target::from_subnet("192.168.5.0/24", None).unwrap();
        // println!("{}", targets.len());
        // let target1 = Target::new(IpAddr::V4(Ipv4Addr::new(192, 168, 5, 77)), None);
        // let target2 = Target::new(IpAddr::V4(Ipv4Addr::new(192, 168, 5, 2)), None);
        // let target3 = Target::new(IpAddr::V4(Ipv4Addr::new(192, 168, 5, 3)), None);
        // let target4 = Target::new(IpAddr::V4(Ipv4Addr::new(192, 168, 5, 4)), None);
        // let targets = vec![target1, target2, target3, target4];
        // let targets = vec![target1];
        let timeout = Duration::from_secs_f32(1.5);
        let threads = 512;
        let max_retries = 2;

        let mut pistol = Pistol::new();
        pistol.set_log_level("debug");
        pistol.init_runners_without_net_infos().unwrap();
        let ret = mac_scan(&targets, timeout, threads, max_retries).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_ndp_ns_scan_subnet() {
        let targets = Target::from_subnet6("fe80::20c:29ff:fe5b:bd5c/126", None).unwrap();
        let timeout = Duration::from_secs_f32(1.5);
        let threads = 512;
        let max_retries = 2;

        let mut pistol = Pistol::new();
        pistol.set_log_level("debug");
        pistol.init_runners_without_net_infos().unwrap();
        let ret = mac_scan(&targets, timeout, threads, max_retries).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_ndp_ns_scan_single() {
        let dst_ipv6 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e4").unwrap();
        let target = Target::new(dst_ipv6.into(), None);
        let targets = vec![target];
        let timeout = Duration::from_secs_f32(0.5);
        let threads = 512;
        let max_retries = 2;

        let mut pistol = Pistol::new();
        pistol.set_log_level("debug");
        pistol.init_runners_without_net_infos().unwrap();
        let ret = mac_scan(&targets, timeout, threads, max_retries).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_tcp_connect_scan() {
        let src_addr = None;
        let src_port = None;
        let timeout = Duration::new(1, 0);
        let dst_ipv4 = Ipv4Addr::new(192, 168, 5, 77);
        // let dst_ipv4 = Ipv4Addr::new(192, 168, 31, 1);
        let target = Target::new(dst_ipv4.into(), Some(vec![22, 80, 443]));
        let targets = vec![target];
        let max_retries = 2;
        let threads = 8;

        let mut pistol = Pistol::new();
        let (net_infos, dur) = pistol.init_runner(&targets, src_addr, src_port).unwrap();

        let ret = tcp_connect_scan(net_infos, threads, timeout, max_retries).unwrap();
        println!("layer2: {:.2}s, {}", dur.as_secs_f32(), ret);
    }
    #[test]
    fn test_tcp_syn_scan() {
        let src_addr = None;
        let src_port = None;
        let timeout = Duration::new(1, 0);
        let max_retries = 2;
        let threads = 8;
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        let addr1 = IpAddr::V4(Ipv4Addr::new(10, 179, 252, 233));
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 77));
        #[cfg(target_os = "linux")]
        let ports = vec![22, 80, 5432, 8080];
        #[cfg(target_os = "windows")]
        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 129));
        #[cfg(target_os = "windows")]
        let ports = vec![22, 80, 3389, 8080];
        #[cfg(target_os = "freebsd")]
        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4));
        #[cfg(target_os = "freebsd")]
        let ports = vec![22, 80, 3389, 8080];

        let target1 = Target::new(addr1, Some(ports));
        let targets = vec![target1];
        let mut pistol = Pistol::new();
        pistol.set_log_level("debug");
        let (net_infos, dur) = pistol.init_runner(&targets, src_addr, src_port).unwrap();
        let ret = tcp_syn_scan(net_infos, threads, timeout, max_retries).unwrap();
        println!("layer2: {:.2}s, {}", dur.as_secs_f32(), ret);
    }
    #[test]
    fn test_tcp_syn_scan_performance() {
        let src_addr = None;
        let src_port = Some(37888);
        let timeout = Duration::from_secs_f32(0.5);
        let max_retries = 1;
        let threads = 65535;
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 77));
        let ports: Vec<u16> = (22..65535).collect();
        // let ports: Vec<u16> = (8000..9000).collect();
        // let ports: Vec<u16> = (22..200).collect();
        // let ports: Vec<u16> = (22..101).collect();

        let target = Target::new(addr, Some(ports));
        let targets = vec![target];

        let mut pistol = Pistol::new();
        let (net_infos, dur) = pistol.init_runner(&targets, src_addr, src_port).unwrap();
        let ret = tcp_syn_scan(net_infos, threads, timeout, max_retries).unwrap();
        for r in &ret.port_reports {
            match r.status {
                PortStatus::Open => println!("{}:{} -> open", r.addr, r.port),
                _ => (),
            }
        }

        let total = ret.finish_time - ret.start_time;
        println!(
            "layer2: {:.2}s, total: {:.2}s",
            dur.as_secs_f32(),
            total.as_seconds_f32()
        );
        // println!("{}", ret);
    }
    #[test]
    fn test_tcp_fin_scan() {
        let src_addr = None;
        let src_port = None;
        let timeout = Duration::new(1, 0);
        let dst_ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5));
        let target = Target::new(dst_ipv4, Some(vec![22, 80, 443]));
        let targets = vec![target];
        let max_retries = 2;
        let threads = 8;
        let mut pistol = Pistol::new();
        let (net_infos, dur) = pistol.init_runner(&targets, src_addr, src_port).unwrap();
        let ret = tcp_fin_scan(net_infos, threads, timeout, max_retries).unwrap();
        println!("layer2: {:.2}s, {}", dur.as_secs_f32(), ret);
    }
    #[test]
    fn test_tcp_ack_scan() {
        let src_addr = None;
        let src_port = None;
        let timeout = Duration::new(1, 0);
        let dst_ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5));
        let target = Target::new(dst_ipv4, Some(vec![22, 80, 443]));
        let targets = vec![target];
        let max_retries = 2;
        let threads = 8;
        let mut pistol = Pistol::new();
        let (net_infos, dur) = pistol.init_runner(&targets, src_addr, src_port).unwrap();
        let ret = tcp_ack_scan(net_infos, threads, timeout, max_retries).unwrap();
        println!("layer2: {:.2}s, {}", dur.as_secs_f32(), ret);
    }
    #[test]
    fn test_tcp_null_scan() {
        let src_addr = None;
        let src_port = None;
        let timeout = Duration::new(1, 0);
        let dst_ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5));
        let target = Target::new(dst_ipv4, Some(vec![22, 80, 443]));
        let targets = vec![target];
        let max_retries = 2;
        let threads = 8;
        let mut pistol = Pistol::new();
        let (net_infos, dur) = pistol.init_runner(&targets, src_addr, src_port).unwrap();
        let ret = tcp_null_scan(net_infos, threads, timeout, max_retries).unwrap();
        println!("layer2: {:.2}s, {}", dur.as_secs_f32(), ret);
    }
    #[test]
    fn test_udp_scan() {
        let src_addr = None;
        let src_port = None;
        let timeout = Duration::new(1, 0);
        let dst_ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5));
        let target = Target::new(dst_ipv4, Some(vec![22, 80, 443, 8080, 8081]));
        let targets = vec![target];
        let max_retries = 2;
        let threads = 8;
        let mut pistol = Pistol::new();
        let (net_infos, dur) = pistol.init_runner(&targets, src_addr, src_port).unwrap();
        let ret = udp_scan(net_infos, threads, timeout, max_retries).unwrap();
        println!("layer2: {:.2}s, {}", dur.as_secs_f32(), ret);
    }
}
