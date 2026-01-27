/* Scan */
#[cfg(any(feature = "scan", feature = "ping"))]
use chrono::DateTime;
#[cfg(any(feature = "scan", feature = "ping"))]
use chrono::Local;
#[cfg(feature = "scan")]
use pnet::datalink::MacAddr;
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
use tracing::debug;
#[cfg(any(feature = "scan", feature = "ping"))]
use tracing::error;
#[cfg(any(feature = "scan", feature = "ping"))]
use tracing::warn;

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
#[cfg(any(feature = "scan", feature = "ping"))]
use crate::error::PistolError;
#[cfg(any(feature = "scan", feature = "ping"))]
#[cfg(feature = "scan")]
use crate::scan::arp::send_arp_scan_packet;
#[cfg(feature = "scan")]
use crate::scan::ndp_ns::send_ndp_ns_scan_packet;
#[cfg(any(feature = "scan", feature = "ping"))]
use crate::utils;

/// This structure is used to indicate whether the status
/// is a conclusion drawn from data received or from no data received.
/// For example, in UDP scan, if no data is received, the status returned is open_or_filtered.
/// So when UDP scan returns to the open_or_filtered state, DataRecvStatus should be set to No.
/// This structure is used to indicate whether the program needs to be retried or terminated directly.
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
pub struct PistolMacScans {
    pub mac_reports: Vec<MacReport>,
    pub start_time: DateTime<Local>,
    pub end_time: DateTime<Local>,
    attempts: usize,
}

#[cfg(feature = "scan")]
impl PistolMacScans {
    pub fn new(attempts: usize) -> PistolMacScans {
        PistolMacScans {
            mac_reports: Vec::new(),
            start_time: Local::now(),
            end_time: Local::now(),
            attempts,
        }
    }
    pub fn value(&self) -> Vec<MacReport> {
        self.mac_reports.clone()
    }
    pub fn finish(&mut self, mac_reports: Vec<MacReport>) {
        self.end_time = Local::now();
        self.mac_reports = mac_reports;
    }
}

#[cfg(feature = "scan")]
impl fmt::Display for PistolMacScans {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let total_cost = self.end_time - self.start_time;
        let total_cost_str =
            utils::time_sec_to_string(Duration::from_secs_f64(total_cost.as_seconds_f64()));
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new(&format!("Mac Scan Results (attempts:{})", self.attempts))
                .style_spec("c")
                .with_hspan(5),
        ]));

        table.add_row(row![c -> "seq", c -> "addr", c -> "mac", c -> "oui", c-> "rtt"]);

        // sorted the results
        let mut btm_addr: BTreeMap<IpAddr, MacReport> = BTreeMap::new();
        for report in &self.mac_reports {
            btm_addr.insert(report.addr, report.clone());
        }

        let mut i = 1;
        for (_addr, report) in btm_addr {
            let rtt_str = utils::time_sec_to_string(report.rtt);
            match report.mac {
                Some(mac) => {
                    table.add_row(
                        row![c -> i, c -> report.addr, c -> mac, c -> report.ouis, c -> rtt_str],
                    );
                    i += 1;
                }
                None => (),
            }
        }

        let avg_cost = total_cost.as_seconds_f64() / self.mac_reports.len() as f64;
        let summary = format!(
            "total cost: {}\navg cost: {:.3}s\nalive hosts: {}",
            total_cost_str,
            avg_cost,
            self.mac_reports.len(),
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(5)]));

        write!(f, "{}", table)
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
    net_info: &NetInfo,
    timeout: Option<Duration>,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    let mut net_info = *net_info.clone();
    // fixed dst mac to broadcast
    net_info.dst_mac = MacAddr::broadcast();

    let timeout = match timeout {
        Some(t) => t,
        None => utils::get_attack_default_timeout(),
    };

    match send_arp_scan_packet(&net_info, timeout) {
        Ok((mac, rtt)) => Ok((mac, rtt)),
        Err(e) => Err(e),
    }
}

#[cfg(feature = "scan")]
pub fn ndp_ns_scan_raw(
    net_info: &NetInfo,
    timeout: Option<Duration>,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    let src_mac = match net_info.interface.mac {
        Some(m) => m,
        None => return Err(PistolError::CanNotFoundMacAddress),
    };
    let timeout = match timeout {
        Some(t) => t,
        None => utils::get_attack_default_timeout(),
    };

    let (dst_ipv6, src_ipv6) = net_info.addr.get_ipv6_addr()?;
    match send_ndp_ns_scan_packet(dst_ipv6, src_ipv6, src_mac, &net_info.interface, timeout) {
        Ok((mac, rtt)) => Ok((mac, rtt)),
        Err(e) => Err(e),
    }
}

#[cfg(feature = "scan")]
pub fn mac_scan(
    net_infos: Vec<NetInfo>,
    timeout: Option<Duration>,
    threads: usize,
    attempts: usize,
) -> Result<PistolMacScans, PistolError> {
    let nmap_mac_prefixes = get_nmap_mac_prefixes();
    let mut ret = PistolMacScans::new(attempts);
    let threads = utils::num_threads_check(threads);
    let pool = utils::get_threads_pool(threads);
    let (tx, rx) = channel();
    let mut recv_size = 0;
    for ni in net_infos {
        let infer_addr = ni.addr;
        let dst_addr = infer_addr.dst_addr;
        if infer_addr.is_ipv4() {
            let tx = tx.clone();
            recv_size += 1;
            pool.execute(move || {
                for i in 0..attempts {
                    debug!("arp scan packets: #{}/{}", i + 1, attempts);
                    let scan_ret = arp_scan_raw(&ni, timeout);
                    if i == attempts - 1 {
                        let _ = tx.send((dst_addr, scan_ret));
                    } else {
                        match scan_ret {
                            Ok((value, _)) => match value {
                                Some(_) => {
                                    let _ = tx.send((dst_addr, scan_ret));
                                    break;
                                }
                                None => (),
                            },
                            Err(_) => {
                                let _ = tx.send((dst_addr, scan_ret));
                                break;
                            }
                        }
                    }
                }
            });
        } else if infer_addr.is_ipv6() {
            let tx = tx.clone();
            recv_size += 1;
            pool.execute(move || {
                for i in 0..attempts {
                    debug!("ndp_ns scan packets: #{}/{}", i + 1, attempts);
                    let scan_ret = ndp_ns_scan_raw(&ni, timeout);
                    if i == attempts - 1 {
                        let _ = tx.send((dst_addr, scan_ret));
                    } else {
                        match scan_ret {
                            Ok((value, _)) => match value {
                                Some(_) => {
                                    let _ = tx.send((dst_addr, scan_ret));
                                    break;
                                }
                                None => (),
                            },
                            Err(_) => {
                                // println!("{}", e);
                                let _ = tx.send((dst_addr, scan_ret));
                                break;
                            }
                        }
                    }
                }
            });
        } else {
            return Err(PistolError::IpVersionNotMatch);
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
#[derive(Debug, Clone)]
pub struct PortReport {
    pub addr: IpAddr,
    pub port: u16,
    pub ori_target: Option<String>,
    pub status: PortStatus,
    pub cost: Duration, // from layer2
}

#[cfg(any(feature = "scan", feature = "ping"))]
#[derive(Debug, Clone)]
pub struct PistolPortScans {
    // The order of this Vec is the same as the order in which the data packets are received.
    // The detection that receives the data first is in the front.
    pub port_reports: Vec<PortReport>,
    pub start_time: DateTime<Local>,
    pub end_time: DateTime<Local>,
    pub attempts: usize,
}

#[cfg(any(feature = "scan", feature = "ping"))]
impl PistolPortScans {
    pub fn new(attempts: usize) -> PistolPortScans {
        PistolPortScans {
            port_reports: Vec::new(),
            start_time: Local::now(),
            end_time: Local::now(),
            attempts,
        }
    }
    pub fn value(&self) -> Vec<PortReport> {
        self.port_reports.clone()
    }
    pub fn finish(&mut self, port_reports: Vec<PortReport>) {
        self.end_time = Local::now();
        self.port_reports = port_reports;
    }
}

#[cfg(any(feature = "scan", feature = "ping"))]
impl fmt::Display for PistolPortScans {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let total_cost = self.end_time - self.start_time;

        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new(&format!("Port Scan Results (attempts:{})", self.attempts,))
                .style_spec("c")
                .with_hspan(5),
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
                let addr_str = match report.ori_target {
                    Some(o) => format!("{}({})", report.addr, o),
                    None => format!("{}", report.addr),
                };
                let status_str = format!("{}", report.status);
                let time_cost_str = utils::time_sec_to_string(report.cost);
                table.add_row(
                    row![c -> i, c -> addr_str, c -> report.port, c -> status_str, c -> time_cost_str],
                );
                i += 1;
            }
        }

        // let help_info = format!(
        //     "NOTE:\nO: OPEN, OF: OPEN_OR_FILTERED, F: FILTERED,\nUF: UNFILTERED, C: CLOSED, UR: UNREACHABLE,\nCF: CLOSE_OF_FILTERED, E: ERROR, OL: OFFLINE."
        // );
        // table.add_row(Row::new(vec![Cell::new(&help_info).with_hspan(5)]));

        let avg_cost = total_cost.as_seconds_f64() / self.port_reports.len() as f64;
        let summary = format!(
            "total cost: {:.3}s, avg cost: {:.3}s, open ports: {}",
            total_cost.as_seconds_f64(),
            avg_cost,
            open_ports_num,
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(5)]));
        write!(f, "{}", table)
    }
}

#[cfg(any(feature = "scan", feature = "ping"))]
fn scan_thread(
    method: ScanMethod,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    timeout: Duration,
) -> Result<(PortStatus, DataRecvStatus, Duration), PistolError> {
    let (port_status, data_return, rtt) = match method {
        ScanMethod::Connect => tcp::send_connect_scan_packet(dst_ipv4.into(), dst_port, timeout)?,
        ScanMethod::Syn => {
            tcp::send_syn_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?
        }
        ScanMethod::Fin => {
            tcp::send_fin_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?
        }
        ScanMethod::Ack => {
            tcp::send_ack_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?
        }
        ScanMethod::Null => {
            tcp::send_null_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?
        }
        ScanMethod::Xmas => {
            tcp::send_xmas_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?
        }
        ScanMethod::Window => {
            tcp::send_window_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?
        }
        ScanMethod::Maimon => {
            tcp::send_maimon_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?
        }
        ScanMethod::Idle => {
            // this two parameters must be Some
            let zombie_ipv4 = zombie_ipv4.unwrap();
            let zombie_port = zombie_port.unwrap();
            tcp::send_idle_scan_packet(
                dst_ipv4,
                dst_port,
                src_ipv4,
                src_port,
                zombie_ipv4,
                zombie_port,
                timeout,
            )?
        }
        ScanMethod::Udp => {
            udp::send_udp_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port, timeout)?
        }
    };

    Ok((port_status, data_return, rtt))
}

#[cfg(any(feature = "scan", feature = "ping"))]
fn scan_thread6(
    method: ScanMethod,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    timeout: Duration,
) -> Result<(PortStatus, DataRecvStatus, Duration), PistolError> {
    let (port_status, data_return, rtt) = match method {
        ScanMethod::Connect => tcp::send_connect_scan_packet(dst_ipv6.into(), dst_port, timeout)?,
        ScanMethod::Syn => {
            tcp6::send_syn_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?
        }
        ScanMethod::Fin => {
            tcp6::send_fin_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?
        }
        ScanMethod::Ack => {
            tcp6::send_ack_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?
        }
        ScanMethod::Null => {
            tcp6::send_null_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?
        }
        ScanMethod::Xmas => {
            tcp6::send_xmas_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?
        }
        ScanMethod::Window => {
            tcp6::send_window_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?
        }
        ScanMethod::Maimon => {
            tcp6::send_maimon_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?
        }
        ScanMethod::Udp => {
            udp6::send_udp_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port, timeout)?
        }
        ScanMethod::Idle => {
            warn!("idel scan not supported the ipv6 address, use connect scan instead now");
            tcp::send_connect_scan_packet(dst_ipv6.into(), dst_port, timeout)?
        }
    };

    Ok((port_status, data_return, rtt))
}

/// General scan function.
#[cfg(any(feature = "scan", feature = "ping"))]
fn scan(
    net_infos: &[NetInfo],
    method: ScanMethod,
    threads: Option<usize>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPortScans, PistolError> {
    let mut pistol_port_scans = PistolPortScans::new(attempts);

    let threads = match threads {
        Some(t) => t,
        None => {
            let mut init_numm_threads = 0;
            for ni in net_infos {
                init_numm_threads += ni.dst_ports.len();
            }
            let threads = utils::num_threads_check(init_numm_threads);
            threads
        }
    };
    let timeout = match timeout {
        Some(t) => t,
        None => utils::get_attack_default_timeout(),
    };

    debug!("scan will create {} threads to do the jobs", threads);
    let pool = utils::get_threads_pool(threads);
    let (tx, rx) = channel();
    let mut recv_size = 0;

    for ni in net_infos {
        if ni.addr.is_ipv4() {
            let (dst_ipv4, src_ipv4) = ni.addr.get_ipv4_addr()?;
            let dst_addr: IpAddr = dst_ipv4.into();
            for &dst_port in &ni.dst_ports {
                let src_port = match ni.src_port {
                    Some(s) => s,
                    None => utils::random_port(),
                };
                // debug!(
                //     "sending scan packet to [{}] port [{}] and src port [{}]",
                //     dst_addr, dst_port, src_port
                // );
                let tx = tx.clone();
                let ori_target = format!("{}:{}", ni.addr.ori_dst_addr, dst_port);
                recv_size += 1;

                pool.execute(move || {
                    for ind in 0..attempts {
                        let start_time = Instant::now();
                        debug!(
                            "sending scan packet to [{}] port [{}] try [{}]",
                            dst_ipv4, dst_port, ind
                        );
                        let scan_ret = scan_thread(
                            method,
                            dst_ipv4,
                            dst_port,
                            src_ipv4,
                            src_port,
                            zombie_ipv4,
                            zombie_port,
                            timeout,
                        );
                        if ind == attempts - 1 {
                            // last attempt
                            tx.send((
                                dst_addr,
                                dst_port,
                                ori_target.clone(),
                                scan_ret,
                                start_time.elapsed(),
                            ));
                        } else {
                            match scan_ret {
                                Ok((_port_status, data_return, _)) => {
                                    match data_return {
                                        DataRecvStatus::Yes => {
                                            // conclusions drawn from the returned data
                                            tx.send((
                                                dst_addr,
                                                dst_port,
                                                ori_target.clone(),
                                                scan_ret,
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
                                    tx.send((
                                        dst_addr,
                                        dst_port,
                                        ori_target,
                                        scan_ret,
                                        start_time.elapsed(),
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        } else if ni.addr.is_ipv6() {
            let (dst_ipv6, src_ipv6) = ni.addr.get_ipv6_addr()?;
            let dst_addr: IpAddr = dst_ipv6.into();
            for &dst_port in &ni.dst_ports {
                let src_port = match ni.src_port {
                    Some(s) => s,
                    None => utils::random_port(),
                };
                let tx = tx.clone();
                let ori_target = format!("{}:{}", ni.addr.ori_dst_addr, dst_port);
                recv_size += 1;

                pool.execute(move || {
                    for ind in 0..attempts {
                        let start_time = Instant::now();
                        let scan_ret =
                            scan_thread6(method, dst_ipv6, dst_port, src_ipv6, src_port, timeout);
                        if ind == attempts - 1 {
                            tx.send((
                                dst_addr,
                                dst_port,
                                ori_target.clone(),
                                scan_ret,
                                start_time.elapsed(),
                            ));
                        } else {
                            match scan_ret {
                                Ok((_port_status, data_return, _)) => {
                                    match data_return {
                                        DataRecvStatus::Yes => {
                                            // conclusions drawn from the returned data
                                            tx.send((
                                                dst_addr,
                                                dst_port,
                                                ori_target.clone(),
                                                scan_ret,
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
                                    tx.send((
                                        dst_addr,
                                        dst_port,
                                        ori_target,
                                        scan_ret,
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
    for (dst_addr, dst_port, ori_target, v, elapsed) in iter {
        match v {
            Ok((port_status, _data_return, rtt)) => {
                // println!("rtt: {:.3}", rtt.as_secs_f64());
                let scan_report = PortReport {
                    addr: dst_addr,
                    port: dst_port,
                    ori_target: Some(ori_target),
                    status: port_status,
                    cost: rtt,
                };
                reports.push(scan_report);
            }
            Err(e) => match e {
                PistolError::CanNotFoundMacAddress => {
                    let scan_report = PortReport {
                        addr: dst_addr,
                        port: dst_port,
                        ori_target: Some(ori_target),
                        status: PortStatus::Offline,
                        cost: elapsed,
                    };
                    reports.push(scan_report);
                }
                _ => {
                    error!("scan error: {}", e);
                    let scan_report = PortReport {
                        addr: dst_addr,
                        port: dst_port,
                        ori_target: Some(ori_target),
                        status: PortStatus::Error,
                        cost: elapsed,
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
    net_infos: &[NetInfo],
    threads: Option<usize>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPortScans, PistolError> {
    scan(
        net_infos,
        ScanMethod::Connect,
        threads,
        None,
        None,
        timeout,
        attempts,
    )
}

/// TCP connect() Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_connect_scan_raw(
    net_info: &NetInfo,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(net_info, ScanMethod::Connect, None, None, timeout)
}

#[cfg(any(feature = "scan", feature = "ping"))]
pub fn tcp_syn_scan(
    net_infos: &[NetInfo],
    threads: Option<usize>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPortScans, PistolError> {
    scan(
        net_infos,
        ScanMethod::Syn,
        threads,
        None,
        None,
        timeout,
        attempts,
    )
}

/// TCP SYN Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_syn_scan_raw(
    net_info: &NetInfo,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(net_info, ScanMethod::Syn, None, None, timeout)
}

#[cfg(feature = "scan")]
pub fn tcp_fin_scan(
    net_infos: &[NetInfo],
    threads: Option<usize>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPortScans, PistolError> {
    scan(
        net_infos,
        ScanMethod::Fin,
        threads,
        None,
        None,
        timeout,
        attempts,
    )
}

/// TCP FIN Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_fin_scan_raw(
    net_info: &NetInfo,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(net_info, ScanMethod::Fin, None, None, timeout)
}

#[cfg(feature = "scan")]
pub fn tcp_ack_scan(
    net_infos: &[NetInfo],
    threads: Option<usize>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPortScans, PistolError> {
    scan(
        net_infos,
        ScanMethod::Ack,
        threads,
        None,
        None,
        timeout,
        attempts,
    )
}

/// TCP ACK Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_ack_scan_raw(
    net_info: &NetInfo,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(net_info, ScanMethod::Ack, None, None, timeout)
}

#[cfg(feature = "scan")]
pub fn tcp_null_scan(
    net_infos: &[NetInfo],
    threads: Option<usize>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPortScans, PistolError> {
    scan(
        net_infos,
        ScanMethod::Null,
        threads,
        None,
        None,
        timeout,
        attempts,
    )
}

/// TCP Null Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_null_scan_raw(
    net_info: &NetInfo,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(net_info, ScanMethod::Null, None, None, timeout)
}

#[cfg(feature = "scan")]
pub fn tcp_xmas_scan(
    net_infos: &[NetInfo],
    threads: Option<usize>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPortScans, PistolError> {
    scan(
        net_infos,
        ScanMethod::Xmas,
        threads,
        None,
        None,
        timeout,
        attempts,
    )
}

/// TCP Xmas Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_xmas_scan_raw(
    net_info: &NetInfo,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(net_info, ScanMethod::Xmas, None, None, timeout)
}

#[cfg(feature = "scan")]
pub fn tcp_window_scan(
    net_infos: &[NetInfo],
    threads: Option<usize>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPortScans, PistolError> {
    scan(
        net_infos,
        ScanMethod::Window,
        threads,
        None,
        None,
        timeout,
        attempts,
    )
}

/// TCP Window Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_window_scan_raw(
    net_info: &NetInfo,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(net_info, ScanMethod::Window, None, None, timeout)
}

#[cfg(feature = "scan")]
pub fn tcp_maimon_scan(
    net_infos: &[NetInfo],
    threads: Option<usize>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPortScans, PistolError> {
    scan(
        net_infos,
        ScanMethod::Maimon,
        threads,
        None,
        None,
        timeout,
        attempts,
    )
}

/// TCP Maimon Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_maimon_scan_raw(
    net_info: &NetInfo,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(net_info, ScanMethod::Maimon, None, None, timeout)
}

#[cfg(feature = "scan")]
pub fn tcp_idle_scan(
    net_infos: &[NetInfo],
    threads: Option<usize>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPortScans, PistolError> {
    scan(
        net_infos,
        ScanMethod::Idle,
        threads,
        zombie_ipv4,
        zombie_port,
        timeout,
        attempts,
    )
}

/// TCP Idle Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_idle_scan_raw(
    net_info: &NetInfo,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        net_info,
        ScanMethod::Idle,
        zombie_ipv4,
        zombie_port,
        timeout,
    )
}

#[cfg(feature = "scan")]
pub fn udp_scan(
    net_infos: &[NetInfo],
    threads: Option<usize>,
    timeout: Option<Duration>,
    attempts: usize,
) -> Result<PistolPortScans, PistolError> {
    scan(
        net_infos,
        ScanMethod::Udp,
        threads,
        None,
        None,
        timeout,
        attempts,
    )
}

/// UDP Scan, raw version.
#[cfg(feature = "scan")]
pub fn udp_scan_raw(
    net_info: &NetInfo,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(net_info, ScanMethod::Udp, None, None, timeout)
}

#[cfg(feature = "scan")]
fn scan_raw(
    net_info: &NetInfo,
    method: ScanMethod,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    let src_port = match net_info.src_port {
        Some(s) => s,
        None => utils::random_port(),
    };
    let timeout = match timeout {
        Some(t) => t,
        None => utils::get_attack_default_timeout(),
    };

    let dst_port = if net_info.dst_ports.len() > 0 {
        net_info.dst_ports[0]
    } else {
        return Err(PistolError::NoDstPortSpecified);
    };

    // dst_addr may change during the processing.
    // It is only used here to determine whether the target is ipv4 or ipv6.
    // The real dst_addr is inferred from infer_addr.
    if net_info.addr.is_ipv4() {
        let (dst_ipv4, src_ipv4) = net_info.addr.get_ipv4_addr()?;
        let (port_status, _data_return, rtt) = scan_thread(
            method,
            dst_ipv4,
            dst_port,
            src_ipv4,
            src_port,
            zombie_ipv4,
            zombie_port,
            timeout,
        )?;
        Ok((port_status, rtt))
    } else if net_info.addr.is_ipv6() {
        let (dst_ipv6, src_ipv6) = net_info.addr.get_ipv6_addr()?;
        let (port_status, _data_return, rtt) =
            scan_thread6(method, dst_ipv6, dst_port, src_ipv6, src_port, timeout)?;
        Ok((port_status, rtt))
    } else {
        return Err(PistolError::IpVersionNotMatch);
    }
}

/*
#[cfg(feature = "scan")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Pistol, Target};
    use std::str::FromStr;
    #[test]
    fn test_arp_scan_subnet() {
        let targets = Target::from_subnet("192.168.5.0/24", None).unwrap();
        // println!("{}", targets.len());
        // let target1 = Target::new(IpAddr::V4(Ipv4Addr::new(192, 168, 5, 1)), None);
        // let target2 = Target::new(IpAddr::V4(Ipv4Addr::new(192, 168, 5, 2)), None);
        // let target3 = Target::new(IpAddr::V4(Ipv4Addr::new(192, 168, 5, 3)), None);
        // let target4 = Target::new(IpAddr::V4(Ipv4Addr::new(192, 168, 5, 4)), None);
        // let targets = vec![target1, target2, target3, target4];q
        let timeout = 0.5;
        let src_ipv4 = None;
        let threads = 512;
        let attempts = 2;

        let mut p = Pistol::new();
        p.set_timeout(timeout);
        p.set_threads(threads);
        p.set_attempts(attempts);

        let ret = p.mac_scan(&targets, src_ipv4).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_ndp_ns_scan_subnet() {
        let targets = Target::from_subnet6("fe80::20c:29ff:fe5b:bd5c/126", None).unwrap();
        let timeout = 0.5;
        let src_ipv6 = None;
        let threads = 512;
        let attempts = 2;

        let mut p = Pistol::new();
        p.set_timeout(timeout);
        p.set_threads(threads);
        p.set_attempts(attempts);

        let ret = p.mac_scan(&targets, src_ipv6).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_ndp_ns_scan_single() {
        let dst_ipv6 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e4").unwrap();
        let target = Target::new(dst_ipv6.into(), None);
        let timeout = 0.5;
        let src_ipv6 = None;
        let threads = 512;
        let attempts = 2;

        let mut p = Pistol::new();
        p.set_timeout(timeout);
        p.set_threads(threads);
        p.set_attempts(attempts);

        let ret = p.mac_scan(&[target], src_ipv6).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_tcp_connect_scan() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
        let dst_ipv4 = Ipv4Addr::new(192, 168, 5, 5);
        // let dst_ipv4 = Ipv4Addr::new(192, 168, 31, 1);
        let target = Target::new(dst_ipv4.into(), Some(vec![22, 80, 443]));
        // let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let attempts = 2;
        let threads = Some(8);
        let ret =
            tcp_connect_scan(&[target], threads, src_ipv4, src_port, timeout, attempts).unwrap();
        println!("{}", ret);

        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
        let dst_ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        // let dst_ipv4 = Ipv4Addr::new(192, 168, 31, 1);
        let target = Target::new(dst_ipv4.into(), Some(vec![22, 80, 443]));
        // let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let attempts = 2;
        let threads = Some(8);
        let ret =
            tcp_connect_scan(&[target], threads, src_ipv4, src_port, timeout, attempts).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_tcp_syn_scan() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        let addr1 = IpAddr::V4(Ipv4Addr::new(10, 179, 252, 233));
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 129));
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
        let attempts = 2;
        let threads = None;
        let ret = tcp_syn_scan(&[target1], threads, src_ipv4, src_port, timeout, attempts).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_tcp_syn_scan_performance() {
        let src_ipv4 = None;
        let src_port = Some(37888);
        let timeout = Some(Duration::from_secs_f32(2.5));
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 152));
        // let ports: Vec<u16> = (22..65535).collect();
        // let ports: Vec<u16> = (8000..9000).collect();
        // let ports: Vec<u16> = (22..200).collect();
        let ports: Vec<u16> = (22..101).collect();

        let target1 = Target::new(addr, Some(ports));
        let attempts = 1;
        let threads = Some(10240);
        let ret = tcp_syn_scan(&[target1], threads, src_ipv4, src_port, timeout, attempts).unwrap();
        for r in ret.port_reports {
            match r.status {
                PortStatus::Open => println!("{}:{} -> open", r.addr, r.port),
                _ => (),
            }
        }
        // println!("{}", ret);
    }
    #[test]
    fn test_tcp_fin_scan() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
        let dst_ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5));
        let target = Target::new(dst_ipv4, Some(vec![22, 80, 443]));
        let attempts = 2;
        let threads = Some(8);
        let ret = tcp_fin_scan(&[target], threads, src_ipv4, src_port, timeout, attempts).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_tcp_ack_scan() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
        let dst_ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5));
        let target = Target::new(dst_ipv4, Some(vec![22, 80, 443]));
        let attempts = 2;
        let threads = Some(8);
        let ret = tcp_ack_scan(&[target], threads, src_ipv4, src_port, timeout, attempts).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_tcp_null_scan() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
        let dst_ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5));
        let target = Target::new(dst_ipv4, Some(vec![22, 80, 443]));
        let attempts = 2;
        let threads = Some(8);
        let ret = tcp_null_scan(&[target], threads, src_ipv4, src_port, timeout, attempts).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_udp_scan() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
        let dst_ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5));
        let target = Target::new(dst_ipv4, Some(vec![22, 80, 443, 8080, 8081]));
        let attempts = 2;
        let threads = Some(8);
        let ret = udp_scan(&[target], threads, src_ipv4, src_port, timeout, attempts).unwrap();
        println!("{}", ret);
    }
}
*/
