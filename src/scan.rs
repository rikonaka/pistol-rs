/* Scan */
#[cfg(any(feature = "scan", feature = "ping"))]
use chrono::DateTime;
#[cfg(any(feature = "scan", feature = "ping"))]
use chrono::Local;
#[cfg(any(feature = "scan", feature = "ping"))]
use log::debug;
#[cfg(any(feature = "scan", feature = "ping"))]
use log::error;
#[cfg(any(feature = "scan", feature = "ping"))]
use log::warn;
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
use std::fmt;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::net::IpAddr;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::net::Ipv4Addr;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::net::Ipv6Addr;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::panic::Location;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::sync::mpsc::channel;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::time::Duration;

#[cfg(feature = "scan")]
pub mod arp;
#[cfg(feature = "scan")]
pub mod ndp_ns;
#[cfg(any(feature = "scan", feature = "ping"))]
pub mod tcp;
#[cfg(any(feature = "scan", feature = "ping"))]
pub mod tcp6;
#[cfg(any(feature = "scan", feature = "ping"))]
pub mod udp;
#[cfg(any(feature = "scan", feature = "ping"))]
pub mod udp6;

#[cfg(any(feature = "scan", feature = "ping"))]
use crate::Target;
#[cfg(any(feature = "scan", feature = "ping"))]
use crate::error::PistolError;
#[cfg(feature = "scan")]
use crate::utils::find_interface_by_ip;
#[cfg(any(feature = "scan", feature = "ping"))]
use crate::utils::find_source_addr;
#[cfg(any(feature = "scan", feature = "ping"))]
use crate::utils::find_source_addr6;
#[cfg(any(feature = "scan", feature = "ping"))]
use crate::utils::get_threads_pool;
#[cfg(any(feature = "scan", feature = "ping"))]
use crate::utils::random_port;
#[cfg(any(feature = "scan", feature = "ping"))]
use crate::utils::rtt_to_string;
#[cfg(any(feature = "scan", feature = "ping"))]
use crate::utils::threads_num_check;

#[cfg(feature = "scan")]
#[derive(Debug, Clone)]
pub struct ArpScanReport {
    pub addr: IpAddr,
    pub mac: MacAddr,
    pub ouis: String, // productions organization name
    pub rtt: Duration,
}

#[cfg(feature = "scan")]
#[derive(Debug, Clone)]
pub struct PistolArpScanReport {
    pub arp_scan_reports: Vec<ArpScanReport>,
    pub start_time: DateTime<Local>,
    pub end_time: DateTime<Local>,
    tests: usize,
}

#[cfg(feature = "scan")]
impl PistolArpScanReport {
    pub fn new(tests: usize) -> PistolArpScanReport {
        PistolArpScanReport {
            arp_scan_reports: Vec::new(),
            start_time: Local::now(),
            end_time: Local::now(),
            tests,
        }
    }
    pub fn value(&self) -> Vec<ArpScanReport> {
        self.arp_scan_reports.clone()
    }
    pub fn finish(&mut self) {
        self.end_time = Local::now();
    }
}

#[cfg(feature = "scan")]
impl fmt::Display for PistolArpScanReport {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let total_cost = self.end_time - self.start_time;
        let total_cost_str = rtt_to_string(Duration::from_secs_f32(total_cost.as_seconds_f32()));
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new(&format!("Mac Scan Results (max tests:{})", self.tests))
                .style_spec("c")
                .with_hspan(5),
        ]));

        table.add_row(row![c -> "seq", c -> "addr", c -> "mac", c -> "oui", c-> "rtt"]);

        for (i, arp_scan_report) in self.arp_scan_reports.iter().enumerate() {
            let rtt_str = rtt_to_string(arp_scan_report.rtt);
            table.add_row(row![c -> (i + 1), c -> arp_scan_report.addr, c -> arp_scan_report.mac, c -> arp_scan_report.ouis, c -> rtt_str]);
        }
        let avg_cost = total_cost.as_seconds_f32() / self.arp_scan_reports.len() as f32;

        let summary = format!(
            "total cost: {}\navg cost: {:.3}s\nalive hosts: {}",
            total_cost_str,
            avg_cost,
            self.arp_scan_reports.len(),
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
fn ipv4_arp_scan(
    dst_ipv4: Ipv4Addr,
    dst_mac: MacAddr,
    src_addr: Option<IpAddr>,
    timeout: Option<Duration>,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    let src_ipv4 = match find_source_addr(src_addr, dst_ipv4)? {
        Some(s) => s,
        None => return Err(PistolError::CanNotFoundSourceAddress),
    };
    let interface = match find_interface_by_ip(src_ipv4.into()) {
        Some(i) => i,
        None => return Err(PistolError::CanNotFoundInterface),
    };
    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(PistolError::CanNotFoundMacAddress),
    };
    arp::send_arp_scan_packet(dst_ipv4, dst_mac, src_ipv4, src_mac, interface, timeout)
}

#[cfg(feature = "scan")]
fn ipv6_ndp_ns_scan(
    dst_ipv6: Ipv6Addr,
    src_addr: Option<IpAddr>,
    timeout: Option<Duration>,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    let src_ipv6 = match find_source_addr6(src_addr, dst_ipv6)? {
        Some(s) => s,
        None => return Err(PistolError::CanNotFoundSourceAddress),
    };
    let interface = match find_interface_by_ip(src_ipv6.into()) {
        Some(i) => i,
        None => return Err(PistolError::CanNotFoundInterface),
    };
    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(PistolError::CanNotFoundMacAddress),
    };
    ndp_ns::send_ndp_ns_scan_packet(dst_ipv6, src_ipv6, src_mac, interface, timeout)
}

#[cfg(feature = "scan")]
pub fn arp_scan_raw(
    dst_ipv4: Ipv4Addr,
    src_addr: Option<IpAddr>,
    timeout: Option<Duration>,
) -> Result<Option<MacAddr>, PistolError> {
    let dst_mac = MacAddr::broadcast();
    let src_ipv4 = match find_source_addr(src_addr, dst_ipv4)? {
        Some(s) => s,
        None => return Err(PistolError::CanNotFoundSourceAddress),
    };
    let interface = match find_interface_by_ip(src_ipv4.into()) {
        Some(i) => i,
        None => return Err(PistolError::CanNotFoundInterface),
    };
    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(PistolError::CanNotFoundMacAddress),
    };
    match arp::send_arp_scan_packet(dst_ipv4, dst_mac, src_ipv4, src_mac, interface, timeout) {
        Ok((mac, _)) => Ok(mac),
        Err(e) => Err(e),
    }
}

/// ARP Scan (IPv4) or NDP NS Scan (IPv6).
/// This will sends ARP packet or NDP NS packet to hosts on the local network and displays any responses that are received.
/// ```rust
/// use pistol::PistolRunner;
/// use pistol::PistolLogger;
/// use pistol::Target;
/// use std::time::Duration;
///
/// fn main() {
///     // you cannot use `_` here because it will be automatically optimized and ignored by the compiler
///     let _pr = PistolRunner::init(
///         PistolLogger::None,
///         Some(String::from("arp_scan.pcapng")),
///         Some(Duration::from_secs_f32(0.001)),
///     )
///     .unwrap();
///     let targets = Target::from_subnet("192.168.5.0/24", None).unwrap();
///     // set the timeout same as `arp-scan`
///     let timeout = Some(Duration::from_secs_f32(0.5));
///     let src_ipv4 = None;
///     let threads_num = Some(512);
///     let max_tests = 2;
///     let ret = mac_scan(&targets, threads_num, src_ipv4, timeout, max_tests).unwrap();
///     println!("{}", ret);
/// }
/// ```
/// Compare the speed with arp-scan.
/// pistol:
/// ```
/// +--------+---------------+-------------------+--------+---------+
/// |                Mac Scan Results (max tests:2)                 |
/// +--------+---------------+-------------------+--------+---------+
/// |  seq   |     addr      |        mac        |  oui   |   rtt   |
/// +--------+---------------+-------------------+--------+---------+
/// |   1    |  192.168.5.2  | 00:50:56:ff:a6:97 | VMware | 0.84ms  |
/// +--------+---------------+-------------------+--------+---------+
/// |   2    |  192.168.5.1  | 00:50:56:c0:00:08 | VMware | 19.50ms |
/// +--------+---------------+-------------------+--------+---------+
/// |   3    | 192.168.5.254 | 00:50:56:f8:c4:8f | VMware | 9.89ms  |
/// +--------+---------------+-------------------+--------+---------+
/// | total cost: 1.13s                                             |
/// | avg cost: 0.376s                                              |
/// | alive hosts: 3                                                |
/// +--------+---------------+-------------------+--------+---------+
/// ```
/// arp-scan:
/// ```
/// ➜  pistol-rs git:(main) ✗ sudo arp-scan 192.168.5.0/24
/// Interface: ens33, type: EN10MB, MAC: 00:0c:29:5b:bd:5c, IPv4: 192.168.5.3
/// Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
/// 192.168.5.1     00:50:56:c0:00:08       VMware, Inc.
/// 192.168.5.2     00:50:56:ff:a6:97       VMware, Inc.
/// 192.168.5.254   00:50:56:f8:c4:8f       VMware, Inc.
///
/// 3 packets received by filter, 0 packets dropped by kernel
/// Ending arp-scan 1.10.0: 256 hosts scanned in 2.001 seconds (127.94 hosts/sec). 3 responded
/// ```
#[cfg(feature = "scan")]
pub fn mac_scan(
    targets: &[Target],
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PistolArpScanReport, PistolError> {
    let nmap_mac_prefixes = get_nmap_mac_prefixes();
    let mut ret = PistolArpScanReport::new(tests);

    let threads_num = match threads_num {
        Some(t) => t,
        None => {
            let threads_num = targets.len();
            let threads_num = threads_num_check(threads_num);
            threads_num
        }
    };

    let pool = get_threads_pool(threads_num);
    let broadcast_mac = MacAddr::broadcast();
    let (tx, rx) = channel();
    let mut recv_size = 0;
    for target in targets {
        let dst_addr = target.addr;
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                let tx = tx.clone();
                recv_size += 1;
                pool.execute(move || {
                    for i in 0..tests {
                        debug!("arp scan packets: #{}/{}", i + 1, tests);
                        let scan_ret = ipv4_arp_scan(dst_ipv4, broadcast_mac, src_addr, timeout);
                        if i == tests - 1 {
                            tx.send((dst_addr, scan_ret))
                                .expect(&format!("tx send failed at {}", Location::caller()));
                        } else {
                            match scan_ret {
                                Ok((value, _)) => match value {
                                    Some(_) => {
                                        tx.send((dst_addr, scan_ret)).expect(&format!(
                                            "tx send failed at {}",
                                            Location::caller()
                                        ));
                                        break;
                                    }
                                    None => (),
                                },
                                Err(_) => tx
                                    .send((dst_addr, scan_ret))
                                    .expect(&format!("tx send failed at {}", Location::caller())),
                            }
                        }
                    }
                });
            }
            IpAddr::V6(dst_ipv6) => {
                let tx = tx.clone();
                recv_size += 1;
                pool.execute(move || {
                    for i in 0..tests {
                        debug!("ndp_ns scan packets: #{}/{}", i + 1, tests);
                        let scan_ret = ipv6_ndp_ns_scan(dst_ipv6, src_addr, timeout);
                        if i == tests - 1 {
                            tx.send((dst_addr, scan_ret))
                                .expect(&format!("tx send failed at {}", Location::caller()));
                        } else {
                            match scan_ret {
                                Ok((value, _)) => match value {
                                    Some(_) => {
                                        tx.send((dst_addr, scan_ret)).expect(&format!(
                                            "tx send failed at {}",
                                            Location::caller()
                                        ));
                                        break;
                                    }
                                    None => (),
                                },
                                Err(_) => tx
                                    .send((dst_addr, scan_ret))
                                    .expect(&format!("tx send failed at {}", Location::caller())),
                            }
                        }
                    }
                });
            }
        }
    }

    let mut arp_scan_reports = Vec::new();
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
                let asr = ArpScanReport {
                    addr: target_addr,
                    mac: target_mac,
                    ouis: target_ouis,
                    rtt,
                };
                arp_scan_reports.push(asr);
            }
            (_, _) => (),
        }
    }
    ret.arp_scan_reports = arp_scan_reports;
    ret.finish();
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
pub struct ScanReport {
    pub addr: IpAddr,
    pub port: u16,
    pub status: PortStatus,
    pub rtt: Duration, // from layer2
}

pub struct PistolPortScanReport {
    scan_reports: Vec<ScanReport>,
    start_time: DateTime<Local>,
    end_time: DateTime<Local>,
    tests: usize,
}

#[cfg(any(feature = "scan", feature = "ping"))]
impl PistolPortScanReport {
    pub fn new(tests: usize) -> PistolPortScanReport {
        PistolPortScanReport {
            scan_reports: Vec::new(),
            start_time: Local::now(),
            end_time: Local::now(),
            tests,
        }
    }
    pub fn value(&self) -> Vec<ScanReport> {
        let list = self.scan_reports.clone();
        list
    }
    pub fn finish(&mut self) {
        self.end_time = Local::now();
    }
}

#[cfg(any(feature = "scan", feature = "ping"))]
impl fmt::Display for PistolPortScanReport {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let total_cost = self.end_time - self.start_time;

        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new(&format!(
                "Scan Results (max tests:{}, total cost:{:.3}s)",
                self.tests,
                total_cost.as_seconds_f32()
            ))
            .style_spec("c")
            .with_hspan(5),
        ]));

        table.add_row(row![c -> "id", c -> "addr", c -> "port", c-> "status", c -> "rtt"]);

        let mut open_ports_num = 0;
        let mut total_cost = 0.0;
        for (i, scan_report) in self.scan_reports.iter().enumerate() {
            total_cost += scan_report.rtt.as_secs_f32();
            match scan_report.status {
                PortStatus::Open => open_ports_num += 1,
                _ => (),
            }
            let status_str = format!("{}", scan_report.status);
            let rtt_str = format!("{:.3}s", scan_report.rtt.as_secs_f32());
            table.add_row(row![c -> (i + 1), c -> scan_report.addr, c-> scan_report.port, c -> status_str, c-> rtt_str ]);
        }

        let help_info = format!(
            "NOTE:\nO: OPEN, OF: OPEN_OR_FILTERED, F: FILTERED,\nUF: UNFILTERED, C: CLOSED, UR: UNREACHABLE,\nCF: CLOSE_OF_FILTERED, E: ERROR, OL: OFFLINE."
        );
        table.add_row(Row::new(vec![Cell::new(&help_info).with_hspan(5)]));

        let avg_cost = total_cost / self.scan_reports.len() as f32;
        let summary = format!(
            "total cost: {:.3}s\navg cost: {:.3}s\nopen ports: {}",
            total_cost, avg_cost, open_ports_num,
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(5)]));
        write!(f, "{}", table)
    }
}

#[cfg(any(feature = "scan", feature = "ping"))]
#[derive(Debug, Clone, Copy)]
pub struct TcpIdleScans {
    pub zombie_ip_id_1: u16,
    pub zombie_ip_id_2: u16,
}

#[cfg(any(feature = "scan", feature = "ping"))]
fn threads_scan(
    method: ScanMethod,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    let (scan_ret, rtt) = match method {
        ScanMethod::Connect => {
            tcp::send_connect_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?
        }
        ScanMethod::Syn => {
            tcp::send_syn_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?
        }
        ScanMethod::Fin => {
            tcp::send_fin_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?
        }
        ScanMethod::Ack => {
            tcp::send_ack_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?
        }
        ScanMethod::Null => {
            tcp::send_null_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?
        }
        ScanMethod::Xmas => {
            tcp::send_xmas_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?
        }
        ScanMethod::Window => {
            tcp::send_window_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?
        }
        ScanMethod::Maimon => {
            tcp::send_maimon_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?
        }
        ScanMethod::Idle => {
            // here is always has value, so just use unwrap is fine
            let zombie_ipv4 = zombie_ipv4.unwrap();
            let zombie_port = zombie_port.unwrap();
            match tcp::send_idle_scan_packet(
                src_ipv4,
                src_port,
                dst_ipv4,
                dst_port,
                zombie_ipv4,
                zombie_port,
                timeout,
            ) {
                Ok((status, _idel_rets, rtt)) => (status, rtt),
                Err(e) => return Err(e.into()),
            }
        }
        ScanMethod::Udp => {
            udp::send_udp_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?
        }
    };

    Ok((scan_ret, rtt))
}

#[cfg(any(feature = "scan", feature = "ping"))]
fn threads_scan6(
    method: ScanMethod,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    let (scan_ret, rtt) = match method {
        ScanMethod::Connect => {
            tcp6::send_connect_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
        ScanMethod::Syn => {
            tcp6::send_syn_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
        ScanMethod::Fin => {
            tcp6::send_fin_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
        ScanMethod::Ack => {
            tcp6::send_ack_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
        ScanMethod::Null => {
            tcp6::send_null_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
        ScanMethod::Xmas => {
            tcp6::send_xmas_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
        ScanMethod::Window => {
            tcp6::send_window_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
        ScanMethod::Maimon => {
            tcp6::send_maimon_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
        ScanMethod::Udp => {
            udp6::send_udp_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
        ScanMethod::Idle => {
            warn!("idel scan not supported the ipv6 address, use connect scan instead now");
            tcp6::send_connect_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
    };

    Ok((scan_ret, rtt))
}

/// General scan function.
#[cfg(any(feature = "scan", feature = "ping"))]
fn scan(
    targets: &[Target],
    threads_num: Option<usize>,
    method: ScanMethod,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    timeout: Option<Duration>,
    max_tests: usize,
) -> Result<PistolPortScanReport, PistolError> {
    let mut port_scan_ret = PistolPortScanReport::new(max_tests);

    let threads_num = match threads_num {
        Some(t) => t,
        None => {
            let threads_num = targets.len();
            let threads_num = threads_num_check(threads_num);
            threads_num
        }
    };

    let pool = get_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut recv_size = 0;

    let src_port = match src_port {
        Some(s) => s,
        None => {
            warn!("can not found src port, use random port instead");
            random_port()
        }
    };

    for target in targets {
        let dst_addr = target.addr;
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                for &dst_port in &target.ports {
                    let tx = tx.clone();
                    recv_size += 1;
                    let src_ipv4 = match find_source_addr(src_addr, dst_ipv4)? {
                        Some(s) => s,
                        None => {
                            warn!("can not found src addr");
                            return Err(PistolError::CanNotFoundSourceAddress);
                        }
                    };

                    pool.execute(move || {
                        for ind in 0..max_tests {
                            let scan_ret = threads_scan(
                                method,
                                dst_ipv4,
                                dst_port,
                                src_ipv4,
                                src_port,
                                zombie_ipv4,
                                zombie_port,
                                timeout,
                            );
                            if ind == max_tests - 1 {
                                // last attempt
                                tx.send((dst_addr, dst_port, scan_ret))
                                    .expect(&format!("tx send failed at {}", Location::caller()));
                            } else {
                                match scan_ret {
                                    Ok((port_status, _)) => {
                                        match port_status {
                                            PortStatus::Open | PortStatus::OpenOrFiltered => {
                                                tx.send((dst_addr, dst_port, scan_ret)).expect(
                                                    &format!(
                                                        "tx send failed at {}",
                                                        Location::caller()
                                                    ),
                                                );
                                                break; // quit loop now
                                            }
                                            _ => (), // continue probing
                                        }
                                    }
                                    Err(_) => {
                                        // stop probe immediately if an error occurs
                                        tx.send((dst_addr, dst_port, scan_ret)).expect(&format!(
                                            "tx send failed at {}",
                                            Location::caller()
                                        ));
                                    }
                                }
                            }
                        }
                    });
                }
            }
            IpAddr::V6(dst_ipv6) => {
                for &dst_port in &target.ports {
                    let tx = tx.clone();
                    recv_size += 1;
                    let src_ipv6 = match find_source_addr6(src_addr, dst_ipv6)? {
                        Some(s) => s,
                        None => return Err(PistolError::CanNotFoundSourceAddress),
                    };
                    pool.execute(move || {
                        for ind in 0..max_tests {
                            let scan_ret = threads_scan6(
                                method, dst_ipv6, dst_port, src_ipv6, src_port, timeout,
                            );
                            if ind == max_tests - 1 {
                                tx.send((dst_addr, dst_port, scan_ret))
                                    .expect(&format!("tx send failed at {}", Location::caller()));
                            } else {
                                match scan_ret {
                                    Ok((port_status, _)) => match port_status {
                                        PortStatus::Open | PortStatus::OpenOrFiltered => {
                                            tx.send((dst_addr, dst_port, scan_ret)).expect(
                                                &format!(
                                                    "tx send failed at {}",
                                                    Location::caller()
                                                ),
                                            );
                                            break; // quit loop now
                                        }
                                        _ => (), // continue probing
                                    },
                                    Err(_) => {
                                        // stop probe immediately if an error occurs
                                        tx.send((dst_addr, dst_port, scan_ret)).expect(&format!(
                                            "tx send failed at {}",
                                            Location::caller()
                                        ));
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
    let mut rets = Vec::new();
    for (dst_addr, dst_port, v) in iter {
        match v {
            Ok((port_status, rtt)) => {
                // println!("rtt: {:.3}", rtt.as_secs_f32());
                let scan_report = ScanReport {
                    addr: dst_addr,
                    port: dst_port,
                    status: port_status,
                    rtt,
                };
                rets.push(scan_report);
            }
            Err(e) => {
                let rtt = Duration::new(0, 0);
                match e {
                    PistolError::CanNotFoundMacAddress => {
                        let scan_report = ScanReport {
                            addr: dst_addr,
                            port: dst_port,
                            status: PortStatus::Offline,
                            rtt,
                        };
                        rets.push(scan_report);
                    }
                    _ => {
                        error!("scan error: {}", e);
                        let scan_report = ScanReport {
                            addr: dst_addr,
                            port: dst_port,
                            status: PortStatus::Error,
                            rtt,
                        };
                        rets.push(scan_report);
                    }
                }
            }
        }
    }
    port_scan_ret.finish();
    Ok(port_scan_ret)
}

/// TCP Connect() Scan.
/// This is the most basic form of TCP scanning.
/// The connect() system call provided by your operating system is used to open a connection to every interesting port on the machine.
/// If the port is listening, connect() will succeed, otherwise the port isn't reachable.
/// One strong advantage to this technique is that you don't need any special privileges.
/// Any user on most UNIX boxes is free to use this call.
/// Another advantage is speed.
/// While making a separate connect() call for every targeted port in a linear fashion would take ages over a slow connection,
/// you can hasten the scan by using many sockets in parallel.
/// Using non-blocking I/O allows you to set a low time-out period and watch all the sockets at once.
/// This is the fastest scanning method supported by nmap, and is available with the -t (TCP) option.
/// The big downside is that this sort of scan is easily detectable and filterable.
/// The target hosts logs will show a bunch of connection and error messages for the services which take the connection and then have it immediately shutdown.
#[cfg(feature = "scan")]
pub fn tcp_connect_scan(
    targets: &[Target],
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    max_tests: usize,
) -> Result<PistolPortScanReport, PistolError> {
    scan(
        targets,
        threads_num,
        ScanMethod::Connect,
        src_addr,
        src_port,
        None,
        None,
        timeout,
        max_tests,
    )
}

/// TCP connect() Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_connect_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethod::Connect,
        dst_addr,
        dst_port,
        src_addr,
        src_port,
        None,
        None,
        timeout,
    )
}

/// TCP SYN Scan.
/// This technique is often referred to as "half-open" scanning, because you don't open a full TCP connection.
/// You send a SYN packet, as if you are going to open a real connection and wait for a response.
/// A SYN|ACK indicates the port is listening.
/// A RST is indicative of a non-listener.
/// If a SYN|ACK is received, you immediately send a RST to tear down the connection (actually the kernel does this for us).
/// The primary advantage to this scanning technique is that fewer sites will log it.
/// Unfortunately you need root privileges to build these custom SYN packets.
/// SYN scan is the default and most popular scan option for good reason.
/// It can be performed quickly,
/// scanning thousands of ports per second on a fast network not hampered by intrusive firewalls.
/// SYN scan is relatively unobtrusive and stealthy, since it never completes TCP connections.
#[cfg(any(feature = "scan", feature = "ping"))]
pub fn tcp_syn_scan(
    targets: &[Target],
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    max_tests: usize,
) -> Result<PistolPortScanReport, PistolError> {
    scan(
        targets,
        threads_num,
        ScanMethod::Syn,
        src_addr,
        src_port,
        None,
        None,
        timeout,
        max_tests,
    )
}

/// TCP SYN Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_syn_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethod::Syn,
        dst_addr,
        dst_port,
        src_addr,
        src_port,
        None,
        None,
        timeout,
    )
}

/// TCP FIN Scan.
/// There are times when even SYN scanning isn't clandestine enough.
/// Some firewalls and packet filters watch for SYNs to an unallowed port,
/// and programs like synlogger and Courtney are available to detect these scans.
/// FIN packets, on the other hand, may be able to pass through unmolested.
/// This scanning technique was featured in detail by Uriel Maimon in Phrack 49, article 15.
/// The idea is that closed ports tend to reply to your FIN packet with the proper RST.
/// Open ports, on the other hand, tend to ignore the packet in question.
/// This is a bug in TCP implementations and so it isn't 100% reliable
/// (some systems, notably Micro$oft boxes, seem to be immune).
/// When scanning systems compliant with this RFC text,
/// any packet not containing SYN, RST, or ACK bits will result in a returned RST if the port is closed and no response at all if the port is open.
/// As long as none of those three bits are included, any combination of the other three (FIN, PSH, and URG) are OK.
#[cfg(feature = "scan")]
pub fn tcp_fin_scan(
    targets: &[Target],
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    max_tests: usize,
) -> Result<PistolPortScanReport, PistolError> {
    scan(
        targets,
        threads_num,
        ScanMethod::Fin,
        src_addr,
        src_port,
        None,
        None,
        timeout,
        max_tests,
    )
}

/// TCP FIN Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_fin_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethod::Fin,
        dst_addr,
        dst_port,
        src_addr,
        src_port,
        None,
        None,
        timeout,
    )
}

/// TCP ACK Scan.
/// This scan is different than the others discussed so far in that it never determines open (or even open|filtered) ports.
/// It is used to map out firewall rulesets, determining whether they are stateful or not and which ports are filtered.
/// When scanning unfiltered systems, open and closed ports will both return a RST packet.
/// We then labels them as unfiltered, meaning that they are reachable by the ACK packet, but whether they are open or closed is undetermined.
/// Ports that don't respond, or send certain ICMP error messages back, are labeled filtered.
#[cfg(feature = "scan")]
pub fn tcp_ack_scan(
    targets: &[Target],
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    max_tests: usize,
) -> Result<PistolPortScanReport, PistolError> {
    scan(
        targets,
        threads_num,
        ScanMethod::Ack,
        src_addr,
        src_port,
        None,
        None,
        timeout,
        max_tests,
    )
}

/// TCP ACK Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_ack_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethod::Ack,
        dst_addr,
        dst_port,
        src_addr,
        src_port,
        None,
        None,
        timeout,
    )
}

/// TCP Null Scan.
/// Does not set any bits (TCP flag header is 0).
/// When scanning systems compliant with this RFC text,
/// any packet not containing SYN, RST, or ACK bits will result in a returned RST if the port is closed and no response at all if the port is open.
/// As long as none of those three bits are included, any combination of the other three (FIN, PSH, and URG) are OK.
#[cfg(feature = "scan")]
pub fn tcp_null_scan(
    targets: &[Target],
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PistolPortScanReport, PistolError> {
    scan(
        targets,
        threads_num,
        ScanMethod::Null,
        src_addr,
        src_port,
        None,
        None,
        timeout,
        tests,
    )
}

/// TCP Null Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_null_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethod::Null,
        dst_addr,
        dst_port,
        src_addr,
        src_port,
        None,
        None,
        timeout,
    )
}

/// TCP Xmas Scan.
/// Sets the FIN, PSH, and URG flags, lighting the packet up like a Christmas tree.
/// When scanning systems compliant with this RFC text,
/// any packet not containing SYN, RST, or ACK bits will result in a returned RST if the port is closed and no response at all if the port is open.
/// As long as none of those three bits are included, any combination of the other three (FIN, PSH, and URG) are OK.
#[cfg(feature = "scan")]
pub fn tcp_xmas_scan(
    targets: &[Target],
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    max_tests: usize,
) -> Result<PistolPortScanReport, PistolError> {
    scan(
        targets,
        threads_num,
        ScanMethod::Xmas,
        src_addr,
        src_port,
        None,
        None,
        timeout,
        max_tests,
    )
}

/// TCP Xmas Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_xmas_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethod::Xmas,
        dst_addr,
        dst_port,
        src_addr,
        src_port,
        None,
        None,
        timeout,
    )
}

/// TCP Window Scan.
/// Window scan is exactly the same as ACK scan except that it exploits an implementation detail of certain systems to differentiate open ports from closed ones,
/// rather than always printing unfiltered when a RST is returned.
/// It does this by examining the TCP Window value of the RST packets returned.
/// On some systems, open ports use a positive window size (even for RST packets) while closed ones have a zero window.
/// Window scan sends the same bare ACK probe as ACK scan.
#[cfg(feature = "scan")]
pub fn tcp_window_scan(
    targets: &[Target],
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    max_tests: usize,
) -> Result<PistolPortScanReport, PistolError> {
    scan(
        targets,
        threads_num,
        ScanMethod::Window,
        src_addr,
        src_port,
        None,
        None,
        timeout,
        max_tests,
    )
}

/// TCP Window Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_window_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethod::Window,
        dst_addr,
        dst_port,
        src_addr,
        src_port,
        None,
        None,
        timeout,
    )
}

/// TCP Maimon Scan.
/// The Maimon scan is named after its discoverer, Uriel Maimon.
/// He described the technique in Phrack Magazine issue #49 (November 1996).
/// This technique is exactly the same as NULL, FIN, and Xmas scan, except that the probe is FIN/ACK.
/// According to RFC 793 (TCP), a RST packet should be generated in response to such a probe whether the port is open or closed.
/// However, Uriel noticed that many BSD-derived systems simply drop the packet if the port is open.
#[cfg(feature = "scan")]
pub fn tcp_maimon_scan(
    targets: &[Target],
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    max_tests: usize,
) -> Result<PistolPortScanReport, PistolError> {
    scan(
        targets,
        threads_num,
        ScanMethod::Maimon,
        src_addr,
        src_port,
        None,
        None,
        timeout,
        max_tests,
    )
}

/// TCP Maimon Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_maimon_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethod::Maimon,
        dst_addr,
        dst_port,
        src_addr,
        src_port,
        None,
        None,
        timeout,
    )
}

/// TCP Idle Scan.
/// In 1998, security researcher Antirez (who also wrote the hping2 tool used in parts of this book)
/// posted to the Bugtraq mailing list an ingenious new port scanning technique.
/// Idle scan, as it has become known, allows for completely blind port scanning.
/// Attackers can actually scan a target without sending a single packet to the target from their own IP address!
/// Instead, a clever side-channel attack allows for the scan to be bounced off a dumb "zombie host".
/// Intrusion detection system (IDS) reports will finger the innocent zombie as the attacker.
/// Besides being extraordinarily stealthy, this scan type permits discovery of IP-based trust relationships between machines.
#[cfg(feature = "scan")]
pub fn tcp_idle_scan(
    targets: &[Target],
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    timeout: Option<Duration>,
    max_tests: usize,
) -> Result<PistolPortScanReport, PistolError> {
    scan(
        targets,
        threads_num,
        ScanMethod::Idle,
        src_addr,
        src_port,
        zombie_ipv4,
        zombie_port,
        timeout,
        max_tests,
    )
}

/// TCP Idle Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_idle_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethod::Idle,
        dst_addr,
        dst_port,
        src_addr,
        src_port,
        zombie_ipv4,
        zombie_port,
        timeout,
    )
}

/// UDP Scan.
/// While most popular services on the Internet run over the TCP protocol, UDP services are widely deployed.
/// DNS, SNMP, and DHCP (registered ports 53, 161/162, and 67/68) are three of the most common.
/// Because UDP scanning is generally slower and more difficult than TCP, some security auditors ignore these ports.
/// This is a mistake, as exploitable UDP services are quite common and attackers certainly don't ignore the whole protocol.
/// UDP scan works by sending a UDP packet to every targeted port.
/// For most ports, this packet will be empty (no payload), but for a few of the more common ports a protocol-specific payload will be sent.
/// Based on the response, or lack thereof, the port is assigned to one of four states.
#[cfg(feature = "scan")]
pub fn udp_scan(
    targets: &[Target],
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    max_tests: usize,
) -> Result<PistolPortScanReport, PistolError> {
    scan(
        targets,
        threads_num,
        ScanMethod::Udp,
        src_addr,
        src_port,
        None,
        None,
        timeout,
        max_tests,
    )
}

/// UDP Scan, raw version.
#[cfg(feature = "scan")]
pub fn udp_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethod::Udp,
        dst_addr,
        dst_port,
        src_addr,
        src_port,
        None,
        None,
        timeout,
    )
}

#[cfg(feature = "scan")]
fn scan_raw(
    method: ScanMethod,
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    let src_port = match src_port {
        Some(s) => s,
        None => random_port(),
    };
    match dst_addr {
        IpAddr::V4(dst_ipv4) => {
            let src_ipv4 = match find_source_addr(src_addr, dst_ipv4)? {
                Some(s) => s,
                None => return Err(PistolError::CanNotFoundSourceAddress),
            };
            threads_scan(
                method,
                dst_ipv4,
                dst_port,
                src_ipv4,
                src_port,
                zombie_ipv4,
                zombie_port,
                timeout,
            )
        }
        IpAddr::V6(dst_ipv6) => {
            let src_ipv6 = match find_source_addr6(src_addr, dst_ipv6)? {
                Some(s) => s,
                None => return Err(PistolError::CanNotFoundSourceAddress),
            };
            threads_scan6(method, dst_ipv6, dst_port, src_ipv6, src_port, timeout)
        }
    }
}

pub static ARP_LOCAL_DEFAULT_TIMEOUT: f32 = 0.001;

#[cfg(feature = "scan")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::PistolCapture;
    use crate::PistolLogger;
    use crate::PistolRunner;
    use crate::TEST_IPV4_LOCAL;
    use crate::Target;
    use std::time::Instant;
    use subnetwork::CrossIpv4Pool;
    #[test]
    fn test_arp_scan_subnet() {
        let _pr = PistolRunner::init(
            PistolLogger::None,
            Some(String::from("arp_scan.pcapng")),
            Some(Duration::from_secs_f32(0.001)),
        )
        .unwrap();
        let targets = Target::from_subnet("192.168.5.0/24", None).unwrap();
        println!("{}", targets.len());
        // let target1 = Target::new(IpAddr::V4(Ipv4Addr::new(192, 168, 5, 1)), None);
        // let target2 = Target::new(IpAddr::V4(Ipv4Addr::new(192, 168, 5, 2)), None);
        // let target3 = Target::new(IpAddr::V4(Ipv4Addr::new(192, 168, 5, 3)), None);
        // let target4 = Target::new(IpAddr::V4(Ipv4Addr::new(192, 168, 5, 4)), None);
        // let targets = vec![target1, target2, target3, target4];
        let timeout = Some(Duration::from_secs_f32(0.5));
        let src_ipv4 = None;
        let threads_num = Some(512);
        let max_tests = 2;
        let ret = mac_scan(&targets, threads_num, src_ipv4, timeout, max_tests).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_tcp_connect_scan() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 2);
        // let dst_ipv4 = Ipv4Addr::new(192, 168, 31, 1);
        let target = Target::new(dst_ipv4.into(), Some(vec![22, 80]));
        // let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let max_tests = 8;
        let threads_num = Some(8);
        let ret = tcp_connect_scan(
            &[target],
            threads_num,
            src_ipv4,
            src_port,
            timeout,
            max_tests,
        )
        .unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_tcp_syn_scan() {
        let mut ts = PistolCapture::init("tcp_syn_scan.pcapng").unwrap();
        // let _ = Logger::init_debug_logging();
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
        // let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 2);
        // let dst_ipv4 = Ipv4Addr::new(192, 168, 31, 1);
        let target = Target::new(dst_ipv4.into(), Some(vec![22]));
        let max_tests = 1;
        let threads_num = Some(8);
        let ret = tcp_syn_scan(
            &[target],
            threads_num,
            src_ipv4,
            src_port,
            timeout,
            max_tests,
        )
        .unwrap();
        println!("{}", ret);
        // println!("{:#?}", ret.get(&dst_ipv4.into()).unwrap().status);
        ts.save_to_file().unwrap();
    }
    #[test]
    fn test_tcp_fin_scan() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(3, 0));
        let target = Target::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let max_tests = 8;
        let threads_num = Some(8);
        let ret = tcp_fin_scan(
            &[target],
            threads_num,
            src_ipv4,
            src_port,
            timeout,
            max_tests,
        )
        .unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_tcp_ack_scan() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(3, 0));
        let target = Target::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let max_tests = 8;
        let threads_num = Some(8);
        let ret = tcp_ack_scan(
            &[target],
            threads_num,
            src_ipv4,
            src_port,
            timeout,
            max_tests,
        )
        .unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_tcp_null_scan() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(3, 0));
        let target = Target::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let max_tests = 8;
        let threads_num = Some(8);
        let ret = tcp_null_scan(
            &[target],
            threads_num,
            src_ipv4,
            src_port,
            timeout,
            max_tests,
        )
        .unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_udp_scan() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(3, 0));
        let target = Target::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let max_tests = 8;
        let threads_num = Some(8);
        let ret = udp_scan(
            &[target],
            threads_num,
            src_ipv4,
            src_port,
            timeout,
            max_tests,
        )
        .unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_scan_timeout() {
        // scanme.nmap.org
        let dst_ip = Ipv4Addr::new(192, 168, 5, 1);
        let timeout = Some(Duration::new(1, 0));
        let start_time = Instant::now();
        match tcp_syn_scan_raw(dst_ip.into(), 80, None, None, timeout) {
            Ok((status, dura)) => {
                println!(
                    "status: {:?}, dura: {:?}, elapsed: {:.3}",
                    status,
                    dura,
                    start_time.elapsed().as_secs_f32()
                );
            }
            Err(e) => {
                println!("{}", e);
                println!("elapsed: {:.3}", start_time.elapsed().as_secs_f32());
            }
        };
    }
    #[test]
    fn test_scan_timeout2() {
        // use crate::Logger;
        // let _ = Logger::init_debug_logging().unwrap();
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));

        let start = Ipv4Addr::new(192, 168, 5, 1);
        let end = Ipv4Addr::new(192, 168, 5, 10);
        let subnet = CrossIpv4Pool::new(start, end).unwrap();
        // let subnet = Ipv4Pool::from("192.168.5.0/24").unwrap();
        let mut targets = vec![];
        for ip in subnet {
            let host = Target::new(ip.into(), Some(vec![22]));
            targets.push(host);
        }
        let max_tests = 2;

        let start_time = Instant::now();
        let threads_num = Some(8);
        let ret = tcp_syn_scan(
            &targets,
            threads_num,
            src_ipv4,
            src_port,
            timeout,
            max_tests,
        )
        .unwrap();
        // let ret = tcp_ack_scan(target, src_ipv4, src_port, timeout, tests).unwrap();
        // let ret = tcp_connect_scan(target, src_ipv4, src_port, timeout, tests).unwrap();
        println!("{}", ret);
        println!("elapsed: {:.3}", start_time.elapsed().as_secs_f32());
    }
}
