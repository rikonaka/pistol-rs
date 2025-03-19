use chrono::DateTime;
/* Scan */
use chrono::Local;
use log::warn;
use pnet::datalink::MacAddr;
use prettytable::row;
use prettytable::Cell;
use prettytable::Row;
use prettytable::Table;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::mpsc::channel;
use std::time::Duration;

pub mod arp;
pub mod tcp;
pub mod tcp6;
pub mod udp;
pub mod udp6;

use crate::error::PistolError;
use crate::utils::find_interface_by_ip;
use crate::utils::find_source_addr;
use crate::utils::find_source_addr6;
use crate::utils::get_default_timeout;
use crate::utils::get_threads_pool;
use crate::utils::random_port;
use crate::utils::threads_num_check;
use crate::Target;

#[derive(Debug, Clone)]
pub struct AliveHost {
    pub mac_addr: MacAddr,
    pub ouis: String, // productions organization name
}

#[derive(Debug, Clone)]
pub struct ArpScans {
    pub alives: HashMap<Ipv4Addr, AliveHost>, // only ipv4 has arp scan
    pub avg_cost: f64,
    pub total_cost: i64,
    pub alives_num: usize,
    pub stime: DateTime<Local>,
    pub etime: DateTime<Local>,
    tests: usize,
}

impl ArpScans {
    pub fn new() -> ArpScans {
        ArpScans {
            alives: HashMap::new(),
            avg_cost: 0.0,
            total_cost: 0,
            alives_num: 0,
            stime: Local::now(),
            etime: Local::now(),
            tests: 0,
        }
    }
    pub fn get(&self, k: &Ipv4Addr) -> Option<&AliveHost> {
        self.alives.get(k)
    }
    pub fn enrichment(&mut self) {
        self.etime = Local::now();
        // alive hosts
        self.alives_num = self.alives.len();
        self.total_cost = self
            .etime
            .signed_duration_since(self.stime)
            .num_milliseconds();
        self.avg_cost = self.total_cost as f64 / self.tests as f64;
    }
}

impl fmt::Display for ArpScans {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![Cell::new("ARP Scan Results")
            .style_spec("c")
            .with_hspan(3)]));

        let ah = &self.alives;
        let ah: BTreeMap<Ipv4Addr, &AliveHost> = ah.into_iter().map(|(i, a)| (*i, a)).collect();
        for (ip, aah) in ah {
            table.add_row(row![c -> ip, c -> aah.mac_addr, c -> aah.ouis]);
        }

        let summary = format!(
            "total cost: {:.2} ms\navg cost: {:.2} ms\nalive hosts: {}",
            self.total_cost, self.avg_cost, self.alives_num
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(3)]));

        write!(f, "{}", table)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapMacPrefix {
    pub prefix: String,
    pub ouis: String,
}

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

fn ipv4_arp_scan(
    dst_ipv4: Ipv4Addr,
    dst_mac: MacAddr,
    src_addr: Option<IpAddr>,
    timeout: Duration,
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

pub fn arp_scan_raw(
    dst_ipv4: Ipv4Addr,
    src_addr: Option<IpAddr>,
    timeout: Duration,
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

/// ARP Scan.
/// This will sends ARP packets to hosts on the local network and displays any responses that are received.
pub fn arp_scan(
    target: &Target,
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    timeout: Option<Duration>,
) -> Result<ArpScans, PistolError> {
    let nmap_mac_prefixes = get_nmap_mac_prefixes();
    let mut ret = ArpScans::new();
    ret.tests = target.hosts.len();

    let threads_num = match threads_num {
        Some(t) => t,
        None => {
            let threads_num = target.hosts.len();
            let threads_num = threads_num_check(threads_num);
            threads_num
        }
    };

    let pool = get_threads_pool(threads_num);
    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };

    let dst_mac = MacAddr::broadcast();
    let (tx, rx) = channel();
    let mut recv_size = 0;
    for host in &target.hosts {
        let dst_addr = host.addr;
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                let tx = tx.clone();
                recv_size += 1;
                pool.execute(move || {
                    let scan_ret = ipv4_arp_scan(dst_ipv4, dst_mac, src_addr, timeout);
                    match tx.send(Ok((dst_ipv4, scan_ret))) {
                        _ => (),
                    }
                });
            }
            IpAddr::V6(_) => {
                warn!("arp scan not support the ipv6 address");
            }
        }
    }
    let iter = rx.into_iter().take(recv_size);
    for v in iter {
        match v {
            Ok((target_ipv4, target_mac)) => match target_mac? {
                (Some(m), _rtt) => {
                    let mut ouis = String::new();
                    let mut mac_prefix = String::new();
                    let m0 = format!("{:X}", m.0);
                    let m1 = format!("{:X}", m.1);
                    let m2 = format!("{:X}", m.2);
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
                            ouis = p.ouis.to_string();
                        }
                    }
                    let aah = AliveHost { mac_addr: m, ouis };
                    ret.alives.insert(target_ipv4, aah);
                }
                (_, _) => (),
            },
            Err(e) => return Err(e),
        }
    }
    ret.enrichment();
    Ok(ret)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanMethods {
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

#[derive(Debug, Clone, Copy)]
pub struct PortScans {
    pub status: PortStatus,
    pub rtt: Duration,
    pub stime: DateTime<Local>, // start date time
    pub etime: DateTime<Local>, // end date time
}

#[derive(Debug, Clone)]
pub struct TcpUdpScans {
    pub scans: HashMap<IpAddr, HashMap<u16, Vec<PortScans>>>,
    pub avg_cost: f64,
    pub total_cost: i64,
    pub open_ports: usize,
    pub stime: DateTime<Local>,
    pub etime: DateTime<Local>,
    tests: usize,
}

impl TcpUdpScans {
    pub fn new() -> TcpUdpScans {
        TcpUdpScans {
            scans: HashMap::new(),
            avg_cost: 0.0,
            total_cost: 0,
            open_ports: 0,
            stime: Local::now(),
            etime: Local::now(),
            tests: 0,
        }
    }
    pub fn get(&self, k: &IpAddr) -> Option<HashMap<u16, Vec<PortScans>>> {
        match self.scans.get(k) {
            Some(ph) => Some(ph.clone()),
            None => None,
        }
    }
    pub fn enrichment(&mut self) {
        // assign the end time
        self.etime = Local::now();
        // avg rtt
        let mut total_cost = 0;
        let mut total_num = 0;
        // open ports
        let mut open_ports = 0;
        for (_ip, ports_status) in &self.scans {
            for (_port, psr) in ports_status {
                self.tests = psr.len();
                for ps in psr {
                    match ps.status {
                        PortStatus::Open => {
                            open_ports += 1;
                            break;
                        }
                        _ => (),
                    }
                    let time_cost = ps.etime.signed_duration_since(ps.stime);
                    if time_cost.num_milliseconds() != 0 {
                        total_cost += time_cost.num_milliseconds();
                        total_num += 1;
                    }
                }
            }
        }
        self.avg_cost = total_cost as f64 / total_num as f64; // milli seconds
        self.open_ports = open_ports;
        self.total_cost = self
            .etime
            .signed_duration_since(self.stime)
            .num_milliseconds();
    }
    fn insert(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        port_status: PortStatus,
        rtt: Duration,
        stime: DateTime<Local>,
        etime: DateTime<Local>,
    ) {
        let psr = PortScans {
            status: port_status,
            rtt,
            stime,
            etime,
        };

        match self.scans.get_mut(&dst_addr) {
            Some(s) => match s.get_mut(&dst_port) {
                Some(d) => {
                    d.push(psr);
                }
                None => {
                    let d = vec![psr];
                    s.insert(dst_port, d);
                }
            },
            None => {
                let mut s = HashMap::new();
                s.insert(dst_port, vec![psr]);
                self.scans.insert(dst_addr, s);
            }
        }
    }
}

impl fmt::Display for TcpUdpScans {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![Cell::new(&format!(
            "Scan Results (tests:{})",
            self.tests
        ))
        .style_spec("c")
        .with_hspan(5)]));

        table.add_row(row![c -> "id", c -> "addr", c -> "port", c-> "status", c -> "avg cost"]);

        // convert hashmap to btreemap here
        let scans = &self.scans;
        let scans: BTreeMap<IpAddr, &HashMap<u16, Vec<PortScans>>> =
            scans.into_iter().map(|(i, h)| (*i, h)).collect();
        for (i, (ip, ports_status)) in scans.into_iter().enumerate() {
            let ports_status: BTreeMap<u16, &Vec<PortScans>> =
                ports_status.into_iter().map(|(p, s)| (*p, s)).collect();
            let mut total_ports_time_cost = 0;

            for (port, psr) in ports_status {
                let mut open_num = 0;
                let mut open_or_filtered_num = 0;
                let mut filtered_num = 0;
                let mut unfiltered_num = 0;
                let mut closed_num = 0;
                let mut unreachable_num = 0;
                let mut close_or_filtered_num = 0;
                let mut error_num = 0;
                let mut offline_num = 0;

                for p in psr {
                    let port_time_cost = p.etime.signed_duration_since(p.stime).num_milliseconds();
                    total_ports_time_cost += port_time_cost;

                    match p.status {
                        PortStatus::Open => open_num += 1,
                        PortStatus::OpenOrFiltered => open_or_filtered_num += 1,
                        PortStatus::Filtered => filtered_num += 1,
                        PortStatus::Unfiltered => unfiltered_num += 1,
                        PortStatus::Closed => closed_num += 1,
                        PortStatus::Unreachable => unreachable_num += 1,
                        PortStatus::ClosedOrFiltered => close_or_filtered_num += 1,
                        PortStatus::Error => error_num += 1,
                        PortStatus::Offline => offline_num += 1,
                    };
                }
                // let status_str = status_str_vec.join("|");
                let status_str = format!(
                    "O({})OF({})F({})UF({})C({})UR({})CF({})E({})OL({})",
                    open_num,
                    open_or_filtered_num,
                    filtered_num,
                    unfiltered_num,
                    closed_num,
                    unreachable_num,
                    close_or_filtered_num,
                    error_num,
                    offline_num
                );
                let ports_rtt_str =
                    format!("{:.2} ms", total_ports_time_cost as f64 / self.tests as f64);
                table.add_row(
                    row![c -> (i + 1), c -> ip, c-> port, c -> status_str, c-> ports_rtt_str ],
                );
            }
        }

        let help_info = format!("NOTE:\nO: OPEN, OF: OPEN_OR_FILTERED, F: FILTERED,\nUF: UNFILTERED, C: CLOSED, UR: UNREACHABLE,\nCF: CLOSE_OF_FILTERED, E: ERROR, OL: OFFLINE.");
        table.add_row(Row::new(vec![Cell::new(&help_info).with_hspan(5)]));

        let summary = format!(
            "total cost: {:.2} ms\navg cost: {:.2} ms\nopen ports: {}",
            self.total_cost, self.avg_cost, self.open_ports
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(5)]));
        write!(f, "{}", table)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TcpIdleScans {
    pub zombie_ip_id_1: u16,
    pub zombie_ip_id_2: u16,
}

fn threads_scan(
    method: ScanMethods,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    timeout: Duration,
) -> Result<(PortStatus, Duration), PistolError> {
    let (scan_ret, rtt) = match method {
        ScanMethods::Connect => {
            tcp::send_connect_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?
        }
        ScanMethods::Syn => {
            tcp::send_syn_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?
        }
        ScanMethods::Fin => {
            tcp::send_fin_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?
        }
        ScanMethods::Ack => {
            tcp::send_ack_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?
        }
        ScanMethods::Null => {
            tcp::send_null_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?
        }
        ScanMethods::Xmas => {
            tcp::send_xmas_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?
        }
        ScanMethods::Window => {
            tcp::send_window_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?
        }
        ScanMethods::Maimon => {
            tcp::send_maimon_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?
        }
        ScanMethods::Idle => {
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
        ScanMethods::Udp => {
            udp::send_udp_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, timeout)?
        }
    };

    Ok((scan_ret, rtt))
}

fn threads_scan6(
    method: ScanMethods,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    timeout: Duration,
) -> Result<(PortStatus, Duration), PistolError> {
    let (scan_ret, rtt) = match method {
        ScanMethods::Connect => {
            tcp6::send_connect_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
        ScanMethods::Syn => {
            tcp6::send_syn_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
        ScanMethods::Fin => {
            tcp6::send_fin_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
        ScanMethods::Ack => {
            tcp6::send_ack_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
        ScanMethods::Null => {
            tcp6::send_null_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
        ScanMethods::Xmas => {
            tcp6::send_xmas_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
        ScanMethods::Window => {
            tcp6::send_window_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
        ScanMethods::Maimon => {
            tcp6::send_maimon_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
        ScanMethods::Udp => {
            udp6::send_udp_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
        ScanMethods::Idle => {
            warn!("idel scan not supported the ipv6 address, use connect scan instead now");
            tcp6::send_connect_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout)?
        }
    };

    Ok((scan_ret, rtt))
}

/// General scan function.
pub fn scan(
    target: &Target,
    threads_num: Option<usize>,
    method: ScanMethods,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<TcpUdpScans, PistolError> {
    let mut port_scan_ret = TcpUdpScans::new();

    let threads_num = match threads_num {
        Some(t) => t,
        None => {
            let mut threads_num = 0;
            for host in &target.hosts {
                threads_num += host.ports.len() * tests;
            }
            let threads_num = threads_num_check(threads_num);
            threads_num
        }
    };

    let pool = get_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut recv_size = 0;
    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };
    let src_port = match src_port {
        Some(s) => s,
        None => {
            warn!("can not found src port, use random port instead");
            random_port()
        }
    };

    for host in &target.hosts {
        let dst_addr = host.addr;
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                for &dst_port in &host.ports {
                    for _ in 0..tests {
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
                            let stime = Local::now();
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
                            match tx.send((dst_addr, dst_port, scan_ret, stime)) {
                                _ => (),
                            }
                        });
                    }
                }
            }
            IpAddr::V6(dst_ipv6) => {
                for &dst_port in &host.ports {
                    for _ in 0..tests {
                        let tx = tx.clone();
                        recv_size += 1;
                        let src_ipv6 = match find_source_addr6(src_addr, dst_ipv6)? {
                            Some(s) => s,
                            None => return Err(PistolError::CanNotFoundSourceAddress),
                        };
                        pool.execute(move || {
                            let stime = Local::now();
                            let scan_ret = threads_scan6(
                                method, dst_ipv6, dst_port, src_ipv6, src_port, timeout,
                            );
                            match tx.send((dst_addr, dst_port, scan_ret, stime)) {
                                _ => (),
                            }
                        });
                    }
                }
            }
        }
    }

    let iter = rx.into_iter().take(recv_size);

    for (dst_ipv4, dst_port, v, stime) in iter {
        let etime = Local::now();
        match v {
            Ok((port_status, rtt)) => {
                // println!("rtt: {:.2}", rtt.as_secs_f32());
                port_scan_ret.insert(dst_ipv4.into(), dst_port, port_status, rtt, stime, etime);
            }
            Err(e) => {
                let rtt = Duration::new(0, 0);
                match e {
                    PistolError::CanNotFoundMacAddress => {
                        port_scan_ret.insert(
                            dst_ipv4.into(),
                            dst_port,
                            PortStatus::Offline,
                            rtt,
                            stime,
                            etime,
                        );
                    }
                    _ => {
                        warn!("scan error: {}", e);
                        port_scan_ret.insert(
                            dst_ipv4.into(),
                            dst_port,
                            PortStatus::Error,
                            rtt,
                            stime,
                            etime,
                        );
                    }
                }
            }
        }
    }
    port_scan_ret.enrichment();
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
pub fn tcp_connect_scan(
    target: &Target,
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<TcpUdpScans, PistolError> {
    scan(
        target,
        threads_num,
        ScanMethods::Connect,
        src_addr,
        src_port,
        None,
        None,
        timeout,
        tests,
    )
}

/// TCP connect() Scan, raw version.
pub fn tcp_connect_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethods::Connect,
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
pub fn tcp_syn_scan(
    target: &Target,
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<TcpUdpScans, PistolError> {
    scan(
        target,
        threads_num,
        ScanMethods::Syn,
        src_addr,
        src_port,
        None,
        None,
        timeout,
        tests,
    )
}

/// TCP SYN Scan, raw version.
pub fn tcp_syn_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethods::Syn,
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
pub fn tcp_fin_scan(
    target: &Target,
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<TcpUdpScans, PistolError> {
    scan(
        target,
        threads_num,
        ScanMethods::Fin,
        src_addr,
        src_port,
        None,
        None,
        timeout,
        tests,
    )
}

/// TCP FIN Scan, raw version.
pub fn tcp_fin_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethods::Fin,
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
pub fn tcp_ack_scan(
    target: &Target,
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<TcpUdpScans, PistolError> {
    scan(
        target,
        threads_num,
        ScanMethods::Ack,
        src_addr,
        src_port,
        None,
        None,
        timeout,
        tests,
    )
}

/// TCP ACK Scan, raw version.
pub fn tcp_ack_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethods::Ack,
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
pub fn tcp_null_scan(
    target: &Target,
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<TcpUdpScans, PistolError> {
    scan(
        target,
        threads_num,
        ScanMethods::Null,
        src_addr,
        src_port,
        None,
        None,
        timeout,
        tests,
    )
}

/// TCP Null Scan, raw version.
pub fn tcp_null_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethods::Null,
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
pub fn tcp_xmas_scan(
    target: &Target,
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<TcpUdpScans, PistolError> {
    scan(
        target,
        threads_num,
        ScanMethods::Xmas,
        src_addr,
        src_port,
        None,
        None,
        timeout,
        tests,
    )
}

/// TCP Xmas Scan, raw version.
pub fn tcp_xmas_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethods::Xmas,
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
pub fn tcp_window_scan(
    target: &Target,
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<TcpUdpScans, PistolError> {
    scan(
        target,
        threads_num,
        ScanMethods::Window,
        src_addr,
        src_port,
        None,
        None,
        timeout,
        tests,
    )
}

/// TCP Window Scan, raw version.
pub fn tcp_window_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethods::Window,
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
pub fn tcp_maimon_scan(
    target: &Target,
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<TcpUdpScans, PistolError> {
    scan(
        target,
        threads_num,
        ScanMethods::Maimon,
        src_addr,
        src_port,
        None,
        None,
        timeout,
        tests,
    )
}

/// TCP Maimon Scan, raw version.
pub fn tcp_maimon_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethods::Maimon,
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
pub fn tcp_idle_scan(
    target: &Target,
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<TcpUdpScans, PistolError> {
    scan(
        target,
        threads_num,
        ScanMethods::Idle,
        src_addr,
        src_port,
        zombie_ipv4,
        zombie_port,
        timeout,
        tests,
    )
}

/// TCP Idle Scan, raw version.
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
        ScanMethods::Idle,
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
pub fn udp_scan(
    target: &Target,
    threads_num: Option<usize>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<TcpUdpScans, PistolError> {
    scan(
        target,
        threads_num,
        ScanMethods::Udp,
        src_addr,
        src_port,
        None,
        None,
        timeout,
        tests,
    )
}

/// UDP Scan, raw version.
pub fn udp_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Option<Duration>,
) -> Result<(PortStatus, Duration), PistolError> {
    scan_raw(
        ScanMethods::Udp,
        dst_addr,
        dst_port,
        src_addr,
        src_port,
        None,
        None,
        timeout,
    )
}

pub fn scan_raw(
    method: ScanMethods,
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
    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Host;
   //  use crate::Logger;
    use crate::Target;
    use crate::TEST_IPV4_LOCAL;
    use std::time::Instant;
    use subnetwork::CrossIpv4Pool;
    use subnetwork::Ipv4Pool;
    #[test]
    fn test_arp_scan_subnet() {
        let subnet: Ipv4Pool = Ipv4Pool::from("192.168.1.0/24").unwrap();
        let mut hosts: Vec<Host> = vec![];
        for ip in subnet {
            let host = Host::new(ip.into(), None);
            hosts.push(host);
        }
        let target: Target = Target::new(hosts);
        let timeout = Some(Duration::new(1, 0));
        let src_ipv4 = None;
        let threads_num = Some(8);
        let ret: ArpScans = arp_scan(&target, threads_num, src_ipv4, timeout).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_arp_scan_subnet_new() {
        let target: Target = Target::from_subnet("192.168.1.1/24", None).unwrap();
        let timeout = Some(Duration::new(1, 0));
        let src_ipv4 = None;
        let threads_num = Some(8);
        let ret: ArpScans = arp_scan(&target, threads_num, src_ipv4, timeout).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_tcp_connect_scan() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(0, 500));
        let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let tests = 8;
        let threads_num = Some(8);
        let ret =
            tcp_connect_scan(&target, threads_num, src_ipv4, src_port, timeout, tests).unwrap();
        println!("{}", ret);

        // let target: Target = Target::from_subnet("192.168.1.1/24", Some(vec![22]))?;
        // let ret = tcp_connect_scan(target, src_ipv4, src_port, threads_num, timeout).unwrap();
        // println!("{}", ret);
    }
    #[test]
    fn test_tcp_syn_scan() {
        // let _ = Logger::init_debug_logging();
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(3, 0));
        // let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let dst_ipv4 = Ipv4Addr::new(139, 180, 156, 169);
        // let dst_ipv4 = Ipv4Addr::new(192, 168, 31, 1);
        let host = Host::new(dst_ipv4.into(), Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let tests = 4;
        let threads_num = Some(8);
        let ret = tcp_syn_scan(&target, threads_num, src_ipv4, src_port, timeout, tests).unwrap();
        println!("{}", ret);
        // println!("{:#?}", ret.get(&dst_ipv4.into()).unwrap().status);
    }
    #[test]
    fn test_tcp_fin_scan() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(3, 0));
        let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let tests = 8;
        let threads_num = Some(8);
        let ret = tcp_fin_scan(&target, threads_num, src_ipv4, src_port, timeout, tests).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_tcp_ack_scan() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(3, 0));
        let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let tests = 8;
        let threads_num = Some(8);
        let ret = tcp_ack_scan(&target, threads_num, src_ipv4, src_port, timeout, tests).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_tcp_null_scan() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(3, 0));
        let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let tests = 8;
        let threads_num = Some(8);
        let ret = tcp_null_scan(&target, threads_num, src_ipv4, src_port, timeout, tests).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_udp_scan() {
        let src_ipv4 = None;
        let src_port = None;
        let timeout = Some(Duration::new(3, 0));
        let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let tests = 8;
        let threads_num = Some(8);
        let ret = udp_scan(&target, threads_num, src_ipv4, src_port, timeout, tests).unwrap();
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
                    "status: {:?}, dura: {:?}, elapsed: {:.2}",
                    status,
                    dura,
                    start_time.elapsed().as_secs_f32()
                );
            }
            Err(e) => {
                println!("{}", e);
                println!("elapsed: {:.2}", start_time.elapsed().as_secs_f32());
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
        let mut hosts = vec![];
        for ip in subnet {
            let host = Host::new(ip.into(), Some(vec![22]));
            hosts.push(host);
        }
        let target = Target::new(hosts);
        let tests = 2;

        let start_time = Instant::now();
        let threads_num = Some(8);
        let ret = tcp_syn_scan(&target, threads_num, src_ipv4, src_port, timeout, tests).unwrap();
        // let ret = tcp_ack_scan(target, src_ipv4, src_port, timeout, tests).unwrap();
        // let ret = tcp_connect_scan(target, src_ipv4, src_port, timeout, tests).unwrap();
        println!("{}", ret);
        println!("elapsed: {:.2}", start_time.elapsed().as_secs_f32());
    }
}
