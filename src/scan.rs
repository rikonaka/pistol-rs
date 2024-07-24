/* Scan */
use anyhow::Result;
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

use crate::errors::CanNotFoundInterface;
use crate::errors::CanNotFoundMacAddress;
use crate::errors::CanNotFoundSourceAddress;
use crate::utils::find_interface_by_ip;
use crate::utils::find_source_addr;
use crate::utils::find_source_addr6;
use crate::utils::get_default_timeout;
use crate::utils::get_threads_pool;
use crate::utils::random_port;
use crate::Target;

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
}

#[derive(Debug, Clone)]
pub struct PortScanResults {
    pub scans: HashMap<IpAddr, HashMap<u16, Vec<PortStatus>>>,
    pub rtts: HashMap<IpAddr, HashMap<u16, Vec<Duration>>>,
    pub avg_rtt: Option<Duration>,
    pub open_ports: usize,
}

impl PortScanResults {
    pub fn new() -> PortScanResults {
        PortScanResults {
            scans: HashMap::new(),
            rtts: HashMap::new(),
            avg_rtt: None,
            open_ports: 0,
        }
    }
    pub fn get(&self, k: &IpAddr) -> Option<&HashMap<u16, Vec<PortStatus>>> {
        self.scans.get(k)
    }
    pub fn enrichment(&mut self) {
        // avg rtt
        let mut total_rtt = 0.0;
        let mut total_num = 0;
        for (_ip, rtts0) in &self.rtts {
            for (_port, rtts1) in rtts0 {
                for rtt in rtts1 {
                    total_rtt += rtt.as_secs_f64();
                    total_num += 1;
                }
            }
        }
        let avg_rtt = if total_num != 0 {
            let avg_rtt = total_rtt / total_num as f64;
            let avg_rtt = Duration::from_secs_f64(avg_rtt);
            Some(avg_rtt)
        } else {
            None
        };
        self.avg_rtt = avg_rtt;

        let mut open_ports = 0;
        for (_ip, ports_status) in &self.scans {
            for (_port, status) in ports_status {
                if status.contains(&PortStatus::Open) {
                    open_ports += 1;
                    break;
                }
            }
        }
        self.open_ports = open_ports;
    }
    fn insert(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        scan_ret: PortStatus,
        rtt: Option<Duration>,
    ) {
        match self.scans.get_mut(&dst_addr) {
            Some(s) => match s.get_mut(&dst_port) {
                Some(d) => {
                    d.push(scan_ret);
                }
                None => {
                    let d = vec![scan_ret];
                    s.insert(dst_port, d);
                }
            },
            None => {
                let mut s = HashMap::new();
                s.insert(dst_port, vec![scan_ret]);
                self.scans.insert(dst_addr, s);
            }
        }
        match self.rtts.get_mut(&dst_addr) {
            Some(s) => match s.get_mut(&dst_port) {
                Some(d) => match rtt {
                    Some(r) => {
                        d.push(r);
                    }
                    None => (),
                },
                None => {
                    let d = match rtt {
                        Some(r) => vec![r],
                        None => vec![],
                    };
                    s.insert(dst_port, d);
                }
            },
            None => {
                let mut s = HashMap::new();
                let d = match rtt {
                    Some(r) => vec![r],
                    None => vec![],
                };
                s.insert(dst_port, d);
                self.rtts.insert(dst_addr.into(), s);
            }
        }
    }
}

impl fmt::Display for PortScanResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![Cell::new("Scan Results")
            .style_spec("c")
            .with_hspan(3)]));

        // convert hashmap to btreemap here
        let scans = &self.scans;
        let scans: BTreeMap<IpAddr, &HashMap<u16, Vec<PortStatus>>> =
            scans.into_iter().map(|(i, h)| (*i, h)).collect();
        for (ip, ports_status) in scans {
            let ports_status: BTreeMap<u16, &Vec<PortStatus>> =
                ports_status.into_iter().map(|(p, s)| (*p, s)).collect();
            for (port, status) in ports_status {
                let mut status_str_vec = Vec::new();
                for s in status {
                    let s_str = match s {
                        PortStatus::Open => String::from("open"),
                        PortStatus::OpenOrFiltered => String::from("open_or_filtered"),
                        PortStatus::Filtered => String::from("filtered"),
                        PortStatus::Unfiltered => String::from("unfiltered"),
                        PortStatus::Closed => String::from("closed"),
                        PortStatus::Unreachable => String::from("unreachable"),
                        PortStatus::ClosedOrFiltered => String::from("closed_or_filtered"),
                        PortStatus::Error => String::from("error"),
                    };
                    status_str_vec.push(s_str);
                }
                let status_str = status_str_vec.join("|");
                table.add_row(row![c -> ip, c-> port, c -> status_str]);
            }
        }
        let avg_rtt = match self.avg_rtt {
            Some(avg_rtt) => avg_rtt,
            None => Duration::new(0, 0),
        };
        let summary = format!(
            "avg rtt: {:.1}ms\nopen ports: {}",
            avg_rtt.as_secs_f32() * 1000.0,
            self.open_ports
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(3)]));
        write!(f, "{}", table)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IdleScanResults {
    pub zombie_ip_id_1: u16,
    pub zombie_ip_id_2: u16,
}

#[derive(Debug, Clone)]
pub struct ArpAliveHost {
    pub mac_addr: MacAddr,
    pub ouis: String,
}

#[derive(Debug, Clone)]
pub struct ArpScanResults {
    pub alive_hosts: HashMap<Ipv4Addr, ArpAliveHost>,
    pub alive_host_num: usize,
}

impl ArpScanResults {
    pub fn new() -> ArpScanResults {
        ArpScanResults {
            alive_hosts: HashMap::new(),
            alive_host_num: 0,
        }
    }
    pub fn get(&self, k: &Ipv4Addr) -> Option<&ArpAliveHost> {
        self.alive_hosts.get(k)
    }
    pub fn enrichment(&mut self) {
        // alive hosts
        self.alive_host_num = self.alive_hosts.len();
    }
}

impl fmt::Display for ArpScanResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![Cell::new("ARP Scan Results")
            .style_spec("c")
            .with_hspan(3)]));

        let ah = &self.alive_hosts;
        let ah: BTreeMap<Ipv4Addr, &ArpAliveHost> = ah.into_iter().map(|(i, a)| (*i, a)).collect();
        for (ip, aah) in ah {
            table.add_row(row![c -> ip, c -> aah.mac_addr, c -> aah.ouis]);
        }

        let summary = format!("Summary:\nalive hosts: {}", self.alive_host_num);
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
) -> Result<(Option<MacAddr>, Option<Duration>)> {
    let src_ipv4 = match find_source_addr(src_addr, dst_ipv4)? {
        Some(s) => s,
        None => return Err(CanNotFoundSourceAddress::new().into()),
    };
    let interface = match find_interface_by_ip(src_ipv4.into()) {
        Some(i) => i,
        None => return Err(CanNotFoundInterface::new().into()),
    };
    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(CanNotFoundMacAddress::new().into()),
    };
    let scan_ret =
        arp::send_arp_scan_packet(dst_ipv4, dst_mac, src_ipv4, src_mac, interface, timeout);
    scan_ret
}

pub fn arp_scan_raw(
    dst_ipv4: Ipv4Addr,
    src_addr: Option<IpAddr>,
    timeout: Duration,
) -> Result<Option<MacAddr>> {
    let dst_mac = MacAddr::broadcast();
    let src_ipv4 = match find_source_addr(src_addr, dst_ipv4)? {
        Some(s) => s,
        None => return Err(CanNotFoundSourceAddress::new().into()),
    };
    let interface = match find_interface_by_ip(src_ipv4.into()) {
        Some(i) => i,
        None => return Err(CanNotFoundInterface::new().into()),
    };
    let src_mac = match interface.mac {
        Some(m) => m,
        None => return Err(CanNotFoundMacAddress::new().into()),
    };
    match arp::send_arp_scan_packet(dst_ipv4, dst_mac, src_ipv4, src_mac, interface, timeout) {
        Ok((mac, _)) => Ok(mac),
        Err(e) => Err(e),
    }
}

/// ARP Scan.
/// This will sends ARP packets to hosts on the local network and displays any responses that are received.
pub fn arp_scan(
    target: Target,
    src_addr: Option<IpAddr>,
    threads_num: usize,
    timeout: Option<Duration>,
) -> Result<ArpScanResults> {
    let nmap_mac_prefixes = get_nmap_mac_prefixes();
    let mut ret = ArpScanResults::new();

    let pool = get_threads_pool(threads_num);
    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };

    let dst_mac = MacAddr::broadcast();
    let (tx, rx) = channel();
    let mut recv_size = 0;
    for host in target.hosts {
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
                (Some(m), Some(_rtt)) => {
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
                    let aah = ArpAliveHost { mac_addr: m, ouis };
                    ret.alive_hosts.insert(target_ipv4, aah);
                }
                (_, _) => (),
            },
            Err(e) => return Err(e),
        }
    }
    ret.enrichment();
    Ok(ret)
}

fn threads_scan(
    method: ScanMethod,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    timeout: Duration,
) -> Result<(PortStatus, Option<Duration>)> {
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

fn threads_scan6(
    method: ScanMethod,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    timeout: Duration,
) -> Result<(PortStatus, Option<Duration>)> {
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

fn ipv4_scan(
    method: ScanMethod,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    timeout: Duration,
) -> Result<(PortStatus, Option<Duration>)> {
    let src_ipv4 = match find_source_addr(src_addr, dst_ipv4)? {
        Some(s) => s,
        None => return Err(CanNotFoundSourceAddress::new().into()),
    };
    let src_port = match src_port {
        Some(s) => s,
        None => random_port(),
    };
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
    scan_ret
}

fn ipv6_scan(
    method: ScanMethod,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    timeout: Duration,
) -> Result<(PortStatus, Option<Duration>)> {
    let src_ipv6 = match find_source_addr6(src_addr, dst_ipv6)? {
        Some(s) => s,
        None => return Err(CanNotFoundSourceAddress::new().into()),
    };
    let src_port = match src_port {
        Some(s) => s,
        None => random_port(),
    };
    let scan_ret = threads_scan6(method, dst_ipv6, dst_port, src_ipv6, src_port, timeout);
    scan_ret
}

/// General scan function.
pub fn scan(
    target: Target,
    method: ScanMethod,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PortScanResults> {
    let pool = get_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut recv_size = 0;
    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };

    for host in target.hosts {
        let dst_addr = host.addr;
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                for dst_port in host.ports {
                    for _ in 0..tests {
                        let tx = tx.clone();
                        recv_size += 1;
                        pool.execute(move || {
                            let scan_ret = ipv4_scan(
                                method,
                                dst_ipv4,
                                dst_port,
                                src_addr,
                                src_port,
                                zombie_ipv4,
                                zombie_port,
                                timeout,
                            );
                            match tx.send((dst_addr, dst_port, scan_ret)) {
                                _ => (),
                            }
                        });
                    }
                }
            }
            IpAddr::V6(dst_ipv6) => {
                for dst_port in host.ports {
                    for _ in 0..tests {
                        let tx = tx.clone();
                        recv_size += 1;
                        pool.execute(move || {
                            let scan_ret =
                                ipv6_scan(method, dst_ipv6, dst_port, src_addr, src_port, timeout);
                            match tx.send((dst_addr, dst_port, scan_ret)) {
                                _ => (),
                            }
                        });
                    }
                }
            }
        }
    }

    let iter = rx.into_iter().take(recv_size);
    let mut port_scan_ret = PortScanResults::new();

    for (dst_ipv4, dst_port, v) in iter {
        match v {
            Ok((port_status, rtt)) => {
                port_scan_ret.insert(dst_ipv4.into(), dst_port, port_status, rtt);
            }
            Err(e) => {
                warn!("scan error: {}", e);
                port_scan_ret.insert(dst_ipv4.into(), dst_port, PortStatus::Error, None);
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
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PortScanResults> {
    scan(
        target,
        ScanMethod::Connect,
        src_addr,
        src_port,
        None,
        None,
        threads_num,
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
    timeout: Duration,
) -> Result<(PortStatus, Option<Duration>)> {
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
pub fn tcp_syn_scan(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PortScanResults> {
    scan(
        target,
        ScanMethod::Syn,
        src_addr,
        src_port,
        None,
        None,
        threads_num,
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
    timeout: Duration,
) -> Result<(PortStatus, Option<Duration>)> {
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
pub fn tcp_fin_scan(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PortScanResults> {
    scan(
        target,
        ScanMethod::Fin,
        src_addr,
        src_port,
        None,
        None,
        threads_num,
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
    timeout: Duration,
) -> Result<(PortStatus, Option<Duration>)> {
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
pub fn tcp_ack_scan(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PortScanResults> {
    scan(
        target,
        ScanMethod::Ack,
        src_addr,
        src_port,
        None,
        None,
        threads_num,
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
    timeout: Duration,
) -> Result<(PortStatus, Option<Duration>)> {
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
pub fn tcp_null_scan(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PortScanResults> {
    scan(
        target,
        ScanMethod::Null,
        src_addr,
        src_port,
        None,
        None,
        threads_num,
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
    timeout: Duration,
) -> Result<(PortStatus, Option<Duration>)> {
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
pub fn tcp_xmas_scan(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PortScanResults> {
    scan(
        target,
        ScanMethod::Xmas,
        src_addr,
        src_port,
        None,
        None,
        threads_num,
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
    timeout: Duration,
) -> Result<(PortStatus, Option<Duration>)> {
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
pub fn tcp_window_scan(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PortScanResults> {
    scan(
        target,
        ScanMethod::Window,
        src_addr,
        src_port,
        None,
        None,
        threads_num,
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
    timeout: Duration,
) -> Result<(PortStatus, Option<Duration>)> {
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
pub fn tcp_maimon_scan(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PortScanResults> {
    scan(
        target,
        ScanMethod::Maimon,
        src_addr,
        src_port,
        None,
        None,
        threads_num,
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
    timeout: Duration,
) -> Result<(PortStatus, Option<Duration>)> {
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
pub fn tcp_idle_scan(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PortScanResults> {
    scan(
        target,
        ScanMethod::Idle,
        src_addr,
        src_port,
        zombie_ipv4,
        zombie_port,
        threads_num,
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
    timeout: Duration,
) -> Result<(PortStatus, Option<Duration>)> {
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
pub fn udp_scan(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    timeout: Option<Duration>,
    tests: usize,
) -> Result<PortScanResults> {
    scan(
        target,
        ScanMethod::Udp,
        src_addr,
        src_port,
        None,
        None,
        threads_num,
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
    timeout: Duration,
) -> Result<(PortStatus, Option<Duration>)> {
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

pub fn scan_raw(
    method: ScanMethod,
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    timeout: Duration,
) -> Result<(PortStatus, Option<Duration>)> {
    let src_port = match src_port {
        Some(s) => s,
        None => random_port(),
    };
    match dst_addr {
        IpAddr::V4(dst_ipv4) => {
            let src_ipv4 = match find_source_addr(src_addr, dst_ipv4)? {
                Some(s) => s,
                None => return Err(CanNotFoundSourceAddress::new().into()),
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
                None => return Err(CanNotFoundSourceAddress::new().into()),
            };
            threads_scan6(method, dst_ipv6, dst_port, src_ipv6, src_port, timeout)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Host;
    use crate::Target;
    use crate::TEST_IPV4_LOCAL;
    use subnetwork::Ipv4Pool;
    #[test]
    fn test_arp_scan_subnet() -> Result<()> {
        let subnet: Ipv4Pool = Ipv4Pool::from("192.168.1.0/24").unwrap();
        let mut hosts: Vec<Host> = vec![];
        for ip in subnet {
            let host = Host::new(ip.into(), None);
            hosts.push(host);
        }
        let target: Target = Target::new(hosts);
        let threads_num = 300;
        let timeout = Some(Duration::new(1, 0));
        // let print_result = false;
        let src_ipv4 = None;
        let ret: ArpScanResults = arp_scan(target, src_ipv4, threads_num, timeout).unwrap();
        println!("{}", ret);
        Ok(())
    }
    #[test]
    fn test_arp_scan_subnet_new() -> Result<()> {
        let target: Target = Target::from_subnet("192.168.1.1/24", None)?;
        let threads_num = 300;
        let timeout = Some(Duration::new(1, 0));
        // let print_result = false;
        let src_ipv4 = None;
        let ret: ArpScanResults = arp_scan(target, src_ipv4, threads_num, timeout).unwrap();
        println!("{}", ret);
        Ok(())
    }
    #[test]
    fn test_tcp_connect_scan() -> Result<()> {
        let src_ipv4 = None;
        let src_port = None;
        let threads_num: usize = 8;
        let timeout = Some(Duration::new(0, 500));
        let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let tests = 8;
        let ret =
            tcp_connect_scan(target, src_ipv4, src_port, threads_num, timeout, tests).unwrap();
        println!("{}", ret);

        // let target: Target = Target::from_subnet("192.168.1.1/24", Some(vec![22]))?;
        // let ret = tcp_connect_scan(target, src_ipv4, src_port, threads_num, timeout).unwrap();
        // println!("{}", ret);
        Ok(())
    }
    #[test]
    fn test_tcp_syn_scan() -> Result<()> {
        let src_ipv4 = None;
        let src_port = None;
        let threads_num: usize = 8;
        let timeout = Some(Duration::new(3, 0));
        let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let tests = 4;
        let ret = tcp_syn_scan(target, src_ipv4, src_port, threads_num, timeout, tests).unwrap();
        println!("{}", ret);
        // println!("{:#?}", ret.get(&dst_ipv4.into()).unwrap().status);
        Ok(())
    }
    #[test]
    fn test_tcp_fin_scan() -> Result<()> {
        let src_ipv4 = None;
        let src_port = None;
        let threads_num: usize = 8;
        let timeout = Some(Duration::new(3, 0));
        let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let tests = 8;
        let ret = tcp_fin_scan(target, src_ipv4, src_port, threads_num, timeout, tests).unwrap();
        println!("{}", ret);
        Ok(())
    }
    #[test]
    fn test_tcp_ack_scan() -> Result<()> {
        let src_ipv4 = None;
        let src_port = None;
        let threads_num: usize = 8;
        let timeout = Some(Duration::new(3, 0));
        let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let tests = 8;
        let ret = tcp_ack_scan(target, src_ipv4, src_port, threads_num, timeout, tests).unwrap();
        println!("{}", ret);
        Ok(())
    }
    #[test]
    fn test_tcp_null_scan() -> Result<()> {
        let src_ipv4 = None;
        let src_port = None;
        let threads_num: usize = 8;
        let timeout = Some(Duration::new(3, 0));
        let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let tests = 8;
        let ret = tcp_null_scan(target, src_ipv4, src_port, threads_num, timeout, tests).unwrap();
        println!("{}", ret);
        Ok(())
    }
    #[test]
    fn test_udp_scan() -> Result<()> {
        let src_ipv4 = None;
        let src_port = None;
        let threads_num: usize = 8;
        let timeout = Some(Duration::new(3, 0));
        let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let tests = 8;
        let ret = udp_scan(target, src_ipv4, src_port, threads_num, timeout, tests).unwrap();
        println!("{}", ret);
        Ok(())
    }
}
