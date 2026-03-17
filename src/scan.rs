/* Scan */
#[cfg(any(feature = "scan", feature = "ping"))]
use chrono::DateTime;
#[cfg(any(feature = "scan", feature = "ping"))]
use chrono::Local;
#[cfg(any(feature = "scan", feature = "ping"))]
use crossbeam::channel::Receiver;
#[cfg(any(feature = "scan", feature = "ping"))]
use crossbeam::channel::Sender;
#[cfg(feature = "scan")]
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
#[cfg(feature = "scan")]
use pnet::datalink::interfaces;
#[cfg(any(feature = "scan", feature = "ping"))]
use pnet::packet::Packet;
#[cfg(any(feature = "scan", feature = "ping"))]
use pnet::packet::arp::ArpPacket;
#[cfg(any(feature = "scan", feature = "ping"))]
use pnet::packet::ethernet::EtherTypes;
#[cfg(any(feature = "scan", feature = "ping"))]
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmpv6::Icmpv6Types;
#[cfg(any(feature = "scan", feature = "ping"))]
use pnet::packet::icmpv6::ndp::NeighborAdvertPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
#[cfg(any(feature = "scan", feature = "ping"))]
use pnet::packet::ipv6::Ipv6Packet;
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
#[cfg(feature = "scan")]
use std::collections::HashMap;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::fmt;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::net::IpAddr;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::net::Ipv4Addr;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::net::Ipv6Addr;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::sync::Arc;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::sync::Mutex;
#[cfg(any(feature = "scan", feature = "ping"))]
use std::thread;
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
pub mod ndp_rs;
#[cfg(any(feature = "scan", feature = "ping"))]
pub mod tcp;
#[cfg(any(feature = "scan", feature = "ping"))]
pub mod tcp6;
#[cfg(any(feature = "scan", feature = "ping"))]
pub mod udp;
#[cfg(any(feature = "scan", feature = "ping"))]
pub mod udp6;

#[cfg(any(feature = "scan", feature = "ping"))]
use crate::GLOBAL_NET_CACHES;
#[cfg(feature = "scan")]
use crate::NetInfo;
#[cfg(any(feature = "scan", feature = "ping"))]
use crate::PacketFilter;
#[cfg(feature = "scan")]
use crate::RRequest;
#[cfg(any(feature = "scan", feature = "ping"))]
use crate::RResponse;
#[cfg(feature = "scan")]
use crate::SRequest;
#[cfg(feature = "scan")]
use crate::Target;
#[cfg(any(feature = "scan", feature = "ping"))]
use crate::error::PistolError;
#[cfg(any(feature = "scan", feature = "ping"))]
use crate::layer::ipv6_multicast_mac;
#[cfg(any(feature = "scan", feature = "ping"))]
#[cfg(feature = "scan")]
use crate::scan::arp::build_arp_scan_packet;
#[cfg(feature = "scan")]
use crate::scan::ndp_ns::build_ndp_ns_scan_packet;
#[cfg(feature = "scan")]
use crate::utils::random_port;
#[cfg(feature = "scan")]
use crate::utils::random_recv_msg_id;
#[cfg(feature = "scan")]
use crate::utils::time_to_string;

/// This structure is used to indicate whether the program has data received or no data received.
/// For example, in UDP scan, if no data is received, the status returned is open_or_filtered.
/// So when UDP scan returns to the open_or_filtered state, DataRecvStatus should be set to No.
#[cfg(any(feature = "scan", feature = "ping"))]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HasResponse {
    Yes,
    No,
}

impl fmt::Display for HasResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            HasResponse::Yes => "yes",
            HasResponse::No => "no",
        };
        write!(f, "{}", s)
    }
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
            let time_cost_str = time_to_string(report.rtt);
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
        let total_cost_str = time_to_string(Duration::from_secs_f32(total_cost.as_seconds_f32()));
        let avg_cost = total_cost.as_seconds_f32() / self.mac_reports.len() as f32;
        let avg_cost_str = time_to_string(Duration::from_secs_f32(avg_cost));
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

fn loopback_interface() -> Result<NetworkInterface, PistolError> {
    for interface in interfaces() {
        if interface.is_loopback() {
            return Ok(interface);
        }
    }
    Err(PistolError::CanNotFoundLoopbackInterface)
}

/// mac scan target is only can be localnet address.
fn mac_scan_found_interface(dst_addr: IpAddr) -> Result<NetworkInterface, PistolError> {
    if dst_addr.is_loopback() {
        return loopback_interface();
    }

    for n in interfaces() {
        for ipn in &n.ips {
            if ipn.ip() == dst_addr {
                return loopback_interface();
            } else if ipn.contains(dst_addr) {
                return Ok(n.clone());
            }
        }
    }

    Err(PistolError::CanNotFoundInterface {
        i: format!("to {}", dst_addr),
    })
}

#[cfg(feature = "scan")]
pub fn arp_scan_raw(
    dst_ipv4: Ipv4Addr,
    timeout: Duration,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    debug!("start arp scan to {}", dst_ipv4);

    let interface = mac_scan_found_interface(dst_ipv4.into())?;
    let interface_name = interface.name.clone();

    // broadcast mac address
    let dst_mac = MacAddr::broadcast();
    let src_mac = interface.mac.ok_or(PistolError::CanNotFoundSrcMacAddress)?;
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
            let (arp_buff, filters) = build_arp_scan_packet(dst_ipv4, src_mac, src_ipv4)?;

            let recv_msg = RRequest {
                interface_name: interface_name.clone(),
                id: random_recv_msg_id(),
                filters,
                created: Instant::now(),
                elapsed: timeout,
            };
            let send_msg = SRequest {
                interface_name: interface_name.clone(),
                dst_mac,
                src_mac,
                eth_payload: arp_buff,
                eth_type: EtherTypes::Arp,
                retransmit: 1,
            };
            if let Err(e) = push_rd.send(recv_msg) {
                error!("send arp scan recv msg error: {}", e);
            }
            if let Err(e) = push_sd.send(send_msg) {
                error!("send arp scan msg error: {}", e);
            }

            match get_response.recv_timeout(timeout) {
                Ok(recv_response) => {
                    let rtt = recv_response.rtt;
                    match parse_mac_scan_response(recv_response.data) {
                        Some((addr, mac)) => {
                            update_neighbor_cache(addr, mac, rtt)?;
                            Ok((Some(mac), rtt))
                        }
                        None => Ok((None, rtt)),
                    }
                }
                Err(_) => Ok((None, Duration::ZERO)),
            }
        }
        None => Err(PistolError::CanNotFoundSrcAddress),
    }
}

#[cfg(feature = "scan")]
fn arp_scan_thread(
    dst_ipv4: Ipv4Addr,
    timeout: Duration,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
) -> Result<(), PistolError> {
    debug!("start arp scan thread to {}", dst_ipv4);

    let interface = mac_scan_found_interface(dst_ipv4.into())?;
    let interface_name = interface.name.clone();

    // broadcast mac address
    let dst_mac = MacAddr::broadcast();
    let src_mac = interface.mac.ok_or(PistolError::CanNotFoundSrcMacAddress)?;
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
            // only send here
            let (arp_buff, filters) = build_arp_scan_packet(dst_ipv4, src_mac, src_ipv4)?;

            let recv_msg = RRequest {
                interface_name: interface_name.clone(),
                id: random_recv_msg_id(),
                filters,
                created: Instant::now(),
                elapsed: timeout,
            };
            let send_msg = SRequest {
                interface_name: interface_name.clone(),
                dst_mac,
                src_mac,
                eth_payload: arp_buff,
                eth_type: EtherTypes::Arp,
                retransmit: 1,
            };

            if let Err(e) = push_rd.send(recv_msg) {
                error!("send arp scan recv msg error: {}", e);
            }
            if let Err(e) = push_sd.send(send_msg) {
                error!("send arp scan msg error: {}", e);
            }
            Ok(())
        }
        None => Err(PistolError::CanNotFoundSrcAddress),
    }
}

#[cfg(feature = "scan")]
pub fn ndp_ns_scan_raw(
    dst_ipv6: Ipv6Addr,
    timeout: Duration,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    let interface = mac_scan_found_interface(dst_ipv6.into())?;
    let interface_name = interface.name.clone();
    let src_mac = interface.mac.ok_or(PistolError::CanNotFoundSrcMacAddress)?;

    let dst_ipv6_ext: Ipv6AddrExt = dst_ipv6.into();
    let dst_ipv6 = dst_ipv6_ext.link_multicast();
    let dst_mac = ipv6_multicast_mac(dst_ipv6);

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
            let (ndp_ns_buff, filters) = build_ndp_ns_scan_packet(dst_ipv6, src_mac, src_ipv6)?;

            let recv_msg_id = random_recv_msg_id();
            let recv_msg = RRequest {
                interface_name: interface_name.clone(),
                id: recv_msg_id,
                filters,
                created: Instant::now(),
                elapsed: timeout,
            };
            let send_msg = SRequest {
                interface_name: interface_name.clone(),
                dst_mac,
                src_mac,
                eth_payload: ndp_ns_buff,
                eth_type: EtherTypes::Ipv6,
                retransmit: 1,
            };

            if let Err(e) = push_rd.send(recv_msg) {
                error!("send arp scan recv msg error: {}", e);
            }
            if let Err(e) = push_sd.send(send_msg) {
                error!("send arp scan msg error: {}", e);
            }

            match get_response.recv_timeout(timeout) {
                Ok(recv_response) => {
                    let rtt = recv_response.rtt;
                    if recv_response.id == recv_msg_id {
                        match parse_mac_scan_response(recv_response.data) {
                            Some((addr, mac)) => {
                                update_neighbor_cache(addr, mac, rtt)?;
                                Ok((Some(mac), rtt))
                            }
                            None => Ok((None, rtt)),
                        }
                    } else {
                        Ok((None, rtt))
                    }
                }
                Err(_) => Ok((None, Duration::ZERO)),
            }
        }
        None => Err(PistolError::CanNotFoundSrcAddress),
    }
}

#[cfg(feature = "scan")]
pub fn ndp_ns_scan_thread(
    dst_ipv6: Ipv6Addr,
    timeout: Duration,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
) -> Result<(), PistolError> {
    let interface = mac_scan_found_interface(dst_ipv6.into())?;
    let interface_name = interface.name.clone();
    let src_mac = interface.mac.ok_or(PistolError::CanNotFoundSrcMacAddress)?;

    let dst_ipv6_ext: Ipv6AddrExt = dst_ipv6.into();
    let dst_ipv6 = dst_ipv6_ext.link_multicast();
    let dst_mac = ipv6_multicast_mac(dst_ipv6);

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
            let created = Instant::now();
            let (ndp_ns_buff, filters) = build_ndp_ns_scan_packet(dst_ipv6, src_mac, src_ipv6)?;

            let recv_msg = RRequest {
                interface_name: interface_name.clone(),
                id: random_recv_msg_id(),
                filters,
                created,
                elapsed: timeout,
            };
            let send_msg = SRequest {
                interface_name: interface_name.clone(),
                dst_mac,
                src_mac,
                eth_payload: ndp_ns_buff,
                eth_type: EtherTypes::Ipv6,
                retransmit: 1,
            };

            if let Err(e) = push_rd.send(recv_msg) {
                error!("send arp scan recv msg error: {}", e);
            }
            if let Err(e) = push_sd.send(send_msg) {
                error!("send arp scan msg error: {}", e);
            }
            Ok(())
        }
        None => Err(PistolError::CanNotFoundSrcAddress),
    }
}

#[derive(Debug, Clone, Copy)]
struct MacScanStatus {
    retried: usize,
    data_recved: bool,
    start: Instant,
}

fn update_neighbor_cache(addr: IpAddr, mac: MacAddr, rtt: Duration) -> Result<(), PistolError> {
    let mut gncs = GLOBAL_NET_CACHES
        .lock()
        .map_err(|e| PistolError::LockVarFailed { e: e.to_string() })?;
    gncs.system_network_cache
        .update_neighbor_cache(addr.into(), mac, Some(rtt));
    Ok(())
}

pub(crate) fn parse_mac_scan_response(eth_response: Arc<[u8]>) -> Option<(IpAddr, MacAddr)> {
    if eth_response.len() == 0 {
        return None;
    }

    let eth_response = eth_response.as_ref();
    if let Some(eth_packet) = EthernetPacket::new(eth_response) {
        match eth_packet.get_ethertype() {
            EtherTypes::Arp => {
                // arp on ipv6
                if let Some(arp_packet) = ArpPacket::new(eth_packet.payload()) {
                    let mac = arp_packet.get_sender_hw_addr();
                    let addr = arp_packet.get_sender_proto_addr();
                    return Some((addr.into(), mac));
                }
            }
            EtherTypes::Ipv6 => {
                // ndp ns on ipv6
                if let Some(ipv6_packet) = Ipv6Packet::new(eth_packet.payload()) {
                    let addr = ipv6_packet.get_source();
                    match ipv6_packet.get_next_header() {
                        IpNextHeaderProtocols::Icmpv6 => {
                            if let Some(icmpv6_packet) = Icmpv6Packet::new(ipv6_packet.payload()) {
                                match icmpv6_packet.get_icmpv6_type() {
                                    Icmpv6Types::NeighborAdvert => {
                                        if let Some(na_packet) =
                                            NeighborAdvertPacket::new(ipv6_packet.payload())
                                        {
                                            for o in na_packet.get_options() {
                                                if o.data.len() >= 6 {
                                                    let mac = MacAddr::new(
                                                        o.data[0], o.data[1], o.data[2], o.data[3],
                                                        o.data[4], o.data[5],
                                                    );
                                                    return Some((addr.into(), mac));
                                                }
                                            }
                                        }
                                    }
                                    Icmpv6Types::RouterAdvert => {
                                        let mac = eth_packet.get_source();
                                        return Some((addr.into(), mac));
                                    }
                                    _ => {
                                        debug!(
                                            "skip non-NA/RA icmpv6 packet with type {:?}",
                                            icmpv6_packet.get_icmpv6_type()
                                        );
                                    }
                                }
                            }
                        }
                        _ => {
                            debug!(
                                "skip non-icmpv6 packet with next header {:?}",
                                ipv6_packet.get_next_header()
                            );
                        }
                    }
                }
            }
            _ => {
                debug!(
                    "skip non-arp/ipv6 packet with ethertype {:?}",
                    eth_packet.get_ethertype()
                );
            }
        }
    }

    None
}

#[cfg(feature = "scan")]
pub fn mac_scan(
    targets: &[Target],
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<MacScans, PistolError> {
    let nmap_mac_prefixes = get_nmap_mac_prefixes();
    let mut rets = MacScans::new(max_retries);

    let mut mac_scan_status = HashMap::new();
    for t in targets {
        let status = MacScanStatus {
            retried: 0,
            data_recved: false,
            start: Instant::now(),
        };
        mac_scan_status.insert(t.addr, status);
    }
    let mut mac_scan_status_clone = mac_scan_status.clone();
    let mut mac_scan_rets = HashMap::new();

    loop {
        let mut all_done = true;
        for (dst_addr, status) in mac_scan_status {
            let retried = status.retried;
            let data_recved = status.data_recved;
            if retried < max_retries && !data_recved {
                let push_rd = push_rd.clone();
                let push_sd = push_sd.clone();
                match dst_addr {
                    IpAddr::V4(dst_ipv4) => {
                        debug!("arp scan packets: #{}/{}", retried + 1, max_retries);
                        // retry to send arp scan packet and recv response
                        let start = Instant::now();
                        arp_scan_thread(dst_ipv4, timeout, push_rd, push_sd)?;

                        let status = MacScanStatus {
                            retried: retried + 1,
                            data_recved: false,
                            start,
                        };
                        mac_scan_status_clone.insert(dst_addr, status);
                        all_done = false;
                    }
                    IpAddr::V6(dst_ipv6) => {
                        debug!("ndp_ns scan packets: #{}/{}", retried + 1, max_retries);
                        // retry to send ndp_ns scan packet and recv response
                        let start = Instant::now();
                        ndp_ns_scan_thread(dst_ipv6, timeout, push_rd, push_sd)?;

                        let status = MacScanStatus {
                            retried: retried + 1,
                            data_recved: false,
                            start,
                        };
                        mac_scan_status_clone.insert(dst_addr, status);
                        all_done = false;
                    }
                }
            }
        }
        mac_scan_status = mac_scan_status_clone.clone();

        if all_done {
            break;
        }

        let fix_timeout = Duration::from_millis(5);
        let start_get_time = Instant::now();
        loop {
            if start_get_time.elapsed() > timeout {
                break;
            }
            let recv_response = match get_response.recv_timeout(fix_timeout) {
                Ok(r) => r,
                Err(_e) => continue,
            };

            if let Some((addr, mac)) = parse_mac_scan_response(recv_response.data) {
                let rtt = recv_response.rtt;
                let mut status = mac_scan_status[&addr].clone();
                status.data_recved = true;
                mac_scan_status.insert(addr, status);
                mac_scan_rets.insert(addr, (mac, rtt));
                update_neighbor_cache(addr, mac, rtt)?;
            }
        }
    }

    let mut mac_scan_reports = Vec::new();
    for (target_addr, (target_mac, rtt)) in mac_scan_rets {
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
    rets.finish(mac_scan_reports);
    Ok(rets)
}

/// Remove connect and idle scan from here.
#[cfg(any(feature = "scan", feature = "ping"))]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanMethod {
    Syn,
    Fin,
    Ack,
    Null,
    Xmas,
    Window,
    Maimon,
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
    pub addr_origin: IpAddr,
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
                let addr_str = format!("{}", report.addr_origin);
                let status_str = format!("{}", report.status);
                let time_cost_str = if report.cached {
                    time_to_string(report.cost)
                } else {
                    let time_cost_str = time_to_string(report.cost);
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
                let addr_str = format!("{}", report.addr_origin);
                let status_str = format!("{}", report.status);
                let time_cost_str = if report.cached {
                    let time_cost_str = time_to_string(report.cost);
                    format!("{}(cached)", time_cost_str)
                } else {
                    time_to_string(report.cost)
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
        let total_cost_str = time_to_string(Duration::from_secs_f32(total_cost.as_seconds_f32()));
        let avg_cost = if self.port_reports.len() > 0 {
            total_cost.as_seconds_f32() / self.port_reports.len() as f32
        } else {
            total_cost.as_seconds_f32()
        };
        let avg_cost_str = time_to_string(Duration::from_secs_f32(avg_cost));
        let layer2_cost_str = time_to_string(self.layer2_cost);
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
fn build_scan_buff(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    method: ScanMethod,
) -> Result<(Arc<[u8]>, Vec<Arc<PacketFilter>>), PistolError> {
    // The connect scan and idle scan need to send more than one packets,
    // so we put them other functions instead of here.
    match method {
        ScanMethod::Syn => tcp::build_syn_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port),
        ScanMethod::Fin => tcp::build_fin_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port),
        ScanMethod::Ack => tcp::build_ack_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port),
        ScanMethod::Null => tcp::build_null_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port),
        ScanMethod::Xmas => tcp::build_xmas_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port),
        ScanMethod::Window => tcp::build_window_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port),
        ScanMethod::Maimon => tcp::build_maimon_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port),
        ScanMethod::Udp => udp::build_udp_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port),
    }
}

#[cfg(any(feature = "scan", feature = "ping"))]
fn build_scan_buff6(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    method: ScanMethod,
) -> Result<(Arc<[u8]>, Vec<Arc<PacketFilter>>), PistolError> {
    match method {
        ScanMethod::Syn => tcp6::build_syn_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port),
        ScanMethod::Fin => tcp6::build_fin_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port),
        ScanMethod::Ack => tcp6::build_ack_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port),
        ScanMethod::Null => tcp6::build_null_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port),
        ScanMethod::Xmas => tcp6::build_xmas_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port),
        ScanMethod::Window => tcp6::send_window_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port),
        ScanMethod::Maimon => {
            tcp6::build_maimon_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port)
        }
        ScanMethod::Udp => udp6::send_udp_scan_packet(dst_ipv6, dst_port, src_ipv6, src_port),
    }
}

#[cfg(any(feature = "scan", feature = "ping"))]
fn parse_response(eth_response: Arc<[u8]>, method: ScanMethod) -> Result<PortStatus, PistolError> {
    let parse_ipv4 = || -> Result<PortStatus, PistolError> {
        let eth_response = eth_response.clone();
        match method {
            ScanMethod::Syn => tcp::parse_syn_scan_response(eth_response),
            ScanMethod::Fin => tcp::parse_fin_scan_response(eth_response),
            ScanMethod::Ack => tcp::parse_ack_scan_response(eth_response),
            ScanMethod::Null => tcp::parse_null_scan_response(eth_response),
            ScanMethod::Xmas => tcp::parse_xmas_scan_response(eth_response),
            ScanMethod::Window => tcp::parse_window_scan_response(eth_response),
            ScanMethod::Maimon => tcp::parse_maimon_scan_response(eth_response),
            ScanMethod::Udp => udp::parse_udp_scan_response(eth_response),
        }
    };
    let parse_ipv6 = || -> Result<PortStatus, PistolError> {
        let eth_response = eth_response.clone();
        match method {
            ScanMethod::Syn => tcp6::parse_syn_scan_response(eth_response),
            ScanMethod::Fin => tcp6::parse_fin_scan_response(eth_response),
            ScanMethod::Ack => tcp6::parse_ack_scan_response(eth_response),
            ScanMethod::Null => tcp6::parse_null_scan_response(eth_response),
            ScanMethod::Xmas => tcp6::parse_xmas_scan_response(eth_response),
            ScanMethod::Window => tcp6::parse_window_scan_response(eth_response),
            ScanMethod::Maimon => tcp6::parse_maimon_scan_response(eth_response),
            ScanMethod::Udp => udp6::parse_udp_scan_response(eth_response),
        }
    };
    match EthernetPacket::new(eth_response.as_ref()) {
        Some(eth_packet) => match eth_packet.get_ethertype() {
            EtherTypes::Ipv4 => parse_ipv4(),
            EtherTypes::Ipv6 => parse_ipv6(),
            _ => {
                debug!(
                    "skip non-ipv4/ipv6 packet with ethertype {:?}",
                    eth_packet.get_ethertype()
                );
                Err(PistolError::CanNotParseEthernetPacket)
            }
        },
        None => Err(PistolError::CanNotParseEthernetPacket),
    }
}

#[derive(Debug, Clone)]
struct ScanStatus {
    id: u64,
    retried: usize,
    recved: bool,
}

/// General scan function.
#[cfg(any(feature = "scan", feature = "ping"))]
fn scan(
    net_infos: Vec<NetInfo>,
    method: ScanMethod,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<PortScans, PistolError> {
    let mut port_scans = PortScans::new(max_retries);
    let mut reports = Vec::new();

    let mut scan_status = HashMap::new();
    for ni in net_infos {
        // (0, false, None, start) => (retiries, has data recved?, receiver, send probe time)
        if ni.valid {
            let mut hm = HashMap::new();
            for p in ni.dst_ports.clone() {
                let status = ScanStatus {
                    id: 0,
                    retried: 0,
                    recved: false,
                };
                hm.insert(p, status);
            }
            scan_status.insert(ni, hm);
        }
    }
    let mut scan_status_clone = scan_status.clone();

    loop {
        let start_eval = Instant::now();
        let mut all_done = true;
        for (ni, hm) in scan_status {
            let dst_mac = ni.inferred_dst_mac;
            let dst_addr = ni.inferred_dst_addr;
            let src_mac = ni.inferred_src_mac;
            let src_port = match ni.src_port {
                Some(s) => s,
                None => random_port(),
            };
            match dst_addr {
                IpAddr::V4(dst_ipv4) => {
                    let src_ipv4 = match ni.inferred_src_addr {
                        IpAddr::V4(s) => s,
                        _ => {
                            return Err(PistolError::AttackAddressNotMatch {
                                addr: ni.inferred_src_addr,
                            });
                        }
                    };
                    let mut tmp_hm = scan_status_clone[&ni].clone();
                    for (dst_port, status) in hm {
                        let mut status = status.clone();
                        let retried = status.retried;
                        let recved = status.recved;
                        if retried < max_retries && !recved {
                            let (buff, filters) =
                                build_scan_buff(dst_ipv4, dst_port, src_ipv4, src_port, method)?;

                            let interface_name = ni.interface_name.clone();
                            let recv_msg_id = random_recv_msg_id();
                            let recv_msg = RRequest {
                                interface_name: interface_name.clone(),
                                id: recv_msg_id,
                                filters,
                                created: Instant::now(),
                                elapsed: timeout,
                            };
                            let send_msg = SRequest {
                                interface_name: interface_name.clone(),
                                dst_mac,
                                src_mac,
                                eth_payload: buff.clone(),
                                eth_type: EtherTypes::Ipv4,
                                retransmit: retried,
                            };

                            if let Err(e) = push_rd.send(recv_msg) {
                                error!("send scan recv msg error: {}", e);
                            }
                            if let Err(e) = push_sd.send(send_msg) {
                                error!("send scan packet error: {}", e);
                            }

                            status.retried = retried + 1;
                            status.id = recv_msg_id;
                            tmp_hm.insert(dst_port, status);
                            all_done = false;
                        }
                    }
                    scan_status_clone.insert(ni, tmp_hm);
                }
                IpAddr::V6(dst_ipv6) => {
                    let src_ipv6 = match ni.inferred_src_addr {
                        IpAddr::V6(s) => s,
                        _ => {
                            return Err(PistolError::AttackAddressNotMatch {
                                addr: ni.inferred_src_addr,
                            });
                        }
                    };
                    let mut tmp_hm = scan_status_clone[&ni].clone();
                    for (dst_port, status) in hm {
                        let mut status = status.clone();
                        let retried = status.retried;
                        let recved = status.recved;
                        if retried < max_retries && !recved {
                            let (buff, filters) =
                                build_scan_buff6(dst_ipv6, dst_port, src_ipv6, src_port, method)?;

                            let interface_name = ni.interface_name.clone();
                            let recv_msg_id = random_recv_msg_id();
                            let recv_msg = RRequest {
                                interface_name: interface_name.clone(),
                                id: recv_msg_id,
                                filters,
                                created: Instant::now(),
                                elapsed: timeout,
                            };
                            let send_msg = SRequest {
                                interface_name: interface_name.clone(),
                                dst_mac,
                                src_mac,
                                eth_payload: buff.clone(),
                                eth_type: EtherTypes::Ipv6,
                                retransmit: retried,
                            };

                            if let Err(e) = push_rd.send(recv_msg) {
                                error!("send scan recv msg error: {}", e);
                            }
                            if let Err(e) = push_sd.send(send_msg) {
                                error!("send scan packet error: {}", e);
                            }

                            status.retried = retried + 1;
                            status.id = recv_msg_id;
                            tmp_hm.insert(dst_port, status);
                            all_done = false;
                        }
                    }
                    scan_status_clone.insert(ni, tmp_hm);
                }
            }
        }

        println!(
            "send all packet: {:.2}s",
            start_eval.elapsed().as_secs_f32()
        );

        if all_done {
            break;
        }

        let mut responses = Vec::new();
        let start_recv = Instant::now();
        let timeout_5ms = Duration::from_millis(5);
        loop {
            if start_recv.elapsed() > timeout {
                break;
            }
            match get_response.recv_timeout(timeout_5ms) {
                Ok(recv_response) => {
                    responses.push(recv_response);
                }
                Err(_e) => {
                    // timeout error is expected
                    continue;
                }
            };
        }

        scan_status = scan_status_clone.clone();
        for response in &responses {
            for (ni, hm) in &scan_status {
                let mut tmp_hm = scan_status[&ni].clone();
                for (&dst_port, status) in hm {
                    if response.id == status.id {
                        let mut status = status.clone();
                        status.recved = true;
                        tmp_hm.insert(dst_port, status);

                        let port_status = parse_response(response.data.clone(), method)?;
                        let report = PortReport {
                            addr: ni.inferred_dst_addr,
                            addr_origin: ni.dst_addr,
                            port: dst_port,
                            status: port_status,
                            cost: response.rtt,
                            cached: ni.cached,
                        };
                        reports.push(report);
                    }
                }
                scan_status_clone.insert(ni.clone(), tmp_hm);
            }
        }
        scan_status = scan_status_clone.clone();
        println!(
            "recv all packet: {:.2}s",
            start_eval.elapsed().as_secs_f32()
        );
    }
    port_scans.finish(reports);
    Ok(port_scans)
}

#[cfg(feature = "scan")]
fn scan_raw(
    net_info: NetInfo,
    method: ScanMethod,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<PortScan, PistolError> {
    let mut port_scan = PortScan::new(max_retries);
    if !net_info.valid {
        port_scan.finish(None);
        return Ok(port_scan);
    }

    let dst_mac = net_info.inferred_dst_mac;
    let dst_addr = net_info.inferred_dst_addr;
    let src_mac = net_info.inferred_src_mac;
    let addr_origin = net_info.dst_addr;
    let src_port = match net_info.src_port {
        Some(s) => s,
        None => random_port(),
    };

    let dst_port = if net_info.dst_ports.len() > 0 {
        net_info.dst_ports[0]
    } else {
        return Err(PistolError::NoDstPortSpecified);
    };

    // dst_addr may change during the processing.
    // It is only used here to determine whether the target is ipv4 or ipv6.
    // The real dst_addr is inferred from infer_addr.
    let cached = net_info.cached;
    for _ in 0..max_retries {
        let recv_msg_id = random_recv_msg_id();
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                let src_ipv4 = match net_info.inferred_src_addr {
                    IpAddr::V4(s) => s,
                    _ => {
                        return Err(PistolError::AttackAddressNotMatch {
                            addr: net_info.inferred_src_addr,
                        });
                    }
                };
                let (buff, filters) =
                    build_scan_buff(dst_ipv4, dst_port, src_ipv4, src_port, method)?;

                let interface_name = net_info.interface_name.clone();
                let recv_msg = RRequest {
                    interface_name: interface_name.clone(),
                    id: recv_msg_id,
                    filters,
                    created: Instant::now(),
                    elapsed: timeout,
                };
                let send_msg = SRequest {
                    interface_name: interface_name.clone(),
                    dst_mac,
                    src_mac,
                    eth_payload: buff.clone(),
                    eth_type: EtherTypes::Ipv4,
                    retransmit: 1,
                };
                if let Err(e) = push_rd.send(recv_msg) {
                    error!("send scan recv msg error: {}", e);
                }
                if let Err(e) = push_sd.send(send_msg) {
                    error!("send scan packet error: {}", e);
                }
            }
            IpAddr::V6(dst_ipv6) => {
                let src_ipv6 = match net_info.inferred_src_addr {
                    IpAddr::V6(s) => s,
                    _ => {
                        return Err(PistolError::AttackAddressNotMatch {
                            addr: net_info.inferred_src_addr,
                        });
                    }
                };
                let (buff, filters) =
                    build_scan_buff6(dst_ipv6, dst_port, src_ipv6, src_port, method)?;

                let interface_name = net_info.interface_name.clone();
                let recv_msg = RRequest {
                    interface_name: interface_name.clone(),
                    id: recv_msg_id,
                    filters,
                    created: Instant::now(),
                    elapsed: timeout,
                };
                let send_msg = SRequest {
                    interface_name: interface_name.clone(),
                    dst_mac,
                    src_mac,
                    eth_payload: buff.clone(),
                    eth_type: EtherTypes::Ipv4,
                    retransmit: 1,
                };
                if let Err(e) = push_rd.send(recv_msg) {
                    error!("send scan recv msg error: {}", e);
                }
                if let Err(e) = push_sd.send(send_msg) {
                    error!("send scan packet error: {}", e);
                }
            }
        }

        match get_response.recv_timeout(timeout) {
            Ok(r) => {
                if r.id == recv_msg_id && r.data.len() > 0 {
                    let port_status = parse_response(r.data.clone(), method)?;
                    let report = PortReport {
                        addr: dst_addr,
                        addr_origin,
                        port: dst_port,
                        status: port_status,
                        cost: r.rtt,
                        cached,
                    };
                    port_scan.finish(Some(report));
                    return Ok(port_scan);
                }
            }
            Err(_e) => (),
        }
    }
    port_scan.finish(None);
    Ok(port_scan)
}

#[cfg(any(feature = "scan", feature = "ping"))]
pub fn tcp_syn_scan(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<PortScans, PistolError> {
    scan(
        net_infos,
        ScanMethod::Syn,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

/// TCP SYN Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_syn_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<PortScan, PistolError> {
    scan_raw(
        net_info,
        ScanMethod::Syn,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

#[cfg(feature = "scan")]
pub fn tcp_fin_scan(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<PortScans, PistolError> {
    scan(
        net_infos,
        ScanMethod::Fin,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

/// TCP FIN Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_fin_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<PortScan, PistolError> {
    scan_raw(
        net_info,
        ScanMethod::Fin,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

#[cfg(feature = "scan")]
pub fn tcp_ack_scan(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<PortScans, PistolError> {
    scan(
        net_infos,
        ScanMethod::Ack,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

/// TCP ACK Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_ack_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<PortScan, PistolError> {
    scan_raw(
        net_info,
        ScanMethod::Ack,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

#[cfg(feature = "scan")]
pub fn tcp_null_scan(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<PortScans, PistolError> {
    scan(
        net_infos,
        ScanMethod::Null,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

/// TCP Null Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_null_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<PortScan, PistolError> {
    scan_raw(
        net_info,
        ScanMethod::Null,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

#[cfg(feature = "scan")]
pub fn tcp_xmas_scan(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<PortScans, PistolError> {
    scan(
        net_infos,
        ScanMethod::Xmas,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

/// TCP Xmas Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_xmas_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<PortScan, PistolError> {
    scan_raw(
        net_info,
        ScanMethod::Xmas,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

#[cfg(feature = "scan")]
pub fn tcp_window_scan(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<PortScans, PistolError> {
    scan(
        net_infos,
        ScanMethod::Window,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

/// TCP Window Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_window_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<PortScan, PistolError> {
    scan_raw(
        net_info,
        ScanMethod::Window,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

#[cfg(feature = "scan")]
pub fn tcp_maimon_scan(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<PortScans, PistolError> {
    scan(
        net_infos,
        ScanMethod::Maimon,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

/// TCP Maimon Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_maimon_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<PortScan, PistolError> {
    scan_raw(
        net_info,
        ScanMethod::Maimon,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

#[cfg(feature = "scan")]
pub fn tcp_connect_scan(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    let mut port_scans = PortScans::new(max_retries);
    let reports = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    for ni in &net_infos {
        let dst_addr = ni.dst_addr;
        let dst_ports = ni.dst_ports.clone();
        let addr_origin = ni.dst_addr;
        let cached = false;
        for dst_port in dst_ports {
            let reports = reports.clone();
            let h = thread::spawn(move || {
                for i in 0..max_retries {
                    match tcp::send_connect_scan_packet(dst_addr, dst_port, timeout) {
                        Ok((port_status, rtt)) => {
                            if port_status == PortStatus::Open || i == max_retries - 1 {
                                let report = PortReport {
                                    addr: dst_addr,
                                    addr_origin,
                                    port: dst_port,
                                    status: port_status,
                                    cost: rtt,
                                    cached,
                                };

                                if let Ok(mut reports) = reports.lock() {
                                    (*reports).push(report);
                                }
                                break;
                            }
                        }
                        Err(e) => {
                            error!("tcp connect scan error: {}", e);
                        }
                    }
                }
            });
            handles.push(h);
        }
    }

    for h in handles {
        if let Err(e) = h.join() {
            error!("tcp connect scan thread join error: {:?}", e);
        }
    }

    let reports = reports
        .lock()
        .map_err(|e| PistolError::LockVarFailed { e: e.to_string() })?;
    port_scans.finish((*reports).clone());
    Ok(port_scans)
}

/// TCP connect() Scan, raw version.
#[cfg(feature = "scan")]
pub fn tcp_connect_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    let mut port_scan = PortScan::new(max_retries);
    if net_info.dst_ports.len() == 0 {
        return Err(PistolError::NoDstPortSpecified);
    }

    let dst_addr = net_info.dst_addr;
    let dst_port = net_info.dst_ports[0];
    let addr_origin = net_info.dst_addr;
    let cached = false;

    for i in 0..max_retries {
        let (port_status, rtt) = tcp::send_connect_scan_packet(dst_addr, dst_port, timeout)?;
        if port_status == PortStatus::Open || i == max_retries - 1 {
            let report = PortReport {
                addr: addr_origin,
                addr_origin,
                port: dst_port,
                status: port_status,
                cost: rtt,
                cached,
            };
            port_scan.finish(Some(report));
            return Ok(port_scan);
        }
    }

    let report = PortReport {
        addr: addr_origin,
        addr_origin,
        port: dst_port,
        status: PortStatus::Closed,
        cost: timeout,
        cached,
    };
    port_scan.finish(Some(report));
    Ok(port_scan)
}

#[cfg(feature = "scan")]
pub fn udp_scan(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<PortScans, PistolError> {
    scan(
        net_infos,
        ScanMethod::Udp,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}

/// UDP Scan, raw version.
#[cfg(feature = "scan")]
pub fn udp_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
    push_rd: Sender<RRequest>,
    push_sd: Sender<SRequest>,
    get_response: Receiver<RResponse>,
) -> Result<PortScan, PistolError> {
    scan_raw(
        net_info,
        ScanMethod::Udp,
        timeout,
        max_retries,
        push_rd,
        push_sd,
        get_response,
    )
}
