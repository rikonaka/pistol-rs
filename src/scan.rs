/* Scan */
use bitcode;
use chrono::DateTime;
use chrono::Local;
use pnet::datalink::NetworkInterface;
use pnet::datalink::interfaces;
use prettytable::Cell;
use prettytable::Row;
use prettytable::Table;
use prettytable::row;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use subnetwork::Ipv6AddrExt;
use tracing::error;

use pnet::datalink::MacAddr;
use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::icmpv6::ndp::NeighborAdvertPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::debug;

pub(crate) mod arp;
pub(crate) mod ndp_ns;
pub(crate) mod ndp_rs;
pub(crate) mod tcp;
pub(crate) mod tcp6;
pub(crate) mod udp;
pub(crate) mod udp6;

use crate::LoopStates;
use crate::NetInfo;
use crate::PacketFilter;
use crate::PistolStream;
use crate::SendPacketInput;
use crate::Target;
use crate::error::PistolError;
use crate::layer::ipv6_multicast_mac;
use crate::scan::arp::build_arp_scan_buff;
use crate::scan::ndp_ns::build_ndp_ns_scan_packet;
use crate::update_neighbor_cache;
use crate::utils::random_port;
use crate::utils::time_to_string;

#[derive(Debug, Clone)]
pub struct MacReport {
    pub addr: IpAddr,
    pub mac: Option<MacAddr>,
    /// Productions organization name.
    pub oui: String,
    /// The number of retries for this target, not all.
    pub retries: usize,
}

#[derive(Debug, Clone)]
pub struct MacScans {
    pub mac_reports: Vec<MacReport>,
    pub start_time: DateTime<Local>,
    pub finish_time: DateTime<Local>,
    max_retries: usize,
}

impl fmt::Display for MacScans {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new(&format!("Mac Scans (max_retries:{})", self.max_retries))
                .style_spec("c")
                .with_hspan(5),
        ]));

        table.add_row(row![c -> "seq", c -> "addr", c -> "mac", c -> "oui", c-> "retries"]);

        // sorted the results
        let mut btm_addr: BTreeMap<IpAddr, MacReport> = BTreeMap::new();
        for report in &self.mac_reports {
            btm_addr.insert(report.addr, report.clone());
        }

        let mut alive_hosts = 0;
        let mut i = 1;
        for (_addr, report) in btm_addr {
            let rtt_str = format!("{}", report.retries);

            match report.mac {
                Some(mac) => {
                    table.add_row(
                        row![c -> i, c -> report.addr, c -> mac, c -> report.oui, c -> rtt_str],
                    );
                    i += 1;
                    alive_hosts += 1;
                }
                None => (),
            }
        }

        let total_cost = self.finish_time - self.start_time;
        let total_cost_str = time_to_string(Duration::from_secs_f32(total_cost.as_seconds_f32()));
        let summary = format!(
            "total cost: {}, alive hosts: {}",
            total_cost_str, alive_hosts
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(5)]));

        write!(f, "{}", table)
    }
}

impl MacScans {
    pub(crate) fn new(max_retries: usize) -> MacScans {
        MacScans {
            mac_reports: Vec::new(),
            start_time: Local::now(),
            finish_time: Local::now(),
            max_retries,
        }
    }
    pub(crate) fn finish(&mut self, mac_reports: Vec<MacReport>) {
        self.finish_time = Local::now();
        self.mac_reports = mac_reports;
    }
}

fn loopback_interface() -> Result<NetworkInterface, PistolError> {
    for interface in interfaces() {
        if interface.is_loopback() {
            return Ok(interface);
        }
    }
    Err(PistolError::CanNotFoundLoopbackInterface)
}

/// Find the network interface that can reach the destination address.
fn find_interface(dst_addr: IpAddr) -> Result<NetworkInterface, PistolError> {
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

/// Find the source address that can reach the destination address,
/// and it must be an address of the local machine.
fn find_src_addr(dst_addr: IpAddr) -> Result<IpAddr, PistolError> {
    for n in interfaces() {
        for ipn in &n.ips {
            if ipn.contains(dst_addr) {
                return Ok(ipn.ip());
            }
        }
    }
    Err(PistolError::CanNotFoundSrcAddress)
}

pub(crate) fn arp_scan_raw(
    dst_ipv4: Ipv4Addr,
    timeout: Duration,
    max_retries: usize,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    let start = Instant::now();
    let mut stream = PistolStream::new();
    stream.init(Some(String::from("arp")))?;

    let interface = find_interface(dst_ipv4.into())?;
    if interface.is_loopback() {
        return Ok((None, Duration::ZERO));
    }

    let if_name = interface.name;
    // broadcast mac address
    let dst_mac = MacAddr::broadcast();
    let src_mac = interface.mac.ok_or(PistolError::CanNotFoundSrcMacAddress)?;
    let src_ipv4 = match find_src_addr(dst_ipv4.into())? {
        IpAddr::V4(s) => s,
        _ => return Err(PistolError::CanNotFoundSrcAddress),
    };

    debug!(
        "use interface {} and src ipv4 {}",
        &if_name, src_ipv4
    );
    let (arp_buff, filters) = build_arp_scan_buff(dst_ipv4, src_mac, src_ipv4)?;
    let send_packet_input = SendPacketInput {
        dst_mac,
        src_mac,
        l3_payload: arp_buff.clone(),
        eth_type: EtherTypes::Arp,
        if_name: if_name.clone(),
        retransmit: 1,
    };

    for _ in 0..max_retries {
        stream.send_packet(send_packet_input.clone())?;

        let response = stream.recv_packet(timeout)?;

        for r in &response {
            for f in &filters {
                if f.check(r) {
                    match parse_mac_scan_response(r) {
                        Some((addr, mac)) => {
                            update_neighbor_cache(addr, mac)?;
                            let cost = start.elapsed();
                            return Ok((Some(mac), cost));
                        }
                        None => {
                            let cost = start.elapsed();
                            return Ok((None, cost));
                        }
                    }
                }
            }
        }
    }
    Ok((None, start.elapsed()))
}

fn get_arp_scan_buff(
    dst_ipv4: Ipv4Addr,
) -> Result<(SendPacketInput, Vec<Arc<PacketFilter>>), PistolError> {
    let interface = find_interface(dst_ipv4.into())?;

    let if_name = interface.name.clone();
    // broadcast mac address
    let dst_mac = MacAddr::broadcast();
    let src_mac = interface.mac.ok_or(PistolError::CanNotFoundSrcMacAddress)?;
    let src_ipv4 = match find_src_addr(dst_ipv4.into())? {
        IpAddr::V4(s) => s,
        _ => return Err(PistolError::CanNotFoundSrcAddress),
    };

    debug!("use interface {} and src ipv4 {}", if_name, src_ipv4);
    // only send here
    let (arp_buff, filters) = build_arp_scan_buff(dst_ipv4, src_mac, src_ipv4)?;

    let send_packet_input = SendPacketInput {
        dst_mac,
        src_mac,
        l3_payload: arp_buff.clone(),
        eth_type: EtherTypes::Arp,
        if_name: if_name.clone(),
        retransmit: 1,
    };

    Ok((send_packet_input, filters))
}

pub(crate) fn ndp_ns_scan_raw(
    dst_ipv6: Ipv6Addr,
    timeout: Duration,
    max_retries: usize,
) -> Result<(Option<MacAddr>, Duration), PistolError> {
    let start = Instant::now();
    let mut stream = PistolStream::new();
    stream.init(Some(String::from("icmp6")))?;

    let interface = find_interface(dst_ipv6.into())?;
    if interface.is_loopback() {
        return Ok((None, Duration::ZERO));
    }

    let if_name = interface.name;
    let src_mac = interface.mac.ok_or(PistolError::CanNotFoundSrcMacAddress)?;

    let dst_ipv6_ext: Ipv6AddrExt = dst_ipv6.into();
    let dst_ipv6 = dst_ipv6_ext.link_multicast();
    let dst_mac = ipv6_multicast_mac(dst_ipv6);
    let src_ipv6 = match find_src_addr(dst_ipv6.into())? {
        IpAddr::V6(s) => s,
        _ => return Err(PistolError::CanNotFoundSrcAddress),
    };

    debug!(
        "use interface {} and src ipv6 {}",
        &if_name, src_ipv6
    );
    let (ndp_ns_buff, filters) = build_ndp_ns_scan_packet(dst_ipv6, src_mac, src_ipv6)?;
    let send_packet_input = SendPacketInput {
        dst_mac,
        src_mac,
        l3_payload: ndp_ns_buff.clone(),
        eth_type: EtherTypes::Ipv6,
        if_name: if_name.clone(),
        retransmit: 1,
    };

    for _ in 0..max_retries {
        stream.send_packet(send_packet_input.clone())?;

        let response = stream.recv_packet(timeout)?;

        for r in &response {
            for f in &filters {
                if f.check(r) {
                    match parse_mac_scan_response(r) {
                        Some((addr, mac)) => {
                            update_neighbor_cache(addr, mac)?;
                            let cost = start.elapsed();
                            return Ok((Some(mac), cost));
                        }
                        None => {
                            let cost = start.elapsed();
                            return Ok((None, cost));
                        }
                    }
                }
            }
        }
    }

    Ok((None, start.elapsed()))
}

pub(crate) fn get_ndp_ns_scan_buff(
    dst_ipv6: Ipv6Addr,
) -> Result<(SendPacketInput, Vec<Arc<PacketFilter>>), PistolError> {
    let interface = find_interface(dst_ipv6.into())?;

    let if_name = interface.name.clone();
    let src_mac = interface.mac.ok_or(PistolError::CanNotFoundSrcMacAddress)?;

    let dst_ipv6_ext: Ipv6AddrExt = dst_ipv6.into();
    let dst_ipv6 = dst_ipv6_ext.link_multicast();
    let dst_mac = ipv6_multicast_mac(dst_ipv6);

    let mut src_ipv6 = None;
    for ipn in &interface.ips {
        if ipn.contains(dst_ipv6.into()) {
            if let IpAddr::V6(src) = ipn.ip() {
                src_ipv6 = Some(src);
            }
            break;
        }
    }
    let src_ipv6 = src_ipv6.ok_or(PistolError::CanNotFoundSrcAddress)?;

    debug!("use interface {} and src ipv6 {}", interface.name, src_ipv6);
    let (ndp_ns_buff, filters) = build_ndp_ns_scan_packet(dst_ipv6, src_mac, src_ipv6)?;

    let send_packet_input = SendPacketInput {
        dst_mac,
        src_mac,
        l3_payload: ndp_ns_buff.clone(),
        eth_type: EtherTypes::Ipv6,
        if_name: if_name.clone(),
        retransmit: 1,
    };

    Ok((send_packet_input, filters))
}

pub(crate) fn parse_mac_scan_response(eth_response: &[u8]) -> Option<(IpAddr, MacAddr)> {
    if eth_response.len() == 0 {
        return None;
    }

    let eth_packet = match EthernetPacket::new(eth_response) {
        Some(p) => p,
        None => return None,
    };

    match eth_packet.get_ethertype() {
        EtherTypes::Arp => {
            // arp on ipv4
            let arp_packet = match ArpPacket::new(eth_packet.payload()) {
                Some(p) => p,
                None => return None,
            };

            let mac = arp_packet.get_sender_hw_addr();
            let addr = arp_packet.get_sender_proto_addr();
            return Some((addr.into(), mac));
        }
        EtherTypes::Ipv6 => {
            // ndp ns on ipv6
            let ipv6_packet = match Ipv6Packet::new(eth_packet.payload()) {
                Some(p) => p,
                None => return None,
            };
            let addr = ipv6_packet.get_source();
            match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Icmpv6 => {
                    let icmpv6_packet = match Icmpv6Packet::new(ipv6_packet.payload()) {
                        Some(p) => p,
                        None => return None,
                    };
                    match icmpv6_packet.get_icmpv6_type() {
                        Icmpv6Types::NeighborAdvert => {
                            let na_packet = match NeighborAdvertPacket::new(ipv6_packet.payload()) {
                                Some(p) => p,
                                None => return None,
                            };
                            for o in na_packet.get_options() {
                                if o.data.len() >= 6 {
                                    let mac = MacAddr::new(
                                        o.data[0], o.data[1], o.data[2], o.data[3], o.data[4],
                                        o.data[5],
                                    );
                                    return Some((addr.into(), mac));
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
                _ => {
                    debug!(
                        "skip non-icmpv6 packet with next header {:?}",
                        ipv6_packet.get_next_header()
                    );
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

    None
}

fn get_nmap_mac_prefixes() -> Result<HashMap<String, String>, PistolError> {
    let nmap_mac_prefixes_bytes = include_bytes!("./db/nmap-mac-prefixes.bin");
    let nmap_mac_prefixes: HashMap<String, String> = bitcode::deserialize(nmap_mac_prefixes_bytes)?;
    Ok(nmap_mac_prefixes)
}

#[derive(Debug, Clone, Copy)]
struct MacScanState {
    addr: IpAddr,
    retries: usize,
    data_recved: bool,
}

pub(crate) fn mac_scan(
    targets: &[Target],
    timeout: Duration,
    max_retries: usize,
) -> Result<MacScans, PistolError> {
    let mut stream = PistolStream::new();
    stream.init(Some(String::from("arp or icmp6")))?;

    let mut rets = MacScans::new(max_retries);
    let mut loop_states = LoopStates::default();
    for t in targets {
        let dst_addr = t.addr;
        let dst_port = 0;
        let state = MacScanState {
            addr: dst_addr,
            retries: 0,
            data_recved: false,
        };
        loop_states.insert_ip_port(dst_addr, dst_port, state);
    }

    let mut mac_scan_rets = HashMap::new();
    let mut all_filters = Vec::new();
    loop {
        let mut all_done = true;
        for (_key, state) in &mut loop_states {
            if state.retries < max_retries && !state.data_recved {
                let dst_addr = state.addr;
                match dst_addr {
                    IpAddr::V4(dst_ipv4) => {
                        debug!(
                            "arp scan packets to {}: #{}/{}",
                            dst_ipv4,
                            state.retries + 1,
                            max_retries
                        );
                        let (spi, filters) = get_arp_scan_buff(dst_ipv4)?;
                        all_filters.extend(filters);
                        stream.send_packet(spi)?;

                        state.data_recved = false;
                        state.retries += 1;
                        all_done = false;
                    }
                    IpAddr::V6(dst_ipv6) => {
                        debug!(
                            "ndp_ns scan packets to {}: #{}/{}",
                            dst_ipv6,
                            state.retries + 1,
                            max_retries
                        );
                        // retry to send ndp_ns scan packet and recv response
                        let (spi, filters) = get_ndp_ns_scan_buff(dst_ipv6)?;
                        all_filters.extend(filters);
                        stream.send_packet(spi)?;

                        state.data_recved = false;
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
                if f.check(r) {
                    match parse_mac_scan_response(r) {
                        Some((addr, mac)) => {
                            for (_key, state) in &mut loop_states {
                                if state.addr == addr {
                                    state.data_recved = true;
                                    let retries = state.retries;
                                    mac_scan_rets.insert(addr, (mac, retries));
                                    update_neighbor_cache(addr, mac)?;
                                    break;
                                }
                            }
                        }
                        None => (),
                    }
                }
            }
        }
    }

    let nmap_mac_prefixes = get_nmap_mac_prefixes()?;
    let mut mac_scan_reports = Vec::new();
    for (target_addr, (target_mac, retries)) in mac_scan_rets {
        let mac_prefix = format!(
            "{:02X}{:02X}{:02X}",
            target_mac.0, target_mac.1, target_mac.2
        );
        // println!("{}", mac_prefix);
        let target_oui = match nmap_mac_prefixes.get(&mac_prefix) {
            Some(oui) => oui.to_owned(),
            None => String::from("unknown"),
        };

        let mr = MacReport {
            addr: target_addr,
            mac: Some(target_mac),
            oui: target_oui,
            retries,
        };
        mac_scan_reports.push(mr);
    }
    rets.finish(mac_scan_reports);
    Ok(rets)
}

/// Remove connect and idle scan from here.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ScanMethod {
    Syn,
    Fin,
    Ack,
    Null,
    Xmas,
    Window,
    Maimon,
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

#[derive(Debug, Clone, Copy)]
pub struct PortReport {
    pub addr: IpAddr,
    pub origin_addr: IpAddr,
    pub port: u16,
    pub status: PortStatus,
    pub cached: bool,
    pub retries: usize,
}

impl PortReport {
    pub fn is_open(&self) -> bool {
        self.status == PortStatus::Open
    }
}

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

impl fmt::Display for PortScan {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Port Scan").style_spec("c").with_hspan(4),
        ]));

        table.add_row(row![c -> "addr", c -> "port", c-> "status", c -> "retries"]);

        match self.port_report {
            Some(report) => {
                let addr_str = format!("{}", report.origin_addr);
                let status_str = format!("{}", report.status);
                let time_cost_str = format!("{}", report.retries);

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

impl PortScans {
    pub fn as_str(&self, hide_closed: bool) -> String {
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Port Scans").style_spec("c").with_hspan(5),
        ]));

        table.add_row(row![c -> "id", c -> "addr", c -> "port", c-> "status", c -> "retries"]);

        // sorted the resutls
        let mut btm_addr: BTreeMap<IpAddr, BTreeMap<u16, PortReport>> = BTreeMap::new();
        for report in &self.port_reports {
            if report.status == PortStatus::Closed && hide_closed {
                continue;
            }
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
                let addr_str = format!("{}", report.origin_addr);
                let status_str = format!("{}", report.status);
                let retries_str = format!("{}", report.retries);
                table.add_row(
                    row![c -> i, c -> addr_str, c -> report.port, c -> status_str, c -> retries_str],
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
        let layer2_cost_str = time_to_string(self.layer2_cost);
        let summary2 = format!(
            "layer2 cost: {}, total cost: {}, open ports: {}",
            layer2_cost_str, total_cost_str, open_ports_num
        );
        let summary3 =
            format!("l2c means layer2 mac address from cache, r1 means retry 1 time, and so on.");
        let summary = format!("{}\n{}\n{}", summary1, summary2, summary3);
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(5)]));

        table.to_string()
    }
}

impl fmt::Display for PortScans {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str(false))
    }
}

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
}

fn build_scan_buff(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    if_name: String,
    method: ScanMethod,
) -> Result<(SendPacketInput, Vec<Arc<PacketFilter>>), PistolError> {
    // The connect scan and idle scan need to send more than one packets,
    // so we put them other functions instead of here.
    let ret = match method {
        ScanMethod::Syn => tcp::build_syn_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port),
        ScanMethod::Fin => tcp::build_fin_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port),
        ScanMethod::Ack => tcp::build_ack_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port),
        ScanMethod::Null => tcp::build_null_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port),
        ScanMethod::Xmas => tcp::build_xmas_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port),
        ScanMethod::Window => tcp::build_window_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port),
        ScanMethod::Maimon => tcp::build_maimon_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port),
        ScanMethod::Udp => udp::build_udp_scan_packet(dst_ipv4, dst_port, src_ipv4, src_port),
    };

    let (buff, filters) = ret?;
    let send_packet_input = SendPacketInput {
        dst_mac,
        src_mac,
        l3_payload: buff.clone(),
        eth_type: EtherTypes::Ipv4,
        if_name,
        retransmit: 1,
    };

    Ok((send_packet_input, filters))
}

fn build_scan_buff6(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    if_name: String,
    method: ScanMethod,
) -> Result<(SendPacketInput, Vec<Arc<PacketFilter>>), PistolError> {
    let ret = match method {
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
    };

    let (buff, filters) = ret?;
    let send_packet_input = SendPacketInput {
        dst_mac,
        src_mac,
        l3_payload: buff.clone(),
        eth_type: EtherTypes::Ipv6,
        if_name: if_name.to_string(),
        retransmit: 1,
    };

    Ok((send_packet_input, filters))
}

fn parse_response(eth_response: &[u8], method: ScanMethod) -> Result<PortStatus, PistolError> {
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
    match EthernetPacket::new(eth_response) {
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
struct PortScanState {
    retries: usize,
    recved: bool,
    dst_mac: MacAddr,
    dst_addr: IpAddr,
    o_dst_addr: IpAddr,
    dst_port: u16,
    src_mac: MacAddr,
    src_addr: IpAddr,
    src_port: Option<u16>,
    if_name: String,
    cached: bool,
}

/// General scan function.
fn scan(
    net_infos: Vec<NetInfo>,
    method: ScanMethod,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    let mut stream = PistolStream::new();
    stream.init(Some(String::from("tcp or udp or icmp or icmp6")))?;

    let mut port_scans = PortScans::new(max_retries);
    let mut reports = Vec::new();

    let mut loop_states = LoopStates::default();
    for ni in net_infos {
        if ni.valid {
            for p in ni.dst_ports.clone() {
                let dst_mac = ni.inferred_dst_mac;
                let dst_addr = ni.inferred_dst_addr;
                let o_dst_addr = ni.dst_addr;
                let src_mac = ni.inferred_src_mac;
                let src_addr = ni.inferred_src_addr;
                let src_port = ni.src_port;
                let if_name = ni.if_name.clone();
                let cached = ni.cached;

                let state = PortScanState {
                    retries: 0,
                    recved: false,
                    dst_mac,
                    dst_addr,
                    o_dst_addr,
                    dst_port: p,
                    src_mac,
                    src_addr,
                    src_port,
                    if_name: if_name,
                    cached,
                };
                loop_states.insert_ip_port(ni.dst_addr, p, state);
            }
        }
    }

    loop {
        #[cfg(feature = "debug")]
        let all_probes = loop_states.data.len();
        #[cfg(feature = "debug")]
        let mut send_probes = 0;
        #[cfg(feature = "debug")]
        let send_start = Instant::now();

        let mut all_done = true;
        let mut all_filters = Vec::new();
        for (_key, state) in &mut loop_states {
            let dst_mac = state.dst_mac;
            let dst_addr = state.dst_addr;
            let dst_port = state.dst_port;
            let src_mac = state.src_mac;
            let src_port = match state.src_port {
                Some(s) => s,
                None => random_port(),
            };
            match dst_addr {
                IpAddr::V4(dst_ipv4) => {
                    let src_ipv4 = match state.src_addr {
                        IpAddr::V4(s) => s,
                        _ => {
                            return Err(PistolError::AttackAddressNotMatch {
                                addr: state.src_addr,
                            });
                        }
                    };
                    if state.retries < max_retries && !state.recved {
                        let if_name = state.if_name.clone();
                        let (spi, filters) = build_scan_buff(
                            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, if_name,
                            method,
                        )?;
                        all_filters.extend(filters);
                        stream.send_packet(spi)?;

                        state.retries += 1;
                        all_done = false;

                        #[cfg(feature = "debug")]
                        {
                            send_probes += 1;
                        }
                    }
                }
                IpAddr::V6(dst_ipv6) => {
                    let src_ipv6 = match state.src_addr {
                        IpAddr::V6(s) => s,
                        _ => {
                            return Err(PistolError::AttackAddressNotMatch {
                                addr: state.src_addr,
                            });
                        }
                    };
                    if state.retries < max_retries && !state.recved {
                        let if_name = state.if_name.clone();
                        let (spi, filters) = build_scan_buff6(
                            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, if_name,
                            method,
                        )?;
                        all_filters.extend(filters);
                        stream.send_packet(spi)?;

                        state.retries += 1;
                        all_done = false;

                        #[cfg(feature = "debug")]
                        {
                            send_probes += 1;
                        }
                    }
                }
            }
        }

        #[cfg(feature = "debug")]
        println!(
            "send {}/{} scan packets cost {:.2}s",
            send_probes,
            all_probes,
            send_start.elapsed().as_secs_f32()
        );

        if all_done {
            break;
        }

        #[cfg(feature = "debug")]
        let recv_start = Instant::now();
        let response = stream.recv_packet(timeout)?;

        #[cfg(feature = "debug")]
        {
            println!(
                "recv {} responses cost {:.2}s",
                response.len(),
                recv_start.elapsed().as_secs_f32()
            );
        }

        for r in &response {
            for f in &all_filters {
                if f.check(r) {
                    // if the f was TcpUdp filter
                    if let Some((addr, port)) = f.tcp_udp_ip_port() {
                        for (_key, state) in &mut loop_states {
                            if state.dst_addr == addr && state.dst_port == port {
                                state.recved = true;

                                let retries = state.retries;
                                let addr = state.dst_addr;
                                let origin_addr = state.o_dst_addr;
                                let port = state.dst_port;
                                let cached = state.cached;

                                let port_status = parse_response(r, method)?;
                                let report = PortReport {
                                    addr,
                                    origin_addr,
                                    port,
                                    status: port_status,
                                    cached,
                                    retries,
                                };
                                reports.push(report);
                                break;
                            }
                        }
                    } else if let Some(addr) = f.icmp_ip() {
                        for (_key, state) in &mut loop_states {
                            if state.dst_addr == addr {
                                state.recved = true;

                                let retries = state.retries;
                                let addr = state.dst_addr;
                                let origin_addr = state.o_dst_addr;
                                let port = state.dst_port;
                                let cached = state.cached;

                                let port_status = PortStatus::Unreachable;
                                let report = PortReport {
                                    addr,
                                    origin_addr,
                                    port,
                                    status: port_status,
                                    cached,
                                    retries,
                                };
                                reports.push(report);
                            }
                        }
                    }
                }
            }
        }
    }
    port_scans.finish(reports);
    Ok(port_scans)
}

fn scan_raw(
    net_info: NetInfo,
    method: ScanMethod,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    let mut stream = PistolStream::new();
    stream.init(Some(String::from("tcp or udp or icmp or icmp6")))?;

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
    let if_name = net_info.if_name.clone();
    let (spi, filters) = match dst_addr {
        IpAddr::V4(dst_ipv4) => {
            let src_ipv4 = match net_info.inferred_src_addr {
                IpAddr::V4(s) => s,
                _ => {
                    return Err(PistolError::AttackAddressNotMatch {
                        addr: net_info.inferred_src_addr,
                    });
                }
            };
            let (spi, filters) = build_scan_buff(
                dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, if_name, method,
            )?;
            (spi, filters)
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
            let (spi, filters) = build_scan_buff6(
                dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, if_name, method,
            )?;
            (spi, filters)
        }
    };

    for i in 0..max_retries {
        stream.send_packet(spi.clone())?;
        let response = stream.recv_packet(timeout)?;

        for r in &response {
            for f in &filters {
                if f.check(r) {
                    if let Some((addr, port)) = f.tcp_udp_ip_port() {
                        if addr == dst_addr && port == dst_port {
                            debug!("recv response from {}:{}", addr, port);
                            let port_status = parse_response(r, method)?;
                            let report = PortReport {
                                addr: dst_addr,
                                origin_addr: addr_origin,
                                port: dst_port,
                                status: port_status,
                                cached,
                                retries: i + 1,
                            };
                            port_scan.finish(Some(report));
                            return Ok(port_scan);
                        }
                    } else if let Some(addr) = f.icmp_ip() {
                        if addr == dst_addr {
                            debug!("recv icmp response from {}", addr);
                            let port_status = PortStatus::Unreachable;
                            let report = PortReport {
                                addr: dst_addr,
                                origin_addr: addr_origin,
                                port: dst_port,
                                status: port_status,
                                cached,
                                retries: i + 1,
                            };
                            port_scan.finish(Some(report));
                            return Ok(port_scan);
                        }
                    }
                }
            }
        }
    }
    port_scan.finish(None);
    Ok(port_scan)
}

pub(crate) fn tcp_syn_scan(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    scan(net_infos, ScanMethod::Syn, timeout, max_retries)
}

/// TCP SYN Scan, raw version.
pub(crate) fn tcp_syn_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(net_info, ScanMethod::Syn, timeout, max_retries)
}

pub(crate) fn tcp_fin_scan(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    scan(net_infos, ScanMethod::Fin, timeout, max_retries)
}

/// TCP FIN Scan, raw version.
pub(crate) fn tcp_fin_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(net_info, ScanMethod::Fin, timeout, max_retries)
}

pub(crate) fn tcp_ack_scan(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    scan(net_infos, ScanMethod::Ack, timeout, max_retries)
}

/// TCP ACK Scan, raw version.
pub(crate) fn tcp_ack_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(net_info, ScanMethod::Ack, timeout, max_retries)
}

pub(crate) fn tcp_null_scan(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    scan(net_infos, ScanMethod::Null, timeout, max_retries)
}

/// TCP Null Scan, raw version.
pub(crate) fn tcp_null_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(net_info, ScanMethod::Null, timeout, max_retries)
}

pub(crate) fn tcp_xmas_scan(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    scan(net_infos, ScanMethod::Xmas, timeout, max_retries)
}

/// TCP Xmas Scan, raw version.
pub(crate) fn tcp_xmas_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(net_info, ScanMethod::Xmas, timeout, max_retries)
}

pub(crate) fn tcp_window_scan(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    scan(net_infos, ScanMethod::Window, timeout, max_retries)
}

/// TCP Window Scan, raw version.
pub(crate) fn tcp_window_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(net_info, ScanMethod::Window, timeout, max_retries)
}

pub(crate) fn tcp_maimon_scan(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    scan(net_infos, ScanMethod::Maimon, timeout, max_retries)
}

/// TCP Maimon Scan, raw version.
pub(crate) fn tcp_maimon_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(net_info, ScanMethod::Maimon, timeout, max_retries)
}

pub(crate) fn tcp_connect_scan(
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
                for retries in 0..max_retries {
                    let ret = tcp::send_connect_scan_packet(dst_addr, dst_port, timeout);
                    match ret {
                        Ok(port_status) => {
                            if port_status == PortStatus::Open || retries == max_retries - 1 {
                                let report = PortReport {
                                    addr: dst_addr,
                                    origin_addr: addr_origin,
                                    port: dst_port,
                                    status: port_status,
                                    cached,
                                    retries: retries + 1,
                                };

                                if let Ok(mut reports) = reports.lock() {
                                    (*reports).push(report);
                                }
                                break;
                            }
                        }
                        Err(_e) => {
                            if retries == max_retries - 1 {
                                let port_status = PortStatus::Error;
                                let report = PortReport {
                                    addr: dst_addr,
                                    origin_addr: addr_origin,
                                    port: dst_port,
                                    status: port_status,
                                    cached,
                                    retries: retries + 1,
                                };

                                if let Ok(mut reports) = reports.lock() {
                                    (*reports).push(report);
                                }
                            }
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
pub(crate) fn tcp_connect_scan_raw(
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
        let ret = tcp::send_connect_scan_packet(dst_addr, dst_port, timeout);
        match ret {
            Ok(port_status) => {
                if port_status == PortStatus::Open || i == max_retries - 1 {
                    let report = PortReport {
                        addr: addr_origin,
                        origin_addr: addr_origin,
                        port: dst_port,
                        status: port_status,
                        cached,
                        retries: i + 1,
                    };
                    port_scan.finish(Some(report));
                    return Ok(port_scan);
                }
            }
            Err(_e) => {
                if i == max_retries - 1 {
                    let port_status = PortStatus::Error;
                    let report = PortReport {
                        addr: addr_origin,
                        origin_addr: addr_origin,
                        port: dst_port,
                        status: port_status,
                        cached,
                        retries: i + 1,
                    };
                    port_scan.finish(Some(report));
                    return Ok(port_scan);
                }
            }
        }
    }

    let report = PortReport {
        addr: addr_origin,
        origin_addr: addr_origin,
        port: dst_port,
        status: PortStatus::Closed,
        cached,
        retries: max_retries,
    };
    port_scan.finish(Some(report));
    Ok(port_scan)
}

pub(crate) fn udp_scan(
    net_infos: Vec<NetInfo>,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScans, PistolError> {
    scan(net_infos, ScanMethod::Udp, timeout, max_retries)
}

/// UDP Scan, raw version.
pub(crate) fn udp_scan_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(net_info, ScanMethod::Udp, timeout, max_retries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;
    use std::fs;
    fn parse_nmap_mac_prefixes<'a>() -> Result<HashMap<&'a str, &'a str>, PistolError> {
        let db_file = include_str!("./db/nmap-mac-prefixes");
        let mut lines = Vec::new();
        for line in db_file.lines() {
            lines.push(line);
        }

        let re = Regex::new(r"^(?P<prefix>[0-9A-F]+)\s(?P<oui>.+)")?;

        let mut ret = HashMap::new();
        for line in lines {
            if line.starts_with("#") {
                continue;
            }
            match re.captures(line) {
                Some(caps) => {
                    let prefix = caps.name("prefix").map_or("", |m| m.as_str());
                    let oui = caps.name("oui").map_or("", |m| m.as_str());

                    ret.insert(prefix, oui);
                }
                None => {
                    println!("nmap mac prefixes line: [{}] no match", line);
                }
            }
        }
        Ok(ret)
    }
    #[test]
    fn write_and_load_nmap_mac_prefixes() {
        let nmap_mac_prefixes_bin_path: &str = "./db/nmap-mac-prefixes";

        let parse_start = Instant::now();
        let st = parse_nmap_mac_prefixes().unwrap();
        // parse nmap-mac-prefixes: 0.27s
        println!(
            "parse nmap-mac-prefixes: {:.2}s",
            parse_start.elapsed().as_secs_f32()
        );
        let st_bytes = bitcode::serialize(&st).unwrap();
        fs::write(nmap_mac_prefixes_bin_path, st_bytes).unwrap();

        let load_start = Instant::now();
        match fs::read(nmap_mac_prefixes_bin_path) {
            Ok(bytes) => {
                let st_a: HashMap<String, String> = match bitcode::deserialize(&bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        debug!("failed to parse network cache from file: {}, delete it", e);
                        HashMap::new()
                    }
                };
                // lost cost: 0.03s, len: 49058
                println!(
                    "lost cost: {:.2}s, len: {}",
                    load_start.elapsed().as_secs_f32(),
                    st_a.len(),
                );
            }
            Err(e) => {
                error!("failed to read nmap-mac-prefixes.bin from file: {}", e);
            }
        };
    }
}
