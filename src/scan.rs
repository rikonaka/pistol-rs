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
use subnetwork::Ipv4AddrExt;
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
use crate::SendPacketParam;
use crate::SendSpeed;
use crate::SendWindow;
use crate::Target;
use crate::error::PistolError;
use crate::layer::ipv6_multicast_mac;
use crate::route::NeighborInfo;
use crate::scan::arp::build_arp_scan_buff;
use crate::scan::ndp_ns::build_ndp_ns_scan_packet;
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
            Cell::new("Mac Scans").style_spec("c").with_hspan(5),
        ]));

        table.add_row(row![c -> "seq", c -> "addr", c -> "mac", c -> "oui", c-> "retries"]);

        // sorted the results
        let mut btm_addr: BTreeMap<IpAddr, Vec<MacReport>> = BTreeMap::new();
        for report in &self.mac_reports {
            if btm_addr.contains_key(&report.addr) {
                if let Some(v) = btm_addr.get_mut(&report.addr) {
                    v.push(report.clone());
                }
            } else {
                btm_addr.insert(report.addr, vec![report.clone()]);
            }
        }

        let mut alive_hosts = 0;
        let mut i = 1;
        for (addr, reports) in btm_addr {
            for (ind, report) in reports.iter().enumerate() {
                let rtt_str = if ind == 0 {
                    format!("{}", report.retries)
                } else {
                    format!("{} (DUP-{})", report.retries, ind + 1)
                };

                match report.mac {
                    Some(mac) => {
                        table.add_row(
                            row![c -> i, c -> addr, c -> mac, c -> report.oui, c -> rtt_str],
                        );
                        i += 1;
                        alive_hosts += 1;
                    }
                    None => (),
                }
            }
        }

        let total_cost = self.finish_time - self.start_time;
        let total_cost_str = time_to_string(Duration::from_secs_f32(total_cost.as_seconds_f32()));
        let summary = format!(
            "total cost: {}, alive hosts: {}, max retries: {}",
            total_cost_str, alive_hosts, self.max_retries
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

/// Find the source address that can reach the destination address,
/// and it must be an address of the local machine.
fn find_src_addr(
    src_interface: &NetworkInterface,
    dst_addr: IpAddr,
) -> Result<IpAddr, PistolError> {
    struct IpAddrWithLip {
        ip: IpAddr,
        lip: u8,
    }

    let init_ip = match dst_addr {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };

    let mut lip_compare = IpAddrWithLip {
        ip: init_ip,
        lip: 0,
    };

    for ipn in &src_interface.ips {
        if (ipn.is_ipv4() && dst_addr.is_ipv4()) || (ipn.is_ipv6() && dst_addr.is_ipv6()) {
            let ip = ipn.ip();
            match ip {
                IpAddr::V4(i4) => {
                    if let IpAddr::V4(d4) = dst_addr {
                        if d4 == i4 {
                            // If the destination address is the same as the source address,
                            // we can directly return it.
                            return Ok(ip);
                        }
                        let s = Ipv4AddrExt::from(i4);
                        let lip = s.largest_identical_prefix(d4);
                        if lip > lip_compare.lip {
                            lip_compare.ip = ip;
                            lip_compare.lip = lip;
                        }
                    }
                }
                IpAddr::V6(i6) => {
                    if let IpAddr::V6(d6) = dst_addr {
                        if d6 == i6 {
                            return Ok(ip);
                        }
                        if d6.is_unicast_link_local() || d6.is_multicast() {
                            // For link-local or multicast ipv6 address,
                            // the source address must be a link-local address.
                            if !i6.is_unicast_link_local() {
                                continue;
                            }
                        }
                        let s = Ipv6AddrExt::from(i6);
                        let lip = s.largest_identical_prefix(d6);
                        if lip > lip_compare.lip {
                            lip_compare.ip = ip;
                            lip_compare.lip = lip;
                        }
                    }
                }
            }
        }
    }

    if lip_compare.ip.is_unspecified() {
        Err(PistolError::CanNotFoundSrcAddress)
    } else {
        Ok(lip_compare.ip)
    }
}

pub(crate) fn arp_scan_raw(
    dst_ipv4: Ipv4Addr,
    timeout: Duration,
    max_retries: usize,
) -> Result<(Vec<MacAddr>, Duration), PistolError> {
    let start = Instant::now();
    let mut stream = PistolStream::new();
    stream.init(Some(String::from("arp and arp[6:2] = 2")))?;

    let mut neighbor_output = NeighborInfo::new()?;
    let interface = neighbor_output.infer_interface(dst_ipv4.into())?;
    if interface.is_loopback() {
        return Ok((Vec::new(), Duration::ZERO));
    }

    let if_name = interface.name.clone();
    let src_ipv4 = match find_src_addr(&interface, dst_ipv4.into())? {
        IpAddr::V4(s) => s,
        _ => return Err(PistolError::CanNotFoundSrcAddress),
    };
    // broadcast mac address
    let dst_mac = MacAddr::broadcast();
    let src_mac = interface.mac.ok_or(PistolError::CanNotFoundSrcMacAddress)?;

    debug!("use interface {} and src ipv4 {}", &if_name, src_ipv4);
    let (arp_buff, filters) = build_arp_scan_buff(dst_ipv4, src_mac, src_ipv4)?;
    let spp = SendPacketParam {
        dst_mac,
        src_mac,
        l3_payload: arp_buff.clone(),
        eth_type: EtherTypes::Arp,
        if_name: if_name.clone(),
        retransmit: 1,
    };

    let mut all_done = false;
    let mut macs = Vec::new();
    for i in 0..max_retries {
        if all_done {
            break;
        }
        debug!(
            "send arp scan packet to {}, retry: #{}/{}",
            dst_ipv4,
            i + 1,
            max_retries
        );
        stream.send_packet(spp.clone())?;
        let response = stream.recv_packet(timeout)?;
        for r in &response {
            for f in &filters {
                if f.check(r) {
                    match parse_mac_scan_response(r) {
                        Some((addr, mac)) => {
                            if !macs.contains(&mac) {
                                macs.push(mac);
                                all_done = true;
                            }
                        }
                        None => (),
                    }
                    break;
                }
            }
        }
    }
    Ok((macs, start.elapsed()))
}

fn get_arp_scan_buff(
    dst_ipv4: Ipv4Addr,
    interface: NetworkInterface,
) -> Result<(SendPacketParam, Vec<Arc<PacketFilter>>), PistolError> {
    let if_name = interface.name.clone();
    // broadcast mac address
    let dst_mac = MacAddr::broadcast();
    let src_mac = interface.mac.ok_or(PistolError::CanNotFoundSrcMacAddress)?;

    let src_ipv4 = match find_src_addr(&interface, dst_ipv4.into())? {
        IpAddr::V4(s) => s,
        _ => return Err(PistolError::CanNotFoundSrcAddress),
    };

    debug!("use interface {} and src ipv4 {}", if_name, src_ipv4);
    // only send here
    let (arp_buff, filters) = build_arp_scan_buff(dst_ipv4, src_mac, src_ipv4)?;

    let spp = SendPacketParam {
        dst_mac,
        src_mac,
        l3_payload: arp_buff.clone(),
        eth_type: EtherTypes::Arp,
        if_name: if_name.clone(),
        retransmit: 1,
    };

    Ok((spp, filters))
}

pub(crate) fn ndp_ns_scan_raw(
    dst_ipv6: Ipv6Addr,
    timeout: Duration,
    max_retries: usize,
) -> Result<(Vec<MacAddr>, Duration), PistolError> {
    let start = Instant::now();
    let mut stream = PistolStream::new();
    stream.init(Some(String::from("icmp6 and ip6[40] = 136")))?;

    let mut neighbor_info = NeighborInfo::new()?;
    let interface = neighbor_info.infer_interface(dst_ipv6.into())?;
    if interface.is_loopback() {
        return Ok((Vec::new(), Duration::ZERO));
    }

    let if_name = interface.name.clone();
    let src_mac = interface.mac.ok_or(PistolError::CanNotFoundSrcMacAddress)?;
    let src_ipv6 = match find_src_addr(&interface, dst_ipv6.into())? {
        IpAddr::V6(s) => s,
        _ => return Err(PistolError::CanNotFoundSrcAddress),
    };

    let dst_mac = ipv6_multicast_mac(dst_ipv6);

    debug!("use interface {} and src ipv6 {}", &if_name, src_ipv6);
    let (ndp_ns_buff, filters) = build_ndp_ns_scan_packet(dst_ipv6, src_mac, src_ipv6)?;
    let spp = SendPacketParam {
        dst_mac,
        src_mac,
        l3_payload: ndp_ns_buff.clone(),
        eth_type: EtherTypes::Ipv6,
        if_name: if_name.clone(),
        retransmit: 1,
    };

    let mut all_done = false;
    let mut macs = Vec::new();
    for i in 0..max_retries {
        if all_done {
            break;
        }
        debug!(
            "send ndp ns scan packet to {}, retry: #{}/{}",
            dst_ipv6,
            i + 1,
            max_retries
        );
        stream.send_packet(spp.clone())?;
        let response = stream.recv_packet(timeout)?;
        for r in &response {
            for f in &filters {
                if f.check(r) {
                    match parse_mac_scan_response(r) {
                        Some((addr, mac)) => {
                            if !macs.contains(&mac) {
                                all_done = true;
                                macs.push(mac);
                            }
                        }
                        None => (),
                    }
                    break;
                }
            }
        }
    }

    Ok((macs, start.elapsed()))
}

pub(crate) fn get_ndp_ns_scan_buff(
    dst_ipv6: Ipv6Addr,
    interface: NetworkInterface,
) -> Result<(SendPacketParam, Vec<Arc<PacketFilter>>), PistolError> {
    let if_name = interface.name.clone();
    let src_mac = interface.mac.ok_or(PistolError::CanNotFoundSrcMacAddress)?;
    let src_ipv6 = match find_src_addr(&interface, dst_ipv6.into())? {
        IpAddr::V6(s) => s,
        _ => return Err(PistolError::CanNotFoundSrcAddress),
    };
    let dst_mac = ipv6_multicast_mac(dst_ipv6);

    debug!("use interface {} and src ipv6 {}", interface.name, src_ipv6);
    let (ndp_ns_buff, filters) = build_ndp_ns_scan_packet(dst_ipv6, src_mac, src_ipv6)?;

    let spp = SendPacketParam {
        dst_mac,
        src_mac,
        l3_payload: ndp_ns_buff.clone(),
        eth_type: EtherTypes::Ipv6,
        if_name: if_name.clone(),
        retransmit: 1,
    };

    Ok((spp, filters))
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
            if ipv6_packet.get_next_header() == IpNextHeaderProtocols::Icmpv6 {
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
            } else {
                debug!(
                    "skip non-icmpv6 packet with next header {:?}",
                    ipv6_packet.get_next_header()
                );
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

#[derive(Debug, Clone)]
struct MacScanState {
    dst_addr: IpAddr,
    interface: NetworkInterface,
    retries: usize,
    data_recved: bool,
}

pub(crate) fn mac_scan(
    targets: &[Target],
    timeout: Duration,
    max_retries: usize,
    speed: SendSpeed,
) -> Result<MacScans, PistolError> {
    let mut stream = PistolStream::new();
    stream.init(Some(String::from(
        "(arp and arp[6:2] = 2) or (icmp6 and ip6[40] = 136)",
    )))?;

    let mut neighbor_info = NeighborInfo::new()?;

    let mut rets = MacScans::new(max_retries);
    let mut loop_states = LoopStates::default();
    for t in targets {
        let dst_addr = t.dst_addr;
        let interface = neighbor_info.infer_interface(dst_addr)?;
        let dst_port = 0;
        let state = MacScanState {
            dst_addr,
            interface,
            retries: 0,
            data_recved: false,
        };
        loop_states.insert_ip_port(dst_addr, dst_port, state);
    }

    let mut window = SendWindow::new(speed);
    // Sometimes the same target may receive multiple mac responses,
    // so we use a Vec here to store the results of each target.
    let mut mac_scan_rets: HashMap<IpAddr, HashMap<MacAddr, usize>> = HashMap::new();
    let mut all_filters = Vec::new();
    loop {
        #[cfg(feature = "debug")]
        let send_start = Instant::now();

        let mut all_done = true;
        for (_key, state) in &mut loop_states {
            if state.retries < max_retries && !state.data_recved {
                let dst_addr = state.dst_addr;
                let interface = state.interface.clone();
                match dst_addr {
                    IpAddr::V4(dst_ipv4) => {
                        if window.check() {
                            break;
                        }

                        debug!(
                            "arp scan packets to {}: #{}/{}",
                            dst_ipv4,
                            state.retries + 1,
                            max_retries
                        );
                        let (spp, filters) = get_arp_scan_buff(dst_ipv4, interface)?;
                        all_filters.extend(filters);

                        stream.send_packet(spp)?;

                        state.data_recved = false;
                        state.retries += 1;
                        all_done = false;
                    }
                    IpAddr::V6(dst_ipv6) => {
                        if window.check() {
                            break;
                        }
                        debug!(
                            "ndp_ns scan packets to {}: #{}/{}",
                            dst_ipv6,
                            state.retries + 1,
                            max_retries
                        );
                        // retry to send ndp_ns scan packet and recv response
                        let (spp, filters) = get_ndp_ns_scan_buff(dst_ipv6, interface.clone())?;
                        all_filters.extend(filters);
                        stream.send_packet(spp)?;

                        state.data_recved = false;
                        state.retries += 1;
                        all_done = false;
                    }
                }
            }
        }

        #[cfg(feature = "debug")]
        println!(
            "send packets to {} targets, cost: {:.2}s",
            targets.len(),
            send_start.elapsed().as_secs_f32()
        );

        if all_done {
            break;
        }

        let recv_start = Instant::now();
        let response = stream.recv_packet(timeout)?;
        #[cfg(feature = "debug")]
        println!(
            "recv {} packets in mac scan, cost: {:.2}s",
            response.len(),
            recv_start.elapsed().as_secs_f32()
        );

        let mut matched_packets = 0;
        for r in &response {
            for f in &all_filters {
                if f.check_fast(r) {
                    matched_packets += 1;
                    match parse_mac_scan_response(r) {
                        Some((addr, mac)) => {
                            #[cfg(feature = "debug")]
                            println!("recv mac scan response from {}, mac: {}", addr, mac);
                            for (_key, state) in &mut loop_states {
                                if state.dst_addr == addr {
                                    state.data_recved = true;
                                    let retries = state.retries;
                                    match mac_scan_rets.get_mut(&addr) {
                                        Some(v) => {
                                            if let Some(r) = v.get_mut(&mac) {
                                                *r = retries;
                                            } else {
                                                v.insert(mac, retries);
                                            }
                                        }
                                        None => {
                                            let mut map = HashMap::new();
                                            map.insert(mac, retries);
                                            mac_scan_rets.insert(addr, map);
                                        }
                                    }

                                    break;
                                }
                            }
                        }
                        None => (),
                    }
                }
            }
        }

        window.update(matched_packets);
    }

    let nmap_mac_prefixes = get_nmap_mac_prefixes()?;
    let mut mac_scan_reports = Vec::new();
    for (target_addr, v) in mac_scan_rets {
        for (target_mac, retries) in v {
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
            "start at {} then finish at {}, max_retries: {}",
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
        let summary = format!("{}\n{}", summary1, summary2);
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
) -> Result<(SendPacketParam, Vec<Arc<PacketFilter>>), PistolError> {
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
    let spp = SendPacketParam {
        dst_mac,
        src_mac,
        l3_payload: buff.clone(),
        eth_type: EtherTypes::Ipv4,
        if_name,
        retransmit: 1,
    };

    Ok((spp, filters))
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
) -> Result<(SendPacketParam, Vec<Arc<PacketFilter>>), PistolError> {
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
    let spp = SendPacketParam {
        dst_mac,
        src_mac,
        l3_payload: buff.clone(),
        eth_type: EtherTypes::Ipv6,
        if_name: if_name.to_string(),
        retransmit: 1,
    };

    Ok((spp, filters))
}

fn parse_response(eth_response: &[u8], method: ScanMethod) -> Result<PortStatus, PistolError> {
    let parse_ipv4 = || -> Result<PortStatus, PistolError> {
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

struct PortScanState {
    retries: usize,
    recved: bool,
    net_info: NetInfo,
    dst_port: u16,
    src_port: Option<u16>,
    cached: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ScanTarget {
    pub net_info: NetInfo,
    pub dst_ports: Vec<u16>,
    pub src_port: Option<u16>,
}

/// General scan function.
fn scan(
    scan_targets: Vec<ScanTarget>,
    method: ScanMethod,
    timeout: Duration,
    max_retries: usize,
    filter: Option<String>,
    speed: SendSpeed,
) -> Result<PortScans, PistolError> {
    let mut stream = PistolStream::new();
    stream.init(filter)?;

    let mut port_scans = PortScans::new(max_retries);
    let mut reports = Vec::new();

    let mut loop_states = LoopStates::default();
    for st in scan_targets {
        let nt = st.net_info;
        if nt.valid {
            for dst_port in st.dst_ports {
                let if_name = nt.inferred_interface.name.clone();
                let cached = nt.cached;

                let state = PortScanState {
                    retries: 0,
                    recved: false,
                    net_info: nt.clone(),
                    dst_port,
                    src_port: st.src_port,
                    cached,
                };
                loop_states.insert_ip_port(nt.origin_dst_addr, dst_port, state);
            }
        }
    }

    debug!("start scan loop with {} targets", loop_states.len());

    let mut window = SendWindow::new(speed);
    let mut all_filters = Vec::new();
    loop {
        #[cfg(feature = "debug")]
        let send_start = Instant::now();

        let mut all_done = true;
        for (_key, state) in &mut loop_states {
            let net_info = &state.net_info;
            let dst_mac = net_info.inferred_dst_mac;
            let src_mac = net_info.inferred_src_mac;
            let dst_addr = net_info.inferred_dst_addr;
            let src_addr = net_info.inferred_src_addr;

            let dst_port = state.dst_port;
            let src_port = match state.src_port {
                Some(s) => s,
                None => random_port(),
            };

            match dst_addr {
                IpAddr::V4(dst_ipv4) => {
                    let src_ipv4 = match src_addr {
                        IpAddr::V4(s) => s,
                        _ => {
                            return Err(PistolError::AttackAddressNotMatch { addr: src_addr });
                        }
                    };

                    if state.retries < max_retries && !state.recved {
                        if window.check() {
                            break;
                        }

                        let if_name = net_info.inferred_interface.name.clone();
                        let (spp, filters) = build_scan_buff(
                            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, if_name,
                            method,
                        )?;
                        all_filters.extend(filters);
                        stream.send_packet(spp)?;

                        state.retries += 1;
                        all_done = false;
                    }
                }
                IpAddr::V6(dst_ipv6) => {
                    let src_ipv6 = match src_addr {
                        IpAddr::V6(s) => s,
                        _ => {
                            return Err(PistolError::AttackAddressNotMatch { addr: src_addr });
                        }
                    };
                    if state.retries < max_retries && !state.recved {
                        if window.check() {
                            break;
                        }
                        let if_name = net_info.inferred_interface.name.clone();
                        let (spp, filters) = build_scan_buff6(
                            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, if_name,
                            method,
                        )?;
                        all_filters.extend(filters);
                        stream.send_packet(spp)?;

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
        let parse_start = Instant::now();

        let mut matched_packets = 0;
        for r in &response {
            for f in &all_filters {
                if f.check_fast(r) {
                    matched_packets += 1;
                    debug!("filter {} matched", f.name());
                    if let Some((addr, port)) = f.tcp_udp_ip_port() {
                        if let Some(state) = loop_states.get_ip_port_mut(addr, port) {
                            state.recved = true;

                            let net_info = &state.net_info;
                            let retries = state.retries;
                            let addr = net_info.inferred_dst_addr;
                            let origin_addr = net_info.origin_dst_addr;
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
                    } else if let Some(addr) = f.icmp_ip() {
                        if let Some(state) = loop_states.get_ip_mut(addr) {
                            state.recved = true;

                            let net_info = &state.net_info;
                            let retries = state.retries;
                            let addr = net_info.inferred_dst_addr;
                            let origin_addr = net_info.origin_dst_addr;
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
                    break;
                }
            }
        }

        let speed = matched_packets as f64 / send_start.elapsed().as_secs_f64();
        debug!(
            "parse packets cost: {:.2}s, matched: {}, speed: {:.2} packets/s",
            parse_start.elapsed().as_secs_f32(),
            matched_packets,
            speed,
        );
        window.update(matched_packets);
    }
    port_scans.finish(reports);
    Ok(port_scans)
}

fn scan_raw(
    scan_target: ScanTarget,
    method: ScanMethod,
    timeout: Duration,
    max_retries: usize,
    filter: Option<String>,
) -> Result<PortScan, PistolError> {
    let mut stream = PistolStream::new();
    stream.init(filter)?;

    let mut port_scan = PortScan::new(max_retries);
    let net_info = scan_target.net_info;
    if !net_info.valid {
        port_scan.finish(None);
        return Ok(port_scan);
    }

    let dst_mac = net_info.inferred_dst_mac;
    let dst_addr = net_info.inferred_dst_addr;
    let src_mac = net_info.inferred_src_mac;
    let addr_origin = net_info.origin_dst_addr;
    let src_port = match scan_target.src_port {
        Some(s) => s,
        None => random_port(),
    };

    let dst_port = if scan_target.dst_ports.len() > 0 {
        scan_target.dst_ports[0]
    } else {
        return Err(PistolError::NoDstPortSpecified);
    };

    // dst_addr may change during the processing.
    // It is only used here to determine whether the target is ipv4 or ipv6.
    // The real dst_addr is inferred from infer_addr.
    let cached = net_info.cached;
    let if_name = net_info.inferred_interface.name.clone();
    let (spp, filters) = match dst_addr {
        IpAddr::V4(dst_ipv4) => {
            let src_ipv4 = match net_info.inferred_src_addr {
                IpAddr::V4(s) => s,
                _ => {
                    return Err(PistolError::AttackAddressNotMatch {
                        addr: net_info.inferred_src_addr,
                    });
                }
            };
            let (spp, filters) = build_scan_buff(
                dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, if_name, method,
            )?;
            (spp, filters)
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
            let (spp, filters) = build_scan_buff6(
                dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, if_name, method,
            )?;
            (spp, filters)
        }
    };

    for i in 0..max_retries {
        stream.send_packet(spp.clone())?;
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
    scan_targets: Vec<ScanTarget>,
    timeout: Duration,
    max_retries: usize,
    speed: SendSpeed,
) -> Result<PortScans, PistolError> {
    let filter = Some(String::from(
        "(tcp and (((tcp[tcpflags] & (tcp-syn|tcp-ack)) == (tcp-syn|tcp-ack)) or ((tcp[tcpflags] & tcp-rst) != 0))) or (icmp and icmp[0] == 3 and (icmp[1] == 1 or icmp[1] == 2 or icmp[1] == 3 or icmp[1] == 9 or icmp[1] == 10 or icmp[1] == 13)) or (icmp6 and icmp6[0] == 1 and (icmp6[1] == 0 or icmp6[1] == 1 or icmp6[1] == 3 or icmp6[1] == 4))",
    ));
    scan(
        scan_targets,
        ScanMethod::Syn,
        timeout,
        max_retries,
        filter,
        speed,
    )
}

/// TCP SYN Scan, raw version.
pub(crate) fn tcp_syn_scan_raw(
    scan_target: ScanTarget,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    let filter = Some(String::from(
        "(tcp and (((tcp[tcpflags] & (tcp-syn|tcp-ack)) == (tcp-syn|tcp-ack)) or ((tcp[tcpflags] & tcp-rst) != 0))) or (icmp and icmp[0] == 3 and (icmp[1] == 1 or icmp[1] == 2 or icmp[1] == 3 or icmp[1] == 9 or icmp[1] == 10 or icmp[1] == 13)) or (icmp6 and icmp6[0] == 1 and (icmp6[1] == 0 or icmp6[1] == 1 or icmp6[1] == 3 or icmp6[1] == 4))",
    ));
    scan_raw(scan_target, ScanMethod::Syn, timeout, max_retries, filter)
}

pub(crate) fn tcp_fin_scan(
    scan_targets: Vec<ScanTarget>,
    timeout: Duration,
    max_retries: usize,
    speed: SendSpeed,
) -> Result<PortScans, PistolError> {
    let filter = Some(String::from(
        "tcp and (tcp[13] & 0x11 != 0) or (icmp and ip[icmplen] == 3 and ip[icmplen+1] == 3)",
    ));
    scan(
        scan_targets,
        ScanMethod::Fin,
        timeout,
        max_retries,
        filter,
        speed,
    )
}

/// TCP FIN Scan, raw version.
pub(crate) fn tcp_fin_scan_raw(
    scan_target: ScanTarget,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    let filter = Some(String::from(
        "tcp and (tcp[13] & 0x11 != 0) or (icmp and ip[icmplen] == 3 and ip[icmplen+1] == 3)",
    ));
    scan_raw(scan_target, ScanMethod::Fin, timeout, max_retries, filter)
}

pub(crate) fn tcp_ack_scan(
    scan_targets: Vec<ScanTarget>,
    timeout: Duration,
    max_retries: usize,
    speed: SendSpeed,
) -> Result<PortScans, PistolError> {
    let filter = Some(String::from("tcp and tcp[13] & 0x10 != 0"));
    scan(
        scan_targets,
        ScanMethod::Ack,
        timeout,
        max_retries,
        filter,
        speed,
    )
}

/// TCP ACK Scan, raw version.
pub(crate) fn tcp_ack_scan_raw(
    scan_target: ScanTarget,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    let filter = Some(String::from("tcp and tcp[13] & 0x10 != 0"));
    scan_raw(scan_target, ScanMethod::Ack, timeout, max_retries, filter)
}

pub(crate) fn tcp_null_scan(
    scan_targets: Vec<ScanTarget>,
    timeout: Duration,
    max_retries: usize,
    speed: SendSpeed,
) -> Result<PortScans, PistolError> {
    scan(
        scan_targets,
        ScanMethod::Null,
        timeout,
        max_retries,
        None,
        speed,
    )
}

/// TCP Null Scan, raw version.
pub(crate) fn tcp_null_scan_raw(
    scan_target: ScanTarget,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(scan_target, ScanMethod::Null, timeout, max_retries, None)
}

pub(crate) fn tcp_xmas_scan(
    scan_targets: Vec<ScanTarget>,
    timeout: Duration,
    max_retries: usize,
    speed: SendSpeed,
) -> Result<PortScans, PistolError> {
    scan(
        scan_targets,
        ScanMethod::Xmas,
        timeout,
        max_retries,
        None,
        speed,
    )
}

/// TCP Xmas Scan, raw version.
pub(crate) fn tcp_xmas_scan_raw(
    scan_target: ScanTarget,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(scan_target, ScanMethod::Xmas, timeout, max_retries, None)
}

pub(crate) fn tcp_window_scan(
    scan_targets: Vec<ScanTarget>,
    timeout: Duration,
    max_retries: usize,
    speed: SendSpeed,
) -> Result<PortScans, PistolError> {
    scan(
        scan_targets,
        ScanMethod::Window,
        timeout,
        max_retries,
        None,
        speed,
    )
}

/// TCP Window Scan, raw version.
pub(crate) fn tcp_window_scan_raw(
    scan_target: ScanTarget,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(scan_target, ScanMethod::Window, timeout, max_retries, None)
}

pub(crate) fn tcp_maimon_scan(
    scan_targets: Vec<ScanTarget>,
    timeout: Duration,
    max_retries: usize,
    speed: SendSpeed,
) -> Result<PortScans, PistolError> {
    scan(
        scan_targets,
        ScanMethod::Maimon,
        timeout,
        max_retries,
        None,
        speed,
    )
}

/// TCP Maimon Scan, raw version.
pub(crate) fn tcp_maimon_scan_raw(
    scan_target: ScanTarget,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    scan_raw(scan_target, ScanMethod::Maimon, timeout, max_retries, None)
}

pub(crate) fn tcp_connect_scan(
    scan_targets: Vec<ScanTarget>,
    timeout: Duration,
    max_retries: usize,
    _speed: SendSpeed,
) -> Result<PortScans, PistolError> {
    let mut port_scans = PortScans::new(max_retries);
    let reports = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    for st in &scan_targets {
        let ni = &st.net_info;
        let dst_addr = ni.origin_dst_addr;
        let dst_ports = st.dst_ports.clone();
        let addr_origin = ni.origin_dst_addr;
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
    scan_target: ScanTarget,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    let mut port_scan = PortScan::new(max_retries);
    if scan_target.dst_ports.len() == 0 {
        return Err(PistolError::NoDstPortSpecified);
    }

    let net_info = scan_target.net_info;
    let dst_addr = net_info.origin_dst_addr;
    let dst_port = scan_target.dst_ports[0];
    let addr_origin = net_info.origin_dst_addr;
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
    scan_targets: Vec<ScanTarget>,
    timeout: Duration,
    max_retries: usize,
    speed: SendSpeed,
) -> Result<PortScans, PistolError> {
    let filter = None;
    scan(
        scan_targets,
        ScanMethod::Udp,
        timeout,
        max_retries,
        filter,
        speed,
    )
}

/// UDP Scan, raw version.
pub(crate) fn udp_scan_raw(
    scan_target: ScanTarget,
    timeout: Duration,
    max_retries: usize,
) -> Result<PortScan, PistolError> {
    let filter = None;
    scan_raw(scan_target, ScanMethod::Udp, timeout, max_retries, filter)
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
