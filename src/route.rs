use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::datalink::interfaces;
use pnet::ipnetwork::IpNetwork;
use pnet::packet::ethernet::EtherTypes;
use regex::Regex;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;
use tracing::error;
use tracing::warn;

use crate::LoopKey;
use crate::LoopStates;
use crate::PistolStream;
use crate::SendPacketParam;
use crate::SendSpeed;
use crate::SendWindow;
use crate::error::PistolError;
use crate::layer::PacketFilter;
use crate::layer::find_interface_by_index;
use crate::layer::find_interface_by_src_ip;
use crate::layer::ipv6_multicast_mac;
use crate::scan::arp::build_arp_scan_buff;
use crate::scan::ndp_ns::build_ndp_ns_scan_packet;
use crate::scan::ndp_rs::build_ndp_ra_scan_packet;
use crate::scan::parse_mac_scan_response;

pub(crate) fn fake_interface() -> NetworkInterface {
    NetworkInterface {
        name: String::from("fake"),
        index: 0,
        mac: Some(MacAddr::zero()),
        ips: Vec::new(),
        flags: 0,
        description: String::new(),
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct NetInfo {
    inferred_dst_mac: MacAddr,
    inferred_src_mac: MacAddr,
    /// Inferred destination IP address.
    inferred_dst_addr: IpAddr,
    /// If user did not specify source IP address, we will use the IP address of the selected interface.
    inferred_src_addr: IpAddr,
    /// Original user input destination IP address,
    /// which may be the same as infer_dst_addr if user input a valid IP address,
    /// or may be different if user input a hostname or an invalid IP address.
    dst_addr: IpAddr,
    src_addr: Option<IpAddr>,
    /// User input destination ports.
    dst_ports: Vec<u16>,
    /// User input source port.
    src_port: Option<u16>,
    if_name: String,
    /// Whether the network information is cached or inferred.
    cached: bool,
    cost: Duration,
    valid: bool,
}

impl NetInfo {
    pub(crate) fn invalid() -> Self {
        NetInfo {
            inferred_dst_mac: MacAddr::zero(),
            inferred_src_mac: MacAddr::zero(),
            inferred_dst_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            inferred_src_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_addr: None,
            dst_ports: Vec::new(),
            src_port: None,
            if_name: String::new(),
            cached: true,
            cost: Duration::ZERO,
            valid: false,
        }
    }
}

impl fmt::Display for NetInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.valid {
            let output = format!(
                "dst_mac: {}, src_mac: {}, dst_addr: {}, src_addr: {}, dst_ports: {:?}, interface: {}",
                self.inferred_dst_mac,
                self.inferred_src_mac,
                self.inferred_dst_addr,
                self.inferred_src_addr,
                self.dst_ports,
                self.if_name
            );
            write!(f, "{}", output)
        } else {
            let output = format!(
                "dst_addr: {}, dst_ports: {:?} is down or unreachable",
                self.inferred_dst_addr, self.dst_ports
            );
            write!(f, "{}", output)
        }
    }
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
))]
fn get_neighbor_cache() -> Result<HashMap<IpAddr, MacAddr>, PistolError> {
    let mut neighbor_cache = HashMap::new();
    let ipv4_output = Command::new("arp").arg("-an").output()?;
    let ipv4_output_str = String::from_utf8_lossy(&ipv4_output.stdout);
    let arp_re = Regex::new(r"\? \((?P<ip>\d+\.\d+.\d+.\d+)\) at (?P<mac>[0-9a-fA-F:]+).+")?;

    // ? (169.254.169.254) at (incomplete) on en0 [ethernet]
    // ? (172.16.86.1) at c2:c7:db:1d:39:66 on bridge102 ifscope permanent [bridge]
    // ? (172.16.86.255) at ff:ff:ff:ff:ff:ff on bridge102 ifscope [bridge]
    // ? (192.168.0.1) at f8:ce:21:39:5b:f4 on en0 ifscope [ethernet]
    // ? (192.168.0.102) at cc:4d:75:8d:a1:a5 on en0 ifscope [ethernet]
    // ? (192.168.0.105) at de:cb:f1:62:24:68 on en0 ifscope permanent [ethernet]
    // ? (192.168.0.108) at 6:69:3c:a5:6a:3e on en0 ifscope [ethernet]
    // ? (192.168.0.109) at f4:28:9d:1b:f2:95 on en0 ifscope [ethernet]
    // ? (192.168.0.110) at 42:6c:f:e9:a8:65 on en0 ifscope [ethernet]
    // ? (192.168.0.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
    // ? (192.168.5.1) at c2:c7:db:1d:39:65 on bridge101 ifscope permanent [bridge]
    // ? (192.168.5.78) at 0:c:29:65:2d:9b on bridge101 ifscope [bridge]
    // ? (192.168.5.255) at ff:ff:ff:ff:ff:ff on bridge101 ifscope [bridge]
    // ? (192.168.62.1) at c2:c7:db:1d:39:64 on bridge100 ifscope permanent [bridge]
    // ? (192.168.62.255) at ff:ff:ff:ff:ff:ff on bridge100 ifscope [bridge]
    // ? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
    // ? (232.215.218.197) at 1:0:5e:57:da:c5 on en0 ifscope permanent [ethernet]
    for line in ipv4_output_str.lines() {
        if let Some(caps) = arp_re.captures(line) {
            if let Some(ip_str) = caps.name("ip") {
                let ip_str = ip_str.as_str();
                let ip = IpAddr::from_str(ip_str)?;
                if let Some(mac_str) = caps.name("mac") {
                    let mac_str = mac_str.as_str();
                    match MacAddr::from_str(mac_str) {
                        Ok(m) => {
                            neighbor_cache.insert(ip, m);
                        }
                        Err(_e) => {
                            return Err(PistolError::ParseMacAddrErr {
                                mac: mac_str.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    let ipv6_output = Command::new("ndp").arg("-an").output()?;
    let ipv6_output_str = String::from_utf8_lossy(&ipv6_output.stdout);
    let ndp_re = Regex::new(r"(?P<ip>[\w\d:%]+)\s+(?P<mac>[\w\d:]+).+")?;

    // Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs
    // 2409:8a6c:1763:4351::1000               de:cb:f1:62:24:68    en0 permanent R
    // 2409:8a6c:1763:4351:da:8c8b:e171:9e55   de:cb:f1:62:24:68    en0 permanent R
    // 2409:8a6c:1763:4351:8001:1205:abef:f5f8 de:cb:f1:62:24:68    en0 permanent R
    // fe80::1%lo0                             (incomplete)         lo0 permanent R
    // fe80::1234:5678:abcd:ef01%en0           (incomplete)         en0 expired   N
    // fe80::1807:d761:578a:6885%en0           42:6c:f:e9:a8:65     en0 21h58m44s S
    // fe80::1c53:4e36:7c1a:e431%en0           de:cb:f1:62:24:68    en0 permanent R
    // fe80::6e16:29ff:fe00:fd5b%en0           6c:16:29:0:fd:5b     en0 21h46m41s S
    // fe80::ae49:4251:a476:1253%en0           (incomplete)         en0 expired   N
    // fe80::ce81:b1c:bd2c:69e%en0             (incomplete)         en0 expired   N
    // fe80::face:21ff:fe39:5bf4%en0           f8:ce:21:39:5b:f4    en0 5s        R  R
    // fe80::849f:6fff:fecf:28ff%awdl0         86:9f:6f:cf:28:ff  awdl0 permanent R
    // fe80::849f:6fff:fecf:28ff%llw0          86:9f:6f:cf:28:ff   llw0 permanent R
    // fe80::f693:9983:bc6c:485b%utun0         (incomplete)       utun0 permanent R
    // fe80::799c:5339:de85:ff18%utun1         (incomplete)       utun1 permanent R
    // fe80::6c04:b35b:22df:351e%utun2         (incomplete)       utun2 permanent R
    // fe80::ce81:b1c:bd2c:69e%utun3           (incomplete)       utun3 permanent R
    // fe80::c0c7:dbff:fe1d:3964%bridge100     c2:c7:db:1d:39:64 bridge100 permanent R
    // fe80::c0c7:dbff:fe1d:3965%bridge101     c2:c7:db:1d:39:65 bridge101 permanent R
    // fe80::c0c7:dbff:fe1d:3966%bridge102     c2:c7:db:1d:39:66 bridge102 permanent R
    for line in ipv6_output_str.lines() {
        if let Some(caps) = ndp_re.captures(line) {
            if let Some(ip_str) = caps.name("ip") {
                let ip_str = ip_str.as_str();
                let ip_str = if ip_str.contains("%") {
                    let ip_str_split: Vec<&str> = ip_str.split("%").collect();
                    ip_str_split[0]
                } else {
                    ip_str
                };
                let ip = IpAddr::from_str(ip_str)?;
                if let Some(mac_str) = caps.name("mac") {
                    let mac_str = mac_str.as_str();
                    match MacAddr::from_str(mac_str) {
                        Ok(m) => {
                            neighbor_cache.insert(ip, m);
                        }
                        Err(_e) => {
                            return Err(PistolError::ParseMacAddrErr {
                                mac: mac_str.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(neighbor_cache)
}

pub(crate) struct NetInfos {
    pub net_infos: Vec<NetInfo>,
    pub neighbor_cache: HashMap<IpAddr, MacAddr>,
}

impl NetInfos {
    pub(crate) fn new() -> Result<Self, PistolError> {
        let neighbor_cache = get_neighbor_cache()?;
        Ok(NetInfos {
            net_infos: Vec::new(),
            neighbor_cache,
        })
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn infer(
        &mut self,
        dst_addr: IpAddr,
        src_addr: Option<IpAddr>,
    ) -> Result<Option<NetInfo>, PistolError> {
        todo!()
    }
    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "macos"
    ))]
    pub(crate) fn infer(
        &mut self,
        dst_addr: IpAddr,
        src_addr: Option<IpAddr>,
    ) -> Result<Option<NetInfo>, PistolError> {
        let output = Command::new("route")
            .arg("-n")
            .arg("get")
            .arg(dst_addr.to_string())
            .output()?;

        // ➜  pistol-rs git:(dev) ✗ route -n get 192.168.5.78
        //    route to: 192.168.5.78
        // destination: 192.168.5.0
        //        mask: 255.255.255.0
        //   interface: bridge101
        //       flags: <UP,DONE,CLONING>
        //  recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
        //        0         0         0         0         0         0      1500    -96267
        // ➜  pistol-rs git:(dev) ✗ route -n get 114.114.114.114
        //    route to: 114.114.114.114
        // destination: default
        //        mask: default
        //     gateway: 192.168.0.1
        //   interface: en0
        //       flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
        //  recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut inferred_dst_addr = None;
        let mut interface = None;
        for line in output_str.lines() {
            if line.contains("interface:") {
                let line_split: Vec<&str> = line.split(":").map(|x| x.trim()).collect();
                if line_split.len() >= 2 {
                    let interface_name = line_split[1];
                    let interfaces = interfaces();
                    for i in interfaces {
                        if i.name == interface_name {
                            interface = Some(i.clone());
                            break;
                        }
                    }
                }
            } else if line.contains("gateway") {
                let line_split: Vec<&str> = line.split(":").map(|x| x.trim()).collect();
                if line_split.len() >= 2 {
                    let gateway_str = line_split[1];
                    if let Ok(gateway_ip) = IpAddr::from_str(gateway_str) {
                        inferred_dst_addr = Some(gateway_ip);
                    }
                }
            }
        }

        let interface = match interface {
            Some(i) => i,
            None => {
                return Err(PistolError::CanNotFoundInterface {
                    i: format!("to dst {}", dst_addr),
                });
            }
        };

        let inferred_dst_addr = match inferred_dst_addr {
            Some(i) => i,
            None => dst_addr,
        };

        let inferred_src_addr = match src_addr {
            Some(s) => s,
            None => {
                let mut isa = None;
                for ipn in &interface.ips {
                    if ipn.contains(inferred_dst_addr) {
                        isa = Some(ipn.ip());
                    }
                }

                match isa {
                    Some(s) => s,
                    None => return Err(PistolError::CanNotFoundSrcAddress),
                }
            }
        };

        let inferred_src_mac = match interface.mac {
            Some(m) => m,
            None => return Err(PistolError::CanNotFoundSrcMacAddress),
        };
        let mut inferred_dst_mac = MacAddr::zero();

        let mut arp_buffs = Vec::new();
        let mut ndp_buffs = Vec::new();
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                let neighbor_cache = &self.neighbor_cache;
                if let Some(mac) = neighbor_cache.get(&inferred_dst_addr) {
                    inferred_dst_mac = *mac;
                } else {
                    let mac = build_arp_scan_buff(dst_ipv4, inferred_src_mac, src_ipv4)?;
                    arp_buffs.push(mac);
                }
            }
            IpAddr::V6(dst_ipv6) => {
                let neighbor_cache = &self.neighbor_cache;
                if let Some(mac) = neighbor_cache.get(&inferred_dst_addr) {
                    inferred_dst_mac = *mac;
                } else {
                    let mac = build_ndp_ns_scan_packet(dst_ipv6, inferred_src_mac, src_ipv6)?;
                    ndp_buffs.push(mac);
                }
            }
        }

        if arp_buffs.len() > 0 || ndp_buffs.len() > 0 {
            let mut stream = PistolStream::new();
            stream.init(Some(String::from("arp[6:2] = 2")))?;
            let mut all_filters = Vec::new();
            for (buff, filters) in arp_buffs {
                let ssp = SendPacketParam {
                    dst_mac: MacAddr::broadcast(),
                    src_mac: inferred_src_mac,
                    eth_type: EtherTypes::Arp,
                    l3_payload: buff,
                    if_name: interface.name.clone(),
                    retransmit: 1,
                };
                stream.send_packet(ssp)?;
                all_filters.extend(filters);
            }
            for (buff, filters) in ndp_buffs {
                if let IpAddr::V6(dst_ipv6) = dst_addr {
                    let ssp = SendPacketParam {
                        dst_mac: ipv6_multicast_mac(dst_ipv6),
                        src_mac: inferred_src_mac,
                        eth_type: EtherTypes::Ipv6,
                        l3_payload: buff,
                        if_name: interface.name.clone(),
                        retransmit: 1,
                    };
                    stream.send_packet(ssp)?;
                    all_filters.extend(filters);
                }
            }

            let response = stream.recv_packet(Duration::from_millis(500))?;

            for r in &response {
                for f in &all_filters {
                    if f.check(r) {
                        if let Some((ip, mac)) = parse_mac_scan_response(r) {
                            inferred_dst_mac = mac;
                            break;
                        }
                    }
                }
            }
        }

        let ni = NetInfo {
            interface,
            inferred_dst_addr,
            inferred_src_addr,
        };

        Ok(Some(ni))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    #[test]
    fn test_infer_net_info() {
        let start = Instant::now();
        let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 78));
        let src = None;
        if let Some(infer_result) = NetInfo::infer(dst, src).unwrap() {
            println!(
                "infer result: {}, elapsed: {:?}",
                infer_result.interface.name,
                start.elapsed()
            );
        } else {
            println!("infer result: None, elapsed: {:?}", start.elapsed());
        }
    }
}
