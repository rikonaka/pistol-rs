use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::datalink::interfaces;
use pnet::ipnetwork::IpNetwork;
use regex::Regex;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;
use tracing::debug;
use tracing::warn;

use crate::error::PistolError;

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn find_interface_by_name(name: &str) -> Option<NetworkInterface> {
    for interface in interfaces() {
        if interface.name == name {
            return Some(interface);
        }
    }
    None
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
fn ipv6_addr_bsd_fix(dst_str: &str) -> Result<String, PistolError> {
    // Remove the %em0 .etc
    // fe80::%lo0/10 => fe80::/10
    // fe80::20c:29ff:fe1f:6f71%lo0 => fe80::20c:29ff:fe1f:6f71
    if dst_str.contains("%") {
        let bsd_fix_re = Regex::new(r"(?P<subnet>[^\s^%^/]+)(%(?P<dev>\w+))?(/(?P<mask>\d+))?")?;
        match bsd_fix_re.captures(dst_str) {
            Some(caps) => {
                let addr = caps.name("subnet").map_or("", |m| m.as_str());
                let mask = caps.name("mask").map_or("", |m| m.as_str());
                if dst_str.contains("/") {
                    let output = addr.to_string() + "/" + mask;
                    return Ok(output);
                } else {
                    return Ok(addr.to_string());
                }
            }
            None => {
                warn!("line: [{}] bsd_fix_re no match", dst_str);
                Ok(String::new())
            }
        }
    } else {
        Ok(dst_str.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct DefaultRoute {
    pub via: IpAddr,           // Next hop gateway address
    pub dev: NetworkInterface, // Device interface name
}

impl fmt::Display for DefaultRoute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let default_routes_string = format!(
            "default dst: {}, default interface: {}",
            self.via, self.dev.name
        );
        write!(f, "{}", default_routes_string)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RouteAddr {
    IpNetwork(IpNetwork),
    IpAddr(IpAddr),
}

#[derive(Debug, Clone)]
pub struct RouteTable {
    pub default_route: Option<DefaultRoute>,
    pub default_route6: Option<DefaultRoute>,
    pub routes: HashMap<RouteAddr, NetworkInterface>,
}

impl fmt::Display for RouteTable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut new_routes = HashMap::new();
        for (r, n) in &self.routes {
            let addr = match r {
                RouteAddr::IpAddr(i) => i.to_string(),
                RouteAddr::IpNetwork(i) => i.to_string(),
            };
            let interface_name = n.name.clone();
            new_routes.insert(addr, interface_name);
        }
        let mut output = String::new();
        match &self.default_route {
            Some(r) => {
                output += &format!("ipv4: {}, ", r);
            }
            None => (),
        }
        match &self.default_route6 {
            Some(r) => {
                output += &format!("ipv6: {}, ", r);
            }
            None => (),
        }
        let routes_string = format!("{:?}", new_routes);
        output += &routes_string;
        match output.strip_suffix(", ") {
            Some(o) => write!(f, "{}", o),
            None => write!(f, "{}", output),
        }
    }
}

impl RouteTable {
    #[cfg(target_os = "linux")]
    fn parser(system_route_lines: Vec<String>) -> Result<RouteTable, PistolError> {
        let mut default_ipv4_route = None;
        let mut default_ipv6_route = None;
        let mut routes = HashMap::new();

        // regex
        let default_route_re =
            Regex::new(r"default\s+via\s+(?P<via>[^\s]+)\s+dev\s+(?P<dev>[^\s]+)(.+)?")?;
        let route_re = Regex::new(r"(?P<subnet>[^\s]+)\s+dev\s+(?P<dev>[^\s]+)(.+)?")?;

        for line in system_route_lines {
            let default_route_judge = |line: &str| -> bool { line.contains("default") };
            if default_route_judge(&line) {
                match default_route_re.captures(&line) {
                    Some(caps) => {
                        let via_str = caps.name("via").map_or("", |m| m.as_str());
                        let via: IpAddr = match via_str.parse() {
                            Ok(v) => v,
                            Err(e) => {
                                warn!("parse route table 'via' error:  {e}");
                                continue;
                            }
                        };
                        // debug!("via: {}", via);
                        let dev_str = caps.name("dev").map_or("", |m| m.as_str());
                        let dev = match find_interface_by_name(dev_str) {
                            Some(i) => i,
                            None => {
                                warn!("invaild default route string: [{}]", line);
                                continue; // not raise error here
                            }
                        };
                        // debug!("dev: {}", dev.name);
                        let mut is_ipv4 = true;
                        if via_str.contains(":") {
                            is_ipv4 = false;
                        }

                        let default_route = DefaultRoute { via, dev };

                        if is_ipv4 {
                            default_ipv4_route = Some(default_route);
                        } else {
                            default_ipv6_route = Some(default_route);
                        }
                    }
                    None => warn!("line: [{}] default_route_re no match", line),
                }
            } else {
                match route_re.captures(&line) {
                    Some(caps) => {
                        let dst_str = caps.name("subnet").map_or("", |m| m.as_str());
                        let dst = if dst_str.contains("/") {
                            let dst = match IpNetwork::from_str(dst_str) {
                                Ok(d) => d,
                                Err(e) => {
                                    warn!("parse route table 'dst' error:  {e}");
                                    continue;
                                }
                            };
                            let dst = RouteAddr::IpNetwork(dst);
                            dst
                        } else {
                            let dst: IpAddr = match dst_str.parse() {
                                Ok(d) => d,
                                Err(e) => {
                                    warn!("parse route table 'dst' error:  {e}");
                                    continue;
                                }
                            };
                            let dst = RouteAddr::IpAddr(dst);
                            dst
                        };
                        let dev_str = caps.name("dev").map_or("", |m| m.as_str());
                        let dev = match find_interface_by_name(dev_str) {
                            Some(i) => i,
                            None => {
                                warn!("invaild route string: [{}]", line);
                                continue; // not raise error here
                            }
                        };
                        routes.insert(dst, dev);
                    }
                    None => warn!("line: [{}] route_re no match", line),
                }
            }
        }

        let rt = RouteTable {
            default_route: default_ipv4_route,
            default_route6: default_ipv6_route,
            routes,
        };
        Ok(rt)
    }
    #[cfg(target_os = "linux")]
    pub fn init() -> Result<RouteTable, PistolError> {
        let system_route_lines = || -> Result<Vec<String>, PistolError> {
            // Linux
            // ubuntu22.04 output:
            // default via 192.168.72.2 dev ens33
            // 192.168.1.0/24 dev ens36 proto kernel scope link src 192.168.1.132
            // 192.168.72.0/24 dev ens33 proto kernel scope link src 192.168.72.128
            // fe80::/64 dev ens33 proto kernel metric 256 pref medium
            // centos7 output:
            // default via 192.168.72.2 dev ens33 proto dhcp metric 100
            // 192.168.72.0/24 dev ens33 proto kernel scope link src 192.168.72.138 metric 100
            let c = Command::new("sh").args(["-c", "ip -4 route"]).output()?;
            let ipv4_output = String::from_utf8_lossy(&c.stdout);
            let c = Command::new("sh").args(["-c", "ip -6 route"]).output()?;
            let ipv6_output = String::from_utf8_lossy(&c.stdout);
            let output = ipv4_output.to_string() + &ipv6_output;
            let lines: Vec<String> = output
                .lines()
                .map(|x| x.trim().to_string())
                .filter(|v| v.len() > 0)
                .collect();
            Ok(lines)
        };
        let system_route_lines = system_route_lines()?;
        RouteTable::parser(system_route_lines)
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    fn parser(system_route_lines: Vec<String>) -> Result<RouteTable, PistolError> {
        let mut default_ipv4_route = None;
        let mut default_ipv6_route = None;
        let mut routes = HashMap::new();

        // regex
        let default_route_re =
            Regex::new(r"default\s+(?P<via>[^\s]+)\s+\w+\s+(?P<dev>[^\s]+)([^\s]+)?")?;
        let route_re = Regex::new(r"(?P<subnet>[^\s]+)\s+link#\d+\s+\w+\s+(?P<dev>[^\s]+)")?;

        for line in system_route_lines {
            let default_route_judge = |line: &str| -> bool { line.contains("default") };
            if default_route_judge(&line) {
                match default_route_re.captures(&line) {
                    Some(caps) => {
                        let via_str = caps.name("via").map_or("", |m| m.as_str());
                        let via_str = ipv6_addr_bsd_fix(via_str)?;
                        let via: IpAddr = match via_str.parse() {
                            Ok(v) => v,
                            Err(e) => {
                                warn!("parse route table 'via' error:  {e}");
                                continue;
                            }
                        };
                        let dev_str = caps.name("dev").map_or("", |m| m.as_str());
                        let dev = match find_interface_by_name(dev_str) {
                            Some(i) => i,
                            None => {
                                warn!("invaild default route string: [{}]", line);
                                continue; // not raise error here
                            }
                        };

                        let mut is_ipv4 = true;
                        if via_str.contains(":") {
                            is_ipv4 = false;
                        }

                        let default_route = DefaultRoute { via, dev };

                        if is_ipv4 {
                            default_ipv4_route = Some(default_route);
                        } else {
                            default_ipv6_route = Some(default_route);
                        }
                    }
                    None => warn!("line: [{}] default_route_re no match", line),
                }
            } else {
                match route_re.captures(&line) {
                    Some(caps) => {
                        let dst_str = caps.name("subnet").map_or("", |m| m.as_str());

                        let dst_str = ipv6_addr_bsd_fix(dst_str)?;
                        let dst = if dst_str.contains("/") {
                            let dst = match IpNetwork::from_str(&dst_str) {
                                Ok(d) => d,
                                Err(e) => {
                                    warn!("parse route table 'dst' error:  {e}");
                                    continue;
                                }
                            };
                            let dst = RouteAddr::IpNetwork(dst);
                            dst
                        } else {
                            let dst: IpAddr = match dst_str.parse() {
                                Ok(d) => d,
                                Err(e) => {
                                    warn!("parse route table 'dst' error:  {e}");
                                    continue;
                                }
                            };
                            let dst = RouteAddr::IpAddr(dst);
                            dst
                        };
                        let dev_str = caps.name("dev").map_or("", |m| m.as_str());
                        let dev = match find_interface_by_name(dev_str) {
                            Some(i) => i,
                            None => {
                                continue; // not raise error here
                            }
                        };
                        routes.insert(dst, dev);
                    }
                    None => warn!("line: [{}] route_re no match", line),
                }
            }
        }
        let rt = RouteTable {
            default_route: default_ipv4_route,
            default_route6: default_ipv6_route,
            routes,
        };
        Ok(rt)
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    pub fn init() -> Result<RouteTable, PistolError> {
        let system_route_lines = || -> Result<Vec<String>, PistolError> {
            // default 192.168.72.2 UGS em0
            // default fe80::4a5f:8ff:fee0:1394%em1 UG em1
            // 127.0.0.1          link#2             UH          lo0
            let c = Command::new("sh").args(["-c", "netstat -rn"]).output()?;
            let output = String::from_utf8_lossy(&c.stdout);
            let lines: Vec<String> = output
                .lines()
                .map(|x| x.trim().to_string())
                .filter(|v| {
                    v.len() > 0
                        && !v.contains("Destination")
                        && !v.contains("Routing tables")
                        && !v.contains("Internet")
                })
                .collect();
            Ok(lines)
        };
        let system_route_lines = system_route_lines()?;
        RouteTable::parser(system_route_lines)
    }
    #[cfg(target_os = "windows")]
    fn parser(system_route_lines: Vec<String>) -> Result<RouteTable, PistolError> {
        let mut default_ipv4_route = None;
        let mut default_ipv6_route = None;
        let mut routes = HashMap::new();

        // regex
        let default_route_re =
            Regex::new(r"(?P<index>[^\s]+)\s+(?P<dst>[^\s]+)\s+(?P<via>[^\s]+)(.+)?")?;
        let route_re = Regex::new(r"(?P<index>[^\s]+)\s+(?P<dst>[^\s]+)\s+(?P<via>[^\s]+)(.+)?")?;

        for line in system_route_lines {
            let default_route_judge =
                |line: &str| -> bool { line.contains("0.0.0.0/0") || line.contains("::/0") };
            if default_route_judge(&line) {
                match default_route_re.captures(&line) {
                    Some(caps) => {
                        let if_index = caps.name("index").map_or("", |m| m.as_str());
                        let if_index: u32 = match if_index.parse() {
                            Ok(i) => i,
                            Err(e) => {
                                warn!("parse route table 'if_index' error:  {e}");
                                continue;
                            }
                        };
                        let find_interface = |if_index: u32| -> Option<NetworkInterface> {
                            for interface in interfaces() {
                                if if_index == interface.index {
                                    return Some(interface);
                                }
                            }
                            None
                        };

                        let via_str = caps.name("via").map_or("", |m| m.as_str());
                        let via: IpAddr = match via_str.parse() {
                            Ok(v) => v,
                            Err(e) => {
                                warn!("parse route table 'via' error:  {e}");
                                continue;
                            }
                        };
                        let dev = find_interface(if_index);
                        match dev {
                            Some(dev) => {
                                let mut is_ipv4 = true;
                                if via_str.contains(":") {
                                    is_ipv4 = false;
                                }

                                let default_route = DefaultRoute { via, dev };

                                if is_ipv4 {
                                    default_ipv4_route = Some(default_route);
                                } else {
                                    default_ipv6_route = Some(default_route);
                                }
                            }
                            None => {
                                warn!(
                                    "default route string [{}] has no interface, id {}",
                                    line, if_index
                                );
                                continue; // not raise error here
                            }
                        }
                    }
                    None => warn!("line: [{}] default_route_re no match", line),
                }
            } else {
                match route_re.captures(&line) {
                    Some(caps) => {
                        let if_index = caps.name("index").map_or("", |m| m.as_str());
                        let if_index: u32 = match if_index.parse() {
                            Ok(i) => i,
                            Err(e) => {
                                warn!("parse route table 'if_index' error:  {e}");
                                continue;
                            }
                        };
                        let find_interface_by_id = |if_index: u32| -> Option<NetworkInterface> {
                            for interface in interfaces() {
                                if if_index == interface.index {
                                    return Some(interface);
                                }
                            }
                            None
                        };

                        let dst = caps.name("dst").map_or("", |m| m.as_str());
                        let dst = match IpNetwork::from_str(dst) {
                            Ok(d) => d,
                            Err(e) => {
                                warn!("parse route table 'dst' error:  {e}");
                                continue;
                            }
                        };
                        let dst = RouteAddr::IpNetwork(dst);
                        let dev = find_interface_by_id(if_index);
                        let dev = match dev {
                            Some(i) => i,
                            None => {
                                warn!("invaild default route string: [{}]", line);
                                continue; // not raise error here
                            }
                        };
                        routes.insert(dst, dev);
                    }
                    None => warn!("line: [{}] default_route_re no match", line),
                }
            }
        }

        let rt = RouteTable {
            default_route: default_ipv4_route,
            default_route6: default_ipv6_route,
            routes,
        };
        Ok(rt)
    }
    #[cfg(target_os = "windows")]
    pub fn init() -> Result<RouteTable, PistolError> {
        let system_route_lines = || -> Result<Vec<String>, PistolError> {
            // 17      255.255.255.255/32                             0.0.0.0                                          256 25       ActiveStore
            // 17      fe80::d547:79a9:84eb:767d/128                  ::                                               256 25       ActiveStore
            let c = Command::new("powershell").args(["Get-NetRoute"]).output()?;
            let output = String::from_utf8_lossy(&c.stdout);
            let route_lines: Vec<String> = output
                .lines()
                .map(|x| x.trim().to_string())
                .filter(|v| v.len() > 0 && !v.contains("ifIndex") && !v.contains("--"))
                .collect();
            Ok(route_lines)
        };
        let system_route_lines = system_route_lines()?;
        RouteTable::parser(system_route_lines)
    }
}

#[derive(Debug, Clone)]
pub struct NeighborCache {}

impl NeighborCache {
    #[cfg(target_os = "linux")]
    pub fn init() -> Result<HashMap<IpAddr, MacAddr>, PistolError> {
        // Debian 12:
        // 192.168.72.2 dev ens33 lladdr 00:50:56:fb:1d:74 STALE
        // 192.168.1.107 dev ens36 lladdr 74:05:a5:53:69:bb STALE
        // 192.168.1.1 dev ens36 lladdr 48:5f:08:e0:13:94 STALE
        // 192.168.1.128 dev ens36 lladdr a8:9c:ed:d5:00:4c STALE
        // 192.168.72.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE
        // fe80::4a5f:8ff:fee0:1394 dev ens36 lladdr 48:5f:08:e0:13:94 router STALE
        // fe80::250:56ff:fec0:2222 dev ens33 router FAILED
        // CentOS 7:
        // 192.168.3.456 dev em2 lladdr fc:e3:3c:a6:a9:8c REACHABLE
        let c = Command::new("sh").args(["-c", "ip neigh show"]).output()?;
        let output = String::from_utf8_lossy(&c.stdout);
        let lines: Vec<&str> = output
            .lines()
            .map(|x| x.trim())
            .filter(|v| v.len() > 0)
            .collect();

        // regex
        let neighbor_re =
            Regex::new(r"(?P<addr>[\d\w\.:]+)\s+dev[\w\s]+lladdr\s+(?P<mac>[\d\w:]+).+")?;

        let mut ret = HashMap::new();
        for line in lines {
            match neighbor_re.captures(line) {
                Some(caps) => {
                    let addr = caps.name("addr").map_or("", |m| m.as_str());
                    let addr: IpAddr = match addr.parse() {
                        Ok(a) => a,
                        Err(e) => {
                            warn!("parse neighbor 'addr' error:  {e}");
                            continue;
                        }
                    };
                    let mac = caps.name("mac").map_or("", |m| m.as_str());
                    let mac: MacAddr = match mac.parse() {
                        Ok(m) => m,
                        Err(e) => {
                            warn!("parse neighbor 'mac' error:  {e}");
                            continue;
                        }
                    };
                    ret.insert(addr, mac);
                }
                None => warn!("line: [{}] neighbor_re no match", line),
            }
        }
        Ok(ret)
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    pub fn init() -> Result<HashMap<IpAddr, MacAddr>, PistolError> {
        // Examples:
        // # arp -a
        // ? (192.168.72.1) at 00:50:56:c0:00:08 on em0 expires in 1139 seconds [ethernet]
        // ? (192.168.72.129) at 00:0c:29:88:20:d2 on em0 permanent [ethernet]
        // ? (192.168.72.2) at 00:50:56:fb:1d:74 on em0 expires in 1168 seconds [ethernet]
        // MacOS
        // ? (192.168.50.2) at (incomplete) on en0 ifscope [ethernet]
        // # ndp -a
        // Neighbor                             Linklayer Address  Netif Expire    1s 5s
        // fe80::20c:29ff:fe88:20d2%em0         00:0c:29:88:20:d2    em0 permanent R
        // fe80::20c:29ff:feb8:a41%em0          00:0c:29:b8:0a:41    em0 permanent R
        let c = Command::new("sh").args(["-c", "arp -a"]).output()?;
        let arp_output = String::from_utf8_lossy(&c.stdout);
        let c = Command::new("sh").args(["-c", "ndp -a"]).output()?;
        let ndp_output = String::from_utf8_lossy(&c.stdout);
        let output = arp_output.to_string() + &ndp_output;
        let lines: Vec<&str> = output
            .lines()
            .map(|x| x.trim())
            .filter(|v| v.len() > 0 && !v.contains("Neighbor"))
            .collect();

        // regex
        let neighbor_re = Regex::new(r"\?\s+\((?P<addr>[^\s]+)\)\s+at\s+(?P<mac>[\w\d:]+).+")?;
        let neighbor_re6 = Regex::new(r"(?P<addr>[^\s]+)\s+(?P<mac>[^\s]+).+")?;

        let mut ret = HashMap::new();
        for line in lines {
            match neighbor_re.captures(line) {
                Some(caps) => {
                    let addr_str = caps.name("addr").map_or("", |m| m.as_str());
                    let addr_str = ipv6_addr_bsd_fix(addr_str)?;
                    let addr: IpAddr = match addr_str.parse() {
                        Ok(a) => a,
                        Err(e) => {
                            warn!("parse neighbor 'addr' error:  {e}");
                            continue;
                        }
                    };
                    let mac = caps.name("mac").map_or("", |m| m.as_str());
                    let mac: MacAddr = match mac.parse() {
                        Ok(m) => m,
                        Err(e) => {
                            warn!("parse neighbor 'mac' error:  {e}");
                            continue;
                        }
                    };
                    ret.insert(addr, mac);
                }
                // it maybe the ipv6 addr
                None => match neighbor_re6.captures(line) {
                    Some(caps) => {
                        let addr_str = caps.name("addr").map_or("", |m| m.as_str());
                        let addr_str = ipv6_addr_bsd_fix(addr_str)?;
                        let addr: IpAddr = match addr_str.parse() {
                            Ok(a) => a,
                            Err(e) => {
                                warn!("parse neighbor 'addr' error:  {e}");
                                continue;
                            }
                        };
                        let mac = caps.name("mac").map_or("", |m| m.as_str());
                        let mac: MacAddr = match mac.parse() {
                            Ok(m) => m,
                            Err(e) => {
                                warn!("parse neighbor 'mac' error:  {e}");
                                continue;
                            }
                        };
                        ret.insert(addr, mac);
                    }
                    None => warn!(
                        "line: [{}] neighbor_re and neighbor_re6 both no match",
                        line
                    ),
                },
            }
        }
        Ok(ret)
    }
    #[cfg(target_os = "windows")]
    pub fn init() -> Result<HashMap<IpAddr, MacAddr>, PistolError> {
        // Examples:
        // 58 ff02::1:ff73:3ff4 33-33-FF-73-3F-F4 Permanent ActiveStore
        // 58 ff02::1:2  33-33-00-01-00-02 Permanent ActiveStore
        // 12 ff05::c Permanent ActiveStore
        let c = Command::new("powershell")
            .args(["Get-NetNeighbor"])
            .output()?;
        let output = String::from_utf8_lossy(&c.stdout);
        let lines: Vec<&str> = output
            .lines()
            .map(|x| x.trim())
            .filter(|v| v.len() > 0 && !v.contains("ifIndex") && !v.contains("--"))
            .collect();

        // regex
        let neighbor_re =
            Regex::new(r"\d+\s+(?P<addr>[\w\d\.:]+)\s+(?P<mac>[\w\d-]+)\s+\w+\s+\w+")?;

        let mut ret = HashMap::new();
        for line in lines {
            match neighbor_re.captures(line) {
                Some(caps) => {
                    let addr = caps.name("addr").map_or("", |m| m.as_str());
                    let addr: IpAddr = match addr.parse() {
                        Ok(a) => a,
                        Err(e) => {
                            warn!("parse neighbor 'addr' error:  {e}");
                            continue;
                        }
                    };
                    let mac = caps.name("mac").map_or("", |m| m.as_str());
                    // 33-33-00-01-00-02 => 33:33:00:01:00:02
                    let mac = mac.replace("-", ":");
                    let mac: MacAddr = match mac.parse() {
                        Ok(m) => m,
                        Err(e) => {
                            warn!("parse neighbor 'mac' error:  {e}");
                            continue;
                        }
                    };
                    ret.insert(addr, mac);
                }
                None => warn!("line: [{}] neighbor_re no match", line),
            }
        }
        Ok(ret)
    }
}

#[derive(Debug, Clone)]
pub struct SystemNetCache {
    pub default_route: Option<DefaultRoute>,
    pub default_route6: Option<DefaultRoute>,
    pub routes: HashMap<RouteAddr, NetworkInterface>,
    pub neighbor: HashMap<IpAddr, MacAddr>,
}

impl SystemNetCache {
    pub fn init() -> Result<SystemNetCache, PistolError> {
        let route_table = RouteTable::init()?;
        debug!("route table init done");
        debug!("route table: {}", route_table);
        let neighbor_cache = NeighborCache::init()?;
        debug!("neighbor cache init done");
        debug!("neighbor cache: {:?}", neighbor_cache);
        let snc = SystemNetCache {
            default_route: route_table.default_route,
            default_route6: route_table.default_route6,
            routes: route_table.routes,
            neighbor: neighbor_cache,
        };
        Ok(snc)
    }
    pub fn search_mac(&self, ipaddr: IpAddr) -> Option<MacAddr> {
        let mac = match self.neighbor.get(&ipaddr) {
            Some(m) => Some(*m),
            None => None,
        };
        mac
    }
    pub fn update_neighbor_cache(&mut self, ipaddr: IpAddr, mac: MacAddr) {
        self.neighbor.insert(ipaddr, mac);
    }
    pub fn search_route(&self, ipaddr: IpAddr) -> Option<NetworkInterface> {
        for (dst, dev) in &self.routes {
            match dst {
                RouteAddr::IpAddr(dst) => {
                    if *dst == ipaddr {
                        return Some(dev.clone());
                    }
                }
                RouteAddr::IpNetwork(dst) => {
                    if dst.contains(ipaddr) {
                        return Some(dev.clone());
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::datalink::interfaces;
    use std::fs::read_to_string;
    #[test]
    fn test_neighbor() {
        let n = NeighborCache::init().unwrap();
        println!("{:?}", n);

        let r = RouteTable::init().unwrap();
        println!("{:?}", r);
    }
    #[test]
    fn test_network_cache() {
        let snc = SystemNetCache::init().unwrap();
        for (a, n) in snc.routes {
            println!("a: {:?}, n: {}", a, n.name);
        }
        // println!("routes: {:?}", snc.routes);
        // println!("default ipv4 route: {:?}", snc.default_route);
        // println!("default ipv6 route: {:?}", snc.default_route6);
        // println!("neighbor cache: {:?}", snc.neighbor);
        // println!("{:?}", nc);
    }
    #[test]
    fn test_windows_interface() {
        println!("TEST!!!!");
        for interface in interfaces() {
            // can not found ipv6 address in windows
            println!("{}", interface);
            println!("{}", interface.index);
        }
    }
    #[test]
    fn test_unix() {
        let input = "fe80::%em0/64";
        let input_split: Vec<&str> = input
            .split("%")
            .map(|x| x.trim())
            .filter(|v| v.len() > 0)
            .collect();
        let _ip: IpAddr = input_split[0].parse().unwrap();
        let ipnetwork = IpNetwork::from_str("fe80::").unwrap();
        let test_ipv6: IpAddr = "fe80::20c:29ff:feb6:8d99".parse().unwrap();
        println!("{}", ipnetwork.contains(test_ipv6));
        let ipnetwork = IpNetwork::from_str("fe80::/64").unwrap();
        let test_ipv6: IpAddr = "fe80::20c:29ff:feb6:8d99".parse().unwrap();
        println!("{}", ipnetwork.contains(test_ipv6));
        let ipnetwork = IpNetwork::from_str("::/96").unwrap();
        let test_ipv6: IpAddr = "fe80::20c:29ff:feb6:8d99".parse().unwrap();
        println!("{}", ipnetwork.contains(test_ipv6));
    }
    #[test]
    fn test_all() {
        #[cfg(target_os = "linux")]
        let routetable_str = read_to_string("./tests/linux_routetable.txt").unwrap();
        #[cfg(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        let routetable_str = read_to_string("./tests/macos_routetable.txt").unwrap();
        #[cfg(target_os = "windows")]
        let routetable_str = read_to_string("./tests/windows_routetable.txt").unwrap();
        let routetable: Vec<String> = routetable_str.lines().map(|x| x.to_string()).collect();
        let ret = RouteTable::parser(routetable).unwrap();
        println!("{}", ret);
    }
}
