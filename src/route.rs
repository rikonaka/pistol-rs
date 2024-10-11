use anyhow::Result;
use log::debug;
use log::warn;
#[cfg(target_os = "windows")]
use pnet::datalink::interfaces;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::IpNetwork;
use regex::Regex;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::metadata;
use std::fs::remove_file;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;

// use crate::errors::InvalidRouteFormat;
#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "linux"
))]
use crate::utils::find_interface_by_name;

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
fn ipv6_addr_bsd_fix(dst_str: &str) -> Result<String> {
    // Remove the %em0 .etc
    // fe80::%lo0/10 => fe80::/10
    // fe80::20c:29ff:fe1f:6f71%lo0 => fe80::20c:29ff:fe1f:6f71
    if dst_str.contains("%") {
        let bsd_fix_re = Regex::new(r"(?P<subnet>[^\s^%^/]+)(%(?P<dev>\w+))?(/(?P<mask>\d+))?")?;
        match bsd_fix_re.captures(dst_str) {
            Some(caps) => {
                let addr = &caps["subnet"];
                if dst_str.contains("/") {
                    let mask = &caps["mask"];
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultRoute {
    pub via: IpAddr,           // Next hop gateway address
    pub dev: NetworkInterface, // Device interface name
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RouteAddr {
    IpNetwork(IpNetwork),
    IpAddr(IpAddr),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub dst: RouteAddr,        // Destination network or host address
    pub dev: NetworkInterface, // Device interface name
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteTable {
    pub default_ipv4_route: Option<DefaultRoute>,
    pub default_ipv6_route: Option<DefaultRoute>,
    pub routes: Vec<Route>,
}

impl RouteTable {
    #[cfg(target_os = "linux")]
    pub fn init() -> Result<RouteTable> {
        let system_route_lines = || -> Result<Vec<String>> {
            // Linux
            // ubuntu22.04 output:
            // default via 192.168.72.2 dev ens33
            // 192.168.1.0/24 dev ens36 proto kernel scope link src 192.168.1.132
            // 192.168.72.0/24 dev ens33 proto kernel scope link src 192.168.72.128
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

        let mut default_ipv4_route = None;
        let mut default_ipv6_route = None;
        let mut routes = Vec::new();

        // regex
        let default_route_re =
            Regex::new(r"default\s+via\s+(?P<via>.+)\s+dev\s+(?P<dev>\w+)\s+.+")?;
        let route_re = Regex::new(r"(?P<subnet>.+/\d{1,2})\s+dev\s+(?P<dev>\w+)\s+.+")?;

        for line in system_route_lines()? {
            let default_route_judge = |line: &str| -> bool { line.contains("default") };
            if default_route_judge(&line) {
                match default_route_re.captures(&line) {
                    Some(caps) => {
                        let via_str = &caps["via"];
                        let via: IpAddr = via_str.parse()?;
                        let dev_str = &caps["dev"];
                        let dev = match find_interface_by_name(dev_str) {
                            Some(i) => i,
                            None => {
                                // return Err(InvalidRouteFormat::new(line.to_string()).into());
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
                        let dst_str = &caps["subnet"];
                        let dst = if dst_str.contains("/") {
                            let dst = IpNetwork::from_str(dst_str)?;
                            let dst = RouteAddr::IpNetwork(dst);
                            dst
                        } else {
                            let dst: IpAddr = dst_str.parse()?;
                            let dst = RouteAddr::IpAddr(dst);
                            dst
                        };
                        let dev_str = &caps["dev"];
                        let dev = match find_interface_by_name(dev_str) {
                            Some(i) => i,
                            None => {
                                // return Err(InvalidRouteFormat::new(line.to_string()).into());
                                warn!("invaild route string: [{}]", line);
                                continue; // not raise error here
                            }
                        };
                        let route = Route { dst, dev };
                        routes.push(route);
                    }
                    None => warn!("line: [{}] route_re no match", line),
                }
            }
        }

        let rt = RouteTable {
            default_ipv4_route,
            default_ipv6_route,
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
    pub fn init() -> Result<RouteTable> {
        let system_route_lines = || -> Result<Vec<String>> {
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

        let mut default_ipv4_route = None;
        let mut default_ipv6_route = None;
        let mut routes = Vec::new();

        // regex
        let default_route_re =
            Regex::new(r"default\s+(?P<via>[^\s]+)\s+\w+\s+(?P<dev>[^\s]+)([\s\w]+)?")?;
        let route_re = Regex::new(r"(?P<subnet>[^\s]+)\s+link#\d+\s+\w+\s+(?P<dev>\w+)")?;

        for line in system_route_lines()? {
            let default_route_judge = |line: &str| -> bool { line.contains("default") };
            if default_route_judge(&line) {
                match default_route_re.captures(&line) {
                    Some(caps) => {
                        let via_str = &caps["via"];
                        let via_str = ipv6_addr_bsd_fix(via_str)?;
                        let via: IpAddr = via_str.parse()?;
                        let dev_str = &caps["dev"];
                        let dev = match find_interface_by_name(dev_str) {
                            Some(i) => i,
                            None => {
                                // return Err(InvalidRouteFormat::new(line.to_string()).into());
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
                        let dst_str = &caps["subnet"];

                        let dst_str = ipv6_addr_bsd_fix(dst_str)?;
                        let dst = if dst_str.contains("/") {
                            let dst = IpNetwork::from_str(&dst_str)?;
                            let dst = RouteAddr::IpNetwork(dst);
                            dst
                        } else {
                            let dst: IpAddr = dst_str.parse()?;
                            let dst = RouteAddr::IpAddr(dst);
                            dst
                        };
                        let dev_str = &caps["dev"];
                        let dev = match find_interface_by_name(dev_str) {
                            Some(i) => i,
                            None => {
                                // return Err(InvalidRouteFormat::new(line.to_string()).into());
                                warn!("invaild route string: [{}]", line);
                                continue; // not raise error here
                            }
                        };
                        let route = Route { dst, dev };
                        routes.push(route);
                    }
                    None => warn!("line: [{}] route_re no match", line),
                }
            }
        }

        let rt = RouteTable {
            default_ipv4_route,
            default_ipv6_route,
            routes,
        };
        Ok(rt)
    }
    #[cfg(target_os = "windows")]
    pub fn init() -> Result<RouteTable> {
        let system_route_lines = || -> Result<Vec<String>> {
            // 1 ::1/128 :: 256 75 ActiveStore
            // 15 ::/0 fe80::ecb5:83ff:fec3:6a6 16 45 ActiveStore
            let c = Command::new("powershell").args(["Get-NetRoute"]).output()?;
            let output = String::from_utf8_lossy(&c.stdout);
            let route_lines: Vec<String> = output
                .lines()
                .map(|x| x.trim().to_string())
                .filter(|v| v.len() > 0 && !v.contains("ifIndex") && !v.contains("-"))
                .collect();
            Ok(route_lines)
        };

        let mut default_ipv4_route = None;
        let mut default_ipv6_route = None;
        let mut routes = Vec::new();

        // regex
        let default_route_re =
            Regex::new(r"(?P<index>\d+)\s+(?P<dst>[\d\w\./:]+)\s+(?P<via>[\d\./]+)\s+.+")?;
        let route_re =
            Regex::new(r"(?P<index>\d+)\s+(?P<dst>[\d\w\./:]+)\s+(?P<via>[\d\./]+)\s+.+")?;

        for line in system_route_lines()? {
            let default_route_judge =
                |line: &str| -> bool { line.contains("0.0.0.0/0") || line.contains("::/0") };
            if default_route_judge(&line) {
                match default_route_re.captures(&line) {
                    Some(caps) => {
                        let if_index: u32 = caps["index"].parse()?;
                        let find_interface = |if_index: u32| -> Option<NetworkInterface> {
                            for interface in interfaces() {
                                if if_index == interface.index {
                                    return Some(interface);
                                }
                            }
                            None
                        };

                        // let dst = &caps["dst"];
                        // let dst = IpNetwork::from_str(dst)?;
                        let via_str = &caps["via"];
                        let via: IpAddr = via_str.parse()?;
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
                                // return Err(InvalidRouteFormat::new(line.to_string()).into());
                                warn!("invaild default route string: [{}]", line);
                                continue; // not raise error here
                            }
                        }
                    }
                    None => warn!("line: [{}] default_route_re no match", line),
                }
            } else {
                match route_re.captures(&line) {
                    Some(caps) => {
                        let if_index: u32 = caps["index"].parse()?;
                        let find_interface = |if_index: u32| -> Option<NetworkInterface> {
                            for interface in interfaces() {
                                if if_index == interface.index {
                                    return Some(interface);
                                }
                            }
                            None
                        };

                        let dst = &caps["dst"];
                        let dst = IpNetwork::from_str(dst)?;
                        let dst = RouteAddr::IpNetwork(dst);
                        // let via: IpAddr = caps["via"].parse()?;
                        let dev = find_interface(if_index);
                        match dev {
                            Some(dev) => {
                                let route = Route { dst, dev };
                                routes.push(route);
                            }
                            None => {
                                // return Err(InvalidRouteFormat::new(line.to_string()).into());
                                warn!("invaild default route string: [{}]", line);
                                continue; // not raise error here
                            }
                        }
                    }
                    None => warn!("line: [{}] default_route_re no match", line),
                }
            }
        }

        let rt = RouteTable {
            default_ipv4_route,
            default_ipv6_route,
            routes,
        };
        Ok(rt)
    }
}

#[derive(Debug, Clone)]
pub struct NeighborCache {}

impl NeighborCache {
    #[cfg(target_os = "linux")]
    pub fn init() -> Result<HashMap<IpAddr, MacAddr>> {
        // 192.168.72.2 dev ens33 lladdr 00:50:56:fb:1d:74 STALE
        // 192.168.1.107 dev ens36 lladdr 74:05:a5:53:69:bb STALE
        // 192.168.1.1 dev ens36 lladdr 48:5f:08:e0:13:94 STALE
        // 192.168.1.128 dev ens36 lladdr a8:9c:ed:d5:00:4c STALE
        // 192.168.72.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE
        // fe80::4a5f:8ff:fee0:1394 dev ens36 lladdr 48:5f:08:e0:13:94 router STALE
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
                    debug!("neighbor captures addr: {}", &caps["addr"]);
                    debug!("neighbor captures mac: {}", &caps["mac"]);
                    let addr: IpAddr = caps["addr"].parse()?;
                    let mac: MacAddr = caps["mac"].parse()?;
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
    pub fn init() -> Result<HashMap<IpAddr, MacAddr>> {
        // # arp -a
        // ? (192.168.72.1) at 00:50:56:c0:00:08 on em0 expires in 1139 seconds [ethernet]
        // ? (192.168.72.129) at 00:0c:29:88:20:d2 on em0 permanent [ethernet]
        // ? (192.168.72.2) at 00:50:56:fb:1d:74 on em0 expires in 1168 seconds [ethernet]
        // MacOS
        // ? (192.168.50.2) at (incomplete) on en0 ifscope [ethernet]
        // # ndp -a
        // Neighbor                             Linklayer Address  Netif Expire    1s 5s
        // fe80::20c:29ff:fe88:20d2%em0         00:0c:29:88:20:d2    em0 permanent R
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

        let mut ret = HashMap::new();
        for line in lines {
            match neighbor_re.captures(line) {
                Some(caps) => {
                    debug!("neighbor captures addr: {}", &caps["addr"]);
                    debug!("neighbor captures mac: {}", &caps["mac"]);
                    let addr_str = &caps["addr"];
                    let addr_str = ipv6_addr_bsd_fix(addr_str)?;
                    let addr: IpAddr = addr_str.parse()?;
                    let mac: MacAddr = caps["mac"].parse()?;
                    ret.insert(addr, mac);
                }
                None => warn!("line: [{}] neighbor_re no match", line),
            }
        }
        Ok(ret)
    }
    #[cfg(target_os = "windows")]
    pub fn init() -> Result<HashMap<IpAddr, MacAddr>> {
        // 58 ff02::1:ff73:3ff4 33-33-FF-73-3F-F4 Permanent ActiveStore
        // 58 ff02::1:2  33-33-00-01-00-02 Permanent ActiveStore
        let c = Command::new("powershell")
            .args(["Get-NetNeighbor"])
            .output()?;
        let output = String::from_utf8_lossy(&c.stdout);
        let lines: Vec<&str> = output
            .lines()
            .map(|x| x.trim())
            .filter(|v| v.len() > 0 && !v.contains("ifIndex") && !v.contains("-"))
            .collect();

        // regex
        let neighbor_re = Regex::new(r"\d+\s+(?P<addr>[\w\d\.:]+)\s+(?P<mac>[\w\d\-]+).+")?;

        let mut ret = HashMap::new();
        for line in lines {
            match neighbor_re.captures(line) {
                Some(caps) => {
                    debug!("neighbor captures addr: {}", &caps["addr"]);
                    debug!("neighbor captures mac: {}", &caps["mac"]);
                    let addr: IpAddr = caps["addr"].parse()?;
                    let mac: MacAddr = caps["mac"].parse()?;
                    ret.insert(addr, mac);
                }
                None => warn!("line: [{}] neighbor_re no match", line),
            }
        }
        Ok(ret)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemNetCache {
    pub route_table: RouteTable,
    pub neighbor_cache: HashMap<IpAddr, MacAddr>,
}

const NET_CACHE_FILE: &str = ".pistol_net_cache";

impl Drop for SystemNetCache {
    fn drop(&mut self) {
        // Write the newest config file to disk
        let net_cache_path = Path::new(NET_CACHE_FILE);
        if net_cache_path.exists() {
            let mt =
                metadata(NET_CACHE_FILE).expect("can not get the file metadata: {NET_CACHE_FILE}");
            debug!("net cache config file exists [{}], delete it", mt.len());
            remove_file(NET_CACHE_FILE).expect("remove file {NET_CACHE_FILE} failed");
        }

        let mut file =
            File::create(NET_CACHE_FILE).expect("create config file {NET_CACHE_FILE} failed");
        let snc_string = serde_json::to_string(self).expect("serde config to string failed");
        file.write_all(snc_string.as_bytes())
            .expect("write serde to disk failed");
        debug!("write config file to disk {NET_CACHE_FILE} done");
    }
}

impl SystemNetCache {
    pub fn init() -> Result<SystemNetCache> {
        let net_cache_path = Path::new(NET_CACHE_FILE);
        if net_cache_path.exists() {
            let mt = metadata(NET_CACHE_FILE)?;
            debug!("net cache config file exists [{}]", mt.len());
            let mut file = File::open(NET_CACHE_FILE)?;
            let mut snc_string = String::new();
            file.read_to_string(&mut snc_string)?;
            let snc: SystemNetCache = serde_json::from_str(&snc_string)?;
            Ok(snc)
        } else {
            let route_table = RouteTable::init()?;
            debug!("route table [{}] done", route_table.routes.len());
            let neighbor_cache = NeighborCache::init()?;
            debug!("neighbor cache [{}] done", neighbor_cache.len());
            let snc = SystemNetCache {
                route_table,
                neighbor_cache,
            };

            let mut file = File::create(NET_CACHE_FILE)?;
            let snc_string = serde_json::to_string(&snc)?;
            file.write_all(snc_string.as_bytes())?;
            Ok(snc)
        }
    }
    pub fn search_mac(&self, ipaddr: IpAddr) -> Option<MacAddr> {
        let mac = match self.neighbor_cache.get(&ipaddr) {
            Some(m) => Some(*m),
            None => None,
        };
        mac
    }
    pub fn update_neighbor_cache(&mut self, ipaddr: IpAddr, mac: MacAddr) {
        self.neighbor_cache.insert(ipaddr, mac);
    }
    pub fn search_route(&self, ipaddr: IpAddr) -> Result<Option<NetworkInterface>> {
        debug!("search route: {}", ipaddr);
        let route_table = &self.route_table;
        for route in &route_table.routes {
            let dst = &route.dst;
            match dst {
                RouteAddr::IpAddr(dst) => {
                    if *dst == ipaddr {
                        debug!(
                            "found route interface: {}, ip: {}, ipn: {}",
                            route.dev.name, ipaddr, dst
                        );
                        return Ok(Some(route.dev.clone()));
                    }
                }
                RouteAddr::IpNetwork(dst) => {
                    if dst.contains(ipaddr) {
                        debug!(
                            "found route interface: {}, ip: {}, ipn: {}",
                            route.dev.name, ipaddr, dst
                        );
                        return Ok(Some(route.dev.clone()));
                    }
                }
            }
        }
        Ok(None)
    }
    pub fn default_ipv4_route(&self) -> Option<DefaultRoute> {
        self.route_table.default_ipv4_route.clone()
    }
    pub fn default_ipv6_route(&self) -> Option<DefaultRoute> {
        self.route_table.default_ipv6_route.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // use std::time::Instant;
    use crate::Logger;
    use pnet::datalink::interfaces;
    #[test]
    fn test_network_cache() -> Result<()> {
        Logger::init_debug_logging()?;
        let nc = SystemNetCache::init()?;
        println!(
            "default ipv4 route: {:?}",
            nc.route_table.default_ipv4_route
        );
        println!(
            "default ipv6 route: {:?}",
            nc.route_table.default_ipv6_route
        );
        println!("neighbor cache: {:?}", nc.neighbor_cache);
        // println!("{:?}", nc);
        Ok(())
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
    fn test_unix() -> Result<()> {
        let input = "fe80::%em0/64";
        let input_split: Vec<&str> = input
            .split("%")
            .map(|x| x.trim())
            .filter(|v| v.len() > 0)
            .collect();
        let _ip: IpAddr = input_split[0].parse()?;
        let ipnetwork = IpNetwork::from_str("fe80::")?;
        let test_ipv6: IpAddr = "fe80::20c:29ff:feb6:8d99".parse()?;
        println!("{}", ipnetwork.contains(test_ipv6));
        let ipnetwork = IpNetwork::from_str("fe80::/64")?;
        let test_ipv6: IpAddr = "fe80::20c:29ff:feb6:8d99".parse()?;
        println!("{}", ipnetwork.contains(test_ipv6));
        let ipnetwork = IpNetwork::from_str("::/96")?;
        let test_ipv6: IpAddr = "fe80::20c:29ff:feb6:8d99".parse()?;
        println!("{}", ipnetwork.contains(test_ipv6));
        Ok(())
    }
}
