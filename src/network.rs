use anyhow::Result;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;

use crate::errors::InvalidRouteFormat;
#[cfg(target_os = "windows")]
use crate::errors::UnsupportedSystemDetected;
use crate::utils::find_interface_by_name;
#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
use crate::utils::find_interface_by_subnetwork;

// ubuntu22.04 output:
// default via 192.168.72.2 dev ens33
// 192.168.1.0/24 dev ens36 proto kernel scope link src 192.168.1.132
// 192.168.72.0/24 dev ens33 proto kernel scope link src 192.168.72.128
// centos7 output:
// default via 192.168.72.2 dev ens33 proto dhcp metric 100
// 192.168.72.0/24 dev ens33 proto kernel scope link src 192.168.72.138 metric 100
#[derive(Debug, Clone)]
pub struct DefaultRoute {
    pub dst: String,           // Destination network or host address
    pub via: IpAddr,           // Next hop gateway address
    pub dev: NetworkInterface, // Device interface name
    pub raw: String,           // The raw output
}

impl DefaultRoute {
    #[cfg(target_os = "linux")]
    pub fn parse(line: &str) -> Result<(DefaultRoute, bool)> {
        // default via 192.168.72.2 dev ens33
        let line_split: Vec<&str> = line
            .split(" ")
            .map(|x| x.trim())
            .filter(|v| v.len() > 0)
            .collect();
        let max_iters = line_split.len();
        let mut i = 0;
        let dst = String::from("default");
        let mut via = None;
        let mut dev = None;
        let mut is_ipv4 = true;

        while i < max_iters {
            let item = line_split[i];
            if item == "via" {
                i += 1;
                let v: IpAddr = line_split[i].parse()?;
                via = Some(v);
                if line_split[i].contains(":") {
                    is_ipv4 = false;
                }
            } else if item == "dev" {
                i += 1;
                let dev_name = line_split[i];
                let d = find_interface_by_name(dev_name);
                dev = d;
            }
            i += 1;
        }

        match via {
            Some(via) => match dev {
                Some(dev) => {
                    let dr = DefaultRoute {
                        dst,
                        via,
                        dev,
                        raw: line.to_string(),
                    };
                    return Ok((dr, is_ipv4));
                }
                None => (),
            },
            None => (),
        }

        Err(InvalidRouteFormat::new(line.to_string()).into())
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    pub fn parse(line: &str) -> Result<(DefaultRoute, bool)> {
        // default 192.168.72.2 UGS em0
        let line_split: Vec<&str> = line
            .split(" ")
            .map(|x| x.trim())
            .filter(|v| v.len() > 0)
            .collect();

        let mut is_ipv4 = true;
        let dst = String::from("default");
        let via: IpAddr = line_split[1].parse()?;
        if line_split[1].contains(":") {
            is_ipv4 = false;
        }
        let dev = find_interface_by_subnetwork(via);

        match dev {
            Some(dev) => {
                let dr = DefaultRoute {
                    dst,
                    via,
                    dev,
                    raw: line.to_string(),
                };
                // println!("{:?}", dr);
                return Ok((dr, is_ipv4));
            }
            None => (),
        }

        Err(InvalidRouteFormat::new(line.to_string()).into())
    }
    #[cfg(target_os = "windows")]
    pub fn parse(_line: &str) -> Result<DefaultRoute> {
        // The Windows is not supported now.
        Err(UnsupportedSystemDetected::new(String::from("windows")).into())
    }
}

#[derive(Debug, Clone)]
pub struct Route {
    pub dst: String,           // Destination network or host address
    pub dev: NetworkInterface, // Device interface name
    pub raw: String,           // The raw output
}

impl Route {
    #[cfg(target_os = "linux")]
    pub fn parse(line: &str) -> Result<Route> {
        // 192.168.1.0/24 dev ens36 proto kernel scope link src 192.168.1.132
        let line_split: Vec<&str> = line
            .split(" ")
            .map(|x| x.trim())
            .filter(|v| v.len() > 0)
            .collect();
        let max_iters = line_split.len();
        let mut i = 0;
        let dst = line_split[0].to_string();
        let mut dev = None;

        while i < max_iters {
            let item = line_split[i];
            if item == "dev" {
                i += 1;
                let dev_name = line_split[i];
                let d = find_interface_by_name(dev_name);
                dev = d;
            }
            i += 1;
        }

        match dev {
            Some(dev) => {
                let r = Route {
                    dst,
                    dev,
                    raw: line.to_string(),
                };
                return Ok(r);
            }
            None => (),
        }

        Err(InvalidRouteFormat::new(line.to_string()).into())
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    pub fn parse(line: &str) -> Result<Route> {
        // 127.0.0.1          link#2             UH          lo0
        println!("line: {}", line);
        let line_split: Vec<&str> = line
            .split(" ")
            .map(|x| x.trim())
            .filter(|v| v.len() > 0)
            .collect();
        let dst = line_split[0].to_string();
        let dst = if dst.contains("%") {
            let dst_split: Vec<&str> = dst
                .split("%")
                .map(|x| x.trim())
                .filter(|v| v.len() > 0)
                .collect();
            dst_split[0].to_string()
        } else {
            dst
        };

        let dev_name = line_split[3];
        let dev = find_interface_by_name(dev_name);

        match dev {
            Some(dev) => {
                let r = Route {
                    dst,
                    dev,
                    raw: line.to_string(),
                };
                // println!("{:?}", r);
                return Ok(r);
            }
            None => (),
        }

        Err(InvalidRouteFormat::new(line.to_string()).into())
    }
    #[cfg(target_os = "windows")]
    pub fn parse(_line: &str) -> Result<Route> {
        // The Windows is not supported now.
        Err(UnsupportedSystemDetected::new(String::from("windows")).into())
    }
}

#[derive(Debug, Clone)]
pub struct RouteTable {
    pub default_ipv4_route: Option<DefaultRoute>,
    pub default_ipv6_route: Option<DefaultRoute>,
    pub routes: Vec<Route>,
}

impl RouteTable {
    #[cfg(target_os = "linux")]
    pub fn init() -> Result<RouteTable> {
        let c = Command::new("sh").args(["-c", "ip -4 route"]).output()?;
        let ipv4_output = String::from_utf8_lossy(&c.stdout);
        let c = Command::new("sh").args(["-c", "ip -6 route"]).output()?;
        let ipv6_output = String::from_utf8_lossy(&c.stdout);
        let output = ipv4_output.to_string() + &ipv6_output;
        let lines: Vec<&str> = output
            .lines()
            .map(|x| x.trim())
            .filter(|v| v.len() > 0)
            .collect();

        let mut default_ipv4_route = None;
        let mut default_ipv6_route = None;
        let mut routes = Vec::new();

        for line in lines {
            let line_split: Vec<&str> = line
                .split(" ")
                .map(|x| x.trim())
                .filter(|v| v.len() > 0)
                .collect();
            let dst = line_split[0];
            if dst == "default" {
                let (d, is_ipv4) = DefaultRoute::parse(line)?;
                if is_ipv4 {
                    default_ipv4_route = Some(d);
                } else {
                    default_ipv6_route = Some(d);
                }
            } else {
                let r = Route::parse(line)?;
                routes.push(r);
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
        let c = Command::new("sh").args(["-c", "netstat -rn"]).output()?;
        let output = String::from_utf8_lossy(&c.stdout);
        let lines: Vec<&str> = output
            .lines()
            .map(|x| x.trim())
            .filter(|v| v.len() > 0)
            .collect();

        let mut default_ipv4_route = None;
        let mut default_ipv6_route = None;
        let mut routes = Vec::new();

        for line in lines {
            let line_split: Vec<&str> = line
                .split(" ")
                .map(|x| x.trim())
                .filter(|v| v.len() > 0)
                .collect();
            let dst = line_split[0];
            if dst == "default" {
                let (d, is_ipv4) = DefaultRoute::parse(line)?;
                if is_ipv4 {
                    default_ipv4_route = Some(d);
                } else {
                    default_ipv6_route = Some(d);
                }
            } else {
                if line_split.len() >= 4 && (dst.contains(".") || dst.contains(":")) {
                    let r = Route::parse(line)?;
                    routes.push(r);
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
        // let c = Command::new("powershell")
        //     .args(["route", "print"])
        //     .output()?;
        // let output = String::from_utf8_lossy(&c.stdout);
        // let lines: Vec<&str> = output
        //     .lines()
        //     .map(|x| x.trim())
        //     .filter(|v| v.len() > 0)
        //     .collect();

        // The Windows is not supported now.
        Err(UnsupportedSystemDetected::new(String::from("windows")).into())
    }
}

#[derive(Debug, Clone)]
pub struct NetworkCache {
    pub route_table: RouteTable,
    pub neighbor_cache: HashMap<IpAddr, MacAddr>,
}

impl NetworkCache {
    #[cfg(target_os = "linux")]
    pub fn neighbor_cache_init() -> Result<HashMap<IpAddr, MacAddr>> {
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

        let mut ret = HashMap::new();
        for line in lines {
            let line_split: Vec<&str> = line
                .split(" ")
                .map(|x| x.trim())
                .filter(|v| v.len() > 0)
                .collect();
            let max_iters = line_split.len();
            let mut i = 0;
            let ipaddr: IpAddr = line_split[0].parse()?;

            while i < max_iters {
                let item = line_split[i];
                if item == "lladdr" {
                    i += 1;
                    let mac: MacAddr = line_split[i].parse()?;
                    ret.insert(ipaddr, mac);
                    break;
                }
                i += 1;
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
    pub fn neighbor_cache_init() -> Result<HashMap<IpAddr, MacAddr>> {
        // # arp -a
        // ? (192.168.72.1) at 00:50:56:c0:00:08 on em0 expires in 1139 seconds [ethernet]
        // ? (192.168.72.129) at 00:0c:29:88:20:d2 on em0 permanent [ethernet]
        // ? (192.168.72.2) at 00:50:56:fb:1d:74 on em0 expires in 1168 seconds [ethernet]
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
            .filter(|v| v.len() > 0)
            .collect();

        let mut ret = HashMap::new();
        for line in line {
            let line_split: Vec<&str> = line
                .split(" ")
                .map(|x| x.trim())
                .filter(|v| v.len() > 0)
                .collect();
            if line_split[0].contains("?") {
                // ipv4 cache
                let ip_str = line_split[1].replace("(", "").replace(")", "");
                let ip: IpAddr = ip_str.parse()?;
                let mac: MacAddr = line_split[3].parse()?;
                ret.insert(ip, mac);
            } else if line_split[0].contains(":") {
                // ipv6 cache
                let ip_str = if line_split[0].contains("%") {
                    let ip_split: Vec<&str> = line_split[0]
                        .split("%")
                        .map(|x| x.trim())
                        .filter(|v| v.len() > 0)
                        .collect();
                    ip_split[0]
                } else {
                    line_split[0]
                };
                let ip: IpAddr = ip_str.parse()?;
                let mac: MacAddr = line_split[3].parse()?;
                ret.insert(ip, mac);
            }
        }
        Ok(ret)
    }
    #[cfg(target_os = "windows")]
    pub fn neighbor_cache_init() -> Result<HashMap<IpAddr, MacAddr>> {
        // The Windows is not supported now.
        Err(UnsupportedSystemDetected::new(String::from("windows")).into())
    }
    pub fn init() -> Result<NetworkCache> {
        let route_table = RouteTable::init()?;
        let neighbor_cache = NetworkCache::neighbor_cache_init()?;
        let lnc = NetworkCache {
            route_table,
            neighbor_cache,
        };
        Ok(lnc)
    }
    pub fn search_mac(&self, ipaddr: IpAddr) -> Option<MacAddr> {
        let mac = match self.neighbor_cache.get(&ipaddr) {
            Some(m) => Some(*m),
            None => None,
        };
        mac
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
    use pnet::datalink::interfaces;
    #[test]
    fn test_route_table() -> Result<()> {
        let rt = RouteTable::init()?;
        println!("{:?}", rt.default_ipv4_route);
        println!("{:?}", rt.default_ipv6_route);
        println!("{:?}", rt.routes);
        Ok(())
    }
    #[test]
    fn test_network_cache() -> Result<()> {
        let nc = NetworkCache::init()?;
        // println!("{:?}", nc);
        println!("{:?}", nc.neighbor_cache);
        Ok(())
    }
    #[test]
    fn test_windows() {
        for interface in interfaces() {
            // can not found ipv6 address in windows
            println!("{}", interface);
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
        let ip: IpAddr = input_split[0].parse()?;
        Ok(())
    }
}
