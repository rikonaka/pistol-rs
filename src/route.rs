use anyhow::Result;
use log::debug;
use log::warn;
#[cfg(target_os = "windows")]
use pnet::datalink::interfaces;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;

use crate::errors::InvalidRouteFormat;
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
    target_os = "netbsd"
))]
use crate::utils::find_interface_by_subnetwork;

#[derive(Debug, Clone)]
pub struct DefaultRoute {
    pub via: IpAddr,           // Next hop gateway address
    pub dev: NetworkInterface, // Device interface name
}

impl DefaultRoute {
    #[cfg(target_os = "linux")]
    pub fn parse(line: &str) -> Result<(DefaultRoute, bool)> {
        // ubuntu22.04 output:
        // default via 192.168.72.2 dev ens33
        // 192.168.1.0/24 dev ens36 proto kernel scope link src 192.168.1.132
        // 192.168.72.0/24 dev ens33 proto kernel scope link src 192.168.72.128
        // centos7 output:
        // default via 192.168.72.2 dev ens33 proto dhcp metric 100
        // 192.168.72.0/24 dev ens33 proto kernel scope link src 192.168.72.138 metric 100
        let line_split: Vec<&str> = line
            .split(" ")
            .map(|x| x.trim())
            .filter(|v| v.len() > 0)
            .collect();
        let max_iters = line_split.len();
        let mut i = 0;
        let mut via = None;
        let mut dev = None;
        let mut is_ipv4 = true;

        while i < max_iters {
            let item = line_split[i];
            if item == "via" {
                i += 1;
                debug!("default route parse: {}", line_split[i]);
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
                    let dr = DefaultRoute { via, dev };
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
        // default fe80::4a5f:8ff:fee0:1394%em1 UG em1
        let line_split: Vec<&str> = line
            .split(" ")
            .map(|x| x.trim())
            .filter(|v| v.len() > 0)
            .collect();

        let mut is_ipv4 = true;
        debug!("default route parse (unix): {}", line_split[1]);
        let via_str = if line_split[1].contains("%") {
            let via_split: Vec<&str> = line_split[1]
                .split("%")
                .map(|x| x.trim())
                .filter(|v| v.len() > 0)
                .collect();
            via_split[0]
        } else {
            line_split[1]
        };
        let via: IpAddr = via_str.parse()?;
        if line_split[1].contains(":") {
            is_ipv4 = false;
        }
        let dev = find_interface_by_subnetwork(via);

        match dev {
            Some(dev) => {
                let dr = DefaultRoute { via, dev };
                // println!("{:?}", dr);
                return Ok((dr, is_ipv4));
            }
            None => (),
        }

        Err(InvalidRouteFormat::new(line.to_string()).into())
    }
    #[cfg(target_os = "windows")]
    pub fn parse(line: &str) -> Result<(DefaultRoute, bool)> {
        let line_split: Vec<&str> = line
            .split(" ")
            .map(|x| x.trim())
            .filter(|v| v.len() > 0)
            .collect();

        if line_split.len() > 5 {
            let mut is_ipv4 = true;
            debug!("default route parse (windows): {}", line_split[2]);
            let via: IpAddr = line_split[2].parse()?;
            if line_split[2].contains(":") {
                is_ipv4 = false;
            }
            let if_index: u32 = line_split[0].parse()?;
            for interface in interfaces() {
                if if_index == interface.index {
                    let dr = DefaultRoute {
                        via,
                        dev: interface,
                    };
                    return Ok((dr, is_ipv4));
                }
            }
        }

        Err(InvalidRouteFormat::new(line.to_string()).into())
    }
}

#[derive(Debug, Clone)]
pub struct Route {
    pub dst: IpNetwork,        // Destination network or host address
    pub dev: NetworkInterface, // Device interface name
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
        let dst = IpNetwork::from_str(line_split[0])?;
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
                let r = Route { dst, dev };
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
        // println!("line: {}", line);
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
            let mut ret = dst_split[0].to_string();
            if dst_split[1].contains("/") {
                let i_split: Vec<&str> = dst_split[1]
                    .split("/")
                    .map(|x| x.trim())
                    .filter(|v| v.len() > 0)
                    .collect();
                ret += "/";
                ret += i_split[1];
            }
            ret
        } else {
            dst
        };

        let dst = IpNetwork::from_str(&dst)?;
        let dev_name = line_split[3];
        let dev = find_interface_by_name(dev_name);

        match dev {
            Some(dev) => {
                let r = Route { dst, dev };
                // println!("{:?}", r);
                return Ok(r);
            }
            None => (),
        }

        Err(InvalidRouteFormat::new(line.to_string()).into())
    }
    #[cfg(target_os = "windows")]
    pub fn parse(line: &str) -> Result<Route> {
        // 10 fe80::e186:d8c7:b82:159f/128 :: 256 25 ActiveStore
        let line_split: Vec<&str> = line
            .split(" ")
            .map(|x| x.trim())
            .filter(|v| v.len() > 0)
            .collect();

        let find_interface = |if_index: u32| -> Option<NetworkInterface> {
            for interface in interfaces() {
                if if_index == interface.index {
                    return Some(interface);
                }
            }
            None
        };

        if line_split.len() > 5 {
            let if_index: u32 = line_split[0].parse()?;
            let dst = line_split[1];
            let dst = IpNetwork::from_str(dst)?;
            let dev = find_interface(if_index);
            match dev {
                Some(dev) => {
                    let route = Route { dst, dev };
                    return Ok(route);
                }
                None => (),
            }
        }
        Err(InvalidRouteFormat::new(line.to_string()).into())
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
                match DefaultRoute::parse(line) {
                    Ok((d, is_ipv4)) => {
                        if is_ipv4 {
                            default_ipv4_route = Some(d);
                        } else {
                            default_ipv6_route = Some(d);
                        }
                    }
                    Err(e) => warn!("default route parse error: {}", e),
                }
            } else {
                match Route::parse(line) {
                    Ok(r) => routes.push(r),
                    Err(e) => warn!("route parse error: {}", e),
                };
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
                match DefaultRoute::parse(line) {
                    Ok((d, is_ipv4)) => {
                        if is_ipv4 {
                            default_ipv4_route = Some(d);
                        } else {
                            default_ipv6_route = Some(d);
                        }
                    }
                    Err(e) => warn!("default route parse error: {}", e),
                }
            } else {
                if line_split.len() >= 4 && (dst.contains(".") || dst.contains(":")) {
                    match Route::parse(line) {
                        Ok(r) => routes.push(r),
                        Err(e) => warn!("route parse error: {}", e),
                    };
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
        let c = Command::new("powershell").args(["Get-NetRoute"]).output()?;
        let output = String::from_utf8_lossy(&c.stdout);
        let route_lines: Vec<&str> = output
            .lines()
            .map(|x| x.trim())
            .filter(|v| v.len() > 0)
            .collect();

        let mut default_ipv4_route = None;
        let mut default_ipv6_route = None;
        let mut routes = Vec::new();

        for line in route_lines {
            match Route::parse(line) {
                Ok(r) => routes.push(r),
                Err(e) => warn!("route parse error: {}", e),
            };
            if line.contains("::/0") {
                let (r, _) = DefaultRoute::parse(line)?;
                default_ipv6_route = Some(r);
            } else if line.contains("0.0.0.0/0") {
                let (r, _) = DefaultRoute::parse(line)?;
                default_ipv4_route = Some(r);
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
pub struct SystemCache {
    pub route_table: RouteTable,
    pub neighbor_cache: HashMap<IpAddr, MacAddr>,
}

impl SystemCache {
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
            match line_split[0].parse() {
                Ok(ipaddr) => {
                    while i < max_iters {
                        let item = line_split[i];
                        if item == "lladdr" {
                            i += 1;
                            match line_split[i].parse() {
                                Ok(mac) => {
                                    ret.insert(ipaddr, mac);
                                    break;
                                }
                                Err(e) => warn!("neighbor cache parse mac error: {}", e),
                            }
                        }
                        i += 1;
                    }
                }
                Err(e) => warn!("neighbor cache parse ip error: {}", e),
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
        for line in lines {
            let line_split: Vec<&str> = line
                .split(" ")
                .map(|x| x.trim())
                .filter(|v| v.len() > 0)
                .collect();
            if line_split.len() > 3 {
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
                    match ip_str.parse() {
                        Ok(ip) => match line_split[1].parse() {
                            Ok(mac) => {
                                ret.insert(ip, mac);
                            }
                            Err(e) => warn!("neighbor cache parse mac error: {}", e),
                        },
                        Err(e) => warn!("neighbor cache parse ip error: {}", e),
                    }
                }
            }
        }
        Ok(ret)
    }
    #[cfg(target_os = "windows")]
    pub fn neighbor_cache_init() -> Result<HashMap<IpAddr, MacAddr>> {
        let c = Command::new("powershell")
            .args(["Get-NetNeighbor"])
            .output()?;
        let output = String::from_utf8_lossy(&c.stdout);
        let nei_lines: Vec<&str> = output
            .lines()
            .map(|x| x.trim())
            .filter(|v| v.len() > 0)
            .collect();

        let mut ret = HashMap::new();
        for line in nei_lines {
            let line_split: Vec<&str> = line
                .split(" ")
                .map(|x| x.trim())
                .filter(|v| v.len() > 0)
                .collect();

            if line_split.len() > 4 {
                match line_split[1].parse() {
                    Ok(ip) => match line_split[2].parse() {
                        Ok(mac) => {
                            ret.insert(ip, mac);
                        }
                        Err(e) => warn!("neighbor cache parse mac error: {}", e),
                    },
                    Err(e) => warn!("neighbor cache parse ip error: {}", e),
                }
            }
        }
        Ok(ret)
    }
    pub fn init() -> Result<SystemCache> {
        let route_table = RouteTable::init()?;
        debug!("route table done");
        let neighbor_cache = SystemCache::neighbor_cache_init()?;
        debug!("neighbor cache done");
        let lnc = SystemCache {
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
    pub fn update_neighbor_cache(&mut self, ipaddr: IpAddr, mac: MacAddr) {
        self.neighbor_cache.insert(ipaddr, mac);
    }
    pub fn search_route(&self, ipaddr: IpAddr) -> Result<Option<NetworkInterface>> {
        debug!("search route: {}", ipaddr);
        let route_table = &self.route_table;
        for route in &route_table.routes {
            let ipn = route.dst;
            if ipn.contains(ipaddr) {
                debug!(
                    "found route interface: {}, ip: {}, ipn: {}",
                    route.dev.name, ipaddr, ipn
                );
                return Ok(Some(route.dev.clone()));
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
    use std::time::Instant;
    // use crate::Logger;
    use pnet::datalink::interfaces;
    #[test]
    fn test_route_table() -> Result<()> {
        // let rt = RouteTable::init()?;
        // println!("{:?}", rt.default_ipv4_route);
        // println!("{:?}", rt.default_ipv6_route);

        // let routes = rt.routes;
        // for r in routes {
        //     let r_str = r.dst.to_string();
        //     println!("{}", r_str);
        // }
        // for route in rt.routes {
        //     println!("{:?}", route);
        // }
        let start = Instant::now();
        let _sc = SystemCache::init()?;
        println!("{:.3}s", start.elapsed().as_secs_f32());
        Ok(())
    }
    #[test]
    fn test_network_cache() -> Result<()> {
        let nc = SystemCache::init()?;
        // println!("{:?}", nc);
        println!("{:?}", nc.neighbor_cache);
        Ok(())
    }
    #[test]
    fn test_windows_interface() {
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
