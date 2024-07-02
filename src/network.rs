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
    pub fn parse(line: &str) -> Result<DefaultRoute> {
        // default 192.168.72.2 UGS em0
        let line_split: Vec<&str> = line
            .split(" ")
            .map(|x| x.trim())
            .filter(|v| v.len() > 0)
            .collect();
        let dst = String::from("default");
        let via: IpAddr = line_split[1].parse()?;
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
                return Ok(dr);
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
            dst_split[0].to_string
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
    pub fn from_system() -> Result<RouteTable> {
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
    pub fn from_system() -> Result<RouteTable> {
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
    #[cfg(target_os = "windows")]
    pub fn from_system() -> Result<RouteTable> {
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
    pub fn init() -> Result<NetworkCache> {
        let route_table = RouteTable::from_system()?;
        let neighbor_cache = HashMap::new();
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::datalink::interfaces;
    #[test]
    fn test_route_table() -> Result<()> {
        let rt = RouteTable::from_system()?;
        println!("{:?}", rt.default_ipv4_route);
        println!("{:?}", rt.default_ipv6_route);
        println!("{:?}", rt.routes);
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
