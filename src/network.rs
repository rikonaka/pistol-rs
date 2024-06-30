use anyhow::Result;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;

use crate::errors::InvalidRouteFormat;
use crate::utils::find_interface_by_name;

// ubuntu22.04 output:
// default via 192.168.72.2 dev ens33
// 192.168.1.0/24 dev ens36 proto kernel scope link src 192.168.1.132
// 192.168.72.0/24 dev ens33 proto kernel scope link src 192.168.72.128
// centos7 output:
// default via 192.168.72.2 dev ens33 proto dhcp metric 100
// 192.168.72.0/24 dev ens33 proto kernel scope link src 192.168.72.138 metric 100
#[derive(Debug, Clone)]
pub struct LinuxDefaultRoute {
    pub dst: String,           // Destination network or host address
    pub via: IpAddr,           // Next hop gateway address
    pub dev: NetworkInterface, // Device interface name
    pub raw: String,           // The raw output
}

impl LinuxDefaultRoute {
    pub fn parse(line: &str) -> Result<LinuxDefaultRoute> {
        // default via 192.168.72.2 dev ens33
        let line_split: Vec<&str> = line.split(" ").collect();
        let max_iters = line_split.len();
        let mut i = 0;
        let dst = line_split[0].to_string();
        let mut via = None;
        let mut dev = None;

        while i < max_iters {
            let item = line_split[i];
            if item == "via" {
                i += 1;
                let v: IpAddr = line_split[i].parse()?;
                via = Some(v);
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
                    let ldr = LinuxDefaultRoute {
                        dst,
                        via,
                        dev,
                        raw: line.to_string(),
                    };
                    return Ok(ldr);
                }
                None => (),
            },
            None => (),
        }

        Err(InvalidRouteFormat::new(line.to_string()).into())
    }
}

#[derive(Debug, Clone)]
pub struct LinuxRoute {
    pub dst: String,           // Destination network or host address
    pub dev: NetworkInterface, // Device interface name
    pub proto: String,         // The protocol source of the route
    pub scope: String,         // The scope of the route
    pub src: IpAddr,           // Source address
    pub raw: String,           // The raw output
}

impl LinuxRoute {
    pub fn parse(line: &str) -> Result<LinuxRoute> {
        // 192.168.1.0/24 dev ens36 proto kernel scope link src 192.168.1.132
        let line_split: Vec<&str> = line.split(" ").collect();
        let max_iters = line_split.len();
        let mut i = 0;
        let dst = line_split[0].to_string();
        let mut dev = None;
        let mut proto = String::new();
        let mut scope = String::new();
        let mut src = None;

        while i < max_iters {
            let item = line_split[i];
            if item == "dev" {
                i += 1;
                let dev_name = line_split[i];
                let d = find_interface_by_name(dev_name);
                dev = d;
            } else if item == "proto" {
                i += 1;
                proto = line_split[i].to_string();
            } else if item == "scope" {
                i += 1;
                scope = line_split[i].to_string();
            } else if item == "src" {
                i += 1;
                let s: IpAddr = line_split[i].parse()?;
                src = Some(s);
            }
            i += 1;
        }

        match dev {
            Some(dev) => match src {
                Some(src) => {
                    let lr = LinuxRoute {
                        dst,
                        dev,
                        proto,
                        scope,
                        src,
                        raw: line.to_string(),
                    };
                    return Ok(lr);
                }
                None => (),
            },
            None => (),
        }

        Err(InvalidRouteFormat::new(line.to_string()).into())
    }
}

#[derive(Debug, Clone)]
pub struct LinuxRouteTable {
    pub default_route: Option<LinuxDefaultRoute>,
    pub routes: Vec<LinuxRoute>,
}

impl LinuxRouteTable {
    pub fn from_system() -> Result<LinuxRouteTable> {
        let c = Command::new("sh").args(["-c", "ip route"]).output()?;
        let output = String::from_utf8_lossy(&c.stdout);
        let lines: Vec<&str> = output
            .lines()
            .map(|x| x.trim())
            .filter(|v| v.len() > 0)
            .collect();

        let mut default_route = None;
        let mut routes = Vec::new();

        for line in lines {
            let line_split: Vec<&str> = line.split(" ").collect();
            let dst = line_split[0];
            if dst == "default" {
                let d = LinuxDefaultRoute::parse(line)?;
                default_route = Some(d);
            } else {
                let r = LinuxRoute::parse(line)?;
                routes.push(r);
            }
        }

        let lrt = LinuxRouteTable {
            default_route,
            routes,
        };
        Ok(lrt)
    }
}

#[derive(Debug, Clone)]
pub struct WindowsRouteTable {}

#[derive(Debug, Clone)]
pub struct NetworkCache {
    #[cfg(target_os = "linux")]
    pub route_table: LinuxRouteTable,
    #[cfg(target_os = "windows")]
    pub route_table: WindowsRouteTable,
    pub neighbor_cache: HashMap<IpAddr, MacAddr>,
}

impl NetworkCache {
    pub fn init() -> Result<NetworkCache> {
        #[cfg(target_os = "linux")]
        let route_table = LinuxRouteTable::from_system()?;
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
    #[test]
    fn test_linux_route_table() -> Result<()> {
        let lrt = LinuxRouteTable::from_system()?;
        println!("{:?}", lrt);
        Ok(())
    }
}