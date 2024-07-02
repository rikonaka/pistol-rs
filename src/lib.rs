#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("lib.md")]
use anyhow::Result;
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::sync::Mutex;
use subnetwork::Ipv4Pool;

pub mod flood;
pub mod os;
pub mod ping;
pub mod scan;
pub mod vs;
// inner use only
mod errors;
mod layers;
mod route;
mod utils;

use crate::route::SystemCache;

// debug code
#[cfg(test)]
const DST_IPV4_REMOTE: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 51);
#[cfg(test)]
const DST_IPV4_LOCAL: Ipv4Addr = Ipv4Addr::new(192, 168, 72, 134);
#[cfg(test)]
const DST_IPV6_REMOTE: Ipv6Addr =
    Ipv6Addr::new(0x240e, 0x34c, 0x84, 0x86a0, 0x5054, 0xff, 0xfeb8, 0xb0ac);
#[cfg(test)]
const DST_IPV6_LOCAL: Ipv6Addr = Ipv6Addr::new(
    0xfe80, 0x0000, 0x0000, 0x0000, 0x020c, 0x29ff, 0xfeb6, 0x8d99,
);

static SYSTEM_CACHE: Lazy<Arc<Mutex<SystemCache>>> = Lazy::new(|| {
    let lnc = SystemCache::init().expect("can not init the system cache");
    Arc::new(Mutex::new(lnc))
});

const DEFAULT_TIMEOUT_SEC: u64 = 3;

pub struct Logger {}

impl Logger {
    pub fn init_debug_logging() -> Result<()> {
        let _ = env_logger::builder()
            // .target(env_logger::Target::Stdout)
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init()?;
        Ok(())
    }
    pub fn init_warn_logging() -> Result<()> {
        let _ = env_logger::builder()
            // .target(env_logger::Target::Stdout)
            .filter_level(log::LevelFilter::Warn)
            .is_test(true)
            .try_init()?;
        Ok(())
    }
    pub fn init_info_logging() -> Result<()> {
        let _ = env_logger::builder()
            // .target(env_logger::Target::Stdout)
            .filter_level(log::LevelFilter::Info)
            .is_test(true)
            .try_init()?;
        Ok(())
    }
}

// Ipv4Addr::is_global() and Ipv6Addr::is_global() is a nightly-only experimental API.
// Use this trait instead until its become stable function.
trait Ipv4CheckMethods {
    fn is_global_x(&self) -> bool;
}

impl Ipv4CheckMethods for Ipv4Addr {
    fn is_global_x(&self) -> bool {
        let octets = self.octets();
        let is_private = if octets[0] == 10 {
            true
        } else if octets[0] == 192 && octets[1] == 168 {
            true
        } else if octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31 {
            true
        } else {
            false
        };
        !is_private
    }
}

trait Ipv6CheckMethods {
    fn is_global_x(&self) -> bool;
}

impl Ipv6CheckMethods for Ipv6Addr {
    fn is_global_x(&self) -> bool {
        let octets = self.octets();
        let is_local = if octets[0] == 0b11111110 && octets[1] >> 6 == 0b00000010 {
            true
        } else {
            false
        };
        !is_local
    }
}

trait IpCheckMethods {
    fn is_global_x(&self) -> bool;
}

impl IpCheckMethods for IpAddr {
    fn is_global_x(&self) -> bool {
        match self {
            IpAddr::V4(ipv4) => ipv4.is_global_x(),
            IpAddr::V6(ipv6) => ipv6.is_global_x(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub addr: Ipv4Addr,
    pub ports: Vec<u16>,
}

impl Host {
    pub fn new(addr: Ipv4Addr, ports: Option<Vec<u16>>) -> Host {
        let h = match ports {
            Some(p) => Host { addr, ports: p },
            None => Host {
                addr,
                ports: vec![],
            },
        };
        h
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let result_str = format!("{} {:?}", self.addr, self.ports);
        write!(f, "{}", result_str)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host6 {
    pub addr: Ipv6Addr,
    pub ports: Vec<u16>,
}

impl Host6 {
    pub fn new(addr: Ipv6Addr, ports: Option<Vec<u16>>) -> Host6 {
        let h = match ports {
            Some(p) => Host6 { addr, ports: p },
            None => Host6 {
                addr,
                ports: vec![],
            },
        };
        h
    }
}

impl fmt::Display for Host6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let result_str = format!("{} {:?}", self.addr, self.ports);
        write!(f, "{}", result_str)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TargetType {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub target_type: TargetType,
    pub hosts: Vec<Host>,
    pub hosts6: Vec<Host6>,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut result_str = format!("Type: {:?}", self.target_type);
        match self.target_type {
            TargetType::Ipv4 => {
                for host in &self.hosts {
                    let s = format!("\n      {}", host);
                    result_str += &s;
                }
            }
            TargetType::Ipv6 => {
                for host6 in &self.hosts6 {
                    let s = format!("\n      {}", host6);
                    result_str += &s;
                }
            }
        }

        write!(f, "{}", result_str)
    }
}

impl Target {
    /// Scan different ports for different targets,
    /// for example, we want to scan ports 22 and 23 of "192.168.1.1" and ports 80 and 81 of "192.168.1.2",
    /// you can define the address and port range of each host yourself.
    /// ```rust
    /// use pistol::{Host, Target};
    /// use std::net::Ipv4Addr;
    ///
    /// fn test() {
    ///     let host1 = Host::new(Ipv4Addr::new(192, 168, 72, 135), Some(vec![22, 23]));
    ///     let host2 = Host::new(Ipv4Addr::new(192, 168, 1, 2), Some(vec![80, 81]));
    ///     let target = Target::new(vec![host1, host2]);
    /// }
    /// ```
    pub fn new(hosts: Vec<Host>) -> Target {
        Target {
            target_type: TargetType::Ipv4,
            hosts: hosts.to_vec(),
            hosts6: vec![],
        }
    }
    /// Ipv6 version.
    pub fn new6(hosts6: Vec<Host6>) -> Target {
        Target {
            target_type: TargetType::Ipv6,
            hosts: vec![],
            hosts6: hosts6.to_vec(),
        }
    }
    /// Scan a IPv4 subnet with same ports.
    /// ```rust
    /// use pistol::{Host, Target};
    /// use std::net::Ipv4Addr;
    ///
    /// fn test() {
    ///     let target = Target::from_subnet("192.168.1.0/24", Some(vec![22])).unwrap();
    /// }
    /// ```
    pub fn from_subnet(subnet: &str, ports: Option<Vec<u16>>) -> Result<Target> {
        let ipv4_pool = Ipv4Pool::from(subnet)?;
        let mut hosts = Vec::new();
        for addr in ipv4_pool {
            let h = Host::new(addr, ports.clone());
            hosts.push(h);
        }
        let target = Target {
            target_type: TargetType::Ipv4,
            hosts,
            hosts6: vec![],
        };
        Ok(target)
    }
}

/* Scan */

pub use scan::arp_scan;

pub use scan::tcp_connect_scan;
pub use scan::tcp_connect_scan6;

pub use scan::tcp_syn_scan;
pub use scan::tcp_syn_scan6;

pub use scan::tcp_fin_scan;
pub use scan::tcp_fin_scan6;

pub use scan::tcp_ack_scan;
pub use scan::tcp_ack_scan6;

pub use scan::tcp_null_scan;
pub use scan::tcp_null_scan6;

pub use scan::tcp_xmas_scan;
pub use scan::tcp_xmas_scan6;

pub use scan::tcp_window_scan;
pub use scan::tcp_window_scan6;

pub use scan::tcp_maimon_scan;
pub use scan::tcp_maimon_scan6;

pub use scan::tcp_idle_scan;

pub use scan::udp_scan;
pub use scan::udp_scan6;

pub use scan::scan;
pub use scan::scan6;

/* Ping */

pub use ping::tcp_syn_ping;
pub use ping::tcp_syn_ping6;

pub use ping::tcp_ack_ping;
pub use ping::tcp_ack_ping6;

pub use ping::udp_ping;
pub use ping::udp_ping6;

pub use ping::icmp_ping;
pub use ping::icmpv6_ping;

/* Flood */

pub use flood::icmp_flood;
pub use flood::icmp_flood6;

pub use flood::tcp_ack_flood;
pub use flood::tcp_ack_flood6;

pub use flood::tcp_ack_psh_flood;
pub use flood::tcp_ack_psh_flood6;

pub use flood::tcp_syn_flood;
pub use flood::tcp_syn_flood6;

pub use flood::udp_flood;
pub use flood::udp_flood6;

/* Finger Printing */

pub use os::dbparser::nmap_os_db_parser;
pub use os::os_detect;
pub use os::os_detect6;
pub use vs::vs_scan;

/* DNS */
pub use layers::dns_query;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_target_print() {
        let host1 = Host::new(Ipv4Addr::new(192, 168, 1, 135), Some(vec![22, 23]));
        let host2 = Host::new(Ipv4Addr::new(192, 168, 1, 2), Some(vec![80, 81]));
        let _target = Target::new(vec![host1, host2]);
        // println!("{}", target);
        assert_eq!(1, 1);
    }
}
