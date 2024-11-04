#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("lib.md")]
use anyhow::Result;
use log::debug;
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
pub mod hop;
pub mod os;
pub mod ping;
pub mod scan;
pub mod vs;
// inner use only
mod errors;
mod layers;
mod route;
mod utils;

use crate::route::SystemNetCache;

// debug code
// #[cfg(test)]
// const TEST_IPV4_REMOTE: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
#[cfg(test)]
const TEST_IPV4_LOCAL: Ipv4Addr = Ipv4Addr::new(192, 168, 5, 133);
#[cfg(test)]
const TEST_IPV6_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x20c, 0x29ff, 0xfe2c, 0x9e4);

static SYSTEM_CACHE: Lazy<Arc<Mutex<SystemNetCache>>> = Lazy::new(|| {
    let lnc = SystemNetCache::init().expect("can not init the system cache");
    Arc::new(Mutex::new(lnc))
});

const DEFAULT_TIMEOUT: u64 = 3;

pub struct Logger {}

impl Logger {
    pub fn init_debug_logging() -> Result<()> {
        let _ = env_logger::builder()
            // .target(env_logger::Target::Stdout)
            .filter_level(log::LevelFilter::Debug)
            .is_test(false)
            .try_init()?;
        Ok(())
    }
    pub fn init_warn_logging() -> Result<()> {
        let _ = env_logger::builder()
            // .target(env_logger::Target::Stdout)
            .filter_level(log::LevelFilter::Warn)
            .is_test(false)
            .try_init()?;
        Ok(())
    }
    pub fn init_info_logging() -> Result<()> {
        let _ = env_logger::builder()
            // .target(env_logger::Target::Stdout)
            .filter_level(log::LevelFilter::Info)
            .is_test(false)
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
        debug!("ip: {}, is_global_x: {}", self, !is_private);
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
        debug!("ip: {}, is_global_x: {}", self, !is_local);
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
    pub addr: IpAddr,
    pub ports: Vec<u16>,
}

impl Host {
    pub fn new(addr: IpAddr, ports: Option<Vec<u16>>) -> Host {
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
        let output_str = format!("{} {:?}", self.addr, self.ports);
        write!(f, "{}", output_str)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub hosts: Vec<Host>,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output_str = String::new();
        for host in &self.hosts {
            let s = format!("{}\n", host);
            output_str += &s;
        }
        write!(f, "{}", output_str)
    }
}

impl Target {
    /// Scan different ports for different targets,
    /// for example, we want to scan ports 22 and 23 of "192.168.1.1" and ports 80 and 81 of "192.168.1.2",
    /// you can define the address and port range of each host yourself.
    /// ```rust
    /// use pistol::Target;
    /// use pistol::Host;
    /// use std::net::Ipv4Addr;
    /// use std::net::Ipv6Addr;
    ///
    /// fn test() {
    ///     let host1 = Host::new(Ipv4Addr::new(192, 168, 72, 135).into(), Some(vec![22, 23]));
    ///     let host2 = Host::new(Ipv6Addr::new(0xfe80, 0x0000, 0x0000, 0x0000, 0x020c, 0x29ff, 0xfeb6, 0x8d99).into(), Some(vec![80, 81]));
    ///     let target = Target::new(vec![host1, host2]);
    /// }
    /// ```
    pub fn new(hosts: Vec<Host>) -> Target {
        Target { hosts }
    }
    /// Scan a IPv4 subnet with same ports.
    /// ```rust
    /// use pistol::Target;
    /// use pistol::Host;
    /// use std::net::Ipv4Addr;
    ///
    /// fn test() {
    ///     let target = Target::from_subnet("192.168.1.0/24", Some(vec![22])).unwrap();
    /// }
    /// ```
    pub fn from_subnet(subnet: &str, ports: Option<Vec<u16>>) -> Result<Target> {
        let ipv4_pool = Ipv4Pool::from(subnet)?;
        let mut hosts = Vec::new();
        for ipv4_addr in ipv4_pool {
            let h = Host::new(ipv4_addr.into(), ports.clone());
            hosts.push(h);
        }
        let target = Target { hosts };
        Ok(target)
    }
}

/* Scan */

pub use scan::arp_scan;
pub use scan::arp_scan_raw;
pub use scan::scan;
pub use scan::scan_raw;
pub use scan::tcp_ack_scan;
pub use scan::tcp_ack_scan_raw;
pub use scan::tcp_connect_scan;
pub use scan::tcp_connect_scan_raw;
pub use scan::tcp_fin_scan;
pub use scan::tcp_fin_scan_raw;
pub use scan::tcp_idle_scan;
pub use scan::tcp_idle_scan_raw;
pub use scan::tcp_maimon_scan;
pub use scan::tcp_maimon_scan_raw;
pub use scan::tcp_null_scan;
pub use scan::tcp_null_scan_raw;
pub use scan::tcp_syn_scan;
pub use scan::tcp_syn_scan_raw;
pub use scan::tcp_window_scan;
pub use scan::tcp_window_scan_raw;
pub use scan::tcp_xmas_scan;
pub use scan::tcp_xmas_scan_raw;
pub use scan::udp_scan;
pub use scan::udp_scan_raw;

/* Ping */

pub use ping::icmp_ping;
pub use ping::icmp_ping_raw;
pub use ping::ping;
pub use ping::tcp_ack_ping;
pub use ping::tcp_ack_ping_raw;
pub use ping::tcp_syn_ping;
pub use ping::tcp_syn_ping_raw;
pub use ping::udp_ping;
pub use ping::udp_ping_raw;

/* Flood */

pub use flood::flood;
pub use flood::flood_raw;
pub use flood::icmp_flood;
pub use flood::icmp_flood_raw;
pub use flood::tcp_ack_flood;
pub use flood::tcp_ack_flood_raw;
pub use flood::tcp_ack_psh_flood;
pub use flood::tcp_ack_psh_flood_raw;
pub use flood::tcp_syn_flood;
pub use flood::tcp_syn_flood_raw;
pub use flood::udp_flood;
pub use flood::udp_flood_raw;

/* Finger Printing */

pub use os::os_detect;
pub use os::os_detect_raw;
pub use vs::vs_scan;
pub use vs::vs_scan_raw;

/* DNS */
pub use layers::dns_query;
