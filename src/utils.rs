use escape_bytes;
use log::warn;
use num_cpus;
use pnet::datalink::interfaces;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use rand::Rng;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::time::Duration;
use threadpool::ThreadPool;

use crate::errors::PistolErrors;
use crate::route::DefaultRoute;
use crate::Ipv6CheckMethods;
use crate::DEFAULT_TIMEOUT;
use crate::SYSTEM_NET_CACHE;

const MAX_THREADS_NUM: usize = 1000;

pub fn threads_num_check(threads_num: usize) -> usize {
    let mut threads_num = threads_num;
    if threads_num > MAX_THREADS_NUM {
        warn!(
            "too many targets (real: {} => now: {}), consider using the _raw function",
            threads_num, MAX_THREADS_NUM
        );
        threads_num = MAX_THREADS_NUM;
    }
    threads_num
}

pub fn system_cache_search_route(dst_addr: IpAddr) -> Option<NetworkInterface> {
    // release the lock when leaving the function
    let snc = SYSTEM_NET_CACHE
        .lock()
        .expect("can not lock SYSTEM_NET_CACHE");
    snc.search_route(dst_addr)
}

pub fn system_cache_search_mac(dst_addr: IpAddr) -> Option<MacAddr> {
    // release the lock when leaving the function
    let snc = SYSTEM_NET_CACHE
        .lock()
        .expect("can not lock SYSTEM_NET_CACHE");
    snc.search_mac(dst_addr)
}

pub fn system_cache_default_route() -> Option<DefaultRoute> {
    // release the lock when leaving the function
    let snc = SYSTEM_NET_CACHE
        .lock()
        .expect("can not lock SYSTEM_NET_CACHE");
    snc.default_route.clone()
}

pub fn system_cache_default_route6() -> Option<DefaultRoute> {
    // release the lock when leaving the function
    let snc = SYSTEM_NET_CACHE
        .lock()
        .expect("can not lock SYSTEM_NET_CACHE");
    snc.default_route6.clone()
}

pub fn system_cache_update(addr: IpAddr, mac: MacAddr) {
    // release the lock when leaving the function
    let mut snc = SYSTEM_NET_CACHE
        .lock()
        .expect("can not lock SYSTEM_NET_CACHE");
    snc.update_neighbor_cache(addr, mac)
}

pub fn dst_ipv4_in_local(dst_ipv4: Ipv4Addr) -> bool {
    for interface in interfaces() {
        for ipnetwork in interface.ips {
            if ipnetwork.contains(dst_ipv4.into()) {
                return true;
            }
        }
    }
    warn!("can not found the dst ip in local net: {}", dst_ipv4);
    false
}

pub fn dst_ipv6_in_local(dst_ipv6: Ipv6Addr) -> bool {
    for interface in interfaces() {
        for ipnetwork in interface.ips {
            if ipnetwork.contains(dst_ipv6.into()) {
                return true;
            }
        }
    }
    warn!("can not found the dst ip in local net: {}", dst_ipv6);
    false
}

pub fn find_source_addr(
    src_addr: Option<IpAddr>,
    dst_ipv4: Ipv4Addr,
) -> Result<Option<Ipv4Addr>, PistolErrors> {
    match src_addr {
        Some(s) => match s {
            IpAddr::V6(_) => (),
            IpAddr::V4(s) => return Ok(Some(s)),
        },
        None => {
            match system_cache_search_route(dst_ipv4.into()) {
                Some(i) => {
                    for ipnetwork in i.ips {
                        match ipnetwork.ip() {
                            IpAddr::V4(src_ipv4) => {
                                if !src_ipv4.is_loopback() {
                                    return Ok(Some(src_ipv4));
                                }
                            }
                            _ => (),
                        }
                    }
                }
                None => {
                    // return the route ip
                    let route = match system_cache_default_route() {
                        Some(d) => d,
                        None => return Err(PistolErrors::CanNotFoundRouterAddress),
                    };
                    if let IpAddr::V4(route_ipv4) = route.via {
                        for interface in interfaces() {
                            for ipnetwork in interface.ips {
                                if ipnetwork.contains(route_ipv4.into()) {
                                    if let IpAddr::V4(src_ipv4) = ipnetwork.ip() {
                                        return Ok(Some(src_ipv4));
                                    }
                                }
                            }
                        }
                    }
                }
            };
        }
    }
    Ok(None)
}

pub fn find_source_addr6(
    src_addr: Option<IpAddr>,
    dst_ipv6: Ipv6Addr,
) -> Result<Option<Ipv6Addr>, PistolErrors> {
    match src_addr {
        Some(s) => match s {
            IpAddr::V4(_) => (),
            IpAddr::V6(s) => return Ok(Some(s)),
        },
        None => {
            match system_cache_search_route(dst_ipv6.into()) {
                Some(i) => {
                    for ipnetwork in i.ips {
                        match ipnetwork.ip() {
                            IpAddr::V6(src_ipv6) => {
                                if !src_ipv6.is_loopback() {
                                    if (dst_ipv6.is_global_x() && src_ipv6.is_global_x())
                                        || (!dst_ipv6.is_global_x() && !src_ipv6.is_global_x())
                                    {
                                        return Ok(Some(src_ipv6));
                                    }
                                }
                            }
                            _ => (),
                        }
                    }
                }
                None => {
                    // return the route ip
                    let route = match system_cache_default_route6() {
                        Some(d) => d,
                        None => return Err(PistolErrors::CanNotFoundRouterAddress),
                    };
                    if let IpAddr::V6(route_ipv6) = route.via {
                        for interface in interfaces() {
                            for ipnetwork in interface.ips {
                                if ipnetwork.contains(route_ipv6.into()) {
                                    if let IpAddr::V6(src_ipv6) = ipnetwork.ip() {
                                        return Ok(Some(src_ipv6));
                                    }
                                }
                            }
                        }
                    }
                }
            };
        }
    }
    Ok(None)
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "linux"
))]
pub fn find_interface_by_name(name: &str) -> Option<NetworkInterface> {
    for interface in interfaces() {
        if interface.name == name {
            return Some(interface);
        }
    }
    None
}

pub fn find_interface_by_ip(ipaddr: IpAddr) -> Option<NetworkInterface> {
    for interface in interfaces() {
        for ip in &interface.ips {
            let i = ip.ip();
            if ipaddr == i && !i.is_unspecified() {
                return Some(interface);
            }
        }
    }
    None
}

/// Returns the random port.
pub fn random_port() -> u16 {
    let mut rng = rand::thread_rng();
    rng.gen_range(10000..=65535)
}

pub fn random_port_sp(start: u16, end: u16) -> u16 {
    let mut rng = rand::thread_rng();
    rng.gen_range(start..=end)
}

/// Returns the number of CPUs in the machine.
pub fn get_cpu_num() -> usize {
    num_cpus::get()
}

pub fn get_threads_pool(threads_num: usize) -> ThreadPool {
    let pool = if threads_num > 0 {
        ThreadPool::new(threads_num)
    } else {
        let cpus = get_cpu_num();
        ThreadPool::new(cpus)
    };
    pool
}

pub fn get_default_timeout() -> Duration {
    Duration::new(DEFAULT_TIMEOUT, 0)
}

pub struct SpHex {
    pub hex: Option<String>, // hex => dec
}

impl SpHex {
    pub fn new_hex(hex_str: &str) -> SpHex {
        SpHex {
            hex: Some(SpHex::length_completion(hex_str).to_string()),
        }
    }
    pub fn length_completion(hex_str: &str) -> String {
        let hex_str_len = hex_str.len();
        if hex_str_len % 2 == 1 {
            format!("0{}", hex_str)
        } else {
            hex_str.to_string()
        }
    }
    pub fn vec_4u8_to_u32(input: &[u8]) -> u32 {
        let mut ret = 0;
        let mut i = input.len();
        for v in input {
            let mut new_v = *v as u32;
            i -= 1;
            new_v <<= i * 8;
            ret += new_v;
        }
        ret
    }
    pub fn decode(&self) -> Result<u32, PistolErrors> {
        match &self.hex {
            Some(hex_str) => match hex::decode(hex_str) {
                Ok(d) => Ok(SpHex::vec_4u8_to_u32(&d)),
                Err(e) => Err(e.into()),
            },
            None => panic!("set value before decode!"),
        }
    }
}

pub fn unescape_string(input: &str) -> Result<Vec<u8>, PistolErrors> {
    let output = match escape_bytes::unescape(input.as_bytes()) {
        Ok(o) => o,
        Err(e) => {
            return Err(PistolErrors::CanNotUnescapeString {
                s: input.to_string(),
                e: format!("{:?}", e),
            })
        }
    };
    Ok(output)
}

pub fn vs_probe_data_to_string(input: &[u8]) -> String {
    let mut ret = String::new();
    for i in input {
        if *i >= 32 && *i <= 126 {
            let s = (*i as char).to_string();
            ret += &s;
        } else if *i == 0 {
            ret += "\\0";
        } else {
            let s = format!("\\x{:02x}", i);
            ret += &s;
        }
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vs_probe_to_string() {
        let data = vec![0, 0, 0x3f, 0x9f];
        let data_str = vs_probe_data_to_string(&data);
        println!("{}", data_str);
    }
    #[test]
    fn test_unescape() {
        let test_str = r"\x80\0\0\x28\x72\xFE\x1D\x13\0\0\0\0\0\0\0\x02\0\x01\x86\xA0\0\x01\x97\x7C\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let output = unescape_string(&test_str).unwrap();
        println!("{:?}", output);
    }
    #[test]
    fn test_convert() {
        let v: Vec<u8> = vec![1, 1];
        let r = SpHex::vec_4u8_to_u32(&v);
        assert_eq!(r, 257);

        let s = "51E80C";
        let h = SpHex::new_hex(s);
        let r = h.decode().unwrap();
        assert_eq!(r, 5367820);

        let s = "1C";
        let h = SpHex::new_hex(s);
        let r = h.decode().unwrap();
        assert_eq!(r, 28);

        let s = "A";
        let h = SpHex::new_hex(s);
        let r = h.decode().unwrap();
        assert_eq!(r, 10);
    }
    #[test]
    fn test_get_cpus() {
        let cpus = get_cpu_num();
        println!("{}", cpus);
    }
}
