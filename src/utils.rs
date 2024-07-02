use anyhow::Result;
use log::debug;
use log::warn;
use num_cpus;
use pnet::datalink::interfaces;
use pnet::datalink::NetworkInterface;
use rand::Rng;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::time::Duration;
use threadpool::ThreadPool;

use crate::errors::CanNotFoundRouterAddress;
use crate::Ipv6CheckMethods;
use crate::DEFAULT_TIMEOUT_SEC;
use crate::SYSTEM_CACHE;

pub fn dst_ipv4_in_local(dst_ipv4: Ipv4Addr) -> bool {
    for interface in interfaces() {
        for ipnetwork in interface.ips {
            if ipnetwork.contains(dst_ipv4.into()) {
                debug!("found dst ipv4: {} in local net", dst_ipv4);
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
                debug!("found dst ipv6: {} in local net", dst_ipv6);
                return true;
            }
        }
    }
    warn!("can not found the dst ip in local net: {}", dst_ipv6);
    false
}

pub fn find_source_addr(
    src_ipv4: Option<Ipv4Addr>,
    dst_ipv4: Ipv4Addr,
) -> Result<Option<Ipv4Addr>> {
    match src_ipv4 {
        Some(s) => return Ok(Some(s)),
        None => {
            let sc = SYSTEM_CACHE.lock().expect("can not lock the network cache");
            match sc.search_route(dst_ipv4.into())? {
                Some(i) => {
                    for ipnetwork in i.ips {
                        match ipnetwork.ip() {
                            IpAddr::V4(src_ipv4) => {
                                if !src_ipv4.is_loopback() {
                                    debug!("found source addr: {}", src_ipv4);
                                    return Ok(Some(src_ipv4));
                                }
                            }
                            _ => (),
                        }
                    }
                }
                None => {
                    // return the route ip
                    let route = match sc.default_ipv4_route() {
                        Some(d) => d,
                        None => return Err(CanNotFoundRouterAddress::new().into()),
                    };
                    if let IpAddr::V4(route_ipv4) = route.via {
                        for interface in interfaces() {
                            for ipnetwork in interface.ips {
                                if ipnetwork.contains(route_ipv4.into()) {
                                    if let IpAddr::V4(src_ipv4) = ipnetwork.ip() {
                                        debug!("can not found source addr, use addr which same subnet with route instead: {}", src_ipv4);
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
    debug!("can not found source of the dst: {}", dst_ipv4);
    Ok(None)
}

pub fn find_source_addr6(
    src_ipv6: Option<Ipv6Addr>,
    dst_ipv6: Ipv6Addr,
) -> Result<Option<Ipv6Addr>> {
    match src_ipv6 {
        Some(s) => return Ok(Some(s)),
        None => {
            let sc = SYSTEM_CACHE.lock().expect("can not lock the network cache");
            match sc.search_route(dst_ipv6.into())? {
                Some(i) => {
                    for ipnetwork in i.ips {
                        match ipnetwork.ip() {
                            IpAddr::V6(src_ipv6) => {
                                if !src_ipv6.is_loopback() {
                                    if (dst_ipv6.is_global_x() && src_ipv6.is_global_x())
                                        || (!dst_ipv6.is_global_x() && !src_ipv6.is_global_x())
                                    {
                                        debug!("found source addr: {}", src_ipv6);
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
                    let route = match sc.default_ipv6_route() {
                        Some(d) => d,
                        None => return Err(CanNotFoundRouterAddress::new().into()),
                    };
                    if let IpAddr::V6(route_ipv6) = route.via {
                        for interface in interfaces() {
                            for ipnetwork in interface.ips {
                                if ipnetwork.contains(route_ipv6.into()) {
                                    if let IpAddr::V6(src_ipv6) = ipnetwork.ip() {
                                        debug!("can not found source addr, use addr which same subnet with route instead: {}", src_ipv6);
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
    debug!("can not found source of the dst: {}", dst_ipv6);
    Ok(None)
}

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
            if ipaddr == ip.ip() && !ip.ip().is_unspecified() {
                debug!("found the interface: {}, by {}", interface.name, ipaddr);
                return Some(interface);
            }
        }
    }
    debug!("can not found interface of the ip: {}", ipaddr);
    None
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub fn find_interface_by_subnetwork(ipaddr: IpAddr) -> Option<NetworkInterface> {
    for interface in interfaces() {
        for ip in &interface.ips {
            if ip.contains(ipaddr) {
                debug!("found the interface (unix): {}, by {}", interface.name, ipaddr);
                return Some(interface);
            }
        }
    }
    debug!("can not found interface of the ip: {}", ipaddr);
    None
}

/// Returns the random port.
pub fn random_port() -> u16 {
    let mut rng = rand::thread_rng();
    rng.gen_range(1024..=65535)
}

/// Returns many random ports.
pub fn random_port_multi(num: usize) -> Vec<u16> {
    let mut rng = rand::thread_rng();
    let mut ret = Vec::new();
    for _ in 0..num {
        let p = rng.gen_range(1024..=65535);
        ret.push(p)
    }
    ret
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
    Duration::new(DEFAULT_TIMEOUT_SEC, 0)
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
    pub fn decode(&self) -> Result<u32> {
        match &self.hex {
            Some(hex_str) => match hex::decode(hex_str) {
                Ok(d) => Ok(SpHex::vec_4u8_to_u32(&d)),
                Err(e) => Err(e.into()),
            },
            None => panic!("set value before decode!"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::datalink;
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
    fn test_list_interfaces() {
        for interface in datalink::interfaces() {
            // println!("{}", interface)
            let ips = interface.ips;
            for ip in ips {
                match ip.ip() {
                    IpAddr::V6(i) => {
                        println!("{}", i);
                    }
                    _ => (),
                }
            }
        }
    }
    #[test]
    fn test_get_cpus() {
        let cpus = get_cpu_num();
        println!("{}", cpus);
    }
    #[test]
    fn test_find_source_ipv6() {
        let dst_ipv6: Ipv6Addr = "fe80::cc6c:3960:8be6:579".parse().unwrap();
        let find = find_source_addr6(None, dst_ipv6).unwrap().unwrap();
        println!("{}", find);

        let dst_ipv6: Ipv6Addr = "2001:da8:8000:1::80".parse().unwrap();
        let find = find_source_addr6(None, dst_ipv6).unwrap().unwrap();
        println!("{}", find);
    }
}
