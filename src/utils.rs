use anyhow::Result;
use num_cpus;
use pnet::datalink;
use pnet::datalink::NetworkInterface;
use rand::Rng;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::time::Duration;
use threadpool::ThreadPool;

use crate::layers::system_route;
use crate::DEFAULT_TIMEOUT;

pub fn find_source_ipv4(
    src_ipv4: Option<Ipv4Addr>,
    dst_ipv4: Ipv4Addr,
) -> Result<Option<Ipv4Addr>> {
    match src_ipv4 {
        Some(s) => return Ok(Some(s)),
        None => {
            let route_ipv4 = system_route()?;
            for interface in datalink::interfaces() {
                for ipnetwork in interface.ips {
                    match ipnetwork.ip() {
                        IpAddr::V4(ipv4) => {
                            if ipnetwork.contains(dst_ipv4.into()) {
                                return Ok(Some(ipv4));
                            } else if ipnetwork.contains(route_ipv4.into()) {
                                return Ok(Some(ipv4));
                            }
                        }
                        _ => (),
                    }
                }
            }
        }
    }
    Ok(None)
}

pub fn find_source_ipv6(
    src_ipv6: Option<Ipv6Addr>,
    dst_ipv6: Ipv6Addr,
) -> Result<Option<Ipv6Addr>> {
    match src_ipv6 {
        Some(s) => return Ok(Some(s)),
        None => {
            for interface in datalink::interfaces() {
                for ipnetwork in interface.ips {
                    match ipnetwork.ip() {
                        IpAddr::V6(ipv6) => {
                            if ipnetwork.contains(dst_ipv6.into()) {
                                return Ok(Some(ipv6));
                            } else if dst_ipv6.is_global() && ipv6.is_unicast_global() {
                                return Ok(Some(ipv6));
                            } else if dst_ipv6.is_unicast_global() && ipv6.is_unicast_global() {
                                return Ok(Some(ipv6));
                            } else if dst_ipv6.is_unicast_link_local()
                                && ipv6.is_unicast_link_local()
                            {
                                return Ok(Some(ipv6));
                            }
                        }
                        _ => (),
                    }
                }
            }
        }
    }
    Ok(None)
}

pub fn find_interface_by_ipv4(src_ipv4: Ipv4Addr) -> Option<NetworkInterface> {
    for interface in datalink::interfaces() {
        for ip in &interface.ips {
            match ip.ip() {
                IpAddr::V4(ipv4) => {
                    if ipv4 == src_ipv4 {
                        return Some(interface);
                    }
                }
                _ => (),
            }
        }
    }
    None
}

pub fn find_interface_by_ipv6(src_ipv6: Ipv6Addr) -> Option<NetworkInterface> {
    for interface in datalink::interfaces() {
        for ip in &interface.ips {
            match ip.ip() {
                IpAddr::V6(ipv6) => {
                    if ipv6 == src_ipv6 {
                        return Some(interface);
                    }
                }
                _ => (),
            }
        }
    }
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
    Duration::new(DEFAULT_TIMEOUT, 0)
}

pub struct Hex {
    pub hex: Option<String>, // hex => dec
}

impl Hex {
    pub fn new_hex(hex_str: &str) -> Hex {
        Hex {
            hex: Some(Hex::length_completion(hex_str).to_string()),
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
                Ok(d) => Ok(Hex::vec_4u8_to_u32(&d)),
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
        let r = Hex::vec_4u8_to_u32(&v);
        assert_eq!(r, 257);

        let s = "51E80C";
        let h = Hex::new_hex(s);
        let r = h.decode().unwrap();
        assert_eq!(r, 5367820);

        let s = "1C";
        let h = Hex::new_hex(s);
        let r = h.decode().unwrap();
        assert_eq!(r, 28);

        let s = "A";
        let h = Hex::new_hex(s);
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
        let find = find_source_ipv6(None, dst_ipv6).unwrap().unwrap();
        println!("{}", find);

        let dst_ipv6: Ipv6Addr = "2001:da8:8000:1::80".parse().unwrap();
        let find = find_source_ipv6(None, dst_ipv6).unwrap().unwrap();
        println!("{}", find);
    }
}
