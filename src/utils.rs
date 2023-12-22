use anyhow::Result;
use num_cpus;
use pnet::datalink;
use pnet::datalink::NetworkInterface;
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use subnetwork;
use subnetwork::{Ipv4Pool, Ipv6Pool};
use threadpool::ThreadPool;

use super::Host;
use super::Host6;
use super::{BindIp2Interface, BindIp2Interface6};

const DEFAILT_MAX_LOOP: usize = 32;

/* CODE */

pub fn get_host_interfaces() -> Vec<NetworkInterface> {
    datalink::interfaces()
}

pub fn bind_interface(target_ips: &Vec<Ipv4Addr>) -> Vec<BindIp2Interface> {
    let interfaces = get_host_interfaces();
    let mut ret: Vec<BindIp2Interface> = Vec::new();
    for dst_ipv4 in target_ips {
        let mut found_interface = false;
        for interface in &interfaces {
            for ip in &interface.ips {
                match ip.ip() {
                    IpAddr::V4(src_ipv4) => {
                        let prefix = ip.prefix();
                        let subnet = Ipv4Pool::new(src_ipv4, prefix).unwrap();
                        if subnet.contain(*dst_ipv4) {
                            found_interface = true;
                            let src_mac = interface.mac;
                            let bi = BindIp2Interface::new(
                                *dst_ipv4,
                                Some(src_ipv4),
                                src_mac,
                                Some(interface.clone()),
                            );
                            ret.push(bi);
                        }
                    }
                    _ => (),
                }
            }
        }
        if !found_interface {
            let bi = BindIp2Interface::new(*dst_ipv4, None, None, None);
            ret.push(bi);
        }
    }
    ret
}

pub fn bind_interface6(target_ips: &[Ipv6Addr]) -> Vec<BindIp2Interface6> {
    let interfaces = get_host_interfaces();
    let mut ret: Vec<BindIp2Interface6> = Vec::new();
    for tip in target_ips {
        let mut found_interface = false;
        for interface in &interfaces {
            for ip in &interface.ips {
                match ip.ip() {
                    IpAddr::V6(src_ipv6) => {
                        let prefix = ip.prefix();
                        let subnet = Ipv6Pool::new(src_ipv6, prefix).unwrap();
                        if subnet.contain(*tip) {
                            found_interface = true;
                            let src_mac = interface.mac;
                            let bi = BindIp2Interface6::new(
                                *tip,
                                Some(src_ipv6),
                                src_mac,
                                Some(interface.clone()),
                            );
                            ret.push(bi);
                        }
                    }
                    _ => (),
                }
            }
        }
        if !found_interface {
            let bi = BindIp2Interface6::new(*tip, None, None, None);
            ret.push(bi);
        }
    }
    ret
}

pub fn get_ips_from_host(hosts: &[Host]) -> Vec<Ipv4Addr> {
    let mut target_ips = Vec::new();
    for h in hosts {
        target_ips.push(h.addr);
    }
    target_ips
}

pub fn get_ips_from_host6(hosts: &[Host6]) -> Vec<Ipv6Addr> {
    let mut target_ips = Vec::new();
    for h in hosts {
        target_ips.push(h.addr);
    }
    target_ips
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

pub fn get_max_loop(max_loop: Option<usize>) -> usize {
    match max_loop {
        Some(m) => m,
        _ => DEFAILT_MAX_LOOP,
    }
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
    pub fn vec_4u8_to_u32(input: &Vec<u8>) -> u32 {
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
    use pnet::datalink::interfaces;
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
        for interface in interfaces() {
            // println!("{}", interface)
            let ips = interface.ips;
            for ip in ips {
                match ip.ip() {
                    IpAddr::V4(i) => {
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
    fn test_i() {
        let interfaces = get_host_interfaces();
        for interface in &interfaces {
            for ip in &interface.ips {
                if ip.is_ipv4() {
                    println!("{}", ip.prefix());
                }
            }
        }
    }
}
