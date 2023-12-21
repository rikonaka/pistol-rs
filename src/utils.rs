use anyhow::Result;
use num_cpus;
use pnet::datalink;
use pnet::datalink::{MacAddr, NetworkInterface};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use subnetwork;
use subnetwork::{Ipv4Pool, Ipv6Pool};
use threadpool::ThreadPool;

use super::errors::{FindInterfaceError, GetInterfaceIPError, GetInterfaceMACError};
use super::Host;
use super::Host6;
use super::{BindIp2Interface, BindIp2Interface6};

const DEFAILT_MAX_LOOP: usize = 32;

/* CODE */

pub fn get_host_interfaces() -> Vec<NetworkInterface> {
    datalink::interfaces()
}

pub fn bind_interface(target_ips: &[Ipv4Addr]) -> Vec<BindIp2Interface> {
    let interfaces = get_host_interfaces();
    let mut ret: Vec<BindIp2Interface> = Vec::new();
    for tip in target_ips {
        let mut found_interface = false;
        for interface in &interfaces {
            for ip in &interface.ips {
                match ip.ip() {
                    IpAddr::V4(ipv4) => {
                        let prefix = ip.prefix();
                        let subnet = Ipv4Pool::new(ipv4, prefix).unwrap();
                        if subnet.contain(*tip) {
                            found_interface = true;
                            let bi = BindIp2Interface::new(*tip, Some(interface.clone()));
                            ret.push(bi);
                        }
                    }
                    _ => (),
                }
            }
        }
        if !found_interface {
            let bi = BindIp2Interface::new(*tip, None);
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
                    IpAddr::V6(ipv6) => {
                        let prefix = ip.prefix();
                        let subnet = Ipv6Pool::new(ipv6, prefix).unwrap();
                        if subnet.contain(*tip) {
                            found_interface = true;
                            let bi = BindIp2Interface6::new(*tip, Some(interface.clone()));
                            ret.push(bi);
                        }
                    }
                    _ => (),
                }
            }
        }
        if !found_interface {
            let bi = BindIp2Interface6::new(*tip, None);
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

/// Returns an interface that matches the name.
pub fn find_interface_by_name(interface_name: &str) -> Option<NetworkInterface> {
    let interfaces = get_host_interfaces();
    for interface in interfaces {
        // println!("{}", interface)
        if interface.name == interface_name {
            return Some(interface);
        }
    }
    None
}

/// Returns source ip of host machine interfaces.
pub fn get_interface_ip(interface: &NetworkInterface) -> Option<Ipv4Addr> {
    for i in &interface.ips {
        if i.is_ipv4() {
            match i.ip() {
                IpAddr::V4(ip) => return Some(ip),
                _ => (),
            }
        }
    }
    None
}

/// Returns source ip(v6) of host machine interfaces.
pub fn get_interface_ip6(interface: &NetworkInterface) -> Option<Ipv6Addr> {
    for i in &interface.ips {
        if i.is_ipv4() {
            match i.ip() {
                IpAddr::V6(ip) => return Some(ip),
                _ => (),
            }
        }
    }
    None
}

pub fn parse_interface(interface: &NetworkInterface) -> Result<(Ipv4Addr, MacAddr)> {
    let ipv4 = match get_interface_ip(&interface) {
        Some(ip) => ip,
        _ => return Err(GetInterfaceIPError::new(&interface.to_string()).into()),
    };
    let mac = match interface.mac {
        Some(m) => m,
        _ => return Err(GetInterfaceMACError::new(&interface.to_string()).into()),
    };

    Ok((ipv4, mac))
}

pub fn parse_interface6(interface: &NetworkInterface) -> Result<(Ipv6Addr, MacAddr)> {
    let ipv6 = match get_interface_ip6(&interface) {
        Some(ip) => ip,
        _ => return Err(GetInterfaceIPError::new(&interface.to_string()).into()),
    };
    let mac = match interface.mac {
        Some(m) => m,
        _ => return Err(GetInterfaceMACError::new(&interface.to_string()).into()),
    };

    Ok((ipv6, mac))
}

/// Convert user input interface and return (NetworkInterface, Ipv4Addr, MacAddr).
pub fn parse_interface_from_str(
    interface_name: &str,
) -> Result<(NetworkInterface, Ipv4Addr, MacAddr)> {
    let i = match find_interface_by_name(interface_name) {
        Some(i) => i,
        _ => return Err(FindInterfaceError::new(interface_name).into()),
    };
    let ipv4 = match get_interface_ip(&i) {
        Some(ip) => ip,
        _ => return Err(GetInterfaceIPError::new(&i.to_string()).into()),
    };
    let mac = match i.mac {
        Some(m) => m,
        _ => return Err(GetInterfaceMACError::new(&i.to_string()).into()),
    };

    Ok((i, ipv4, mac))
}

pub fn parse_interface_from_str6(
    interface_name: &str,
) -> Result<(NetworkInterface, Ipv6Addr, MacAddr)> {
    let i = match find_interface_by_name(interface_name) {
        Some(i) => i,
        _ => return Err(FindInterfaceError::new(interface_name).into()),
    };
    let ipv6 = match get_interface_ip6(&i) {
        Some(ip) => ip,
        _ => return Err(GetInterfaceIPError::new(&i.to_string()).into()),
    };
    let mac = match i.mac {
        Some(m) => m,
        _ => return Err(GetInterfaceMACError::new(&i.to_string()).into()),
    };

    Ok((i, ipv6, mac))
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
