use anyhow::Result;
use num_cpus;
use pnet_datalink::{MacAddr, NetworkInterface};
use rand::Rng;
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
// use subnetwork::Ipv4Pool;
use threadpool::ThreadPool;

const DEFAILT_MAX_WAIT: usize = 128;

/* FindInterfaceError */
#[derive(Debug, Clone)]
pub struct FindInterfaceError {
    interface: String,
}

impl fmt::Display for FindInterfaceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "can not found interface {}", self.interface)
    }
}

impl FindInterfaceError {
    pub fn new(interface: String) -> FindInterfaceError {
        FindInterfaceError { interface }
    }
}

impl Error for FindInterfaceError {}

/* GetInterfaceIPError */
#[derive(Debug, Clone)]
pub struct GetInterfaceIPError {
    interface: String,
}

impl fmt::Display for GetInterfaceIPError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "can not get ip from interface {}", self.interface)
    }
}

impl GetInterfaceIPError {
    pub fn new(interface: String) -> GetInterfaceIPError {
        GetInterfaceIPError { interface }
    }
}

impl Error for GetInterfaceIPError {}

/* GetInterfaceIPError */
#[derive(Debug, Clone)]
pub struct GetInterfaceMACError {
    interface: String,
}

impl fmt::Display for GetInterfaceMACError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "can not get mac from interface {}", self.interface)
    }
}

impl GetInterfaceMACError {
    pub fn new(interface: String) -> GetInterfaceMACError {
        GetInterfaceMACError { interface }
    }
}

impl Error for GetInterfaceMACError {}

/* CODE */

// pub fn get_host_interfaces() -> Vec<NetworkInterface> {
//     pnet_datalink::interfaces()
// }

/// Returns an interface that matches the subnet
// pub fn find_interface_by_subnet(subnet: &Ipv4Pool) -> Option<NetworkInterface> {
//     let interfaces = get_host_interfaces();
//     for interface in &interfaces {
//         for ip in &interface.ips {
//             match ip.ip() {
//                 IpAddr::V4(i) => {
//                     if subnet.contain(i) {
//                         return Some(interface.clone());
//                     }
//                 }
//                 _ => (),
//             }
//         }
//     }
//     None
// }

/// Returns an interface that matches the name
pub fn find_interface_by_name(interface_name: &str) -> Option<NetworkInterface> {
    for interface in pnet_datalink::interfaces() {
        // println!("{}", interface)
        if interface.name == interface_name {
            return Some(interface);
        }
    }
    None
}

/// Returns source ip of host machine interfaces
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

/// Convert user input interface and return (NetworkInterface, Ipv4Addr, MacAddr)
pub fn parse_interface(interface: Option<&str>) -> Result<(NetworkInterface, Ipv4Addr, MacAddr)> {
    let i = match interface {
        Some(name) => match find_interface_by_name(name) {
            Some(i) => i,
            _ => return Err(FindInterfaceError::new(name.to_string()).into()),
        },
        _ => return Err(FindInterfaceError::new("please set interface".to_string()).into()),
    };
    let ipv4 = match get_interface_ip(&i) {
        Some(ip) => ip,
        _ => return Err(GetInterfaceIPError::new(i.to_string()).into()),
    };
    let mac = match i.mac {
        Some(m) => m,
        _ => return Err(GetInterfaceMACError::new(i.to_string()).into()),
    };

    Ok((i, ipv4, mac))
}

/// Returns the random port
pub fn random_port() -> u16 {
    let mut rng = rand::thread_rng();
    let src_port: u16 = rng.gen_range(1024..=41926);
    src_port
}

/// Returns the number of CPUs in the machine
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

pub fn get_max_wait(max_wait_time: Option<usize>) -> usize {
    match max_wait_time {
        Some(m) => m,
        _ => DEFAILT_MAX_WAIT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_list_interfaces() {
        for interface in pnet_datalink::interfaces() {
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
}
