use num_cpus;
use pnet_datalink::NetworkInterface;
use std::net::{IpAddr, Ipv4Addr};
use subnetwork::Ipv4Pool;
use threadpool::ThreadPool;

pub fn get_host_interfaces() -> Vec<NetworkInterface> {
    pnet_datalink::interfaces()
}

/// Returns an interface that matches the subnet
pub fn find_interface_by_subnet(subnet: &Ipv4Pool) -> Option<NetworkInterface> {
    let interfaces = get_host_interfaces();
    for interface in &interfaces {
        for ip in &interface.ips {
            match ip.ip() {
                IpAddr::V4(i) => {
                    if subnet.contain(i) {
                        return Some(interface.clone());
                    }
                }
                _ => (),
            }
        }
    }
    None
}

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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_host_interfaces() {
        get_host_interfaces();
    }
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
    fn test_find_interface_by_subnet() {
        let subnet = Ipv4Pool::new("192.168.1.0/24").unwrap();
        match find_interface_by_subnet(&subnet) {
            Some(i) => println!("{:?}", i),
            _ => (),
        }
    }
    #[test]
    fn test_get_cpus() {
        let cpus = get_cpu_num();
        println!("{}", cpus);
    }
}
