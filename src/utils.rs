use anyhow::Result;
use num_cpus;
use pnet_datalink::{MacAddr, NetworkInterface};
use rand::Rng;
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use subnetwork::Ipv4Pool;
// use subnetwork::Ipv4Pool;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::{Ipv4, Ipv6};
use pnet::transport::{transport_channel, TransportReceiver, TransportSender};
use threadpool::ThreadPool;

const DEFAILT_MAX_LOOP: usize = 32;
const DEFAILT_TIMEOUT: f32 = 1.5;

pub const IP_TTL: u8 = 64;

pub const BUFF_SIZE: usize = 4096;
pub const TCP_BUFF_SIZE: usize = 4096;
pub const UDP_BUFF_SIZE: usize = 4096;

pub const IPV4_HEADER_LEN: usize = 20;
pub const ICMP_BUFF_SIZE: usize = 4096;

pub const TCP_HEADER_LEN: usize = 20;
pub const TCP_DATA_LEN: usize = 0;

pub const UDP_HEADER_LEN: usize = 8;
pub const UDP_DATA_LEN: usize = 0;

pub const ICMP_HEADER_LEN: usize = 8;
pub const ICMP_DATA_LEN: usize = 0;

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
    pub fn new(interface: &str) -> FindInterfaceError {
        let interface = interface.to_string();
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
    pub fn new(interface: &str) -> GetInterfaceIPError {
        let interface = interface.to_string();
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
    pub fn new(interface: &str) -> GetInterfaceMACError {
        let interface = interface.to_string();
        GetInterfaceMACError { interface }
    }
}

impl Error for GetInterfaceMACError {}

/* CODE */

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

/// Returns source ip(v6) of host machine interfaces
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

/// Convert user input interface and return (NetworkInterface, Ipv4Addr, MacAddr)
pub fn parse_interface(interface: Option<&str>) -> Result<(NetworkInterface, Ipv4Addr, MacAddr)> {
    let i = match interface {
        Some(name) => match find_interface_by_name(name) {
            Some(i) => i,
            _ => return Err(FindInterfaceError::new(name).into()),
        },
        _ => return Err(FindInterfaceError::new("please set interface").into()),
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

pub fn parse_interface6(interface: Option<&str>) -> Result<(NetworkInterface, Ipv6Addr, MacAddr)> {
    let i = match interface {
        Some(name) => match find_interface_by_name(name) {
            Some(i) => i,
            _ => return Err(FindInterfaceError::new(name).into()),
        },
        _ => return Err(FindInterfaceError::new("please set interface").into()),
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

/// Convert user input subnet and return (NetworkInterface, Ipv4Addr, MacAddr)
pub fn parse_interface_by_subnet(
    subnet: Ipv4Pool,
) -> Result<(NetworkInterface, Ipv4Addr, MacAddr)> {
    let i = match find_interface_by_subnet(&subnet) {
        Some(i) => i,
        _ => return Err(FindInterfaceError::new("counld not find interface by subnet").into()),
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

/// Returns the random port
pub fn random_port() -> u16 {
    let mut rng = rand::thread_rng();
    rng.gen_range(1024..=65535)
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

pub fn get_max_loop(max_loop: Option<usize>) -> usize {
    match max_loop {
        Some(m) => m,
        _ => DEFAILT_MAX_LOOP,
    }
}

pub fn get_timeout(timeout: Option<Duration>) -> Duration {
    match timeout {
        Some(t) => t,
        _ => Duration::from_secs_f32(DEFAILT_TIMEOUT),
    }
}

pub fn return_layer3_tcp_channel(
    buffer_size: usize,
) -> Result<(TransportSender, TransportReceiver)> {
    let tcp_protocol = Layer3(IpNextHeaderProtocols::Tcp);
    match transport_channel(buffer_size, tcp_protocol) {
        Ok((tx, rx)) => Ok((tx, rx)),
        Err(e) => return Err(e.into()),
    }
}

pub fn return_layer4_tcp_channel(
    buffer_size: usize,
) -> Result<(TransportSender, TransportReceiver)> {
    let tcp_protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
    match transport_channel(buffer_size, tcp_protocol) {
        Ok((tx, rx)) => Ok((tx, rx)),
        Err(e) => return Err(e.into()),
    }
}

pub fn return_layer4_tcp6_channel(
    buffer_size: usize,
) -> Result<(TransportSender, TransportReceiver)> {
    let tcp_protocol = Layer4(Ipv6(IpNextHeaderProtocols::Tcp));
    match transport_channel(buffer_size, tcp_protocol) {
        Ok((tx, rx)) => Ok((tx, rx)),
        Err(e) => return Err(e.into()),
    }
}

pub fn return_layer3_udp_channel(
    buffer_size: usize,
) -> Result<(TransportSender, TransportReceiver)> {
    let udp_protocol = Layer3(IpNextHeaderProtocols::Udp);
    match transport_channel(buffer_size, udp_protocol) {
        Ok((tx, rx)) => Ok((tx, rx)),
        Err(e) => return Err(e.into()),
    }
}

pub fn return_layer4_udp_channel(
    buffer_size: usize,
) -> Result<(TransportSender, TransportReceiver)> {
    let udp_protocol = Layer4(Ipv4(IpNextHeaderProtocols::Udp));
    match transport_channel(buffer_size, udp_protocol) {
        Ok((tx, rx)) => Ok((tx, rx)),
        Err(e) => return Err(e.into()),
    }
}

pub fn return_layer4_udp6_channel(
    buffer_size: usize,
) -> Result<(TransportSender, TransportReceiver)> {
    let udp_protocol = Layer4(Ipv6(IpNextHeaderProtocols::Udp));
    match transport_channel(buffer_size, udp_protocol) {
        Ok((tx, rx)) => Ok((tx, rx)),
        Err(e) => return Err(e.into()),
    }
}

pub fn return_layer3_icmp_channel(
    buffer_size: usize,
) -> Result<(TransportSender, TransportReceiver)> {
    let icmp_protocol = Layer3(IpNextHeaderProtocols::Icmp);
    match transport_channel(buffer_size, icmp_protocol) {
        Ok((tx, rx)) => Ok((tx, rx)),
        Err(e) => return Err(e.into()),
    }
}

pub fn return_layer4_icmp_channel(
    buffer_size: usize,
) -> Result<(TransportSender, TransportReceiver)> {
    let icmp_protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));
    match transport_channel(buffer_size, icmp_protocol) {
        Ok((tx, rx)) => Ok((tx, rx)),
        Err(e) => return Err(e.into()),
    }
}

pub fn return_layer4_icmp6_channel(
    buffer_size: usize,
) -> Result<(TransportSender, TransportReceiver)> {
    let icmp_protocol = Layer4(Ipv6(IpNextHeaderProtocols::Icmpv6));
    match transport_channel(buffer_size, icmp_protocol) {
        Ok((tx, rx)) => Ok((tx, rx)),
        Err(e) => return Err(e.into()),
    }
}

pub fn standard_deviation_vec(values: &Vec<f32>) -> f32 {
    let mut sum = 0.0;
    for v in values {
        sum += *v;
    }
    let mean = sum / values.len() as f32;

    let mut ret = 0.0;
    for v in values {
        ret += (v - mean).powi(2);
    }

    ret.sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
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
