use anyhow::Result;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use subnetwork::Ipv4Pool;

mod scan;
mod utils;

/// ARP scanning.
/// This will sends ARP packets to hosts on the local network and displays any responses that are received.
/// The network interface to use can be specified with the `interface` option.
/// If this option is not present, program will search the system interface list for `subnet` user provided, configured up interface (excluding loopback).
/// By default, the ARP packets are sent to the Ethernet broadcast address, ff:ff:ff:ff:ff:ff, but that can be changed with the `destaddr` option.
/// When `threads_num` is 0, means that automatic threads pool mode is used.
pub fn arp_scan_subnet(
    subnet: &str,
    interface: Option<&str>,
    dstaddr: Option<&str>,
    threads_num: usize,
    print_result: bool,
) -> Result<scan::ArpScanResults> {
    let subnet = Ipv4Pool::new(subnet).unwrap();
    scan::run_arp_scan_subnet(subnet, interface, dstaddr, threads_num, print_result)
}

/// TCP SYN scanning.
/// This technique is often referred to as "half-open" scanning, because you don't open a full TCP connection.
/// You send a SYN packet, as if you are going to open a real connection and wait for a response.
/// A SYN|ACK indicates the port is listening.
/// A RST is indicative of a non-listener.
/// If a SYN|ACK is received, you immediately send a RST to tear down the connection (actually the kernel does this for us).
/// The primary advantage to this scanning technique is that fewer sites will log it.
/// Unfortunately you need root privileges to build these custom SYN packets.
/// SYN scanning is the -s option of nmap.
/// When `threads_num` is 0, means that automatic threads pool mode is used.
pub fn tcp_syn_scan_single_port(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    interface: Option<&str>,
    print_result: bool,
) -> Result<scan::TcpScanResults> {
    scan::run_tcp_syn_scan_single_port(dst_ipv4, dst_port, interface, print_result)
}

pub fn tcp_syn_scan_range_port(
    dst_ipv4: Ipv4Addr,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
) -> Result<scan::TcpScanResults> {
    scan::run_tcp_syn_scan_range_port(
        dst_ipv4,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
    )
}

pub fn tcp_syn_scan_subnet(
    subnet: Ipv4Pool,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
) -> Result<HashMap<Ipv4Addr, scan::TcpScanResults>> {
    scan::run_tcp_syn_scan_subnet(
        subnet,
        start_port,
        end_port,
        interface,
        threads_num,
        print_result,
    )
}

/// TCP connect() scanning.
/// This is the most basic form of TCP scanning.
/// The connect() system call provided by your operating system is used to open a connection to every interesting port on the machine.
/// If the port is listening, connect() will succeed, otherwise the port isn't reachable.
/// One strong advantage to this technique is that you don't need any special privileges.
/// Any user on most UNIX boxes is free to use this call.
/// Another advantage is speed.
/// While making a separate connect() call for every targeted port in a linear fashion would take ages over a slow connection,
/// you can hasten the scan by using many sockets in parallel.
/// Using non-blocking I/O allows you to set a low time-out period and watch all the sockets at once.
/// This is the fastest scanning method supported by nmap, and is available with the -t (TCP) option.
/// The big downside is that this sort of scan is easily detectable and filterable.
/// The target hosts logs will show a bunch of connection and error messages for the services which take the connection and then have it immediately shutdown.
/// When `threads_num` is 0, means that automatic threads pool mode is used.
pub fn tcp_connect_scan_single_port(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    timeout: Duration,
    print_result: bool,
) -> Result<scan::TcpScanResults> {
    scan::run_tcp_connect_scan_single_port(dst_ipv4, dst_port, timeout, print_result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_arp_scan() {
        match arp_scan_subnet("192.168.72.0/24", None, None, 0, true) {
            Ok(rets) => {
                println!("{}", rets.alive_hosts_num);
                for i in rets.alive_hosts_vec {
                    println!("{}, {}", i.host_ip, i.host_mac.unwrap());
                }
            }
            _ => (),
        }
    }
    #[test]
    fn test_syn_scan_single() {
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let i = Some("eth0");
        let ret = tcp_syn_scan_single_port(dst_ipv4, 80, i, true).unwrap();
        assert_eq!(ret.alive_port_num, 1);
        let ret = tcp_syn_scan_single_port(dst_ipv4, 9999, i, true).unwrap();
        assert_eq!(ret.alive_port_num, 0);
    }
    #[test]
    fn test_syn_scan_multi() {
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let i = Some("eth0");
        let ret = tcp_syn_scan_range_port(dst_ipv4, 22, 90, i, 0, true).unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_syn_scan_subnet() {
        let subnet = Ipv4Pool::new("192.168.1.0/30").unwrap();
        let i = Some("eth0");
        let ret = tcp_syn_scan_subnet(subnet, 80, 82, i, 0, true).unwrap();
        println!("{:?}", ret);
    }
}
