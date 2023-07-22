use std::collections::HashMap;
use std::net::Ipv4Addr;
use subnetwork::Ipv4Pool;

mod scan;
mod utils;

use scan::arp::{run_arp_scan, ArpScanResults};
use scan::tcp::{run_syn_scan_range, run_syn_scan_single, run_syn_scan_subnet, SynScanResults};

/// `threads_num=0` means that automatic mode is used.
pub fn arp_scan(subnet: &str, threads_num: usize, print_result: bool) -> Option<ArpScanResults> {
    let subnet = Ipv4Pool::new(subnet).unwrap();
    run_arp_scan(subnet, threads_num, print_result)
}

pub fn syn_scan_single(
    interface: &str,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
) -> Option<SynScanResults> {
    run_syn_scan_single(interface, dst_ipv4, dst_port)
}

pub fn syn_scan_range(
    interface: &str,
    dst_ipv4: Ipv4Addr,
    start_port: u16,
    end_port: u16,
    threads_num: usize,
    print_result: bool,
) -> Option<SynScanResults> {
    run_syn_scan_range(
        dst_ipv4,
        interface,
        start_port,
        end_port,
        threads_num,
        print_result,
    )
}

pub fn syn_scan_subnet(
    subnet: Ipv4Pool,
    interface: &str,
    start_port: u16,
    end_port: u16,
    threads_num: usize,
    print_result: bool,
) -> Option<HashMap<Ipv4Addr, SynScanResults>> {
    run_syn_scan_subnet(
        subnet,
        interface,
        start_port,
        end_port,
        threads_num,
        print_result,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_arp_scan() {
        match arp_scan("192.168.72.0/24", 0, true) {
            Some(rets) => {
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
        let i = "ens33";
        let ret = syn_scan_single(i, dst_ipv4, 80).unwrap();
        assert_eq!(ret.alive_port_num, 1);
        let ret = syn_scan_single(i, dst_ipv4, 9999).unwrap();
        assert_eq!(ret.alive_port_num, 0);
    }
    #[test]
    fn test_syn_scan_multi() {
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let i = "ens33";
        let ret = syn_scan_range(i, dst_ipv4, 22, 90, 0, true).unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_syn_scan_subnet() {
        let subnet = Ipv4Pool::new("192.168.1.0/24").unwrap();
        let i = "ens33";
        let ret = syn_scan_subnet(subnet, i, 80, 90, 0, true).unwrap();
        println!("{:?}", ret);
    }
}
