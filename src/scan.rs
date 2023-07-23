use anyhow::Result;
use pnet::datalink::MacAddr;
use rand::Rng;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::mpsc::channel;
use std::time::Duration;
use subnetwork::Ipv4Pool;

use crate::utils;

pub mod arp;
pub mod tcp;

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

#[derive(Debug)]
pub struct HostInfo {
    pub host_ip: Ipv4Addr,
    pub host_mac: Option<MacAddr>,
}

#[derive(Debug)]
pub struct ArpScanResults {
    pub alive_hosts_num: usize,
    pub alive_hosts_vec: Vec<HostInfo>,
}

#[derive(Debug, Clone)]
pub struct TcpScanResults {
    pub alive_port_num: usize,
    pub alive_port_vec: Vec<u16>,
}

fn _arp_print_result(ip: Ipv4Addr, mac: Option<MacAddr>) {
    match mac {
        Some(mac) => println!("{ip} ({mac})"),
        _ => println!("{ip} (null)"),
    }
}

fn _tcp_print_result(ip: Ipv4Addr, port: u16, ret: bool) {
    match ret {
        true => println!("{ip} {port} OPEN"),
        _ => println!("{ip} {port} CLOSED"),
    }
}

pub fn run_arp_scan_subnet(
    subnet: Ipv4Pool,
    interface: Option<&str>,
    dstaddr: Option<&str>,
    threads_num: usize,
    print_result: bool,
) -> Result<ArpScanResults> {
    let interface = match interface {
        Some(name) => match utils::find_interface_by_name(name) {
            Some(i) => i,
            _ => return Err(FindInterfaceError::new(name.to_string()).into()),
        },
        _ => match utils::find_interface_by_subnet(&subnet) {
            Some(i) => i,
            _ => return Err(FindInterfaceError::new(subnet.to_string()).into()),
        },
    };
    let source_ip = match utils::get_interface_ip(&interface) {
        Some(s) => s,
        _ => return Err(GetInterfaceIPError::new(interface.to_string()).into()),
    };
    let dstaddr = match dstaddr {
        Some(v) => match MacAddr::from_str(v) {
            Ok(m) => m,
            Err(e) => return Err(e.into()),
        },
        _ => MacAddr::broadcast(),
    };

    let source_mac = interface.mac.unwrap();
    let (tx, rx) = channel();
    let pool = utils::get_threads_pool(threads_num);

    for target_ip in subnet {
        let tx = tx.clone();
        let interface = interface.clone();
        pool.execute(move || {
            match arp::send_arp_scan_packet(&interface, &dstaddr, source_ip, source_mac, target_ip)
            {
                Some(target_mac) => {
                    // println!("alive host {}, mac {}", &target_ip, &target_mac);
                    let host_info = HostInfo {
                        host_ip: target_ip,
                        host_mac: Some(target_mac),
                    };
                    if print_result {
                        _arp_print_result(target_ip, Some(target_mac));
                    }
                    tx.send(host_info)
                        .expect("channel will be there waiting for the pool");
                }
                _ => {
                    if print_result {
                        _arp_print_result(target_ip, None);
                    }
                    let host_info = HostInfo {
                        host_ip: target_ip,
                        host_mac: None,
                    };
                    tx.send(host_info)
                        .expect("channel will be there waiting for the pool");
                }
            }
        });
    }
    let iter = rx.into_iter().take(subnet.len());
    let mut alive_hosts_info = Vec::new();
    let mut alive_hosts = 0;
    for host_info in iter {
        if host_info.host_mac.is_some() {
            alive_hosts_info.push(host_info);
            alive_hosts += 1;
        }
    }
    Ok(ArpScanResults {
        alive_hosts_num: alive_hosts,
        alive_hosts_vec: alive_hosts_info,
    })
}

pub fn run_tcp_syn_scan_single_port(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    interface: Option<&str>,
    print_result: bool,
) -> Result<TcpScanResults> {
    let interface = match interface {
        Some(name) => match utils::find_interface_by_name(name) {
            Some(i) => i,
            _ => return Err(FindInterfaceError::new(name.to_string()).into()),
        },
        _ => {
            let guess_subnet = Ipv4Pool::new(&format!("{}/24", dst_ipv4)).unwrap();
            match utils::find_interface_by_subnet(&guess_subnet) {
                Some(i) => i,
                _ => return Err(FindInterfaceError::new(guess_subnet.to_string()).into()),
            }
        }
    };
    let src_ipv4 = match utils::get_interface_ip(&interface) {
        Some(i) => i,
        _ => return Err(GetInterfaceIPError::new(interface.to_string()).into()),
    };
    let mut rng = rand::thread_rng();
    let src_port: u16 = rng.gen_range(1024..=49151);
    let scan_ret = tcp::send_syn_packet(src_ipv4, dst_ipv4, src_port, dst_port);
    if print_result {
        _tcp_print_result(dst_ipv4, dst_port, scan_ret)
    }
    if scan_ret {
        Ok(TcpScanResults {
            alive_port_num: 1,
            alive_port_vec: vec![dst_port],
        })
    } else {
        Ok(TcpScanResults {
            alive_port_num: 0,
            alive_port_vec: vec![],
        })
    }
}

pub fn run_tcp_syn_scan_range_port(
    dst_ipv4: Ipv4Addr,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
) -> Result<TcpScanResults> {
    let interface = match interface {
        Some(name) => match utils::find_interface_by_name(name) {
            Some(i) => i,
            _ => return Err(FindInterfaceError::new(name.to_string()).into()),
        },
        _ => {
            let guess_subnet = Ipv4Pool::new(&format!("{}/24", dst_ipv4)).unwrap();
            match utils::find_interface_by_subnet(&guess_subnet) {
                Some(i) => i,
                _ => return Err(FindInterfaceError::new(guess_subnet.to_string()).into()),
            }
        }
    };
    let src_ipv4 = match utils::get_interface_ip(&interface) {
        Some(i) => i,
        _ => return Err(GetInterfaceIPError::new(interface.to_string()).into()),
    };
    let mut rng = rand::thread_rng();
    let src_port: u16 = rng.gen_range(1024..=49151);
    let pool = utils::get_threads_pool(threads_num);
    let (tx, rx) = channel();

    for dst_port in start_port..end_port {
        let tx = tx.clone();
        pool.execute(move || {
            let scan_ret = tcp::send_syn_packet(src_ipv4, dst_ipv4, src_port, dst_port);
            if print_result {
                _tcp_print_result(dst_ipv4, dst_port, scan_ret);
            }
            tx.send((dst_port, scan_ret))
                .expect("channel will be there waiting for the pool");
        });
    }

    let iter = rx.into_iter().take((end_port - start_port).into());
    let mut alive_port_vec = Vec::new();
    for (port, port_ret) in iter {
        if port_ret {
            alive_port_vec.push(port);
        }
    }
    Ok(TcpScanResults {
        alive_port_num: alive_port_vec.len(),
        alive_port_vec,
    })
}

pub fn run_tcp_syn_scan_subnet(
    subnet: Ipv4Pool,
    start_port: u16,
    end_port: u16,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
) -> Result<HashMap<Ipv4Addr, TcpScanResults>> {
    let interface = match interface {
        Some(name) => match utils::find_interface_by_name(name) {
            Some(i) => i,
            _ => return Err(FindInterfaceError::new(name.to_string()).into()),
        },
        _ => match utils::find_interface_by_subnet(&subnet) {
            Some(i) => i,
            _ => return Err(FindInterfaceError::new(subnet.to_string()).into()),
        },
    };
    let src_ipv4 = match utils::get_interface_ip(&interface) {
        Some(i) => i,
        _ => return Err(GetInterfaceIPError::new(interface.to_string()).into()),
    };

    let pool = utils::get_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut rng = rand::thread_rng();
    for dst_ipv4 in subnet {
        let src_port: u16 = rng.gen_range(1024..=49151);
        for dst_port in start_port..end_port {
            let tx = tx.clone();
            pool.execute(move || {
                let scan_ret = tcp::send_syn_packet(src_ipv4, dst_ipv4, src_port, dst_port);
                if print_result {
                    _tcp_print_result(dst_ipv4, dst_port, scan_ret);
                }
                tx.send((dst_ipv4, dst_port, scan_ret))
                    .expect("channel will be there waiting for the pool");
            });
        }
    }

    let iter = rx
        .into_iter()
        .take(subnet.len() * (end_port - start_port) as usize);

    let mut ret: HashMap<Ipv4Addr, TcpScanResults> = HashMap::new();
    for (dst_ipv4, dst_port, dst_port_ret) in iter {
        if dst_port_ret {
            if ret.contains_key(&dst_ipv4) {
                ret.get_mut(&dst_ipv4).unwrap().alive_port_num += 1;
                ret.get_mut(&dst_ipv4)
                    .unwrap()
                    .alive_port_vec
                    .push(dst_port);
            } else {
                let ssr = TcpScanResults {
                    alive_port_num: 1,
                    alive_port_vec: vec![dst_port],
                };
                ret.insert(dst_ipv4, ssr);
            }
        }
    }

    Ok(ret)
}

pub fn run_tcp_connect_scan_single_port(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    timeout: Duration,
    print_result: bool,
) -> Result<TcpScanResults> {
    let scan_ret = tcp::send_connect_packets(dst_ipv4, dst_port, timeout);
    if print_result {
        _tcp_print_result(dst_ipv4, dst_port, scan_ret);
    }
    if scan_ret {
        Ok(TcpScanResults {
            alive_port_num: 1,
            alive_port_vec: vec![dst_port],
        })
    } else {
        Ok(TcpScanResults {
            alive_port_num: 0,
            alive_port_vec: vec![],
        })
    }
}
