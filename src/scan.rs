use anyhow::Result;
use pnet::datalink::MacAddr;
use pnet::packet::ip::IpNextHeaderProtocol;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::channel;

pub mod arp;
pub mod ip;
pub mod tcp;
pub mod tcp6;
pub mod udp;
pub mod udp6;

use crate::errors::{CanNotFoundInterface, CanNotFoundMacAddress, CanNotFoundSourceAddress};
use crate::utils::{find_interface_by_ipv4, find_source_ipv4, find_source_ipv6};
use crate::utils::{get_max_loop, get_threads_pool, random_port};
use crate::TargetType;

use super::errors::NotSupportIpTypeForArpScan;
use super::ArpScanResults;
use super::IpScanResults;
use super::Target;
use super::TargetScanStatus;
use super::TcpUdpScanResults;

#[derive(Debug, Clone, Copy)]
pub enum ScanMethod {
    Connect,
    Syn,
    Fin,
    Ack,
    Null,
    Xmas,
    Window,
    Maimon,
    Idle, // need ipv4 ip id
    Udp,
    IpProcotol,
}

#[derive(Debug, Clone, Copy)]
pub enum ScanMethod6 {
    Connect,
    Syn,
    Fin,
    Ack,
    Null,
    Xmas,
    Window,
    Maimon,
    Udp,
}

pub fn arp_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<ArpScanResults> {
    match target.target_type {
        TargetType::Ipv4 => {
            let mut ret = ArpScanResults {
                alive_hosts_num: 0,
                alive_hosts: HashMap::new(),
            };

            // println!("{:?}", bi_vec);
            let pool = get_threads_pool(threads_num);
            let max_loop = get_max_loop(max_loop);

            let dst_mac = MacAddr::broadcast();
            let (tx, rx) = channel();
            let mut recv_size = 0;
            for host in target.hosts {
                recv_size += 1;
                let dst_ipv4 = host.addr;
                let src_ipv4 = match find_source_ipv4(src_ipv4, dst_ipv4)? {
                    Some(s) => s,
                    None => return Err(CanNotFoundSourceAddress::new().into()),
                };
                let interface = match find_interface_by_ipv4(src_ipv4) {
                    Some(i) => i,
                    None => return Err(CanNotFoundInterface::new().into()),
                };
                let src_mac = match interface.mac {
                    Some(m) => m,
                    None => return Err(CanNotFoundMacAddress::new().into()),
                };
                let tx = tx.clone();
                pool.execute(move || {
                    let scan_ret = arp::send_arp_scan_packet(
                        dst_ipv4, dst_mac, src_ipv4, src_mac, interface, max_loop,
                    );
                    match tx.send(Ok((dst_ipv4, scan_ret))) {
                        _ => (),
                    }
                });
            }
            let iter = rx.into_iter().take(recv_size);
            for v in iter {
                match v {
                    Ok((target_ipv4, target_mac)) => match target_mac? {
                        Some(m) => {
                            ret.alive_hosts_num += 1;
                            ret.alive_hosts.insert(target_ipv4, m);
                        }
                        None => (),
                    },
                    Err(e) => return Err(e),
                }
            }
            Ok(ret)
        }
        _ => Err(NotSupportIpTypeForArpScan::new(target.target_type).into()),
    }
}

fn run_scan(
    method: ScanMethod,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    protocol: Option<IpNextHeaderProtocol>,
    max_loop: usize,
) -> Result<(
    Ipv4Addr,
    u16,
    Option<IpNextHeaderProtocol>,
    TargetScanStatus,
)> {
    let scan_ret = match method {
        ScanMethod::Connect => {
            tcp::send_connect_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, max_loop)?
        }
        ScanMethod::Syn => {
            tcp::send_syn_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, max_loop)?
        }
        ScanMethod::Fin => {
            tcp::send_fin_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, max_loop)?
        }
        ScanMethod::Ack => {
            tcp::send_ack_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, max_loop)?
        }
        ScanMethod::Null => {
            tcp::send_null_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, max_loop)?
        }
        ScanMethod::Xmas => {
            tcp::send_xmas_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, max_loop)?
        }
        ScanMethod::Window => {
            tcp::send_window_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, max_loop)?
        }
        ScanMethod::Maimon => {
            tcp::send_maimon_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, max_loop)?
        }
        ScanMethod::Idle => {
            let zombie_ipv4 = zombie_ipv4.unwrap();
            let zombie_port = zombie_port.unwrap();
            match tcp::send_idle_scan_packet(
                src_ipv4,
                src_port,
                dst_ipv4,
                dst_port,
                zombie_ipv4,
                zombie_port,
                max_loop,
            ) {
                Ok((status, _idel_rets)) => status,
                Err(e) => return Err(e.into()),
            }
        }
        ScanMethod::Udp => {
            udp::send_udp_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, max_loop)?
        }
        ScanMethod::IpProcotol => {
            ip::send_ip_procotol_scan_packet(src_ipv4, dst_ipv4, protocol.unwrap(), max_loop)?
        }
    };

    Ok((dst_ipv4, dst_port, protocol, scan_ret))
}

fn run_scan6(
    method: ScanMethod6,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    max_loop: usize,
) -> Result<(Ipv6Addr, u16, TargetScanStatus)> {
    let scan_ret = match method {
        ScanMethod6::Connect => {
            tcp6::send_connect_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop)?
        }
        ScanMethod6::Syn => {
            tcp6::send_syn_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop)?
        }
        ScanMethod6::Fin => {
            tcp6::send_fin_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop)?
        }
        ScanMethod6::Ack => {
            tcp6::send_ack_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop)?
        }
        ScanMethod6::Null => {
            tcp6::send_null_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop)?
        }
        ScanMethod6::Xmas => {
            tcp6::send_xmas_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop)?
        }
        ScanMethod6::Window => {
            tcp6::send_window_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop)?
        }
        ScanMethod6::Maimon => {
            tcp6::send_maimon_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop)?
        }
        ScanMethod6::Udp => {
            udp6::send_udp_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop)?
        }
    };

    Ok((dst_ipv6, dst_port, scan_ret))
}

pub fn scan(
    target: Target,
    method: ScanMethod,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    protocol: Option<IpNextHeaderProtocol>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<(
    HashMap<IpAddr, TcpUdpScanResults>,
    HashMap<IpAddr, IpScanResults>,
)> {
    let pool = get_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut recv_size = 0;
    let max_loop = get_max_loop(max_loop);

    for host in target.hosts {
        let dst_ipv4 = host.addr;
        let src_ipv4 = match find_source_ipv4(src_ipv4, dst_ipv4)? {
            Some(s) => s,
            None => return Err(CanNotFoundSourceAddress::new().into()),
        };
        let src_port = match src_port {
            Some(s) => s,
            None => random_port(),
        };
        for dst_port in host.ports {
            let tx = tx.clone();
            recv_size += 1;
            pool.execute(move || {
                let scan_ret = run_scan(
                    method,
                    src_ipv4,
                    src_port,
                    dst_ipv4,
                    dst_port,
                    zombie_ipv4,
                    zombie_port,
                    protocol,
                    max_loop,
                );
                match tx.send(scan_ret) {
                    _ => (),
                }
            });
        }
    }

    let iter = rx.into_iter().take(recv_size);
    let mut ret: HashMap<IpAddr, TcpUdpScanResults> = HashMap::new();
    let mut ret_procotol: HashMap<IpAddr, IpScanResults> = HashMap::new();

    for v in iter {
        match v {
            Ok((dst_ipv4, dst_port, procotol, scan_rets)) => match procotol {
                Some(p) => {
                    if ret_procotol.contains_key(&dst_ipv4.into()) {
                        ret_procotol
                            .get_mut(&dst_ipv4.into())
                            .unwrap()
                            .results
                            .insert(p, scan_rets);
                    } else {
                        let mut v = IpScanResults::new(dst_ipv4.into());
                        v.results.insert(p, scan_rets);
                        ret_procotol.insert(dst_ipv4.into(), v);
                    }
                }
                _ => {
                    if ret.contains_key(&dst_ipv4.into()) {
                        ret.get_mut(&dst_ipv4.into())
                            .unwrap()
                            .results
                            .insert(dst_port, scan_rets);
                    } else {
                        let mut v = TcpUdpScanResults::new(dst_ipv4.into());
                        v.results.insert(dst_port, scan_rets);
                        ret.insert(dst_ipv4.into(), v);
                    }
                }
            },
            Err(e) => return Err(e),
        }
    }
    Ok((ret, ret_procotol))
}

pub fn scan6(
    target: Target,
    method: ScanMethod6,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let pool = get_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut recv_size = 0;
    let max_loop = get_max_loop(max_loop);

    for host in target.hosts6 {
        let dst_ipv6 = host.addr;
        let src_ipv6 = match find_source_ipv6(src_ipv6, dst_ipv6)? {
            Some(s) => s,
            None => return Err(CanNotFoundSourceAddress::new().into()),
        };
        let src_port = match src_port {
            Some(s) => s,
            None => random_port(),
        };
        for dst_port in host.ports {
            let tx = tx.clone();
            recv_size += 1;
            pool.execute(move || {
                let scan_ret = run_scan6(method, src_ipv6, src_port, dst_ipv6, dst_port, max_loop);
                match tx.send(scan_ret) {
                    _ => (),
                }
            });
        }
    }

    let iter = rx.into_iter().take(recv_size);
    let mut ret: HashMap<IpAddr, TcpUdpScanResults> = HashMap::new();

    for v in iter {
        match v {
            Ok((dst_ipv6, dst_port, scan_rets)) => {
                if ret.contains_key(&dst_ipv6.into()) {
                    ret.get_mut(&dst_ipv6.into())
                        .unwrap()
                        .results
                        .insert(dst_port, scan_rets);
                } else {
                    let mut v = TcpUdpScanResults::new(dst_ipv6.into());
                    v.results.insert(dst_port, scan_rets);
                    ret.insert(dst_ipv6.into(), v);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(ret)
}

pub fn tcp_connect_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Connect,
        src_ipv4,
        src_port,
        None,
        None,
        None,
        threads_num,
        max_loop,
    )?;
    Ok(ret)
}

pub fn tcp_connect_scan6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    scan6(
        target,
        ScanMethod6::Connect,
        src_ipv6,
        src_port,
        threads_num,
        max_loop,
    )
}

pub fn tcp_syn_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Syn,
        src_ipv4,
        src_port,
        None,
        None,
        None,
        threads_num,
        max_loop,
    )?;
    Ok(ret)
}

pub fn tcp_syn_scan6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    scan6(
        target,
        ScanMethod6::Syn,
        src_ipv6,
        src_port,
        threads_num,
        max_loop,
    )
}

pub fn tcp_fin_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Fin,
        src_ipv4,
        src_port,
        None,
        None,
        None,
        threads_num,
        max_loop,
    )?;
    Ok(ret)
}

pub fn tcp_fin_scan6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    scan6(
        target,
        ScanMethod6::Fin,
        src_ipv6,
        src_port,
        threads_num,
        max_loop,
    )
}

pub fn tcp_ack_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Ack,
        src_ipv4,
        src_port,
        None,
        None,
        None,
        threads_num,
        max_loop,
    )?;
    Ok(ret)
}

pub fn tcp_ack_scan6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    scan6(
        target,
        ScanMethod6::Ack,
        src_ipv6,
        src_port,
        threads_num,
        max_loop,
    )
}

pub fn tcp_null_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Null,
        src_ipv4,
        src_port,
        None,
        None,
        None,
        threads_num,
        max_loop,
    )?;
    Ok(ret)
}

pub fn tcp_null_scan6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    scan6(
        target,
        ScanMethod6::Null,
        src_ipv6,
        src_port,
        threads_num,
        max_loop,
    )
}

pub fn tcp_xmas_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Xmas,
        src_ipv4,
        src_port,
        None,
        None,
        None,
        threads_num,
        max_loop,
    )?;
    Ok(ret)
}

pub fn tcp_xmas_scan6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    scan6(
        target,
        ScanMethod6::Xmas,
        src_ipv6,
        src_port,
        threads_num,
        max_loop,
    )
}

pub fn tcp_window_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Window,
        src_ipv4,
        src_port,
        None,
        None,
        None,
        threads_num,
        max_loop,
    )?;
    Ok(ret)
}

pub fn tcp_window_scan6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    scan6(
        target,
        ScanMethod6::Window,
        src_ipv6,
        src_port,
        threads_num,
        max_loop,
    )
}

pub fn tcp_maimon_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Maimon,
        src_ipv4,
        src_port,
        None,
        None,
        None,
        threads_num,
        max_loop,
    )?;
    Ok(ret)
}

pub fn tcp_maimon_scan6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    scan6(
        target,
        ScanMethod6::Maimon,
        src_ipv6,
        src_port,
        threads_num,
        max_loop,
    )
}

pub fn tcp_idle_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    zombie_ipv4: Option<Ipv4Addr>,
    zombie_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Idle,
        src_ipv4,
        src_port,
        zombie_ipv4,
        zombie_port,
        None,
        threads_num,
        max_loop,
    )?;
    Ok(ret)
}

pub fn udp_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    let (ret, _) = scan(
        target,
        ScanMethod::Udp,
        src_ipv4,
        src_port,
        None,
        None,
        None,
        threads_num,
        max_loop,
    )?;
    Ok(ret)
}

pub fn udp_scan6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, TcpUdpScanResults>> {
    scan6(
        target,
        ScanMethod6::Udp,
        src_ipv6,
        src_port,
        threads_num,
        max_loop,
    )
}

pub fn ip_procotol_scan(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    protocol: Option<IpNextHeaderProtocol>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<IpAddr, IpScanResults>> {
    let (_, ret) = scan(
        target,
        ScanMethod::IpProcotol,
        src_ipv4,
        src_port,
        None,
        None,
        protocol,
        threads_num,
        max_loop,
    )?;
    Ok(ret)
}
