use anyhow::Result;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::channel;

pub mod icmp;
pub mod icmpv6;

use crate::errors::CanNotFoundSourceAddress;
use crate::scan::{tcp, tcp6, udp, udp6};
use crate::utils::{find_source_ipv4, find_source_ipv6};
use crate::utils::{get_max_loop, get_threads_pool, random_port};
use crate::PingResults;
use crate::PingStatus;
use crate::Target;
use crate::TargetScanStatus;

const SYN_PING_DEFAULT_PORT: u16 = 80;
const ACK_PING_DEFAULT_PORT: u16 = 80;
const UDP_PING_DEFAULT_PORT: u16 = 125;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PingMethods {
    Syn,
    Ack,
    Udp,
    Icmp,
}

fn run_ping(
    method: PingMethods,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: Option<u16>,
    max_loop: usize,
) -> Result<PingResults> {
    let ping_status = match method {
        PingMethods::Syn => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => SYN_PING_DEFAULT_PORT,
            };

            let ret = tcp::send_syn_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, max_loop)?;
            match ret {
                TargetScanStatus::Open => PingStatus::Up,
                _ => PingStatus::Down,
            }
        }
        PingMethods::Ack => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => ACK_PING_DEFAULT_PORT,
            };

            let ret = tcp::send_ack_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, max_loop)?;
            match ret {
                TargetScanStatus::Unfiltered => PingStatus::Up,
                _ => PingStatus::Down,
            }
        }
        PingMethods::Udp => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => UDP_PING_DEFAULT_PORT,
            };

            let ret = udp::send_udp_scan_packet(src_ipv4, src_port, dst_ipv4, dst_port, max_loop)?;
            match ret {
                TargetScanStatus::Open => PingStatus::Up,
                TargetScanStatus::OpenOrFiltered => PingStatus::Up,
                _ => PingStatus::Down,
            }
        }
        PingMethods::Icmp => icmp::send_icmp_ping_packet(src_ipv4, dst_ipv4, max_loop)?,
    };
    Ok(PingResults {
        addr: dst_ipv4.into(),
        status: ping_status,
    })
}

fn run_ping6(
    method: PingMethods,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: Option<u16>,
    max_loop: usize,
) -> Result<PingResults> {
    let ping_status = match method {
        PingMethods::Syn => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => SYN_PING_DEFAULT_PORT,
            };

            let ret = tcp6::send_syn_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop)?;
            match ret {
                TargetScanStatus::Open => PingStatus::Up,
                _ => PingStatus::Down,
            }
        }
        PingMethods::Ack => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => ACK_PING_DEFAULT_PORT,
            };

            let ret = tcp6::send_ack_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop)?;
            match ret {
                TargetScanStatus::Unfiltered => PingStatus::Up,
                _ => PingStatus::Down,
            }
        }
        PingMethods::Udp => {
            let dst_port = match dst_port {
                Some(p) => p,
                None => UDP_PING_DEFAULT_PORT,
            };

            let ret = udp6::send_udp_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, max_loop)?;
            match ret {
                TargetScanStatus::Open => PingStatus::Up,
                TargetScanStatus::OpenOrFiltered => PingStatus::Up,
                _ => PingStatus::Down,
            }
        }
        PingMethods::Icmp => icmpv6::send_icmpv6_ping_packet(src_ipv6, dst_ipv6, max_loop)?,
    };
    Ok(PingResults {
        addr: dst_ipv6.into(),
        status: ping_status,
    })
}

pub fn ping(
    target: Target,
    method: PingMethods,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, PingResults>> {
    let src_port = match src_port {
        Some(p) => p,
        None => random_port(),
    };

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
        if host.ports.len() > 0 && method != PingMethods::Icmp {
            for dst_port in host.ports {
                let tx = tx.clone();
                recv_size += 1;
                pool.execute(move || {
                    let ret = run_ping(
                        method,
                        src_ipv4,
                        src_port,
                        dst_ipv4,
                        Some(dst_port),
                        max_loop,
                    );
                    match tx.send((dst_ipv4, ret)) {
                        _ => (),
                    }
                });
            }
        } else {
            let tx = tx.clone();
            recv_size += 1;
            pool.execute(move || {
                let ret = run_ping(method, src_ipv4, src_port, dst_ipv4, None, max_loop);
                match tx.send((dst_ipv4, ret)) {
                    _ => (),
                }
            });
        }
    }

    let iter = rx.into_iter().take(recv_size);
    let mut hm: HashMap<Ipv4Addr, PingResults> = HashMap::new();

    for (dst_ipv4, pr) in iter {
        match pr {
            Ok(p) => {
                hm.insert(dst_ipv4, p);
            }
            _ => (),
        }
    }
    Ok(hm)
}

pub fn ping6(
    target: Target,
    method: PingMethods,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv6Addr, PingResults>> {
    let src_port = match src_port {
        Some(p) => p,
        None => random_port(),
    };
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
        if host.ports.len() > 0 && method != PingMethods::Icmp {
            for dst_port in host.ports {
                let tx = tx.clone();
                recv_size += 1;
                pool.execute(move || {
                    let ret = run_ping6(
                        method,
                        src_ipv6,
                        src_port,
                        dst_ipv6,
                        Some(dst_port),
                        max_loop,
                    );
                    match tx.send((dst_ipv6, ret)) {
                        _ => (),
                    }
                });
            }
        } else {
            let tx = tx.clone();
            recv_size += 1;
            pool.execute(move || {
                let ret = run_ping6(method, src_ipv6, src_port, dst_ipv6, None, max_loop);
                match tx.send((dst_ipv6, ret)) {
                    _ => (),
                }
            });
        }
    }

    let iter = rx.into_iter().take(recv_size);
    let mut hm: HashMap<Ipv6Addr, PingResults> = HashMap::new();

    for (dst_ipv6, pr) in iter {
        match pr {
            Ok(p) => {
                hm.insert(dst_ipv6, p);
            }
            _ => (),
        }
    }
    Ok(hm)
}

pub fn tcp_syn_ping(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, PingResults>> {
    ping(
        target,
        PingMethods::Syn,
        src_ipv4,
        src_port,
        threads_num,
        max_loop,
    )
}

pub fn tcp_syn_ping6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv6Addr, PingResults>> {
    ping6(
        target,
        PingMethods::Syn,
        src_ipv6,
        src_port,
        threads_num,
        max_loop,
    )
}

pub fn tcp_ack_ping(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, PingResults>> {
    ping(
        target,
        PingMethods::Ack,
        src_ipv4,
        src_port,
        threads_num,
        max_loop,
    )
}

pub fn tcp_ack_ping6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv6Addr, PingResults>> {
    ping6(
        target,
        PingMethods::Ack,
        src_ipv6,
        src_port,
        threads_num,
        max_loop,
    )
}

pub fn udp_ping(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, PingResults>> {
    ping(
        target,
        PingMethods::Udp,
        src_ipv4,
        src_port,
        threads_num,
        max_loop,
    )
}

pub fn udp_ping6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv6Addr, PingResults>> {
    ping6(
        target,
        PingMethods::Udp,
        src_ipv6,
        src_port,
        threads_num,
        max_loop,
    )
}

pub fn icmp_ping(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv4Addr, PingResults>> {
    ping(
        target,
        PingMethods::Icmp,
        src_ipv4,
        src_port,
        threads_num,
        max_loop,
    )
}

pub fn icmpv6_ping(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_loop: Option<usize>,
) -> Result<HashMap<Ipv6Addr, PingResults>> {
    ping6(
        target,
        PingMethods::Icmp,
        src_ipv6,
        src_port,
        threads_num,
        max_loop,
    )
}
