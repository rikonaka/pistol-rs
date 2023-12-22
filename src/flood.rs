use anyhow::Result;
use std::iter::zip;
use std::net::{Ipv4Addr, Ipv6Addr};

pub mod icmp;
pub mod icmp6;
pub mod tcp;
pub mod tcp6;
pub mod udp;
pub mod udp6;

use crate::errors::CanNotFoundSourceAddress;
use crate::{utils, Target};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FloodMethods {
    Icmp,
    Syn,
    Ack,
    AckPsh,
    Udp,
}

fn run_flood(
    method: FloodMethods,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    max_same_packet: usize,
    max_flood_packet: usize,
) {
    let func = match method {
        FloodMethods::Icmp => icmp::send_icmp_flood_packet,
        FloodMethods::Syn => tcp::send_syn_flood_packet,
        FloodMethods::Ack => tcp::send_ack_flood_packet,
        FloodMethods::AckPsh => tcp::send_ack_psh_flood_packet,
        FloodMethods::Udp => udp::send_udp_flood_packet,
    };

    if max_flood_packet > 0 {
        for _loop_num in 0..max_flood_packet {
            let _ = func(src_ipv4, src_port, dst_ipv4, dst_port, max_same_packet);
        }
    } else {
        loop {
            let _ = func(src_ipv4, src_port, dst_ipv4, dst_port, max_same_packet);
        }
    }
}

fn run_flood6(
    method: FloodMethods,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    max_same_packet: usize,
    max_flood_packet: usize,
) {
    let func = match method {
        FloodMethods::Icmp => icmp6::send_icmpv6_flood_packet,
        FloodMethods::Syn => tcp6::send_syn_flood_packet,
        FloodMethods::Ack => tcp6::send_ack_flood_packet,
        FloodMethods::AckPsh => tcp6::send_ack_psh_flood_packet,
        FloodMethods::Udp => udp6::send_udp_flood_packet,
    };

    if max_flood_packet > 0 {
        for _loop_num in 0..max_flood_packet {
            let _ = func(src_ipv6, src_port, dst_ipv6, dst_port, max_same_packet);
        }
    } else {
        loop {
            let _ = func(src_ipv6, src_port, dst_ipv6, dst_port, max_same_packet);
        }
    }
}

pub fn flood(
    target: Target,
    method: FloodMethods,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    let src_port = match src_port {
        Some(p) => p,
        None => utils::random_port(),
    };
    let target_ips = utils::get_ips_from_host(&target.hosts);
    let bi_vec = utils::bind_interface(&target_ips);

    let pool = utils::get_threads_pool(threads_num);

    for (bi, host) in zip(bi_vec, target.hosts) {
        let src_ipv4 = match src_ipv4 {
            Some(s) => s,
            None => match bi.src_ipv4 {
                Some(s) => s,
                None => return Err(CanNotFoundSourceAddress::new().into()),
            },
        };
        let dst_ipv4 = bi.dst_ipv4;
        if host.ports.len() > 0 && method != FloodMethods::Icmp {
            for dst_port in host.ports {
                let dst_port = dst_port.clone();
                pool.execute(move || {
                    run_flood(
                        method,
                        src_ipv4,
                        src_port,
                        dst_ipv4,
                        dst_port,
                        max_same_packet,
                        max_flood_packet,
                    );
                });
            }
        } else if method == FloodMethods::Icmp {
            pool.execute(move || {
                run_flood(
                    method,
                    src_ipv4,
                    src_port,
                    dst_ipv4,
                    0,
                    max_same_packet,
                    max_flood_packet,
                );
            });
        }
    }
    Ok(())
}
pub fn flood6(
    target: Target,
    method: FloodMethods,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    let src_port = match src_port {
        Some(p) => p,
        None => utils::random_port(),
    };
    let target_ips = utils::get_ips_from_host6(&target.hosts6);
    let bi_vec = utils::bind_interface6(&target_ips);

    let pool = utils::get_threads_pool(threads_num);

    for (bi, host) in zip(bi_vec, target.hosts6) {
        let src_ipv6 = match src_ipv6 {
            Some(s) => s,
            None => match bi.src_ipv6 {
                Some(s) => s,
                None => return Err(CanNotFoundSourceAddress::new().into()),
            },
        };
        let dst_ipv6 = bi.dst_ipv6;
        if host.ports.len() > 0 && method != FloodMethods::Icmp {
            for dst_port in host.ports {
                let dst_port = dst_port.clone();
                pool.execute(move || {
                    run_flood6(
                        method,
                        src_ipv6,
                        src_port,
                        dst_ipv6,
                        dst_port,
                        max_same_packet,
                        max_flood_packet,
                    );
                });
            }
        } else if method == FloodMethods::Icmp {
            pool.execute(move || {
                run_flood6(
                    method,
                    src_ipv6,
                    src_port,
                    dst_ipv6,
                    0,
                    max_same_packet,
                    max_flood_packet,
                );
            });
        }
    }
    Ok(())
}

pub fn icmp_flood(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    flood(
        target,
        FloodMethods::Icmp,
        src_ipv4,
        Some(0),
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn icmp_flood6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    flood6(
        target,
        FloodMethods::Icmp,
        src_ipv6,
        Some(0),
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn tcp_syn_flood(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    flood(
        target,
        FloodMethods::Syn,
        src_ipv4,
        src_port,
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn tcp_syn_flood6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    flood6(
        target,
        FloodMethods::Syn,
        src_ipv6,
        src_port,
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn tcp_ack_flood(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    flood(
        target,
        FloodMethods::Ack,
        src_ipv4,
        src_port,
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn tcp_ack_flood6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    flood6(
        target,
        FloodMethods::Ack,
        src_ipv6,
        src_port,
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn tcp_ack_psh_flood(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    flood(
        target,
        FloodMethods::AckPsh,
        src_ipv4,
        src_port,
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn tcp_ack_psh_flood6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    flood6(
        target,
        FloodMethods::AckPsh,
        src_ipv6,
        src_port,
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn udp_flood(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    flood(
        target,
        FloodMethods::Udp,
        src_ipv4,
        src_port,
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn udp_flood6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    flood6(
        target,
        FloodMethods::Udp,
        src_ipv6,
        src_port,
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}
