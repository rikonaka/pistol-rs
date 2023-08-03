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

pub enum FloodMethods {
    Icmp,
}

pub fn _run_flood(
    method: FloodMethods,
    src_ipv4: Option<Ipv4Addr>,
    dst_ipv4: Ipv4Addr,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_packet_num: usize,
) -> Result<()> {
    let src_ipv4 = if src_ipv4.is_none() {
        let (_, src_ipv4, _) = utils::parse_interface(interface)?;
        src_ipv4
    } else {
        src_ipv4.unwrap()
    };

    let func = match method {
        FloodMethods::Icmp => icmp::send_icmp_flood_packet,
    };

    let pool = utils::get_threads_pool(threads_num);
    if max_packet_num > 0 {
        for loop_num in 0..max_packet_num {
            if print_result {
                if loop_num % 10000 == 0 {
                    println!("send {loop_num} packet");
                }
            }
            pool.execute(move || {
                let _ = func(src_ipv4, dst_ipv4);
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
                let _ = func(src_ipv4, dst_ipv4);
            });
        }
    }

    Ok(())
}

pub fn run_icmp_flood(
    src_ipv4: Option<Ipv4Addr>,
    dst_ipv4: Ipv4Addr,
    interface: Option<&str>,
    threads_num: usize,
    print_result: bool,
    max_packet_num: usize,
) -> Result<()> {
    _run_flood(
        FloodMethods::Icmp,
        src_ipv4,
        dst_ipv4,
        interface,
        threads_num,
        print_result,
        max_packet_num,
    )
}
