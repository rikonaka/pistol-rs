use chrono::DateTime;
use chrono::Local;
use dbparser::ServiceProbe;
use prettytable::Cell;
use prettytable::Row;
use prettytable::Table;
use prettytable::row;
use std::collections::BTreeMap;
use std::fmt;
use std::io::Cursor;
use std::io::Read;
use std::net::IpAddr;
use std::sync::mpsc::channel;
use std::time::Duration;
use std::time::Instant;
use threadpool::ThreadPool;
use tracing::debug;
use tracing::error;
use zip::ZipArchive;

use crate::VersionScanTarget;
use crate::error::PistolError;
use crate::utils::time_to_string;
use crate::vs::vscan::MatchX;
use crate::vs::vscan::vs_scan_thread;

pub mod dbparser;
pub mod vscan;

#[derive(Debug, Clone)]
pub struct PortService {
    pub addr: IpAddr,
    pub port: u16,
    pub origin: Option<String>,
    pub matchs: Vec<MatchX>,
    pub time_cost: Duration,
}

#[derive(Debug, Clone)]
pub struct PistolVsScans {
    pub port_services: Vec<PortService>,
    pub start_time: DateTime<Local>,
    pub finish_time: DateTime<Local>,
}

impl fmt::Display for PistolVsScans {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Service Scan Results")
                .style_spec("c")
                .with_hspan(6),
        ]));

        table
            .add_row(row![c -> "id", c -> "addr", c -> "port", c -> "service", c -> "versioninfo", c -> "time cost"]);

        // sorted
        let mut btm_addr: BTreeMap<IpAddr, BTreeMap<u16, PortService>> = BTreeMap::new();
        for service in &self.port_services {
            if let Some(btm_port) = btm_addr.get_mut(&service.addr) {
                btm_port.insert(service.port, service.clone());
            } else {
                let mut btm_port = BTreeMap::new();
                btm_port.insert(service.port, service.clone());
                btm_addr.insert(service.addr, btm_port);
            }
        }
        let mut i = 1;
        let mut total_cost = 0.0;
        for (_addr, btm_port) in btm_addr {
            for (_port, service) in btm_port {
                let mut service_vec = Vec::new();
                let mut vesioninfo_vec = Vec::new();
                for m in &service.matchs {
                    let (service, version) = match m {
                        MatchX::Match(m) => (&m.service, &m.versioninfo.to_string()),
                        MatchX::SoftMatch(sm) => (&sm.service, &String::new()),
                    };
                    if !service_vec.contains(service) && service.trim().len() > 0 {
                        service_vec.push(service.trim().to_string());
                    }
                    if !vesioninfo_vec.contains(version) && version.trim().len() > 0 {
                        vesioninfo_vec.push(version.trim().to_string());
                    }
                }
                let mut services_str = service_vec.join("|");
                let versioninfo_str = vesioninfo_vec.join("|");
                if services_str.trim().len() == 0 {
                    services_str = String::from("unknown|closed");
                }
                let addr_str = match service.origin {
                    Some(o) => format!("{}({})", service.addr, o),
                    None => format!("{}", service.addr),
                };
                total_cost += service.time_cost.as_secs_f32();
                let time_cost_str = time_to_string(service.time_cost);
                table.add_row(
                    row![c -> i, c -> addr_str, c -> service.port, c -> services_str, c -> versioninfo_str, c -> time_cost_str],
                );
                i += 1;
            }
        }

        let total_cost_str = time_to_string(Duration::from_secs_f32(total_cost));
        let summary = format!("total used time: {}", total_cost_str);
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(6)]));
        write!(f, "{}", table)
    }
}

impl PistolVsScans {
    pub fn new() -> PistolVsScans {
        PistolVsScans {
            port_services: Vec::new(),
            start_time: Local::now(),
            finish_time: Local::now(),
        }
    }
    pub fn finish(&mut self, port_services: Vec<PortService>) {
        self.finish_time = Local::now();
        self.port_services = port_services;
    }
}

fn get_nmap_service_probes() -> Result<Vec<ServiceProbe>, PistolError> {
    let data = include_bytes!("./db/nmap-service-probes.zip");
    let reader = Cursor::new(data);
    let mut archive = ZipArchive::new(reader)?;

    if archive.len() > 0 {
        let mut file = archive.by_index(0)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let ret: Vec<ServiceProbe> = serde_json::from_str(&contents)?;
        Ok(ret)
    } else {
        Err(PistolError::ZipEmptyError)
    }
}

pub fn vs_scan(
    targets: &[VersionScanTarget],
    threads: usize,
    intensity: usize,
    timeout: Duration,
) -> Result<PistolVsScans, PistolError> {
    let mut ret = PistolVsScans::new();
    let pool = ThreadPool::new(threads);
    let (tx, rx) = channel();

    let service_probes = get_nmap_service_probes()?;
    debug!("nmap service db load finish");

    let mut recv_size = 0;
    for t in targets {
        let dst_addr = t.dst_addr;
        for &dst_port in &t.dst_ports {
            let origin = t.origin.clone();
            let tx = tx.clone();
            let service_probes = service_probes.clone();

            let only_null_probe = t.only_null_probe;
            let only_tcp_recommended = t.only_tcp_recommended;
            let only_udp_recommended = t.only_udp_recommended;

            debug!("dst: {}, port: {}", dst_addr, dst_port);
            pool.execute(move || {
                let start_time = Instant::now();
                let probe_ret = vs_scan_thread(
                    dst_addr,
                    dst_port,
                    only_null_probe,
                    only_tcp_recommended,
                    only_udp_recommended,
                    intensity,
                    service_probes,
                    timeout,
                );
                if let Err(e) = tx.send((dst_addr, dst_port, origin, probe_ret, start_time)) {
                    error!("failed to send to tx on func vs_scan: {}", e);
                }
            });
            recv_size += 1;
        }
    }

    let rx = rx.into_iter().take(recv_size);
    let mut port_services = Vec::new();
    for (addr, port, origin, probe_ret, start_time) in rx {
        match probe_ret {
            Ok(matchs) => {
                let port_service = PortService {
                    addr,
                    port,
                    origin,
                    matchs,
                    time_cost: start_time.elapsed(),
                };
                port_services.push(port_service);
            }
            Err(e) => return Err(e),
        }
    }
    ret.finish(port_services);
    Ok(ret)
}
