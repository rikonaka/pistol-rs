#[cfg(feature = "vs")]
use chrono::DateTime;
#[cfg(feature = "vs")]
use chrono::Local;
#[cfg(feature = "vs")]
use dbparser::ServiceProbe;
#[cfg(feature = "vs")]
use prettytable::Cell;
#[cfg(feature = "vs")]
use prettytable::Row;
#[cfg(feature = "vs")]
use prettytable::Table;
#[cfg(feature = "vs")]
use prettytable::row;
#[cfg(feature = "vs")]
use std::collections::BTreeMap;
#[cfg(feature = "vs")]
use std::fmt;
#[cfg(feature = "vs")]
use std::io::Cursor;
#[cfg(feature = "vs")]
use std::io::Read;
#[cfg(feature = "vs")]
use std::net::IpAddr;
#[cfg(feature = "vs")]
use std::sync::mpsc::channel;
#[cfg(feature = "vs")]
use std::time::Duration;
#[cfg(feature = "vs")]
use std::time::Instant;
#[cfg(feature = "vs")]
use tracing::debug;
#[cfg(feature = "vs")]
use tracing::error;
#[cfg(feature = "vs")]
use zip::ZipArchive;

#[cfg(feature = "vs")]
use crate::Target;
#[cfg(feature = "vs")]
use crate::error::PistolError;
#[cfg(feature = "vs")]
use crate::utils::get_threads_pool;
#[cfg(feature = "vs")]
use crate::utils::time_to_string;
#[cfg(feature = "vs")]
use crate::vs::dbparser::nmap_service_probes_parser;
#[cfg(feature = "vs")]
use crate::vs::vscan::MatchX;
#[cfg(feature = "vs")]
use crate::vs::vscan::vs_scan_thread;

#[cfg(feature = "vs")]
pub mod dbparser;
#[cfg(feature = "vs")]
pub mod vscan;

#[cfg(feature = "vs")]
#[derive(Debug, Clone)]
pub struct PortService {
    pub addr: IpAddr,
    pub port: u16,
    pub origin: Option<String>,
    pub matchs: Vec<MatchX>,
    pub time_cost: Duration,
}

#[cfg(feature = "vs")]
#[derive(Debug, Clone)]
pub struct PistolVsScans {
    pub port_services: Vec<PortService>,
    pub start_time: DateTime<Local>,
    pub finish_time: DateTime<Local>,
}

#[cfg(feature = "vs")]
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
                total_cost += service.time_cost.as_secs_f64();
                let time_cost_str = time_to_string(service.time_cost);
                table.add_row(
                    row![c -> i, c -> addr_str, c -> service.port, c -> services_str, c -> versioninfo_str, c -> time_cost_str],
                );
                i += 1;
            }
        }

        let avg_cost = total_cost / self.port_services.len() as f64;
        let summary = format!(
            "total used time: {:.2}s, avg time cost: {:.2}s",
            total_cost, avg_cost,
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(6)]));
        write!(f, "{}", table)
    }
}

#[cfg(feature = "vs")]
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

#[cfg(feature = "vs")]
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

#[cfg(feature = "vs")]
pub fn vs_scan(
    targets: &[Target],
    threads: usize,
    only_null_probe: bool,
    only_tcp_recommended: bool,
    only_udp_recommended: bool,
    intensity: usize,
    timeout: Duration,
) -> Result<PistolVsScans, PistolError> {
    let mut ret = PistolVsScans::new();

    let pool = get_threads_pool(threads);
    let (tx, rx) = channel();

    let service_probes = get_nmap_service_probes()?;
    debug!("nmap service db load finish");

    let mut recv_size = 0;
    for target in targets {
        let dst_addr = target.addr;
        for &dst_port in &target.ports {
            let origin = target.origin.clone();
            let tx = tx.clone();
            let service_probes = service_probes.clone();
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

#[cfg(feature = "vs")]
pub fn vs_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    only_null_probe: bool,
    only_tcp_recommended: bool,
    only_udp_recommended: bool,
    intensity: usize,
    timeout: Duration,
) -> Result<PortService, PistolError> {
    let nsp_str = include_str!("./db/nmap-service-probes");
    let mut nsp_lines = Vec::new();
    for l in nsp_str.lines() {
        nsp_lines.push(l.to_string());
    }
    debug!("nmap service db load finish");

    let service_probes = nmap_service_probes_parser(nsp_lines)?;
    debug!("nmap service db parse finish");

    let start_time = Instant::now();
    match vs_scan_thread(
        dst_addr,
        dst_port,
        only_null_probe,
        only_tcp_recommended,
        only_udp_recommended,
        intensity,
        service_probes,
        timeout,
    ) {
        Ok(matchs) => {
            let port_service = PortService {
                addr: dst_addr,
                port: dst_port,
                origin: None,
                matchs,
                time_cost: start_time.elapsed(),
            };
            Ok(port_service)
        }
        Err(e) => Err(e),
    }
}

#[cfg(feature = "vs")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Target;
    use std::net::Ipv4Addr;
    #[test]
    fn test_vs_detect() {
        let dst_ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 152));
        let target = Target::new(dst_ipv4, Some(vec![22, 80, 8080]));
        let timeout = Duration::from_secs_f64(0.5);
        let (only_null_probe, only_tcp_recommended, only_udp_recommended) = (false, true, true);
        let intensity = 7; // nmap default
        let threads = 8;
        let ret = vs_scan(
            &[target],
            threads,
            only_null_probe,
            only_tcp_recommended,
            only_udp_recommended,
            intensity,
            timeout,
        )
        .unwrap();
        println!("{}", ret);
    }
}
