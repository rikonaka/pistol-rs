use dbparser::ServiceProbe;
use log::debug;
use prettytable::row;
use prettytable::Cell;
use prettytable::Row;
use prettytable::Table;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt;
use std::io::Cursor;
use std::io::Read;
use std::net::IpAddr;
use std::sync::mpsc::channel;
use std::time::Duration;
use std::time::Instant;
use zip::ZipArchive;

use crate::errors::PistolErrors;
use crate::utils::get_default_timeout;
use crate::utils::get_threads_pool;
use crate::utils::threads_num_check;
use crate::vs::dbparser::nmap_service_probes_parser;
use crate::vs::vscan::threads_vs_probe;
use crate::vs::vscan::MatchX;
use crate::Target;

pub mod dbparser;
pub mod vscan;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Services {
    pub matchs: Vec<MatchX>,
    pub elapsed: Duration,
}

impl Services {
    pub fn new() -> Services {
        Services {
            matchs: Vec::new(),
            elapsed: Duration::new(0, 0),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VsScanResults {
    pub vss: HashMap<IpAddr, HashMap<u16, Services>>,
    pub total_time_cost: f64,
    pub avg_time_cost: f64,
    start_time: Instant,
}

impl VsScanResults {
    pub fn new() -> VsScanResults {
        VsScanResults {
            vss: HashMap::new(),
            total_time_cost: 0.0,
            avg_time_cost: 0.0,
            start_time: Instant::now(),
        }
    }
    pub fn get(&self, k: &IpAddr) -> Option<&HashMap<u16, Services>> {
        self.vss.get(k)
    }
    pub fn enrichment(&mut self) {
        self.total_time_cost = self.start_time.elapsed().as_secs_f64();
        let mut total_time = 0.0;
        let mut total_num = 0;
        for (_, h) in &self.vss {
            for (_, s) in h {
                total_time += s.elapsed.as_secs_f64();
                total_num += 1;
            }
        }
        self.avg_time_cost = total_time / total_num as f64;
    }
}

impl fmt::Display for VsScanResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![Cell::new("Service Scan Results")
            .style_spec("c")
            .with_hspan(4)]));

        table.add_row(row![c -> "id", c -> "addr", c -> "port", c -> "service"]);
        let vss = &self.vss;
        let vss: BTreeMap<IpAddr, &HashMap<u16, Services>> =
            vss.into_iter().map(|(i, h)| (*i, h)).collect();
        let mut i = 1;
        for (ip, ports_service) in vss {
            let ports_service: BTreeMap<u16, &Services> =
                ports_service.into_iter().map(|(p, s)| (*p, s)).collect();
            for (port, services) in ports_service {
                let mut sv = Vec::new();
                for m in &services.matchs {
                    let service = match m {
                        MatchX::Match(m) => &m.service,
                        MatchX::SoftMatch(sm) => &sm.service,
                    };
                    if !sv.contains(service) {
                        sv.push(service.to_string());
                    }
                }
                let mut services_str = sv.join(",");
                if services_str.trim().len() == 0 {
                    services_str = String::from("closed|nomatch");
                }
                table.add_row(row![c -> i, c -> ip, c -> port, c -> services_str]);
                i += 1;
            }
        }
        let summary = format!(
            "total used time: {:.2}ms\navg time cost: {:.2}ms",
            self.total_time_cost * 1000.0,
            self.avg_time_cost * 1000.0,
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(4)]));
        write!(f, "{}", table)
    }
}

fn get_nmap_service_probes() -> Result<Vec<ServiceProbe>, PistolErrors> {
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
        Err(PistolErrors::ZipEmptyError)
    }
}

/// Detect target port service.
pub fn vs_scan(
    target: Target,
    threads_num: Option<usize>,
    only_null_probe: bool,
    only_tcp_recommended: bool,
    only_udp_recommended: bool,
    intensity: usize,
    timeout: Option<Duration>,
) -> Result<VsScanResults, PistolErrors> {
    let threads_num = match threads_num {
        Some(t) => t,
        None => {
            let mut threads_num = 0;
            for h in &target.hosts {
                threads_num += h.ports.len();
            }
            let threads_num = threads_num_check(threads_num);
            threads_num
        }
    };

    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };

    let pool = get_threads_pool(threads_num);
    let (tx, rx) = channel();

    let service_probes = get_nmap_service_probes()?;
    debug!("nmap service db load finish");

    let mut recv_size = 0;
    for host in target.hosts {
        let dst_addr = host.addr;
        for dst_port in host.ports {
            let tx = tx.clone();
            let service_probes = service_probes.clone();
            pool.execute(move || {
                let ret = threads_vs_probe(
                    dst_addr,
                    dst_port,
                    only_null_probe,
                    only_tcp_recommended,
                    only_udp_recommended,
                    intensity,
                    service_probes,
                    timeout,
                );
                match tx.send((dst_addr, dst_port, ret)) {
                    _ => (),
                }
            });
            recv_size += 1;
        }
    }

    let mut ret = VsScanResults::new();
    let rx = rx.into_iter().take(recv_size);
    for (addr, port, r) in rx {
        match r {
            Ok((r, rtt)) => {
                let mut service_status = Services::new();
                service_status.matchs = r;
                service_status.elapsed = rtt;
                match ret.vss.get_mut(&addr) {
                    Some(services) => {
                        services.insert(port, service_status);
                    }
                    None => {
                        let mut host = HashMap::new();
                        host.insert(port, service_status);
                        ret.vss.insert(addr, host);
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
    ret.enrichment();
    Ok(ret)
}

pub fn vs_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    only_null_probe: bool,
    only_tcp_recommended: bool,
    only_udp_recommended: bool,
    intensity: usize,
    timeout: Option<Duration>,
) -> Result<Services, PistolErrors> {
    let nsp_str = include_str!("./db/nmap-service-probes");
    let mut nsp_lines = Vec::new();
    for l in nsp_str.lines() {
        nsp_lines.push(l.to_string());
    }
    debug!("nmap service db load finish");

    let service_probes = nmap_service_probes_parser(nsp_lines)?;
    debug!("nmap service db parse finish");

    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };

    match threads_vs_probe(
        dst_addr,
        dst_port,
        only_null_probe,
        only_tcp_recommended,
        only_udp_recommended,
        intensity,
        service_probes,
        timeout,
    ) {
        Ok((r, rtt)) => {
            let mut service_status = Services::new();
            service_status.matchs = r;
            service_status.elapsed = rtt;
            Ok(service_status)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Host;
    // use crate::Logger;
    use crate::TEST_IPV4_LOCAL;
    #[test]
    fn test_vs_detect() {
        // Logger::init_debug_logging()?;
        let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 80]));
        let target = Target::new(vec![host]);
        let timeout = Some(Duration::new(1, 0));
        let (only_null_probe, only_tcp_recommended, only_udp_recommended) = (false, true, true);
        let intensity = 7; // nmap default
        let threads_num = Some(8);
        let ret = vs_scan(
            target,
            threads_num,
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
