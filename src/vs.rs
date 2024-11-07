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
use std::net::IpAddr;
use std::sync::mpsc::channel;
use std::time::Duration;

use crate::errors::PistolErrors;
use crate::utils::get_default_timeout;
use crate::utils::get_threads_pool;
use crate::vs::dbparser::nsp_exclued_parser;
use crate::vs::dbparser::nsp_parser;
use crate::vs::dbparser::ExcludePorts;
use crate::vs::dbparser::Match;
use crate::vs::vscan::threads_vs_probe;
use crate::Target;

pub mod dbparser;
pub mod vscan;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Services {
    pub matchs: Vec<Match>,
    pub elapsed: Option<Duration>,
}

impl Services {
    pub fn new() -> Services {
        Services {
            matchs: Vec::new(),
            elapsed: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsScanResults {
    pub vss: HashMap<IpAddr, HashMap<u16, Services>>,
}

impl VsScanResults {
    pub fn new() -> VsScanResults {
        VsScanResults {
            vss: HashMap::new(),
        }
    }
    pub fn get(&self, k: &IpAddr) -> Option<&HashMap<u16, Services>> {
        self.vss.get(k)
    }
}

impl fmt::Display for VsScanResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![Cell::new("Service Scan Results")
            .style_spec("c")
            .with_hspan(3)]));

        let vss = &self.vss;
        let vss: BTreeMap<IpAddr, &HashMap<u16, Services>> =
            vss.into_iter().map(|(i, h)| (*i, h)).collect();
        for (ip, ports_service) in vss {
            let ports_service: BTreeMap<u16, &Services> =
                ports_service.into_iter().map(|(p, s)| (*p, s)).collect();
            for (port, services) in ports_service {
                let mut sv = Vec::new();
                for m in &services.matchs {
                    if !sv.contains(&m.service) {
                        sv.push(m.service.clone());
                    }
                }
                let services_str = sv.join(",");
                table.add_row(row![c -> ip, c -> port, c -> services_str]);
            }
        }
        write!(f, "{}", table)
    }
}

/// Detect target port service.
pub fn vs_scan(
    target: Target,
    only_null_probe: bool,
    only_tcp_recommended: bool,
    only_udp_recommended: bool,
    exclude_ports: Option<ExcludePorts>,
    intensity: usize,
    threads_num: usize,
    timeout: Option<Duration>,
) -> Result<VsScanResults, PistolErrors> {
    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };
    let nsp_str = include_str!("./db/nmap-service-probes");
    let mut nsp_lines = Vec::new();
    for l in nsp_str.lines() {
        nsp_lines.push(l.to_string());
    }
    debug!("nmap service db load finish");

    let pool = get_threads_pool(threads_num);
    let (tx, rx) = channel();
    let mut vs_target = HashMap::new();

    for h in target.hosts {
        vs_target.insert(h.addr, h.ports);
    }

    let exclude_ports = match exclude_ports {
        Some(e) => e,
        None => nsp_exclued_parser(&nsp_lines)?,
    };
    let service_probes = nsp_parser(&nsp_lines)?;
    debug!("nmap service db parse finish");

    let mut recv_size = 0;
    for (dst_addr, ports) in vs_target {
        for dst_port in ports {
            // Nmap checks to see if the port is one of the ports to be excluded.
            if !exclude_ports.ports.contains(&dst_port) {
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
                        &service_probes,
                        timeout,
                    );
                    match tx.send((dst_addr, dst_port, ret)) {
                        _ => (),
                    }
                });
                recv_size += 1;
            }
        }
    }

    let mut ret = VsScanResults::new();
    let rx = rx.into_iter().take(recv_size);
    for (addr, port, r) in rx {
        match r {
            Ok((r, rtt)) => {
                let mut service_status = Services::new();
                service_status.matchs = r;
                service_status.elapsed = Some(rtt);
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

    let service_probes = nsp_parser(&nsp_lines)?;
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
        &service_probes,
        timeout,
    ) {
        Ok((r, rtt)) => {
            let mut service_status = Services::new();
            service_status.matchs = r;
            service_status.elapsed = Some(rtt);
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
        let threads_num = 8;
        let timeout = Some(Duration::new(1, 0));
        let (only_null_probe, only_tcp_recommended, only_udp_recommended) = (false, true, true);
        let exclude_ports = Some(ExcludePorts::new(vec![51, 52]));
        let intensity = 7; // nmap default
        let ret = vs_scan(
            target,
            only_null_probe,
            only_tcp_recommended,
            only_udp_recommended,
            exclude_ports,
            intensity,
            threads_num,
            timeout,
        )
        .unwrap();
        println!("{}", ret);
    }
}
