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

use anyhow::Result;

use self::dbparser::ExcludePorts;
use crate::utils::get_default_timeout;
use crate::utils::get_threads_pool;
use crate::vs::dbparser::nsp_exclued_parser;
use crate::vs::dbparser::nsp_parser;
use crate::vs::dbparser::Match;
use crate::vs::vscan::threads_vs_probe;
use crate::Target;
use crate::TargetType;

pub mod dbparser;
pub mod vscan;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Services {
    pub matchs: Vec<Match>,
    pub rtt: Option<Duration>,
}

impl Services {
    pub fn new() -> Services {
        Services {
            matchs: Vec::new(),
            rtt: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsScanResults {
    pub vss: HashMap<IpAddr, HashMap<u16, Services>>,
    pub avg_rtt: Option<Duration>,
}

impl VsScanResults {
    pub fn new() -> VsScanResults {
        VsScanResults {
            vss: HashMap::new(),
            avg_rtt: None,
        }
    }
    pub fn get(&self, k: &IpAddr) -> Option<&HashMap<u16, Services>> {
        self.vss.get(k)
    }
    pub fn enrichment(&mut self) {
        // avg rtt
        let mut total_rtt = 0.0;
        let mut total_num = 0;
        for (_ip, ports_service) in &self.vss {
            for (_port, services) in ports_service {
                match services.rtt {
                    Some(rtt) => {
                        total_rtt += rtt.as_secs_f64();
                        total_num += 1;
                    }
                    None => (),
                };
            }
        }
        let avg_rtt = if total_num != 0 {
            let avg_rtt = total_rtt / total_num as f64;
            let avg_rtt = Duration::from_secs_f64(avg_rtt);
            Some(avg_rtt)
        } else {
            None
        };
        self.avg_rtt = avg_rtt;
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
        let summary = match self.avg_rtt {
            Some(avg_rtt) => format!("Summary:\navg rtt: {:.3}s", avg_rtt.as_secs_f32(),),
            None => format!("Summary:\navg rtt: 0.00s"),
        };
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(3)]));

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
) -> Result<VsScanResults> {
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
    match target.target_type {
        TargetType::Ipv4 => {
            for h in target.hosts {
                let addr = IpAddr::V4(h.addr);
                vs_target.insert(addr, h.ports);
            }
        }
        TargetType::Ipv6 => {
            for h in target.hosts6 {
                let addr = IpAddr::V6(h.addr);
                vs_target.insert(addr, h.ports);
            }
        }
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
                service_status.rtt = Some(rtt);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Host;
    use crate::Logger;
    use crate::DST_IPV4_REMOTE;
    use fancy_regex::Regex;
    use std::fs::File;
    use std::io::Read;
    #[test]
    fn test_vs_detect() -> Result<()> {
        Logger::init_debug_logging()?;
        let host = Host::new(DST_IPV4_REMOTE, Some(vec![22, 80]));
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
        )?;
        println!("{}", ret);
        Ok(())
    }
    #[test]
    fn test_regex() {
        let mut buff = [0u8; 102400];
        let mut file = File::open("./response.bin").unwrap();
        file.read(&mut buff).unwrap();
        println!("{}", buff.len());

        let buff_str = String::from_utf8_lossy(&buff);

        println!("start nsp");
        let nsp_str = include_str!("./db/nmap-service-probes");
        let mut nsp_lines = Vec::new();
        for l in nsp_str.lines() {
            nsp_lines.push(l.to_string());
        }

        // let _exclude_ports = nsp_exclued_parser(&nsp_lines).unwrap();
        let service_probes = nsp_parser(&nsp_lines).unwrap();
        println!("end nsp");

        // let ssh_str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7";

        for s in service_probes {
            if s.probe.probename == "GetRequest" {
                let _ret = s.check(&buff_str);
                // for m in s.matchs {
                //     if m.pattern == r"^HTTP/1\.[01] \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: Apache[/ ](\d[-.\w]+) ([^\r\n]+)\s" {
                //         println!("FIND!");
                //     }
                // }
            }
        }

        let re = Regex::new(r"^HTTP/1\.[01] \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: Apache[/ ](\d[-.\w]+) ([^\r\n]+)\s").unwrap();
        let m = re.is_match(&buff_str).unwrap();
        println!("{}", m);
    }
}
