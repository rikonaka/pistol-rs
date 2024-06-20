use serde::Deserialize;
use serde::Serialize;
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
use crate::vs::vscan::vs_probe;
use crate::Target;
use crate::TargetType;

pub mod dbparser;
pub mod vscan;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub services: Vec<Match>,
    pub elapsed: Option<Duration>,
}

impl ServiceStatus {
    pub fn new() -> ServiceStatus {
        ServiceStatus {
            services: Vec::new(),
            elapsed: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostServiceScanStatus {
    pub results: HashMap<u16, ServiceStatus>,
    pub avg_elapsed: Option<Duration>,
}

impl HostServiceScanStatus {
    pub fn new() -> HostServiceScanStatus {
        HostServiceScanStatus {
            results: HashMap::new(),
            avg_elapsed: None,
        }
    }
    pub fn get(&self, k: &u16) -> Option<&ServiceStatus> {
        self.results.get(k)
    }
    pub fn enrichment(&mut self) {
        // avg rtt
        let mut total_elapsed = 0.0;
        let mut total_num = 0;
        for (_port, services) in &self.results {
            let elapsed = services.elapsed;
            match elapsed {
                Some(d) => {
                    total_elapsed += d.as_secs_f64();
                    total_num += 1;
                }
                None => (),
            }
        }
        let avg_elapsed = if total_num != 0 {
            let avg_elapsed = total_elapsed / total_num as f64;
            let avg_elapsed = Duration::from_secs_f64(avg_elapsed);
            Some(avg_elapsed)
        } else {
            None
        };
        self.avg_elapsed = avg_elapsed;
    }
}

impl fmt::Display for HostServiceScanStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        for (port, detect_ret) in &self.results {
            output += &format!(">>> port:\n{}\n", port);
            for m in &detect_ret.services {
                output += &format!(
                    ">>> Services:\n{}\n>>> Versioninfo:\n{}\n",
                    m.service, m.versioninfo
                );
            }
        }
        write!(f, "{}", output)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsScanResults {
    pub results: HashMap<IpAddr, HostServiceScanStatus>,
    pub avg_elapsed: Option<Duration>,
}

impl VsScanResults {
    pub fn new() -> VsScanResults {
        VsScanResults {
            results: HashMap::new(),
            avg_elapsed: None,
        }
    }
    pub fn get(&self, k: &IpAddr) -> Option<&HostServiceScanStatus> {
        self.results.get(k)
    }
    pub fn enrichment(&mut self) {
        // reverser
        for (_ip, host_service_status) in &mut self.results {
            host_service_status.enrichment();
        }

        // avg rtt
        let mut total_elapsed = 0.0;
        let mut total_num = 0;
        for (_ip, host_service_status) in &self.results {
            let elapsed = host_service_status.avg_elapsed;
            match elapsed {
                Some(d) => {
                    total_elapsed += d.as_secs_f64();
                    total_num += 1;
                }
                None => (),
            }
        }
        let avg_elapsed = if total_num != 0 {
            let avg_elapsed = total_elapsed / total_num as f64;
            let avg_elapsed = Duration::from_secs_f64(avg_elapsed);
            Some(avg_elapsed)
        } else {
            None
        };
        self.avg_elapsed = avg_elapsed;
    }
}

impl fmt::Display for VsScanResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        for (addr, services) in &self.results {
            output += &format!(">>>> IP:\n{}\n{}", addr, services);
        }
        write!(f, "{}", output)
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

    let mut recv_size = 0;
    for (addr, ports) in vs_target {
        for port in ports {
            // Nmap checks to see if the port is one of the ports to be excluded.
            if !exclude_ports.ports.contains(&port) {
                let tx = tx.clone();
                let service_probes = service_probes.clone();
                pool.execute(move || {
                    let r = vs_probe(
                        addr,
                        port,
                        only_null_probe,
                        only_tcp_recommended,
                        only_udp_recommended,
                        intensity,
                        &service_probes,
                        timeout,
                    );
                    match tx.send((addr, port, r)) {
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
            Ok((r, elapsed)) => {
                let mut service_status = ServiceStatus::new();
                service_status.services = r;
                service_status.elapsed = Some(elapsed);
                match ret.results.get_mut(&addr) {
                    Some(host) => {
                        host.results.insert(port, service_status);
                    }
                    None => {
                        let mut host = HostServiceScanStatus::new();
                        host.results.insert(port, service_status);
                        ret.results.insert(addr, host);
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
    use fancy_regex::Regex;
    use std::fs::File;
    use std::io::Read;
    use std::net::Ipv4Addr;
    #[test]
    fn test_vs_detect() -> Result<()> {
        let dst_addr = Ipv4Addr::new(192, 168, 1, 51);
        let host = Host::new(dst_addr, Some(vec![22, 80]));
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
        println!("{:?}", ret);
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
