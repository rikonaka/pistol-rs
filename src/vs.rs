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
use zip::ZipArchive;

#[cfg(feature = "vs")]
use crate::Target;
#[cfg(feature = "vs")]
use crate::error::PistolError;
#[cfg(feature = "vs")]
use crate::utils::get_default_timeout;
#[cfg(feature = "vs")]
use crate::utils::get_threads_pool;
#[cfg(feature = "vs")]
use crate::utils::num_threads_check;
#[cfg(feature = "vs")]
use crate::utils::time_sec_to_string;
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
    pub end_time: DateTime<Local>,
}

#[cfg(feature = "vs")]
impl PistolVsScans {
    pub fn new() -> PistolVsScans {
        PistolVsScans {
            port_services: Vec::new(),
            start_time: Local::now(),
            end_time: Local::now(),
        }
    }
    pub fn finish(&mut self, port_services: Vec<PortService>) {
        self.end_time = Local::now();
        self.port_services = port_services;
    }
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
                let time_cost_str = time_sec_to_string(service.time_cost);
                table.add_row(
                    row![c -> i, c -> addr_str, c -> service.port, c -> services_str, c -> versioninfo_str, c -> time_cost_str],
                );
                i += 1;
            }
        }

        let avg_cost = total_cost / self.port_services.len() as f64;
        let summary = format!(
            "total used time: {:.3}s, avg time cost: {:.3}s",
            total_cost, avg_cost,
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(6)]));
        write!(f, "{}", table)
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

/// Detect target port service.
#[cfg(feature = "vs")]
pub fn vs_scan(
    targets: &[Target],
    num_threads: Option<usize>,
    only_null_probe: bool,
    only_tcp_recommended: bool,
    only_udp_recommended: bool,
    intensity: usize,
    timeout: Option<Duration>,
) -> Result<PistolVsScans, PistolError> {
    let mut ret = PistolVsScans::new();
    let num_threads = match num_threads {
        Some(t) => t,
        None => {
            let num_threads = targets.len();
            let num_threads = num_threads_check(num_threads);
            num_threads
        }
    };

    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };

    let pool = get_threads_pool(num_threads);
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
                let _ = tx.send((dst_addr, dst_port, origin, probe_ret, start_time));
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
    timeout: Option<Duration>,
) -> Result<PortService, PistolError> {
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
    use crate::PistolLogger;
    use crate::PistolRunner;
    use crate::Target;
    use fancy_regex::Regex as FancyRegex;
    use std::net::Ipv4Addr;
    #[test]
    fn test_vs_detect() {
        let _pr = PistolRunner::init(
            PistolLogger::None,
            None,
            None, // use default value
        )
        .unwrap();

        let dst_ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5));
        let target = Target::new(dst_ipv4, Some(vec![22, 80, 8080]));
        let timeout = Some(Duration::from_secs_f64(0.5));
        let (only_null_probe, only_tcp_recommended, only_udp_recommended) = (false, true, true);
        let intensity = 7; // nmap default
        let num_threads = Some(8);
        let ret = vs_scan(
            &[target],
            num_threads,
            only_null_probe,
            only_tcp_recommended,
            only_udp_recommended,
            intensity,
            timeout,
        )
        .unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_something() {
        let recv_str = r"S\xf5\xc6\x1a{123456}";
        let regex = FancyRegex::new(r"^S\\xf5\\xc6\\x1a{").unwrap();
        let b = regex.is_match(recv_str).unwrap();
        assert_eq!(b, true);

        let recv_str = r"\x2a";
        let regex = FancyRegex::new(r"(\\x2a|\\x2b)").unwrap();
        let b = regex.is_match(recv_str).unwrap();
        assert_eq!(b, true);

        let recv_str = r"\x2d";
        let regex = FancyRegex::new(r"(\\x2a|\\x2b)").unwrap();
        let b = regex.is_match(recv_str).unwrap();
        assert_eq!(b, false);

        let test_strs = vec![r"S\xf5\xc6\x1a{123456}"];

        let service_probes = get_nmap_service_probes().unwrap();
        for s in service_probes {
            for t in &test_strs {
                match s.check(t) {
                    Some(mx) => match mx {
                        MatchX::Match(m) => println!("{}", m.service),
                        MatchX::SoftMatch(m) => println!("{}", m.service),
                    },
                    None => (),
                }
            }
        }
    }
    #[test]
    #[ignore]
    fn test_httpd_regex() {
        // let _ = Logger::init_debug_logging();

        // let regex = FancyRegex::new(r"^HTTP/1\.[01] \d\d\d (?:[^\\r\\n]*\\r\\n(?!\\r\\n))*?Server: Apache[/ ](\d[-.\w]+) ([^\\r\\n]+)").unwrap();
        // let test_string = r"HTTP/1.1 200 OK\r\nDate: Wed, 18 Dec 2024 03:54:01 GMT\r\nServer: Apache/2.4.62 (Debian)\r\n";
        // let ret = regex.is_match(&test_string).unwrap();
        // println!("{}", ret);

        // let regex = FancyRegex::new(r"(?s)^HTTP/1\.[01] \d\d\d (?:[^\\r\\n]*\\r\\n(?!\\r\\n))*?Server: Apache[/ ](\d[-.\w]+) ([^\\r\\n]+)").unwrap();
        // let test_string = r"HTTP/1.1 200 OK\r\nDate: Wed, 18 Dec 2024 03:54:01 GMT\r\nServer: Apache/2.4.62 (Debian)\r\n";
        // let ret = regex.is_match(&test_string).unwrap();
        // println!("{}", ret);

        let regex = FancyRegex::new(r"^HTTP/1\.[01] \d\d\d (?:[^\\r\\n]*\\r\\n(?!\\r\\n))*?Server: Apache[/ ](\d[-.\w]+) ([^\\r\\n]+)").unwrap();
        let test_string = r"HTTP/1.1 200 OK\r\nDate: Tue, 07 Jan 2025 07:07:16 GMT\r\nServer: Apache/2.4.62 (Debian)\r\n";
        let ret = regex.is_match(&test_string).unwrap();
        println!("{}", ret);
        let test_string = r"HTTP/1.1 200 OK\r\nDate: Wed, 18 Dec 2024 03:54:01 GMT\r\nServer: Apache/2.4.62 (Debian)\r\n";
        let ret = regex.is_match(&test_string).unwrap();
        println!("{}", ret);

        // let nsp = get_nmap_service_probes().unwrap();
        // for n in tqdm!(nsp.into_iter()) {
        //     let mx = n.check(&test_string);
        //     if mx.is_some() {
        //         println!("{}", n.probe.probename);
        //     }
        // }
    }
    #[test]
    fn test_fancy_regex() {
        let regex = FancyRegex::new(r"^HTTP/1\.[01] \d\d\d (?:[^\\r\\n]*\\r\\n(?!\\r\\n))*?Server: Apache[/ ](\d[-.\w]+) ([^\\r\\n]+)").unwrap();
        let test_string = r"HTTP/1.1 200 OK\r\nDate: Tue, 07 Jan 2025 07:07:16 GMT\r\nServer: Apache/2.4.62 (Debian)\r\n";
        let ret = regex.is_match(&test_string).unwrap();
        println!("{}", ret);
        let test_string = r"HTTP/1.1 200 OK\r\nDate: Wed, 18 Dec 2024 03:54:01 GMT\r\nServer: Apache/2.4.62 (Debian)\r\n";
        let ret = regex.is_match(&test_string).unwrap();
        println!("{}", ret);

        let regex =
            FancyRegex::new(r"^HTTP/1\.[01] \d\d\d .*Server: Apache[/ ](\d[-.\w]+) ([^\\r\\n]+)")
                .unwrap();
        let test_string = r"HTTP/1.1 200 OK\r\nDate: Tue, 07 Jan 2025 07:07:16 GMT\r\nServer: Apache/2.4.62 (Debian)\r\n";
        let ret = regex.is_match(&test_string).unwrap();
        println!("{}", ret);
        let test_string = r"HTTP/1.1 200 OK\r\nDate: Wed, 18 Dec 2024 03:54:01 GMT\r\nServer: Apache/2.4.62 (Debian)\r\n";
        let ret = regex.is_match(&test_string).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_fancy_regex_github_issues_149() {
        let regex = FancyRegex::new(r"^HTTP/1\.[01] \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: Apache[/ ](\d[-.\w]+) ([^\r\n]+)").unwrap();
        let test_string = "HTTP/1.1 200 OK\r\nDate: Tue, 07 Jan 2025 07:07:16 GMT\r\nServer: Apache/2.4.62 (Debian)\r\n";
        let ret = regex.is_match(&test_string).unwrap();
        println!("{}", ret);
        let test_string = "HTTP/1.1 200 OK\r\nDate: Wed, 18 Dec 2024 03:54:01 GMT\r\nServer: Apache/2.4.62 (Debian)\r\n";
        let ret = regex.is_match(&test_string).unwrap();
        println!("{}", ret);
        let test_string = "HTTP/1.1 200 OK\r\nDate: Wed, 08 Jan 2025 01:50:56 GMT\r\nServer: Apache/2.4.62 (Debian)\r\nLast-Modified: Fri, 07 Jun 2024 03:51:06 GMTETag";
        let ret = regex.is_match(&test_string).unwrap();
        println!("{}", ret);

        let regex = FancyRegex::new(
            r"^HTTP/1\.[01] \d\d\d (?s:.)*Server: Apache[/ ](\d[-.\w]+) ([^\r\n]+)",
        )
        .unwrap();
        let test_string = "HTTP/1.1 200 OK\r\nDate: Tue, 07 Jan 2025 07:07:16 GMT\r\nServer: Apache/2.4.62 (Debian)\r\n";
        let ret = regex.is_match(&test_string).unwrap();
        println!("{}", ret);
        let test_string = "HTTP/1.1 200 OK\r\nDate: Wed, 18 Dec 2024 03:54:01 GMT\r\nServer: Apache/2.4.62 (Debian)\r\n";
        let ret = regex.is_match(&test_string).unwrap();
        println!("{}", ret);
    }
}
