#[cfg(feature = "vs")]
use chrono::DateTime;
#[cfg(feature = "vs")]
use chrono::Local;
#[cfg(feature = "vs")]
use dbparser::ServiceProbe;
#[cfg(feature = "vs")]
use log::debug;
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
use std::collections::HashMap;
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
use crate::utils::threads_num_check;
#[cfg(feature = "vs")]
use crate::vs::dbparser::nmap_service_probes_parser;
#[cfg(feature = "vs")]
use crate::vs::vscan::MatchX;
#[cfg(feature = "vs")]
use crate::vs::vscan::threads_vs_probe;

#[cfg(feature = "vs")]
pub mod dbparser;
#[cfg(feature = "vs")]
pub mod vscan;

#[cfg(feature = "vs")]
#[derive(Debug, Clone)]
pub struct PortServices {
    pub matchs: Vec<MatchX>,
    pub rtt: Duration,
    pub stime: DateTime<Local>,
    pub etime: DateTime<Local>,
}

#[cfg(feature = "vs")]
impl PortServices {
    pub fn new() -> PortServices {
        PortServices {
            matchs: Vec::new(),
            rtt: Duration::new(0, 0),
            stime: Local::now(),
            etime: Local::now(),
        }
    }
}

#[cfg(feature = "vs")]
#[derive(Debug, Clone)]
pub struct VsScans {
    pub vss: HashMap<IpAddr, HashMap<u16, PortServices>>,
    pub total_cost: i64,
    pub avg_cost: f64,
    pub stime: DateTime<Local>,
    pub etime: DateTime<Local>,
}

#[cfg(feature = "vs")]
impl VsScans {
    pub fn new() -> VsScans {
        VsScans {
            vss: HashMap::new(),
            total_cost: 0,
            avg_cost: 0.0,
            stime: Local::now(),
            etime: Local::now(),
        }
    }
    pub fn get(&self, k: &IpAddr) -> Option<&HashMap<u16, PortServices>> {
        self.vss.get(k)
    }
    pub fn enrichment(&mut self) {
        self.etime = Local::now();
        self.total_cost = self
            .etime
            .signed_duration_since(self.stime)
            .num_milliseconds();
        let mut total_num = 0;
        for (_, h) in &self.vss {
            total_num += h.len();
        }
        self.avg_cost = self.total_cost as f64 / total_num as f64;
    }
}

#[cfg(feature = "vs")]
impl fmt::Display for VsScans {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Service Scan Results")
                .style_spec("c")
                .with_hspan(5),
        ]));

        table
            .add_row(row![c -> "id", c -> "addr", c -> "port", c -> "service", c -> "versioninfo"]);
        let vss = &self.vss;
        let vss: BTreeMap<IpAddr, &HashMap<u16, PortServices>> =
            vss.into_iter().map(|(i, h)| (*i, h)).collect();
        let mut i = 1;
        for (ip, ports_service) in vss {
            let ports_service: BTreeMap<u16, &PortServices> =
                ports_service.into_iter().map(|(p, s)| (*p, s)).collect();
            for (port, services) in ports_service {
                let mut sv = Vec::new();
                let mut vv = Vec::new();
                for m in &services.matchs {
                    let (service, version) = match m {
                        MatchX::Match(m) => (&m.service, &m.versioninfo.to_string()),
                        MatchX::SoftMatch(sm) => (&sm.service, &String::new()),
                    };
                    if !sv.contains(service) && service.trim().len() > 0 {
                        sv.push(service.trim().to_string());
                    }
                    if !vv.contains(version) && version.trim().len() > 0 {
                        vv.push(version.trim().to_string());
                    }
                }
                let mut services_str = sv.join("|");
                let versioninfo_str = vv.join("|");
                if services_str.trim().len() == 0 {
                    services_str = String::from("unknown|closed");
                }
                table.add_row(
                    row![c -> i, c -> ip, c -> port, c -> services_str, c -> versioninfo_str],
                );
                i += 1;
            }
        }
        let summary = format!(
            "total used time: {:.2} ms\navg time cost: {:.2} ms",
            self.total_cost, self.avg_cost,
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(5)]));
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
    target: &Target,
    threads_num: Option<usize>,
    only_null_probe: bool,
    only_tcp_recommended: bool,
    only_udp_recommended: bool,
    intensity: usize,
    timeout: Option<Duration>,
) -> Result<VsScans, PistolError> {
    let mut ret = VsScans::new();
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
    for host in &target.hosts {
        let dst_addr = host.addr;
        for &dst_port in &host.ports {
            let tx = tx.clone();
            let service_probes = service_probes.clone();
            debug!("dst: {}, port: {}", dst_addr, dst_port);
            pool.execute(move || {
                let stime = Local::now();
                let probe_ret = threads_vs_probe(
                    dst_addr,
                    dst_port,
                    only_null_probe,
                    only_tcp_recommended,
                    only_udp_recommended,
                    intensity,
                    service_probes,
                    timeout,
                );
                tx.send((dst_addr, dst_port, probe_ret, stime))
                    .expect(&format!("tx send failed: {}-{}", file!(), line!()));
            });
            recv_size += 1;
        }
    }

    let rx = rx.into_iter().take(recv_size);
    for (addr, port, probe_ret, stime) in rx {
        match probe_ret {
            Ok((r, rtt)) => {
                let etime = Local::now();
                let mut port_services = PortServices::new();
                port_services.stime = stime;
                port_services.stime = etime;
                port_services.matchs = r;
                port_services.rtt = rtt;
                match ret.vss.get_mut(&addr) {
                    Some(services) => {
                        services.insert(port, port_services);
                    }
                    None => {
                        let mut host = HashMap::new();
                        host.insert(port, port_services);
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

#[cfg(feature = "vs")]
pub fn vs_scan_raw(
    dst_addr: IpAddr,
    dst_port: u16,
    only_null_probe: bool,
    only_tcp_recommended: bool,
    only_udp_recommended: bool,
    intensity: usize,
    timeout: Option<Duration>,
) -> Result<PortServices, PistolError> {
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
            let mut service_status = PortServices::new();
            service_status.matchs = r;
            service_status.rtt = rtt;
            Ok(service_status)
        }
        Err(e) => Err(e),
    }
}

#[cfg(feature = "vs")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Target;
    use crate::TEST_IPV4_LOCAL;
    use fancy_regex::Regex as FancyRegex;
    use std::net::Ipv4Addr;
    // use kdam::tqdm;
    #[test]
    fn test_vs_detect_github() {
        use crate::Logger;
        let _ = Logger::init_debug_logging();
        // let dst_addr = Ipv4Addr::new(47, 104, 100, 200);
        let dst_addr = Ipv4Addr::new(45, 33, 32, 156); // scanme.nmap.org
        let host = Target::new(dst_addr.into(), Some(vec![80, 8099]));
        let target = Target::new(vec![host]);
        let timeout = Some(Duration::new(1, 0));
        let (only_null_probe, only_tcp_recommended, only_udp_recommended) = (false, true, true);
        let intensity = 7; // nmap default
        let threads_num = Some(8);
        let ret = vs_scan(
            &target,
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
    #[test]
    fn test_vs_detect() {
        // use crate::Logger;
        // let _ = Logger::init_debug_logging();
        let host = Target::new(TEST_IPV4_LOCAL.into(), Some(vec![22, 80, 8080]));
        // let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![8080]));
        // let host = Host::new(TEST_IPV4_LOCAL.into(), Some(vec![80]));
        let target = Target::new(vec![host]);
        let timeout = Some(Duration::new(1, 0));
        let (only_null_probe, only_tcp_recommended, only_udp_recommended) = (false, true, true);
        let intensity = 7; // nmap default
        let threads_num = Some(8);
        let ret = vs_scan(
            &target,
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
