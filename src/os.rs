/* Remote OS Detection */
use log::debug;
use log::warn;
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
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::mpsc::channel;
use std::time::Duration;

use crate::errors::PistolErrors;
use crate::os::dbparser::NmapOsDb;
use crate::os::osscan::threads_os_probe;
use crate::os::osscan::PistolFingerprint;
use crate::os::osscan6::threads_os_probe6;
use crate::os::osscan6::PistolFingerprint6;
use crate::utils::find_source_addr;
use crate::utils::find_source_addr6;
use crate::utils::get_default_timeout;
use crate::utils::get_threads_pool;
use crate::Target;

pub mod dbparser;
pub mod dbparser_re;
pub mod operator;
pub mod operator6;
pub mod osscan;
pub mod osscan6;
pub mod packet;
pub mod packet6;
pub mod rr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub info: String,
    pub class: String,
    pub cpe: String,
    pub score: usize,
    pub total: usize,
    pub db: NmapOsDb,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostOsDetect4 {
    pub fingerprint: PistolFingerprint,
    pub detects: Vec<OsInfo>,
}

impl HostOsDetect4 {
    pub fn new(fingerprint: PistolFingerprint, detects: Vec<OsInfo>) -> HostOsDetect4 {
        HostOsDetect4 {
            fingerprint,
            detects,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsDetectResults {
    pub oss: HashMap<IpAddr, HostOsDetect>,
}

impl OsDetectResults {
    pub fn new() -> OsDetectResults {
        OsDetectResults {
            oss: HashMap::new(),
        }
    }
    pub fn get(&self, k: &IpAddr) -> Option<&HostOsDetect> {
        self.oss.get(k)
    }
}

impl fmt::Display for OsDetectResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![Cell::new("OS Detect Results")
            .style_spec("c")
            .with_hspan(4)]));

        let oss = &self.oss;
        let oss: BTreeMap<IpAddr, &HostOsDetect> = oss.into_iter().map(|(i, h)| (*i, h)).collect();
        for (ip, o) in oss {
            match o {
                HostOsDetect::V4(o) => {
                    for (i, ni) in o.detects.iter().enumerate() {
                        let number_str = format!("#{}", i + 1);
                        let score_str = format!("{}/{}", ni.score, ni.total);
                        // let os_str = format!("{}", ni.db.info);
                        let os_str = format!("");
                        table.add_row(row![c -> ip, c -> number_str, c -> score_str, c -> os_str]);
                    }
                }
                HostOsDetect::V6(o) => {
                    for (i, os_info6) in o.detects.iter().enumerate() {
                        let number_str = format!("#{}", i + 1);
                        let score_str = format!("{:.1}", os_info6.score);
                        let os_str = &os_info6.info;
                        table.add_row(row![c -> ip, c -> number_str, c -> score_str, c -> os_str]);
                    }
                }
            }
        }
        // let summary = format!("Summary");
        // table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(4)]));
        write!(f, "{}", table)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo6 {
    pub info: String,
    pub class: String,
    pub cpe: String,
    pub score: f64,
    pub label: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostOsDetect6 {
    pub fingerprint: PistolFingerprint6,
    pub detects: Vec<OsInfo6>,
}

impl HostOsDetect6 {
    pub fn new(fingerprint: PistolFingerprint6, detects: Vec<OsInfo6>) -> HostOsDetect6 {
        HostOsDetect6 {
            fingerprint,
            detects,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostOsDetect {
    V4(HostOsDetect4),
    V6(HostOsDetect6),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NmapJsonParameters {
    pub name: String,
    pub value: Vec<f64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CPE {
    pub name: String,
    pub osclass: Vec<Vec<String>>,
    pub cpe: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Linear {
    pub infolist: Vec<String>,
    pub w: Vec<Vec<f64>>,
    pub scale: Vec<Vec<f64>>,
    pub mean: Vec<Vec<f64>>,
    pub variance: Vec<Vec<f64>>,
    pub cpe: Vec<CPE>,
}

fn gen_linear() -> Result<Linear, PistolErrors> {
    let variance_json_data = include_str!("./db/nmap-os-db-ipv6/variance.json");
    let variance_json: Vec<NmapJsonParameters> = serde_json::from_str(variance_json_data)?;

    let mut infolist = Vec::new();
    let mut variance = Vec::new();
    for v in variance_json {
        variance.push(v.value);
        infolist.push(v.name);
    }
    assert_eq!(infolist.len(), 92);
    assert_eq!(variance.len(), 92);

    let mean_json_data = include_str!("./db/nmap-os-db-ipv6/mean.json");
    let mean_json: Vec<NmapJsonParameters> = serde_json::from_str(mean_json_data)?;
    let mut mean = Vec::new();
    for m in mean_json {
        mean.push(m.value);
    }
    assert_eq!(mean.len(), 92);

    let scale_json_data = include_str!("./db/nmap-os-db-ipv6/scale.json"); // static
    let scale_json: Vec<NmapJsonParameters> = serde_json::from_str(scale_json_data)?;
    let mut scale: Vec<Vec<f64>> = Vec::new();
    for s in scale_json {
        scale.push(s.value)
    }
    assert_eq!(scale.len(), 695);

    let w_json_data = include_str!("./db/nmap-os-db-ipv6/w.json"); // static
    let w_json: Vec<NmapJsonParameters> = serde_json::from_str(w_json_data)?;
    assert_eq!(w_json.len(), 695);

    let mut w = Vec::new();
    // [695, 92] => [92, 695]
    for i in 0..w_json[0].value.len() {
        let mut tmp = Vec::new();
        for x in &w_json {
            tmp.push(x.value[i]);
        }
        w.push(tmp);
    }

    let cpe_json_data = include_str!("./db/nmap-os-db-ipv6/cpe.json"); // static
    let cpe: Vec<CPE> = serde_json::from_str(cpe_json_data)?;
    assert_eq!(cpe.len(), 92);

    let linear = Linear {
        infolist,
        scale,
        w,
        mean,
        variance,
        cpe,
    };
    Ok(linear)
}

fn ipv4_os_detect(
    dst_ipv4: Ipv4Addr,
    dst_ports: Vec<u16>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    top_k: usize,
    timeout: Duration,
) -> Result<(PistolFingerprint, Vec<OsInfo>), PistolErrors> {
    let src_ipv4 = match find_source_addr(src_addr, dst_ipv4)? {
        Some(s) => s,
        None => return Err(PistolErrors::CanNotFoundSourceAddress),
    };
    let nmap_os_file = include_str!("./db/nmap-os-db");
    let mut nmap_os_file_lines = Vec::new();
    for l in nmap_os_file.lines() {
        nmap_os_file_lines.push(l.to_string());
    }
    let nmap_os_db = dbparser::nmap_os_db_parser(nmap_os_file_lines)?;
    debug!("ipv4 nmap os db parse finish");

    if dst_ports.len() >= 3 {
        let dst_open_tcp_port = dst_ports[0];
        let dst_closed_tcp_port = dst_ports[1];
        let dst_closed_udp_port = dst_ports[2];
        let nmap_os_db = nmap_os_db.to_vec();
        let os_detect_ret = threads_os_probe(
            src_ipv4,
            src_port,
            dst_ipv4,
            dst_open_tcp_port,
            dst_closed_tcp_port,
            dst_closed_udp_port,
            nmap_os_db,
            top_k,
            timeout,
        );
        os_detect_ret
    } else {
        Err(PistolErrors::OsDetectPortError)
    }
}

fn ipv6_os_detect(
    dst_ipv6: Ipv6Addr,
    dst_ports: Vec<u16>,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    top_k: usize,
    timeout: Duration,
) -> Result<(PistolFingerprint6, Vec<OsInfo6>), PistolErrors> {
    let src_ipv6 = match find_source_addr6(src_addr, dst_ipv6)? {
        Some(s) => s,
        None => return Err(PistolErrors::CanNotFoundSourceAddress),
    };
    let linear = gen_linear()?;
    debug!("ipv6 gen linear parse finish");

    if dst_ports.len() >= 3 {
        let dst_open_tcp_port = dst_ports[0];
        let dst_closed_tcp_port = dst_ports[1];
        let dst_closed_udp_port = dst_ports[2];
        let os_detect_ret = threads_os_probe6(
            src_ipv6,
            src_port,
            dst_ipv6,
            dst_open_tcp_port,
            dst_closed_tcp_port,
            dst_closed_udp_port,
            top_k,
            linear,
            timeout,
        );
        os_detect_ret
    } else {
        Err(PistolErrors::OsDetectPortError)
    }
}

/// Detect target machine OS on IPv4 and IPv6.
pub fn os_detect(
    target: Target,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    top_k: usize,
    threads_num: usize,
    timeout: Option<Duration>,
) -> Result<OsDetectResults, PistolErrors> {
    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };
    let (tx, rx) = channel();
    let pool = get_threads_pool(threads_num);
    let mut recv_size = 0;
    for t in target.hosts {
        let dst_addr = t.addr;
        let tx = tx.clone();
        recv_size += 1;
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                let dst_ports = t.ports;
                pool.execute(move || {
                    let ret = match ipv4_os_detect(
                        dst_ipv4, dst_ports, src_addr, src_port, top_k, timeout,
                    ) {
                        Ok((fingerprint, detect_ret)) => {
                            let oss = HostOsDetect4::new(fingerprint, detect_ret);
                            let oss = HostOsDetect::V4(oss);
                            Ok(oss)
                        }
                        Err(e) => {
                            warn!("ipv4 os detect error: {}", e);
                            Err(e)
                        }
                    };
                    match tx.send((dst_addr, ret)) {
                        _ => (),
                    }
                });
            }
            IpAddr::V6(dst_ipv6) => {
                let dst_ports = t.ports;
                pool.execute(move || {
                    let ret = match ipv6_os_detect(
                        dst_ipv6, dst_ports, src_addr, src_port, top_k, timeout,
                    ) {
                        Ok((fingerprint, detect_ret)) => {
                            let oss = HostOsDetect6::new(fingerprint, detect_ret);
                            let oss = HostOsDetect::V6(oss);
                            Ok(oss)
                        }
                        Err(e) => {
                            warn!("ipv6 os detect error: {}", e);
                            Err(e)
                        }
                    };
                    match tx.send((dst_addr, ret)) {
                        _ => (),
                    }
                });
            }
        }
    }

    let mut ret = OsDetectResults::new();
    let iter = rx.into_iter().take(recv_size);
    for (addr, r) in iter {
        match r {
            Ok(detect_ret) => {
                ret.oss.insert(addr, detect_ret);
            }
            Err(e) => return Err(e),
        }
    }

    Ok(ret)
}

pub fn os_detect_raw(
    dst_addr: IpAddr,
    dst_open_tcp_port: u16,
    dst_closed_tcp_port: u16,
    dst_closed_udp_port: u16,
    src_addr: Option<IpAddr>,
    top_k: usize,
    timeout: Option<Duration>,
) -> Result<OsDetectResults, PistolErrors> {
    let src_port = None;
    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };
    match dst_addr {
        IpAddr::V4(dst_ipv4) => match find_source_addr(src_addr, dst_ipv4)? {
            Some(src_ipv4) => {
                let nmap_os_file = include_str!("./db/nmap-os-db");
                let mut nmap_os_file_lines = Vec::new();
                for l in nmap_os_file.lines() {
                    nmap_os_file_lines.push(l.to_string());
                }
                let nmap_os_db = dbparser::nmap_os_db_parser(nmap_os_file_lines)?;
                debug!("ipv4 nmap os db parse finish");

                let nmap_os_db = nmap_os_db.to_vec();
                match threads_os_probe(
                    src_ipv4,
                    src_port,
                    dst_ipv4,
                    dst_open_tcp_port,
                    dst_closed_tcp_port,
                    dst_closed_udp_port,
                    nmap_os_db,
                    top_k,
                    timeout,
                ) {
                    Ok((fingerprint, ret)) => {
                        let oss = HostOsDetect4::new(fingerprint, ret);
                        let oss = HostOsDetect::V4(oss);
                        let mut ret = OsDetectResults::new();
                        ret.oss.insert(dst_addr, oss);
                        Ok(ret)
                    }
                    Err(e) => Err(e),
                }
            }
            None => Err(PistolErrors::CanNotFoundSourceAddress),
        },
        IpAddr::V6(dst_ipv6) => match find_source_addr6(src_addr, dst_ipv6)? {
            Some(src_ipv6) => {
                let linear = gen_linear()?;
                debug!("ipv6 gen linear parse finish");

                match threads_os_probe6(
                    src_ipv6,
                    src_port,
                    dst_ipv6,
                    dst_open_tcp_port,
                    dst_closed_tcp_port,
                    dst_closed_udp_port,
                    top_k,
                    linear,
                    timeout,
                ) {
                    Ok((fingerprint, ret)) => {
                        let oss = HostOsDetect6::new(fingerprint, ret);
                        let oss = HostOsDetect::V6(oss);
                        let mut ret = OsDetectResults::new();
                        ret.oss.insert(dst_addr, oss);
                        Ok(ret)
                    }
                    Err(e) => Err(e),
                }
            }
            None => Err(PistolErrors::CanNotFoundSourceAddress),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::dbparser::nmap_os_db_parser;
    use crate::Host;
    // use crate::Logger;
    use crate::TEST_IPV4_LOCAL;
    use crate::TEST_IPV6_LOCAL;
    use std::time::Instant;
    #[test]
    fn test_os_detect() {
        // Logger::init_debug_logging()?;
        let src_ipv6 = None;
        let dst_open_tcp_port = 22;
        let dst_closed_tcp_port = 8765;
        let dst_closed_udp_port = 9876;
        let host1 = Host::new(
            TEST_IPV6_LOCAL.into(),
            Some(vec![
                dst_open_tcp_port,
                dst_closed_tcp_port,
                dst_closed_udp_port,
            ]),
        );
        let host2 = Host::new(
            TEST_IPV4_LOCAL.into(),
            Some(vec![
                dst_open_tcp_port,
                dst_closed_tcp_port,
                dst_closed_udp_port,
            ]),
        );

        let target = Target::new(vec![host1, host2]);
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
        let top_k = 3;
        let threads_num = 8;
        let ret = os_detect(target, src_ipv6, src_port, top_k, threads_num, timeout).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_parser() {
        let start = Instant::now();

        let nmap_os_file = include_str!("./db/nmap-os-db");
        let mut nmap_os_file_lines = Vec::new();
        for l in nmap_os_file.lines() {
            nmap_os_file_lines.push(l.to_string());
        }
        let ret = nmap_os_db_parser(nmap_os_file_lines).unwrap();
        for i in 0..5 {
            let r = &ret[i];
            println!("{:?}", r.name);
            // println!("{:?}", r.seq.gcd);
        }

        // in my homelab server: parse time: 1.285817538s
        println!("parse time: {:.2}s", start.elapsed().as_secs_f64());
        // let serialized = serde_json::to_string(&ret).unwrap();
        // let mut file_write = File::create("nmap-os-db.pistol").unwrap();
        // file_write.write_all(serialized.as_bytes()).unwrap();
    }
}
