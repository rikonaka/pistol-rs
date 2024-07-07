/* Remote OS Detection */
use anyhow::Result;
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
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::mpsc::channel;
use std::time::Duration;

use crate::errors::CanNotFoundSourceAddress;
use crate::errors::OsDetectPortError;
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
pub struct HostOsDetect {
    pub fingerprint: PistolFingerprint,
    pub detects: Vec<OsInfo>,
}

impl HostOsDetect {
    pub fn new(fingerprint: PistolFingerprint, detects: Vec<OsInfo>) -> HostOsDetect {
        HostOsDetect {
            fingerprint,
            detects,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsDetectResults {
    pub oss: HashMap<Ipv4Addr, HostOsDetect>,
}

impl OsDetectResults {
    pub fn new() -> OsDetectResults {
        OsDetectResults {
            oss: HashMap::new(),
        }
    }
    pub fn get(&self, k: &Ipv4Addr) -> Option<&HostOsDetect> {
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
        let oss: BTreeMap<Ipv4Addr, &HostOsDetect> =
            oss.into_iter().map(|(i, h)| (*i, h)).collect();
        for (ip, o) in oss {
            for (i, ni) in o.detects.iter().enumerate() {
                let number_str = format!("#{}", i + 1);
                let score_str = format!("{}/{}", ni.score, ni.total);
                let os_str = format!("{}", ni.db.info);
                table.add_row(row![c -> ip, c -> number_str, c -> score_str, c -> os_str]);
            }
        }
        // let summary = format!("Summary");
        // table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(4)]));

        write!(f, "{}", table)
    }
}

/// Detect target machine OS.
pub fn os_detect(
    target: Target,
    src_ipv4: Option<Ipv4Addr>,
    src_port: Option<u16>,
    top_k: usize,
    threads_num: usize,
    timeout: Option<Duration>,
) -> Result<OsDetectResults> {
    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };
    let nmap_os_file = include_str!("./db/nmap-os-db");
    let mut nmap_os_file_lines = Vec::new();
    for l in nmap_os_file.lines() {
        nmap_os_file_lines.push(l.to_string());
    }
    let nmap_os_db = dbparser::nmap_os_db_parser(nmap_os_file_lines)?;
    debug!("nmap os db parse finish");

    let (tx, rx) = channel();
    let pool = get_threads_pool(threads_num);
    let mut recv_size = 0;
    for t in target.hosts {
        let dst_ipv4 = t.addr;
        let src_ipv4 = match find_source_addr(src_ipv4, dst_ipv4)? {
            Some(s) => s,
            None => return Err(CanNotFoundSourceAddress::new().into()),
        };
        if t.ports.len() >= 3 {
            recv_size += 1;
            let dst_open_tcp_port = t.ports[0];
            let dst_closed_tcp_port = t.ports[1];
            let dst_closed_udp_port = t.ports[2];
            let tx = tx.clone();
            let nmap_os_db = nmap_os_db.to_vec();
            pool.execute(move || {
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
                match tx.send((dst_ipv4, os_detect_ret)) {
                    _ => (),
                }
            });
        } else {
            return Err(OsDetectPortError::new().into());
        }
    }
    let mut ret = OsDetectResults::new();
    let iter = rx.into_iter().take(recv_size);
    for (ipv4, r) in iter {
        match r {
            Ok((fingerprint, detect_ret)) => {
                let oss = HostOsDetect::new(fingerprint, detect_ret);
                ret.oss.insert(ipv4, oss);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(ret)
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
pub struct OsDetectResults6 {
    pub oss: HashMap<Ipv6Addr, HostOsDetect6>,
}

impl OsDetectResults6 {
    pub fn new() -> OsDetectResults6 {
        OsDetectResults6 {
            oss: HashMap::new(),
        }
    }
    pub fn get(&self, k: &Ipv6Addr) -> Option<&HostOsDetect6> {
        self.oss.get(k)
    }
}

impl fmt::Display for OsDetectResults6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![Cell::new("OS Detect Results")
            .style_spec("c")
            .with_hspan(4)]));

        let oss = &self.oss;
        let oss: BTreeMap<Ipv6Addr, &HostOsDetect6> =
            oss.into_iter().map(|(i, h)| (*i, h)).collect();
        for (ip, o) in oss {
            for (i, os_info6) in o.detects.iter().enumerate() {
                let number_str = format!("#{}", i + 1);
                let score_str = format!("{:.1}", os_info6.score);
                let os_str = &os_info6.info;
                table.add_row(row![c -> ip, c -> number_str, c -> score_str, c -> os_str]);
            }
        }
        // let summary = format!("Summary");
        // table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(4)]));

        write!(f, "{}", table)
    }
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

fn gen_linear() -> Result<Linear> {
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

/// Detect target machine OS on IPv6.
pub fn os_detect6(
    target: Target,
    src_ipv6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    top_k: usize,
    threads_num: usize,
    timeout: Option<Duration>,
) -> Result<OsDetectResults6> {
    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };
    let (tx, rx) = channel();
    let pool = get_threads_pool(threads_num);
    let mut recv_size = 0;
    let linear = gen_linear()?;
    debug!("gen linear parse finish");
    for t in target.hosts6 {
        let dst_ipv6 = t.addr;
        let src_ipv6 = match find_source_addr6(src_ipv6, dst_ipv6)? {
            Some(s) => s,
            None => return Err(CanNotFoundSourceAddress::new().into()),
        };
        if t.ports.len() >= 3 {
            recv_size += 1;
            let dst_open_tcp_port = t.ports[0];
            let dst_closed_tcp_port = t.ports[1];
            let dst_closed_udp_port = t.ports[2];
            let tx = tx.clone();
            let linear = linear.clone();
            pool.execute(move || {
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
                match tx.send((dst_ipv6, os_detect_ret)) {
                    _ => (),
                }
            });
        } else {
            return Err(OsDetectPortError::new().into());
        }
    }

    let mut ret = OsDetectResults6::new();
    let iter = rx.into_iter().take(recv_size);
    for (ipv6, r) in iter {
        match r {
            Ok((fingerprint, detect_ret)) => {
                let oss = HostOsDetect6::new(fingerprint, detect_ret);
                ret.oss.insert(ipv6, oss);
            }
            Err(e) => return Err(e),
        }
    }

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nmap_os_db_parser;
    use crate::Host;
    use crate::Host6;
    // use crate::Logger;
    use crate::DST_IPV4_REMOTE;
    use crate::DST_IPV6_LOCAL;
    use std::time::SystemTime;
    #[test]
    fn test_os_detect6() -> Result<()> {
        // Logger::init_debug_logging()?;
        let src_ipv6 = None;
        let dst_open_tcp_port = 22;
        let dst_closed_tcp_port = 8765;
        let dst_closed_udp_port = 9876;
        let host = Host6::new(
            DST_IPV6_LOCAL,
            Some(vec![
                dst_open_tcp_port,
                dst_closed_tcp_port,
                dst_closed_udp_port,
            ]),
        );

        let target = Target::new6(vec![host]);
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
        let top_k = 3;
        let threads_num = 8;
        let ret = os_detect6(target, src_ipv6, src_port, top_k, threads_num, timeout).unwrap();
        println!("{}", ret);
        Ok(())
    }
    #[test]
    fn test_os_detect() -> Result<()> {
        // Logger::init_debug_logging()?;
        let src_ipv4 = None;
        let src_port = None;
        let dst_open_tcp_port = 22;
        let dst_closed_tcp_port = 8765;
        let dst_closed_udp_port = 9876;
        let host = Host::new(
            DST_IPV4_REMOTE,
            Some(vec![
                dst_open_tcp_port,
                dst_closed_tcp_port,
                dst_closed_udp_port,
            ]),
        );
        let target = Target::new(vec![host]);
        let timeout = Some(Duration::new(1, 0));
        let top_k = 3;
        let threads_num = 8;

        let ret = os_detect(target, src_ipv4, src_port, top_k, threads_num, timeout).unwrap();
        println!("{}", ret);
        Ok(())
    }
    #[test]
    fn test_parser() {
        let start = SystemTime::now();

        let nmap_os_file = include_str!("./db/nmap-os-db");
        let mut nmap_os_file_lines = Vec::new();
        for l in nmap_os_file.lines() {
            nmap_os_file_lines.push(l.to_string());
        }
        let ret = nmap_os_db_parser(nmap_os_file_lines).unwrap();
        for i in 0..5 {
            let r = &ret[i];
            println!("{:?}", r.info);
            println!("{:?}", r.seq.gcd);
        }

        // in my homelab server: parse time: 1.285817538s
        println!("parse time: {:?}", start.elapsed().unwrap());
        // let serialized = serde_json::to_string(&ret).unwrap();
        // let mut file_write = File::create("nmap-os-db.pistol").unwrap();
        // file_write.write_all(serialized.as_bytes()).unwrap();
    }
}
