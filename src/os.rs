/* Remote OS Detection */
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::mpsc::channel;
use std::time::Duration;

use crate::errors::CanNotFoundSourceAddress;
use crate::errors::OsDetectPortError;
use crate::os::dbparser::NmapOsDb;
use crate::os::osscan::PistolFingerprint;
use crate::os::osscan6::PistolFingerprint6;
use crate::utils::find_source_addr;
use crate::utils::find_source_addr6;
use crate::utils::get_default_timeout;
use crate::utils::get_threads_pool;
use crate::Target;

use self::osscan::os_probe;
use self::osscan6::os_probe6;

pub mod dbparser;
pub mod operator;
pub mod operator6;
pub mod osscan;
pub mod osscan6;
pub mod packet;
pub mod packet6;
pub mod rr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapOsDetectRet {
    pub score: usize,
    pub total: usize,
    pub db: NmapOsDb,
}

impl fmt::Display for NmapOsDetectRet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        let s = format!(">>> Score:\n{}/{}\n", self.score, self.total);
        output += &s;

        let info_split: Vec<&str> = self.db.info.split("\n").collect();
        for (i, v) in info_split.iter().enumerate() {
            let v = v.replace("# ", "");
            let s = if i == 0 {
                format!(">>> Info:\n{}\n", v)
            } else {
                format!("{}\n", v)
            };
            output += &s;
        }
        let fingerprint_split: Vec<&str> = self.db.fingerprint.split("\n").collect();
        for (i, v) in fingerprint_split.iter().enumerate() {
            let v = v.replace("Fingerprint ", "");
            let s = if i == 0 {
                format!(">>> Fingerprint:\n{}\n", v)
            } else {
                format!("{}\n", v)
            };
            output += &s;
        }
        let class_split: Vec<&str> = self.db.class.split("\n").collect();
        for (i, v) in class_split.iter().enumerate() {
            let v = v.replace("Class ", "");
            let s = if i == 0 {
                format!(">>> Class:\n{}\n", v)
            } else {
                format!("{}\n", v)
            };
            output += &s;
        }
        let cpe_split: Vec<&str> = self.db.cpe.split("\n").collect();
        for (i, v) in cpe_split.iter().enumerate() {
            let v = v.replace("CPE ", "");
            let s = if i == 0 {
                format!(">>> CPE:\n{}\n", v)
            } else {
                format!("{}\n", v)
            };
            output += &s;
        }
        // let output = output.trim();
        write!(f, "{}", output)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapOsDetectRet6 {
    pub name: String,
    pub osclass: Vec<Vec<String>>,
    pub cpe: Vec<String>,
    pub score: f64,
    pub label: usize,
}

impl fmt::Display for NmapOsDetectRet6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = format!(">>> Score:\n{:.2}%\n", self.score * 100.0);
        output += &format!(">>> Fingerprint:\n{}\n", self.name);
        output += ">>> Class:\n";
        for o in &self.osclass {
            let mut o_str = String::new();
            for c in o {
                let c_str = format!(" {} |", c);
                o_str += &c_str;
            }
            let o_str = o_str[1..o_str.len() - 2].to_string();
            output += &o_str;
            output += "\n";
        }
        output += ">>> CPE:\n";
        for c in &self.cpe {
            output += c;
            output += "\n";
        }
        let output = output.trim();
        write!(f, "{}", output)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostOsDetectStatus {
    pub fingerprint: PistolFingerprint,
    pub detects: Vec<NmapOsDetectRet>,
}

impl HostOsDetectStatus {
    pub fn new(
        fingerprint: PistolFingerprint,
        detects: Vec<NmapOsDetectRet>,
    ) -> HostOsDetectStatus {
        HostOsDetectStatus {
            fingerprint,
            detects,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsDetectResults {
    pub results: HashMap<Ipv4Addr, HostOsDetectStatus>,
}

impl OsDetectResults {
    pub fn new() -> OsDetectResults {
        OsDetectResults {
            results: HashMap::new(),
        }
    }
    pub fn get(&self, k: &Ipv4Addr) -> Option<&HostOsDetectStatus> {
        self.results.get(k)
    }
}

impl fmt::Display for OsDetectResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        for (ipv4, oss) in &self.results {
            let fingerprint = &oss.fingerprint;
            let detect_ret = &oss.detects;
            output += &format!(">>> IP:\n{ipv4}\n");
            output += &format!(">>> Pistol fingerprint:\n{fingerprint}\n");
            output += &format!(">>> Details:");
            for d in detect_ret {
                output += &format!("{}", d);
            }
        }
        write!(f, "{}", output)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostOsDetectStatus6 {
    pub fingerprint: PistolFingerprint6,
    pub detects: Vec<NmapOsDetectRet6>,
}

impl HostOsDetectStatus6 {
    pub fn new(
        fingerprint: PistolFingerprint6,
        detects: Vec<NmapOsDetectRet6>,
    ) -> HostOsDetectStatus6 {
        HostOsDetectStatus6 {
            fingerprint,
            detects,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsDetectResults6 {
    pub results: HashMap<Ipv6Addr, HostOsDetectStatus6>,
}

impl OsDetectResults6 {
    pub fn new() -> OsDetectResults6 {
        OsDetectResults6 {
            results: HashMap::new(),
        }
    }
    pub fn get(&self, k: &Ipv6Addr) -> Option<&HostOsDetectStatus6> {
        self.results.get(k)
    }
}

impl fmt::Display for OsDetectResults6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        for (ipv6, oss) in &self.results {
            let fingerprint = &oss.fingerprint;
            let detect_ret = &oss.detects;
            output += &format!(">>> IP:\n{ipv6}\n");
            output += &format!(">>> Novelty:\n{}", fingerprint.novelty);
            for d in detect_ret {
                output += &format!("{}", d);
            }
        }
        write!(f, "{}", output)
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
    pub namelist: Vec<String>,
    pub w: Vec<Vec<f64>>,
    pub scale: Vec<Vec<f64>>,
    pub mean: Vec<Vec<f64>>,
    pub variance: Vec<Vec<f64>>,
    pub cpe: Vec<CPE>,
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
                let os_detect_ret = os_probe(
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
                let oss = HostOsDetectStatus::new(fingerprint, detect_ret);
                ret.results.insert(ipv4, oss);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(ret)
}

fn gen_linear() -> Result<Linear> {
    let variance_json_data = include_str!("./db/nmap-os-db-ipv6/variance.json");
    let variance_json: Vec<NmapJsonParameters> = serde_json::from_str(variance_json_data)?;

    let mut namelist = Vec::new();
    let mut variance = Vec::new();
    for v in variance_json {
        variance.push(v.value);
        namelist.push(v.name);
    }
    assert_eq!(namelist.len(), 92);
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
        namelist,
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
                let os_detect_ret = os_probe6(
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
                let oss = HostOsDetectStatus6::new(fingerprint, detect_ret);
                ret.results.insert(ipv6, oss);
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
    use crate::DST_IPV4_REMOTE;
    use crate::DST_IPV6_REMOTE;
    use std::time::SystemTime;
    #[test]
    fn test_os_detect6() -> Result<()> {
        let src_ipv6 = None;
        let dst_open_tcp_port = 22;
        let dst_closed_tcp_port = 8765;
        let dst_closed_udp_port = 9876;
        let host = Host6::new(
            DST_IPV6_REMOTE,
            Some(vec![
                dst_open_tcp_port,
                dst_closed_tcp_port,
                dst_closed_udp_port,
            ]),
        );

        let target = Target::new6(vec![host]);
        let src_port = None;
        let timeout = Some(Duration::new(3, 0));
        let top_k = 3;
        let threads_num = 8;
        let ret = os_detect6(target, src_ipv6, src_port, top_k, threads_num, timeout).unwrap();
        println!("{}", ret);
        Ok(())
    }
    #[test]
    fn test_os_detect() -> Result<()> {
        let src_ipv4 = None;
        let src_port = None;
        // let dst_ipv4 = Ipv4Addr::new(127, 0, 0, 1);
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
        let top_k = 1;
        let threads_num = 8;

        let ret = os_detect(target, src_ipv4, src_port, top_k, threads_num, timeout).unwrap();
        // println!("{}", ret.results.get(&dst_ipv4).unwrap().fingerprint);
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
