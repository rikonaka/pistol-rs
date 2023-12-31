use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::channel;

use crate::errors::OsDetectPortError;
use crate::fingerprint::dbparser::NmapOsDb;
use crate::fingerprint::osscan::PistolFingerprint;
use crate::fingerprint::osscan6::PistolFingerprint6;
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

pub struct NmapOsDetectRet {
    pub score: usize,
    pub total: usize,
    pub db: NmapOsDb,
}

impl fmt::Display for NmapOsDetectRet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        let s = format!(">>> Score: {}/{}\n", self.score, self.total);
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

#[derive(Debug, Clone)]
pub struct NmapOsDetectRet6 {
    pub name: String,
    pub osclass: Vec<Vec<String>>,
    pub cpe: Vec<String>,
    pub score: f64,
    pub label: usize,
}

impl fmt::Display for NmapOsDetectRet6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = format!(">>> Score: {:.2}%\n", self.score * 100.0);
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

#[derive(Debug, Clone)]
pub struct Linear {
    pub namelist: Vec<String>,
    pub w: Vec<Vec<f64>>,
    pub scale: Vec<Vec<f64>>,
    pub mean: Vec<Vec<f64>>,
    pub variance: Vec<Vec<f64>>,
    pub cpe: Vec<CPE>,
}

fn find_position_multi(score_vec: &Vec<usize>, value: usize) -> Vec<usize> {
    let mut position = Vec::new();
    for (i, s) in score_vec.iter().enumerate() {
        if *s == value {
            position.push(i)
        }
    }
    position
}

fn find_position_one(score_vec: &Vec<usize>, value: usize) -> Option<usize> {
    for (i, s) in score_vec.iter().enumerate() {
        if *s == value {
            return Some(i);
        }
    }
    None
}

fn top_k_score(score_vec: &Vec<usize>, k: usize) -> Vec<usize> {
    let mut score_vec = score_vec.clone();
    let mut top_k_vec = Vec::new();
    for _ in 0..k {
        let mut max_score = 0;
        for s in &score_vec {
            if *s > max_score {
                max_score = *s;
            }
        }

        loop {
            match find_position_one(&score_vec, max_score) {
                Some(p) => {
                    score_vec.remove(p);
                }
                None => break,
            }
        }

        top_k_vec.push(max_score);
    }
    top_k_vec
}

fn os_detect_thread(
    src_ipv4: Ipv4Addr,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_open_tcp_port: u16,
    dst_closed_tcp_port: u16,
    dst_closed_udp_port: u16,
    nmap_os_db: Vec<NmapOsDb>,
    top_k: usize,
    max_loop: usize,
) -> Result<(PistolFingerprint, Vec<NmapOsDetectRet>)> {
    let nmap_fingerprint = osscan::os_probe(
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_open_tcp_port,
        dst_closed_tcp_port,
        dst_closed_udp_port,
        max_loop,
    )?;

    let mut score_vec = Vec::new();
    let mut total_vec = Vec::new();
    for n in &nmap_os_db {
        let (score, total) = n.check(&nmap_fingerprint);
        score_vec.push(score);
        total_vec.push(total);
    }

    let top_k_score_vec = top_k_score(&score_vec, top_k);
    let mut top_k_index_vec = Vec::new();
    for k in top_k_score_vec {
        for p in find_position_multi(&score_vec, k) {
            top_k_index_vec.push(p);
        }
    }

    let mut dr_vec = Vec::new();
    for i in top_k_index_vec {
        let dr = NmapOsDetectRet {
            score: score_vec[i],
            total: total_vec[i],
            db: nmap_os_db[i].clone(),
        };
        dr_vec.push(dr);
    }
    Ok((nmap_fingerprint, dr_vec))
}

pub fn os_detect(
    target: Target,
    src_ipv4: Ipv4Addr,
    src_port: Option<u16>,
    top_k: usize,
    threads_num: usize,
    max_loop: usize,
) -> Result<HashMap<Ipv4Addr, (PistolFingerprint, Vec<NmapOsDetectRet>)>> {
    let nmap_os_file = include_str!("./db/nmap-os-db");
    let nmap_os_file_lines = nmap_os_file.split("\n").map(str::to_string).collect();
    let nmap_os_db = dbparser::nmap_os_db_parser(nmap_os_file_lines)?;
    let (tx, rx) = channel();
    let pool = get_threads_pool(threads_num);
    let mut recv_size = 0;
    for t in target.hosts {
        let dst_ipv4 = t.addr;
        if t.ports.len() >= 3 {
            recv_size += 1;
            let dst_open_tcp_port = t.ports[0];
            let dst_closed_tcp_port = t.ports[1];
            let dst_closed_udp_port = t.ports[2];
            let tx = tx.clone();
            let nmap_os_db = nmap_os_db.to_vec();
            pool.execute(move || {
                let os_detect_ret = os_detect_thread(
                    src_ipv4,
                    src_port,
                    dst_ipv4,
                    dst_open_tcp_port,
                    dst_closed_tcp_port,
                    dst_closed_udp_port,
                    nmap_os_db,
                    top_k,
                    max_loop,
                );
                match tx.send((dst_ipv4, os_detect_ret)) {
                    _ => (),
                }
            });
        } else {
            return Err(OsDetectPortError::new().into());
        }
    }
    let mut ret: HashMap<Ipv4Addr, (PistolFingerprint, Vec<NmapOsDetectRet>)> = HashMap::new();
    let iter = rx.into_iter().take(recv_size);
    for (i, r) in iter {
        match r {
            Ok(r) => {
                ret.insert(i, r);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(ret)
}

fn gen_linear() -> Result<Linear> {
    let variance_json_data = include_str!("./db/variance.json");
    let variance_json: Vec<NmapJsonParameters> = serde_json::from_str(variance_json_data)?;

    let mut namelist = Vec::new();
    let mut variance = Vec::new();
    for v in variance_json {
        variance.push(v.value);
        namelist.push(v.name);
    }
    assert_eq!(namelist.len(), 92);
    assert_eq!(variance.len(), 92);

    let mean_json_data = include_str!("./db/mean.json");
    let mean_json: Vec<NmapJsonParameters> = serde_json::from_str(mean_json_data)?;
    let mut mean = Vec::new();
    for m in mean_json {
        mean.push(m.value);
    }
    assert_eq!(mean.len(), 92);

    let scale_json_data = include_str!("./db/scale.json"); // static
    let scale_json: Vec<NmapJsonParameters> = serde_json::from_str(scale_json_data)?;
    let mut scale: Vec<Vec<f64>> = Vec::new();
    for s in scale_json {
        scale.push(s.value)
    }
    assert_eq!(scale.len(), 695);

    let w_json_data = include_str!("./db/w.json"); // static
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

    let cpe_json_data = include_str!("./db/cpe.json"); // static
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

pub fn os_detect6(
    target: Target,
    src_ipv6: Ipv6Addr,
    src_port: Option<u16>,
    top_k: usize,
    threads_num: usize,
    max_loop: usize,
) -> Result<HashMap<Ipv6Addr, PistolFingerprint6>> {
    let linear = gen_linear()?;
    let (tx, rx) = channel();
    let pool = get_threads_pool(threads_num);
    let mut recv_size = 0;
    for t in target.hosts6 {
        let dst_ipv6 = t.addr;
        if t.ports.len() >= 3 {
            recv_size += 1;
            let dst_open_tcp_port = t.ports[0];
            let dst_closed_tcp_port = t.ports[1];
            let dst_closed_udp_port = t.ports[2];
            let tx = tx.clone();
            let linear = linear.clone();
            pool.execute(move || {
                let os_detect_ret = osscan6::os_probe6(
                    src_ipv6,
                    src_port,
                    dst_ipv6,
                    dst_open_tcp_port,
                    dst_closed_tcp_port,
                    dst_closed_udp_port,
                    top_k,
                    max_loop,
                    linear,
                );
                match tx.send((dst_ipv6, os_detect_ret)) {
                    _ => (),
                }
            });
        } else {
            return Err(OsDetectPortError::new().into());
        }
    }

    let mut ret: HashMap<Ipv6Addr, PistolFingerprint6> = HashMap::new();
    let iter = rx.into_iter().take(recv_size);
    for (i, r) in iter {
        match r {
            Ok(r) => {
                ret.insert(i, r);
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
    use std::net::Ipv6Addr;
    use std::time::SystemTime;
    #[test]
    fn test_os_detect6() {
        let src_ipv6: Ipv6Addr = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:feb6:8d99".parse().unwrap();
        let dst_open_tcp_port_1 = 22;
        let dst_closed_tcp_port_1 = 8765;
        let dst_closed_udp_port_1 = 9876;
        let host1 = Host6::new(
            dst_ipv6,
            Some(vec![
                dst_open_tcp_port_1,
                dst_closed_tcp_port_1,
                dst_closed_udp_port_1,
            ]),
        );

        let dst_ipv6: Ipv6Addr = "fe80::6445:b9f8:cc82:3015".parse().unwrap();
        let dst_open_tcp_port_2 = 22;
        let dst_closed_tcp_port_2 = 8765;
        let dst_closed_udp_port_2 = 9876;
        let host2 = Host6::new(
            dst_ipv6,
            Some(vec![
                dst_open_tcp_port_2,
                dst_closed_tcp_port_2,
                dst_closed_udp_port_2,
            ]),
        );

        let target = Target::new6(vec![host1, host2]);

        // let dst_ipv6: Ipv6Addr = "fe80::6445:b9f8:cc82:3015".parse().unwrap();
        let src_port = None;
        let max_loop = 8;
        let top_k = 3;
        let threads_num = 8;

        let ret = os_detect6(target, src_ipv6, src_port, top_k, threads_num, max_loop).unwrap();
        for (i, p) in ret {
            println!(">>> IP:\n{}", i);
            println!(">>> Novelty:\n{}", p.novelty);
            for pred in p.predict {
                println!("{}", pred);
            }
        }
    }
    #[test]
    fn test_os_probe() {
        let src_ipv6: Ipv6Addr = "fe80::20c:29ff:fe43:9c82".parse().unwrap();
        let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2a:e252".parse().unwrap();
        // let dst_ipv6: Ipv6Addr = "fe80::6445:b9f8:cc82:3015".parse().unwrap();
        let src_port = None;
        let dst_open_tcp_port = 22;
        let dst_closed_tcp_port = 99;
        let dst_closed_udp_port = 7890;
        let max_loop = 8;
        let top_k = 3;

        let linear = gen_linear().unwrap();
        let _ret = osscan6::os_probe6(
            src_ipv6,
            src_port,
            dst_ipv6,
            dst_open_tcp_port,
            dst_closed_tcp_port,
            dst_closed_udp_port,
            top_k,
            max_loop,
            linear,
        )
        .unwrap();
    }
    #[test]
    fn test_os_detect() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let src_port = None;
        let dst_ipv4_1 = Ipv4Addr::new(192, 168, 72, 134);
        let dst_open_tcp_port_1 = 22;
        let dst_closed_tcp_port_1 = 8765;
        let dst_closed_udp_port_1 = 9876;
        let host1 = Host::new(
            dst_ipv4_1,
            Some(vec![
                dst_open_tcp_port_1,
                dst_closed_tcp_port_1,
                dst_closed_udp_port_1,
            ]),
        );
        let dst_ipv4_2 = Ipv4Addr::new(192, 168, 72, 137);
        let dst_open_tcp_port_2 = 22;
        let dst_closed_tcp_port_2 = 54532;
        let dst_closed_udp_port_2 = 34098;
        let host2 = Host::new(
            dst_ipv4_2,
            Some(vec![
                dst_open_tcp_port_2,
                dst_closed_tcp_port_2,
                dst_closed_udp_port_2,
            ]),
        );
        let target = Target::new(vec![host1, host2]);
        // let target = Target::new(vec![host1]);
        let max_loop = 8;
        let top_k = 1;
        let threads_num = 8;

        let ret = os_detect(target, src_ipv4, src_port, top_k, threads_num, max_loop).unwrap();

        for (ip, (fingerprint, detect_ret)) in ret {
            println!(">>> IP:\n{}", ip);
            println!(">>> Pistol fingerprint:\n{}", fingerprint);
            println!(">>> Details:");
            for d in detect_ret {
                println!("{}", d);
            }
        }
    }
    #[test]
    fn test_parser() {
        let start = SystemTime::now();

        let nmap_os_file = include_str!("./db/nmap-os-db");
        let nmap_os_file_lines = nmap_os_file.split("\n").map(str::to_string).collect();
        let _ret = nmap_os_db_parser(nmap_os_file_lines).unwrap();
        // for i in 0..5 {
        //     let r = &ret[i];
        //     println!("{:?}", r.seq.gcd);
        // }

        // in my homelab server: parse time: 1.285817538s
        println!("parse time: {:?}", start.elapsed().unwrap());
        // let serialized = serde_json::to_string(&ret).unwrap();
        // let mut file_write = File::create("nmap-os-db.pistol").unwrap();
        // file_write.write_all(serialized.as_bytes()).unwrap();
    }
}
