use anyhow::Result;
use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::mpsc::channel;
use std::time::Duration;

use crate::errors::OsDetectPortError;
use crate::fingerprint::dbparser::NmapOsDb;
use crate::fingerprint::osscan::NmapFingerprint;
use crate::utils::get_threads_pool;
use crate::Target;

pub mod dbparser;
pub mod operator;
pub mod osscan;
pub mod osscan6;
pub mod packet;
pub mod packet6;

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

fn find_position(score_vec: &Vec<usize>, value: usize) -> Vec<usize> {
    let mut position = Vec::new();
    for (i, s) in score_vec.iter().enumerate() {
        if *s == value {
            position.push(i);
        }
    }
    position
}

fn score_top_k(score_vec: &Vec<usize>, k: usize) -> Vec<usize> {
    let mut score_vec = score_vec.clone();
    let mut top_k_vec = Vec::new();
    for _ in 0..k {
        let mut max_score = 0;
        for s in &score_vec {
            if *s > max_score {
                max_score = *s;
            }
        }

        let position = find_position(&score_vec, max_score);
        for p in position {
            score_vec.remove(p);
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
    nmap_os_db_file_path: String,
    top_k: usize,
    max_loop: usize,
    read_timeout: Duration,
) -> Result<(NmapFingerprint, Vec<NmapOsDetectRet>)> {
    let nmap_fingerprint = osscan::os_probe(
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_open_tcp_port,
        dst_closed_tcp_port,
        dst_closed_udp_port,
        max_loop,
        read_timeout,
    )?;

    let nmap_od_db = dbparser::nmap_os_db_parser(nmap_os_db_file_path)?;
    let mut score_vec = Vec::new();
    let mut total_vec = Vec::new();
    for n in &nmap_od_db {
        let (score, total) = n.check(&nmap_fingerprint);
        score_vec.push(score);
        total_vec.push(total);
    }

    let top_k_vec = score_top_k(&score_vec, top_k);
    let mut top_k_index = Vec::new();
    for k in top_k_vec {
        for p in find_position(&score_vec, k) {
            top_k_index.push(p);
        }
    }

    let mut dr_vec = Vec::new();
    for i in top_k_index {
        let dr = NmapOsDetectRet {
            score: score_vec[i],
            total: total_vec[i],
            db: nmap_od_db[i].clone(),
        };
        dr_vec.push(dr);
    }
    Ok((nmap_fingerprint, dr_vec))
}

/// Operation system detection is performed on the target server,
/// and return the fingerprint, and guess results (will be returned according to the score from high to low).
/// ```rust
/// use pistol::{Host, Target};
/// use std::net::Ipv4Addr;
///
/// fn test() {
///     let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
///     let src_port = None;
///     let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 130);
///     let dst_open_tcp_port = 22;
///     let dst_closed_tcp_port = 8765;
///     let dst_closed_udp_port = 9876;
///     let host1 = Host::new(
///         dst_ipv4,
///         Some(vec![
///             dst_open_tcp_port,
///             dst_closed_tcp_port,
///             dst_closed_udp_port,
///         ]),
///     );
///     let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
///     let dst_open_tcp_port = 22;
///     let dst_closed_tcp_port = 8765;
///     let dst_closed_udp_port = 9876;
///     let host2 = Host::new(
///         dst_ipv4,
///         Some(vec![
///             dst_open_tcp_port,
///             dst_closed_tcp_port,
///             dst_closed_udp_port,
///         ]),
///     );
///     let target = Target::new(vec![host1, host2]);
///     let max_loop = 8;
///     let read_timeout = Duration::from_secs_f32(0.2);
///     let nmap_os_db_file_path = "./nmap-os-db".to_string();
///     let top_k = 3;
///     let threads_num = 8;

///     let ret = os_detect(
///         target,
///         src_ipv4,
///         src_port,
///         nmap_os_db_file_path,
///         top_k,
///         threads_num,
///         max_loop,
///         read_timeout,
///     )
///     .unwrap();

///     for (ip, (fingerprint, detect_ret)) in ret {
///         println!(">>> IP:\n{}", ip);
///         println!(">>> Fingerprint:\n{}", fingerprint);
///         println!(">>> Details:\n");
///         for d in detect_ret {
///             println!("{}", d);
///         }
///     }
/// }
/// ```
pub fn os_detect(
    target: Target,
    src_ipv4: Ipv4Addr,
    src_port: Option<u16>,
    nmap_os_db_file_path: String,
    top_k: usize,
    threads_num: usize,
    max_loop: usize,
    read_timeout: Duration,
) -> Result<HashMap<Ipv4Addr, (NmapFingerprint, Vec<NmapOsDetectRet>)>> {
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
            let nmap_os_db_file_path = nmap_os_db_file_path.clone();
            pool.execute(move || {
                let os_detect_ret = os_detect_thread(
                    src_ipv4,
                    src_port,
                    dst_ipv4,
                    dst_open_tcp_port,
                    dst_closed_tcp_port,
                    dst_closed_udp_port,
                    nmap_os_db_file_path,
                    top_k,
                    max_loop,
                    read_timeout,
                );
                match tx.send((dst_ipv4, os_detect_ret)) {
                    _ => (),
                }
            });
        } else {
            return Err(OsDetectPortError::new().into());
        }
    }
    let mut ret: HashMap<Ipv4Addr, (NmapFingerprint, Vec<NmapOsDetectRet>)> = HashMap::new();
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
    use crate::Host;
    #[test]
    fn test_os_detect() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
        let src_port = None;
        let dst_ipv4_1 = Ipv4Addr::new(192, 168, 72, 130);
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
        let dst_ipv4_2 = Ipv4Addr::new(192, 168, 72, 129);
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
        // let target = Target::new(vec![host2]);
        let max_loop = 8;
        let read_timeout = Duration::from_secs_f32(0.2);
        let nmap_os_db_file_path = "./nmap-os-db".to_string();
        let top_k = 3;
        let threads_num = 8;

        let ret = os_detect(
            target,
            src_ipv4,
            src_port,
            nmap_os_db_file_path,
            top_k,
            threads_num,
            max_loop,
            read_timeout,
        )
        .unwrap();

        for (ip, (fingerprint, detect_ret)) in ret {
            println!(">>> IP:\n{}", ip);
            println!(">>> Fingerprint:\n{}", fingerprint);
            println!(">>> Details:\n");
            for d in detect_ret {
                println!("{}", d);
            }
        }
    }
}
