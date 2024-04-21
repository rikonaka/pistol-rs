use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::mpsc::channel;

use anyhow::Result;

use crate::utils::get_threads_pool;
use crate::vs::dbparser::Match;
use crate::vs::vscan::vs_probe;
use crate::{Target, TargetType};

pub mod dbparser;
pub mod vscan;

pub struct NmapVsDetectRet {
    pub port: u16,
    pub services: Vec<Match>,
}

impl fmt::Display for NmapVsDetectRet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut services_str = String::new();
        for (i, s) in self.services.iter().enumerate() {
            services_str += &s.service;
            if i != self.services.len() - 1 {
                services_str += ", ";
            }
        }
        let output = format!("port: {}, services: [{}]", self.port, services_str);
        write!(f, "{}", output)
    }
}

pub fn vs_detect(target: Target, threads_num: usize) -> Result<Vec<NmapVsDetectRet>> {
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

    let mut recv_size = 0;
    for (addr, ports) in vs_target {
        for port in ports {
            let tx = tx.clone();
            pool.execute(move || {
                let r = vs_probe(addr, port);
                match tx.send((port, r)) {
                    _ => (),
                }
            });
            recv_size += 1;
        }
    }

    let mut ret = Vec::new();
    let rx = rx.into_iter().take(recv_size);
    for (port, r) in rx {
        match r {
            Ok(r) => {
                let nvdr = NmapVsDetectRet { port, services: r };
                ret.push(nvdr);
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
    use std::net::Ipv4Addr;
    #[test]
    fn test_vs_detect() -> Result<()> {
        let dst_addr = Ipv4Addr::new(192, 168, 1, 51);
        let h1 = Host::new(dst_addr, Some(vec![22, 80]))?;
        let target = Target::new(vec![h1]);
        let threads_num = 8;
        let ret = vs_detect(target, threads_num).unwrap();
        for r in ret {
            println!("{}", r);
        }
        Ok(())
    }
}
