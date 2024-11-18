/* Remote OS Detection */
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
use std::io::Cursor;
use std::io::Read;
use std::net::IpAddr;
use std::sync::mpsc::channel;
use std::time::Duration;
use std::time::Instant;
use zip::ZipArchive;

use crate::errors::PistolErrors;
use crate::os::dbparser::NmapOSDB;
use crate::os::osscan::threads_os_probe;
use crate::os::osscan::TargetFingerprint;
use crate::os::osscan6::threads_os_probe6;
use crate::os::osscan6::TargetFingerprint6;
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

#[derive(Debug, Clone)]
pub struct OSDetectResults {
    pub oss: HashMap<IpAddr, HostOSDetectResult>,
    pub start: Instant,
    pub total_time_cost: f64,
    pub avg_time_cost: f64,
}

impl OSDetectResults {
    pub fn new() -> OSDetectResults {
        OSDetectResults {
            oss: HashMap::new(),
            start: Instant::now(),
            total_time_cost: 0.0,
            avg_time_cost: 0.0,
        }
    }
    pub fn get(&self, k: &IpAddr) -> Option<&HostOSDetectResult> {
        self.oss.get(k)
    }
    pub fn enrichment(&mut self) {
        self.total_time_cost = self.start.elapsed().as_secs_f64();
        let mut total_time = 0.0;
        let mut total_num = 0;
        for (_, v) in &self.oss {
            let t = match v {
                HostOSDetectResult::V4(o) => o.time_cost,
                HostOSDetectResult::V6(o) => o.time_cost,
            };
            total_time += t;
            total_num += 1;
        }
        self.avg_time_cost = total_time / total_num as f64;
    }
}

impl fmt::Display for OSDetectResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![Cell::new("OS Detect Results")
            .style_spec("c")
            .with_hspan(6)]));

        table.add_row(
            row![c -> "id", c -> "addr", c -> "rank", c -> "score", c -> "details", c -> "cpe"],
        );
        let oss = &self.oss;
        let oss: BTreeMap<IpAddr, &HostOSDetectResult> =
            oss.into_iter().map(|(i, h)| (*i, h)).collect();
        let mut id = 1;
        for (ip, o) in oss {
            match o {
                HostOSDetectResult::V4(o) => {
                    if o.alive {
                        for (i, os_info) in o.detects.iter().enumerate() {
                            let rank_str = format!("#{}", i + 1);
                            let score_str = format!("{}/{}", os_info.score, os_info.total);
                            let os_details = &os_info.name;
                            let os_cpe = os_info.cpe.join("|");
                            table.add_row(row![c -> id, c -> ip, c -> rank_str, c -> score_str, c -> os_details, c -> os_cpe]);
                            id += 1;
                        }
                    } else {
                        let rank_str = format!("#{}", 1);
                        table.add_row(row![c -> id, c -> ip, c -> rank_str, c -> "0/0", c -> "target dead", c -> ""]);
                        id += 1;
                    }
                }
                HostOSDetectResult::V6(o) => {
                    if o.alive {
                        for (i, os_info6) in o.detects.iter().enumerate() {
                            let number_str = format!("#{}", i + 1);
                            let score_str = format!("{:.1}", os_info6.score);
                            let os_str = &os_info6.name;
                            let os_cpe = &os_info6.cpe;
                            table.add_row(row![c -> id, c -> ip, c -> number_str, c -> score_str, c -> os_str, c -> os_cpe]);
                            id += 1;
                        }
                    } else {
                        let rank_str = format!("#{}", id + 1);
                        table.add_row(row![c -> id, c -> ip, c -> rank_str, c -> "0.0", c -> "target dead", c -> ""]);
                        id += 1;
                    }
                }
            }
        }
        let summary = format!(
            "total used time: {:.2}ms\navg time cost: {:.2}ms",
            self.total_time_cost * 1000.0,
            self.avg_time_cost * 1000.0,
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(6)]));
        write!(f, "{}", table)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSInfo {
    pub name: String,
    pub class: Vec<String>,
    pub cpe: Vec<String>,
    pub score: usize,
    pub total: usize,
    pub db: NmapOSDB,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSInfo6 {
    pub name: String,
    pub class: String,
    pub cpe: String,
    pub score: f64,
    pub label: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSDetect {
    pub alive: bool,
    pub fingerprint: TargetFingerprint,
    pub detects: Vec<OSInfo>,
    pub time_cost: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSDetect6 {
    pub alive: bool,
    pub fingerprint: TargetFingerprint6,
    pub detects: Vec<OSInfo6>,
    pub time_cost: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostOSDetectResult {
    V4(OSDetect),
    V6(OSDetect6),
}

impl HostOSDetectResult {
    pub fn new(
        fingerprint: TargetFingerprint,
        detects: Vec<OSInfo>,
        time_cost: f64,
    ) -> HostOSDetectResult {
        let h = OSDetect {
            alive: true,
            fingerprint,
            detects,
            time_cost,
        };
        HostOSDetectResult::V4(h)
    }
    pub fn new_dead() -> HostOSDetectResult {
        let h = OSDetect {
            alive: false,
            fingerprint: TargetFingerprint::empty(),
            detects: Vec::new(),
            time_cost: 0.0,
        };
        HostOSDetectResult::V4(h)
    }
    pub fn new6(
        fingerprint: TargetFingerprint6,
        detects: Vec<OSInfo6>,
        time_cost: f64,
    ) -> HostOSDetectResult {
        let h = OSDetect6 {
            alive: true,
            fingerprint,
            detects,
            time_cost,
        };
        HostOSDetectResult::V6(h)
    }
    pub fn new6_dead() -> HostOSDetectResult {
        let h = OSDetect6 {
            alive: false,
            fingerprint: TargetFingerprint6::empty(),
            detects: Vec::new(),
            time_cost: 0.0,
        };
        HostOSDetectResult::V6(h)
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

fn get_nmap_os_db() -> Result<Vec<NmapOSDB>, PistolErrors> {
    let data = include_bytes!("./db/nmap-os-db.zip");
    let reader = Cursor::new(data);
    let mut archive = ZipArchive::new(reader)?;

    if archive.len() > 0 {
        let mut file = archive.by_index(0)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let ret: Vec<NmapOSDB> = serde_json::from_str(&contents)?;
        Ok(ret)
    } else {
        Err(PistolErrors::ZipEmptyError)
    }
}

/// Detect target machine OS on IPv4 and IPv6.
pub fn os_detect(
    target: Target,
    src_addr: Option<IpAddr>,
    top_k: usize,
    timeout: Option<Duration>,
) -> Result<OSDetectResults, PistolErrors> {
    let threads_num = target.hosts.len();
    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };
    let (tx, rx) = channel();
    let pool = get_threads_pool(threads_num);
    let mut recv_size = 0;
    let mut ret = OSDetectResults::new();
    for h in target.hosts {
        let dst_addr = h.addr;
        let tx = tx.clone();
        recv_size += 1;
        let start = Instant::now();
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                let dst_ports = h.ports;
                let src_ipv4 = match find_source_addr(src_addr, dst_ipv4)? {
                    Some(s) => s,
                    None => return Err(PistolErrors::CanNotFoundSourceAddress),
                };

                let nmap_os_db = get_nmap_os_db()?;
                debug!("ipv4 nmap os db parse finish");

                pool.execute(move || {
                    let detect_ret = if dst_ports.len() >= 3 {
                        let dst_open_tcp_port = dst_ports[0];
                        let dst_closed_tcp_port = dst_ports[1];
                        let dst_closed_udp_port = dst_ports[2];

                        let os_detect_ret = threads_os_probe(
                            src_ipv4,
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
                        Err(PistolErrors::OSDetectPortsNotEnough)
                    };
                    let hodr = match detect_ret {
                        Ok((fingerprint, ret)) => {
                            let hodr = HostOSDetectResult::new(
                                fingerprint,
                                ret,
                                start.elapsed().as_secs_f64(),
                            );
                            Ok(hodr)
                        }
                        Err(e) => Err(e),
                    };
                    match tx.send((dst_addr, hodr)) {
                        _ => (),
                    }
                });
            }
            IpAddr::V6(dst_ipv6) => {
                let dst_ports = h.ports;
                let src_ipv6 = match find_source_addr6(src_addr, dst_ipv6)? {
                    Some(s) => s,
                    None => return Err(PistolErrors::CanNotFoundSourceAddress),
                };

                let linear = gen_linear()?;
                debug!("ipv6 gen linear parse finish");

                pool.execute(move || {
                    let detect_ret = if dst_ports.len() >= 3 {
                        let dst_open_tcp_port = dst_ports[0];
                        let dst_closed_tcp_port = dst_ports[1];
                        let dst_closed_udp_port = dst_ports[2];
                        let os_detect_ret = threads_os_probe6(
                            src_ipv6,
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
                        Err(PistolErrors::OSDetectPortsNotEnough)
                    };
                    let hodr = match detect_ret {
                        Ok((fingerprint, ret)) => {
                            let hodr = HostOSDetectResult::new6(
                                fingerprint,
                                ret,
                                start.elapsed().as_secs_f64(),
                            );
                            Ok(hodr)
                        }
                        Err(e) => Err(e),
                    };
                    match tx.send((dst_addr, hodr)) {
                        _ => (),
                    }
                });
            }
        }
    }

    let iter = rx.into_iter().take(recv_size);
    for (addr, r) in iter {
        match r {
            Ok(hodr) => {
                ret.oss.insert(addr, hodr);
            }
            Err(e) => match e {
                PistolErrors::CanNotFoundMacAddress => {
                    let h = match addr {
                        IpAddr::V4(_) => HostOSDetectResult::new_dead(),
                        IpAddr::V6(_) => HostOSDetectResult::new6_dead(),
                    };
                    ret.oss.insert(addr, h);
                }
                _ => return Err(e),
            },
        }
    }
    ret.enrichment();
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
) -> Result<HostOSDetectResult, PistolErrors> {
    let timeout = match timeout {
        Some(t) => t,
        None => get_default_timeout(),
    };
    let start = Instant::now();
    match dst_addr {
        IpAddr::V4(dst_ipv4) => match find_source_addr(src_addr, dst_ipv4)? {
            Some(src_ipv4) => {
                let nmap_os_db = get_nmap_os_db()?;
                debug!("ipv4 nmap os db parse finish");

                let nmap_os_db = nmap_os_db.to_vec();
                match threads_os_probe(
                    src_ipv4,
                    dst_ipv4,
                    dst_open_tcp_port,
                    dst_closed_tcp_port,
                    dst_closed_udp_port,
                    nmap_os_db,
                    top_k,
                    timeout,
                ) {
                    Ok((fingerprint, ret)) => {
                        let oss = HostOSDetectResult::new(
                            fingerprint,
                            ret,
                            start.elapsed().as_secs_f64(),
                        );
                        Ok(oss)
                    }
                    Err(e) => Err(e),
                }
            }
            None => {
                // return Err(PistolErrors::CanNotFoundSourceAddress);
                let h = HostOSDetectResult::new_dead();
                Ok(h)
            }
        },
        IpAddr::V6(dst_ipv6) => match find_source_addr6(src_addr, dst_ipv6)? {
            Some(src_ipv6) => {
                let linear = gen_linear()?;
                debug!("ipv6 gen linear parse finish");

                match threads_os_probe6(
                    src_ipv6,
                    dst_ipv6,
                    dst_open_tcp_port,
                    dst_closed_tcp_port,
                    dst_closed_udp_port,
                    top_k,
                    linear,
                    timeout,
                ) {
                    Ok((fingerprint, ret)) => {
                        let oss = HostOSDetectResult::new6(
                            fingerprint,
                            ret,
                            start.elapsed().as_secs_f64(),
                        );
                        Ok(oss)
                    }
                    Err(e) => Err(e),
                }
            }
            None => {
                // return Err(PistolErrors::CanNotFoundSourceAddress);
                let h = HostOSDetectResult::new6_dead();
                Ok(h)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Host;
    use crate::TEST_IPV4_LOCAL;
    use crate::TEST_IPV6_LOCAL;
    #[test]
    fn test_os_detect() {
        // use crate::Logger;
        // Logger::init_debug_logging()?;
        let src_addr = None;
        let dst_open_tcp_port = 22;
        let dst_closed_tcp_port = 8765;
        let dst_closed_udp_port = 9876;

        let host2 = Host::new(
            TEST_IPV4_LOCAL.into(),
            Some(vec![
                dst_open_tcp_port,
                dst_closed_tcp_port,
                dst_closed_udp_port,
            ]),
        );

        let target = Target::new(vec![host2]);
        let timeout = Some(Duration::new(1, 0));
        let top_k = 3;
        let ret = os_detect(target, src_addr, top_k, timeout).unwrap();
        println!("{}", ret);

        let rr = ret.get(&TEST_IPV4_LOCAL.into()).unwrap();
        match rr {
            HostOSDetectResult::V4(r) => {
                println!("{}", r.fingerprint);
            }
            _ => (),
        }
    }
    #[test]
    fn test_os_detect6() {
        // use crate::Logger;
        // Logger::init_debug_logging()?;
        let src_addr = None;
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

        let target = Target::new(vec![host1]);
        let timeout = Some(Duration::new(1, 0));
        let top_k = 3;
        let ret = os_detect(target, src_addr, top_k, timeout).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_os_detect_raw() {
        let src_addr = None;
        let dst_open_tcp_port = 22;
        let dst_closed_tcp_port = 8765;
        let dst_closed_udp_port = 9876;
        let timeout = Some(Duration::new(1, 0));
        let top_k = 3;
        let ret = os_detect_raw(
            TEST_IPV4_LOCAL.into(),
            dst_open_tcp_port,
            dst_closed_tcp_port,
            dst_closed_udp_port,
            src_addr,
            top_k,
            timeout,
        )
        .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_os_detect6_raw() {
        let src_addr = None;
        let dst_open_tcp_port = 22;
        let dst_closed_tcp_port = 8765;
        let dst_closed_udp_port = 9876;
        let timeout = Some(Duration::new(1, 0));
        let top_k = 3;
        let ret = os_detect_raw(
            TEST_IPV6_LOCAL.into(),
            dst_open_tcp_port,
            dst_closed_tcp_port,
            dst_closed_udp_port,
            src_addr,
            top_k,
            timeout,
        )
        .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_compare_with_nmap() {
        let nmap_fingerprint_format = |input: &str| -> String {
            let output = input.replace("OS:", "");
            let output = output.replace("\n", "");
            let output = output.replace(")", ")\n");
            output
        };

        let nmap_output = "
OS:SCAN(V=7.93%E=4%D=11/13%OT=22%CT=1%CU=39775%PV=Y%DS=1%DC=D%G=Y%M=000C29%
OS:TM=67341E99%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10A%TI=Z%CI=Z%II=
OS:I%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%
OS:O5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W
OS:6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=
OS:O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD
OS:=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0
OS:%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1
OS:(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI
OS:=N%T=40%CD=S)";

        let p = nmap_fingerprint_format(&nmap_output);
        println!("{}", p);
    }
}
