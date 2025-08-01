/* Remote OS Detection */
#[cfg(feature = "os")]
use chrono::DateTime;
#[cfg(feature = "os")]
use chrono::Local;
#[cfg(feature = "os")]
use prettytable::Cell;
#[cfg(feature = "os")]
use prettytable::Row;
#[cfg(feature = "os")]
use prettytable::Table;
#[cfg(feature = "os")]
use prettytable::row;
#[cfg(feature = "os")]
use serde::Deserialize;
#[cfg(feature = "os")]
use serde::Serialize;
#[cfg(feature = "os")]
use std::collections::BTreeMap;
#[cfg(feature = "os")]
use std::fmt;
#[cfg(feature = "os")]
use std::io::Cursor;
#[cfg(feature = "os")]
use std::io::Read;
#[cfg(feature = "os")]
use std::net::IpAddr;
#[cfg(feature = "os")]
use std::sync::mpsc::channel;
#[cfg(feature = "os")]
use std::time::Duration;
#[cfg(feature = "os")]
use std::time::Instant;
#[cfg(feature = "os")]
use tracing::debug;
#[cfg(feature = "os")]
use tracing::warn;
#[cfg(feature = "os")]
use zip::ZipArchive;

#[cfg(feature = "os")]
use crate::Target;
#[cfg(feature = "os")]
use crate::error::PistolError;
#[cfg(feature = "os")]
use crate::layer::infer_addr;
#[cfg(feature = "os")]
use crate::os::dbparser::NmapOSDB;
#[cfg(feature = "os")]
use crate::os::osscan::Fingerprint;
#[cfg(feature = "os")]
use crate::os::osscan::os_probe_thread;
#[cfg(feature = "os")]
use crate::os::osscan6::Fingerprint6;
#[cfg(feature = "os")]
use crate::os::osscan6::os_probe_thread6;
#[cfg(feature = "os")]
use crate::utils::get_threads_pool;
#[cfg(feature = "os")]
use crate::utils::num_threads_check;
#[cfg(feature = "os")]
use crate::utils::time_sec_to_string;

#[cfg(feature = "os")]
pub mod dbparser;
#[cfg(feature = "os")]
pub mod operator;
#[cfg(feature = "os")]
pub mod operator6;
#[cfg(feature = "os")]
pub mod osscan;
#[cfg(feature = "os")]
pub mod osscan6;
#[cfg(feature = "os")]
pub mod packet;
#[cfg(feature = "os")]
pub mod packet6;
#[cfg(feature = "os")]
pub mod rr;

#[cfg(feature = "os")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub name: String,
    pub class: Vec<String>,
    pub cpe: Vec<String>,
    pub score: usize,
    pub total: usize,
    pub db: NmapOSDB,
}

#[cfg(feature = "os")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo6 {
    pub name: String,
    pub class: String,
    pub cpe: String,
    pub score: f64,
    pub label: usize,
}

#[cfg(feature = "os")]
#[derive(Debug, Clone)]
pub struct OsDetect4 {
    pub addr: IpAddr,
    pub origin: Option<String>,
    pub alive: bool,
    pub fingerprint: Fingerprint,
    pub detects: Vec<OsInfo>,
    pub cost: Duration,
}

#[cfg(feature = "os")]
#[derive(Debug, Clone)]
pub struct OsDetect6 {
    pub addr: IpAddr,
    pub origin: Option<String>,
    pub alive: bool,
    pub fingerprint: Fingerprint6,
    pub detects: Vec<OsInfo6>,
    pub cost: Duration,
}

#[cfg(feature = "os")]
#[derive(Debug, Clone)]
pub enum OsDetect {
    V4(OsDetect4),
    V6(OsDetect6),
}

#[cfg(feature = "os")]
impl OsDetect {
    pub fn addr(&self) -> IpAddr {
        match self {
            OsDetect::V4(ipv4) => ipv4.addr,
            OsDetect::V6(ipv6) => ipv6.addr,
        }
    }
}

#[cfg(feature = "os")]
#[derive(Debug, Clone)]
pub struct PistolOsDetects {
    pub os_detects: Vec<OsDetect>,
    pub start_time: DateTime<Local>,
    pub end_time: DateTime<Local>,
}

#[cfg(feature = "os")]
impl PistolOsDetects {
    pub fn new() -> PistolOsDetects {
        PistolOsDetects {
            os_detects: Vec::new(),
            start_time: Local::now(),
            end_time: Local::now(),
        }
    }
    pub fn value(&self) -> Vec<OsDetect> {
        self.os_detects.clone()
    }
    pub fn finish(&mut self, os_detects: Vec<OsDetect>) {
        self.end_time = Local::now();
        self.os_detects = os_detects;
    }
}

#[cfg(feature = "os")]
impl fmt::Display for PistolOsDetects {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("OS Detect Results").style_spec("c").with_hspan(7),
        ]));

        table.add_row(
            row![c -> "id", c -> "addr", c -> "rank", c -> "score", c -> "os", c -> "cpe", c -> "time cost"],
        );

        // sorted
        let mut btm_addr: BTreeMap<IpAddr, OsDetect> = BTreeMap::new();
        for detect in &self.os_detects {
            btm_addr.insert(detect.addr(), detect.clone());
        }

        let mut total_cost = 0.0;
        let mut id = 1;
        for (addr, detect) in btm_addr {
            match detect {
                OsDetect::V4(o) => {
                    let time_cost_str = time_sec_to_string(o.cost);
                    total_cost += o.cost.as_secs_f64();
                    if o.alive {
                        for (i, os_info) in o.detects.iter().enumerate() {
                            let addr_str = match &o.origin {
                                Some(origin) => format!("{}({})", addr, origin),
                                None => format!("{}", addr),
                            };

                            let rank_str = format!("#{}", i + 1);
                            let score_str = format!("{}/{}", os_info.score, os_info.total);
                            let os_details = &os_info.name;
                            let os_cpe = os_info.cpe.join("|");
                            table.add_row(row![c -> id, c -> addr_str, c -> rank_str, c -> score_str, c -> os_details, c -> os_cpe, c -> time_cost_str]);
                            id += 1;
                        }
                    } else {
                        let addr_str = match o.origin {
                            Some(origin) => format!("{}({})", addr, origin),
                            None => format!("{}", addr),
                        };

                        let rank_str = format!("#{}", 1);
                        table.add_row(row![c -> id, c -> addr_str, c -> rank_str, c -> "0/0", c -> "target dead", c -> "", c -> time_cost_str]);
                        id += 1;
                    }
                }
                OsDetect::V6(o) => {
                    let time_cost_str = time_sec_to_string(o.cost);
                    total_cost += o.cost.as_secs_f64();
                    if o.alive {
                        for (i, os_info6) in o.detects.iter().enumerate() {
                            let addr_str = match &o.origin {
                                Some(origin) => format!("{}({})", addr, origin),
                                None => format!("{}", addr),
                            };

                            let number_str = format!("#{}", i + 1);
                            let score_str = format!("{:.1}", os_info6.score);
                            let os_str = &os_info6.name;
                            let os_cpe = &os_info6.cpe;
                            table.add_row(row![c -> id, c -> addr_str, c -> number_str, c -> score_str, c -> os_str, c -> os_cpe, c -> time_cost_str]);
                            id += 1;
                        }
                    } else {
                        let addr_str = match o.origin {
                            Some(origin) => format!("{}({})", addr, origin),
                            None => format!("{}", addr),
                        };

                        let rank_str = format!("#{}", 1);
                        table.add_row(row![c -> id, c -> addr_str, c -> rank_str, c -> "0.0", c -> "target dead", c -> "", c -> time_cost_str]);
                        id += 1;
                    }
                }
            }
        }
        let avg_cost = total_cost / self.os_detects.len() as f64;
        let summary = format!(
            "total used time: {:.3}s, avg time cost: {:.3}s",
            total_cost, avg_cost,
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(7)]));
        write!(f, "{}", table)
    }
}

#[cfg(feature = "os")]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NmapJsonParameters {
    pub name: String,
    pub value: Vec<f64>,
}

#[cfg(feature = "os")]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CPE {
    pub name: String,
    pub osclass: Vec<Vec<String>>,
    pub cpe: Vec<String>,
}

#[cfg(feature = "os")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Linear {
    pub infolist: Vec<String>,
    pub w: Vec<Vec<f64>>,
    pub scale: Vec<Vec<f64>>,
    pub mean: Vec<Vec<f64>>,
    pub variance: Vec<Vec<f64>>,
    pub cpe: Vec<CPE>,
}

#[cfg(feature = "os")]
fn gen_linear() -> Result<Linear, PistolError> {
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

#[cfg(feature = "os")]
fn get_nmap_os_db() -> Result<Vec<NmapOSDB>, PistolError> {
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
        Err(PistolError::ZipEmptyError)
    }
}

/// Detect target machine OS on IPv4 and IPv6.
#[cfg(feature = "os")]
pub fn os_detect(
    targets: &[Target],
    num_threads: Option<usize>,
    src_addr: Option<IpAddr>,
    top_k: usize,
    timeout: Option<Duration>,
) -> Result<PistolOsDetects, PistolError> {
    let num_threads = match num_threads {
        Some(t) => t,
        None => {
            let num_threads = targets.len();
            let num_threads = num_threads_check(num_threads);
            num_threads
        }
    };

    let (tx, rx) = channel();
    let pool = get_threads_pool(num_threads);
    let mut recv_size = 0;
    let mut ret = PistolOsDetects::new();
    for target in targets {
        let dst_addr = target.addr;
        let tx = tx.clone();
        recv_size += 1;
        let ia = match infer_addr(src_addr, dst_addr)? {
            Some(ia) => ia,
            None => return Err(PistolError::CanNotFoundSourceAddress),
        };
        match dst_addr {
            IpAddr::V4(_) => {
                let dst_ports = target.ports.clone();
                let (dst_ipv4, src_ipv4) = ia.ipv4_addr()?;
                let nmap_os_db = get_nmap_os_db()?;
                debug!("ipv4 nmap os db parse finish");
                let origin = target.origin.clone();
                pool.execute(move || {
                    let start_time = Instant::now();
                    let detect_rets = if dst_ports.len() >= 3 {
                        let dst_open_tcp_port = dst_ports[0];
                        let dst_closed_tcp_port = dst_ports[1];
                        let dst_closed_udp_port = dst_ports[2];
                        let os_detect_ret = os_probe_thread(
                            dst_ipv4,
                            dst_open_tcp_port,
                            dst_closed_tcp_port,
                            dst_closed_udp_port,
                            src_ipv4,
                            nmap_os_db,
                            top_k,
                            timeout,
                        );
                        os_detect_ret
                    } else {
                        Err(PistolError::OSDetectPortsNotEnough)
                    };
                    let od = match detect_rets {
                        Ok((fingerprint, detects)) => {
                            let o = OsDetect4 {
                                addr: dst_addr,
                                origin: origin.clone(),
                                alive: true,
                                fingerprint,
                                detects,
                                cost: start_time.elapsed(),
                            };
                            let od = OsDetect::V4(o);
                            Ok(od)
                        }
                        Err(e) => Err(e),
                    };
                    let _ = tx.send((dst_addr, origin.clone(), od, start_time));
                });
            }
            IpAddr::V6(_) => {
                let dst_ports = target.ports.clone();
                let (dst_ipv6, src_ipv6) = ia.ipv6_addr()?;
                let linear = gen_linear()?;
                debug!("ipv6 gen linear parse finish");
                let origin = target.origin.clone();
                pool.execute(move || {
                    let start_time = Instant::now();
                    let detect_rets = if dst_ports.len() >= 3 {
                        let dst_open_tcp_port = dst_ports[0];
                        let dst_closed_tcp_port = dst_ports[1];
                        let dst_closed_udp_port = dst_ports[2];

                        let os_detect_ret = os_probe_thread6(
                            dst_ipv6,
                            dst_open_tcp_port,
                            dst_closed_tcp_port,
                            dst_closed_udp_port,
                            src_ipv6,
                            top_k,
                            linear,
                            timeout,
                        );
                        os_detect_ret
                    } else {
                        Err(PistolError::OSDetectPortsNotEnough)
                    };
                    let od = match detect_rets {
                        Ok((fingerprint, detects)) => {
                            let o = OsDetect6 {
                                addr: dst_addr,
                                origin: origin.clone(),
                                alive: true,
                                fingerprint,
                                detects,
                                cost: start_time.elapsed(),
                            };
                            let od = OsDetect::V6(o);
                            Ok(od)
                        }
                        Err(e) => Err(e),
                    };
                    let _ = tx.send((dst_addr, origin.clone(), od, start_time));
                });
            }
        }
    }

    let iter = rx.into_iter().take(recv_size);
    let mut os_detects = Vec::new();
    for (addr, origin, r, start_time) in iter {
        match r {
            Ok(od) => {
                os_detects.push(od);
            }
            Err(e) => {
                warn!("os probe error: {}", e);
                match addr {
                    IpAddr::V4(_) => {
                        let o = OsDetect4 {
                            addr,
                            origin,
                            alive: false,
                            fingerprint: Fingerprint::empty(),
                            detects: Vec::new(),
                            cost: start_time.elapsed(),
                        };
                        let od = OsDetect::V4(o);
                        os_detects.push(od);
                    }
                    IpAddr::V6(_) => {
                        let o = OsDetect6 {
                            addr,
                            origin,
                            alive: false,
                            fingerprint: Fingerprint6::empty(),
                            detects: Vec::new(),
                            cost: start_time.elapsed(),
                        };
                        let od = OsDetect::V6(o);
                        os_detects.push(od);
                    }
                }
            }
        }
    }
    ret.finish(os_detects);
    Ok(ret)
}

#[cfg(feature = "os")]
pub fn os_detect_raw(
    dst_addr: IpAddr,
    dst_open_tcp_port: u16,
    dst_closed_tcp_port: u16,
    dst_closed_udp_port: u16,
    src_addr: Option<IpAddr>,
    top_k: usize,
    timeout: Option<Duration>,
) -> Result<OsDetect, PistolError> {
    let start_time = Instant::now();
    let ia = match infer_addr(src_addr, dst_addr)? {
        Some(ia) => ia,
        None => return Err(PistolError::CanNotFoundSourceAddress),
    };
    match dst_addr {
        IpAddr::V4(_) => {
            let (dst_ipv4, src_ipv4) = ia.ipv4_addr()?;
            let nmap_os_db = get_nmap_os_db()?;
            debug!("ipv4 nmap os db parse finish");
            let nmap_os_db = nmap_os_db.to_vec();
            match os_probe_thread(
                dst_ipv4,
                dst_open_tcp_port,
                dst_closed_tcp_port,
                dst_closed_udp_port,
                src_ipv4,
                nmap_os_db,
                top_k,
                timeout,
            ) {
                Ok((fingerprint, detects)) => {
                    let o = OsDetect4 {
                        addr: dst_addr,
                        origin: None,
                        alive: true,
                        fingerprint,
                        detects,
                        cost: start_time.elapsed(),
                    };
                    let od = OsDetect::V4(o);
                    Ok(od)
                }
                Err(e) => {
                    warn!("os probe error: {}", e);
                    let o = OsDetect4 {
                        addr: dst_addr,
                        origin: None,
                        alive: false,
                        fingerprint: Fingerprint::empty(),
                        detects: Vec::new(),
                        cost: start_time.elapsed(),
                    };
                    let od = OsDetect::V4(o);
                    Ok(od)
                }
            }
        }
        IpAddr::V6(_) => {
            let (dst_ipv6, src_ipv6) = ia.ipv6_addr()?;
            let linear = gen_linear()?;
            debug!("ipv6 gen linear parse finish");
            match os_probe_thread6(
                dst_ipv6,
                dst_open_tcp_port,
                dst_closed_tcp_port,
                dst_closed_udp_port,
                src_ipv6,
                top_k,
                linear,
                timeout,
            ) {
                Ok((fingerprint, detects)) => {
                    let o = OsDetect6 {
                        addr: dst_addr,
                        origin: None,
                        alive: true,
                        fingerprint,
                        detects,
                        cost: start_time.elapsed(),
                    };
                    let od = OsDetect::V6(o);
                    Ok(od)
                }
                Err(e) => {
                    warn!("os probe error: {}", e);
                    let o = OsDetect6 {
                        addr: dst_addr,
                        origin: None,
                        alive: false,
                        fingerprint: Fingerprint6::empty(),
                        detects: Vec::new(),
                        cost: start_time.elapsed(),
                    };
                    let od = OsDetect::V6(o);
                    Ok(od)
                }
            }
        }
    }
}

#[cfg(feature = "os")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::PistolLogger;
    use crate::PistolRunner;
    use crate::Target;
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;
    use std::str::FromStr;
    #[test]
    fn test_os_detect() {
        let _pr = PistolRunner::init(
            PistolLogger::None,
            Some(String::from("os_detect.pcapng")),
            None, // use default value
        )
        .unwrap();

        let src_addr = None;
        let dst_open_tcp_port = 22;
        let dst_closed_tcp_port = 8765;
        let dst_closed_udp_port = 9876;

        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5));
        let target1 = Target::new(
            addr1,
            Some(vec![
                dst_open_tcp_port,
                dst_closed_tcp_port,
                dst_closed_udp_port,
            ]),
        );

        let timeout = Some(Duration::from_secs_f64(0.5));
        let top_k = 3;
        let num_threads = Some(8);
        let ret = os_detect(&[target1], num_threads, src_addr, top_k, timeout).unwrap();
        println!("{}", ret);

        let detects = ret.value();
        for od in detects {
            match od {
                OsDetect::V4(r) => {
                    println!("{}", r.fingerprint);
                }
                _ => (),
            }
        }
    }
    #[test]
    fn test_os_detect6() {
        let _pr = PistolRunner::init(
            PistolLogger::None,
            Some(String::from("os_detect6.pcapng")),
            None, // use default value
        )
        .unwrap();

        let src_addr = None;
        let dst_open_tcp_port = 22;
        let dst_closed_tcp_port = 8765;
        let dst_closed_udp_port = 9876;
        let addr1 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e4").unwrap();
        let target1 = Target::new(
            addr1.into(),
            Some(vec![
                dst_open_tcp_port,
                dst_closed_tcp_port,
                dst_closed_udp_port,
            ]),
        );

        let timeout = Some(Duration::from_secs_f64(0.5));
        let top_k = 3;
        let num_threads = Some(8);
        let ret = os_detect(&[target1], num_threads, src_addr, top_k, timeout).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_os_detect_raw() {
        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let src_addr = None;
        let dst_open_tcp_port = 22;
        let dst_closed_tcp_port = 8765;
        let dst_closed_udp_port = 9876;
        let timeout = Some(Duration::new(1, 0));
        let top_k = 3;
        let ret = os_detect_raw(
            addr1,
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
        let addr1 = IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0x0020c, 0x29ff, 0xfe2c, 0x09e4,
        ));
        let src_addr = None;
        let dst_open_tcp_port = 22;
        let dst_closed_tcp_port = 8765;
        let dst_closed_udp_port = 9876;
        let timeout = Some(Duration::new(1, 0));
        let top_k = 3;
        let ret = os_detect_raw(
            addr1,
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
