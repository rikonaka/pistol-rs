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
#[derive(Debug, Clone)]
pub struct OsInfo {
    pub name: String,
    pub class: Vec<String>,
    pub cpe: Vec<String>,
    pub score: usize,
    pub total: usize,
    pub db: NmapOSDB,
}

#[cfg(feature = "os")]
#[derive(Debug, Clone)]
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
                        if o.detects.len() > 0 {
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
                            table.add_row(Row::new(vec![
                                Cell::new("there are no matching results, which is very uncommon and is maybe a bug").with_hspan(7),
                            ]));
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
                        if o.detects.len() > 0 {
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
                            table.add_row(Row::new(vec![Cell::new("no results, usually caused by a novelty value greater than 15.0").with_hspan(7)]));
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapJsonParameters {
    pub name: String,
    pub value: Vec<f64>,
}

#[cfg(feature = "os")]
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    fn test_os_detect_windows_server_2025() {
        /*
        -- nmap
        SCAN(V=7.95%E=4%D=8/18%OT=3389%CT=%CU=%PV=Y%DS=1%DC=D%G=N%M=000C29%TM=68A2EE8D%P=x86_64-pc-linux-gnu)
        SEQ(SP=106%GCD=1%ISR=108%TI=I%TS=A)
        OPS(O1=M5B4NW0ST11%O2=M5B4NW0ST11%O3=M5B4NW0NNT11%O4=M5B4NW0ST11%O5=M5B4NW0ST11%O6=M5B4ST11)
        WIN(W1=FA00%W2=FA00%W3=FA00%W4=FA00%W5=FA00%W6=FA00)
        ECN(R=Y%DF=Y%TG=80%W=FA00%O=M5B4NW0NNS%CC=Y%Q=)
        T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
        T2(R=N)
        T3(R=N)
        T4(R=N)
        U1(R=N)
        IE(R=N)

        -- pistol
        SCAN(V=pistol_4.0.16%D=8/19%OT=3389%CT=8765%CU=9876PV=Y%DS=1%DC=D%G=Y%M=0C29%TM=68A41EB0%P=RUST)
        SEQ(SP=114%GCD=2%ISR=113%TI=I%TS=A)
        OPS(O1=M5B4NW0ST11%O2=M5B4NW0ST11%O3=M5B4NW0NNT11%O4=M5B4NW0ST11%O5=M5B4NW0ST11%O6=M5B4ST11)
        WIN(W1=FA00%W2=FA00%W3=FA00%W4=FA00%W5=FA00%W6=FA00)
        ECN(R=Y%DF=Y%TG=80%W=FA00%O=M5B4NW0NNS%CC=Y%Q=)
        T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
        T2(R=N)
        T3(R=N)
        T4(R=N)
        T5(R=N)
        T6(R=N)
        T7(R=N)
        U1(R=N%UN=0)
        IE(R=N)
        */

        let _pr = PistolRunner::init(
            PistolLogger::Debug,
            Some(String::from("os_detect.pcapng")),
            None, // use default value
        )
        .unwrap();

        let src_addr = None;
        let dst_closed_tcp_port = 8765;
        let dst_closed_udp_port = 9876;

        // let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5));
        // let dst_open_tcp_port = 22;
        // let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 6));
        // let dst_open_tcp_port = 22;
        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 128));
        let dst_open_tcp_port = 3389;
        let target1 = Target::new(
            addr1,
            Some(vec![
                dst_open_tcp_port,
                dst_closed_tcp_port,
                dst_closed_udp_port,
            ]),
        );

        let timeout = Some(Duration::from_secs_f64(1.0));
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
    fn test_os_detect_centos_7() {
        /*
        -- nmap
        SCAN(V=7.95%E=4%D=8/19%OT=22%CT=%CU=%PV=Y%DS=1%DC=D%G=N%M=000C29%TM=68A3D962%P=x86_64-pc-linux-gnu)
        SEQ(SP=105%GCD=1%ISR=10B%TI=Z%TS=A)
        SEQ(SP=FF%GCD=1%ISR=10C%TI=Z%II=I%TS=A)
        OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B4ST11)
        WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)
        ECN(R=Y%DF=Y%TG=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)
        T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
        T2(R=N)
        T3(R=N)
        T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
        U1(R=N)
        IE(R=Y%DFI=N%TG=40%CD=S)

        -- pistol
        SCAN(V=pistol_4.0.16%D=8/19%OT=22%CT=8765%CU=9876PV=Y%DS=1%DC=D%G=Y%M=0C29%TM=68A3F024%P=RUST)
        SEQ(SP=114%GCD=1%ISR=112%TI=Z%TS=A)
        OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B4ST11)
        WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)
        ECN(R=Y%DF=Y%T=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)
        T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
        T2(R=N)
        T3(R=N)
        T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
        T5(R=N)
        T6(R=N)
        T7(R=N)
        U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
        IE(R=Y%DFI=N%T=40%CD=S)
        */

        let _pr = PistolRunner::init(
            PistolLogger::Debug,
            Some(String::from("os_detect.pcapng")),
            None, // use default value
        )
        .unwrap();

        let src_addr = None;
        let dst_closed_tcp_port = 8765;
        let dst_closed_udp_port = 9876;

        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 129));
        let dst_open_tcp_port = 22;
        let target1 = Target::new(
            addr1,
            Some(vec![
                dst_open_tcp_port,
                dst_closed_tcp_port,
                dst_closed_udp_port,
            ]),
        );

        let timeout = Some(Duration::from_secs_f64(1.0));
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
    fn test_os_detect6_centos_7() {
        /*
        -- nmap
        SCAN(V=7.95%E=6%D=8/19%OT=22%CT=%CU=43325%PV=N%DS=1%DC=D%G=Y%M=000C29%TM=68A4363F%P=x86_64-pc-linux-gnu)
        S1(P=6000{4}280640XX{32}0016c7a2c2c785dcac3c69aea0126f90d6fc0000020405a00402080a01c245aeff{4}01030307%ST=0.07947%RT=0.080582)
        S2(P=6000{4}280640XX{32}0016c7a3a6b3dd08ac3c69afa0126f909b7e0000020405a00402080a01c24612ff{4}01030307%ST=0.180041%RT=0.180935)
        S3(P=6000{4}280640XX{32}0016c7a4e5cd8492ac3c69b0a0126f90b7750000020405a00101080a01c24676ff{4}01030307%ST=0.279382%RT=0.280225)
        S4(P=6000{4}280640XX{32}0016c7a54200f6b5ac3c69b1a0126f90e5b80000020405a00402080a01c246daff{4}01030307%ST=0.379506%RT=0.380849)
        S5(P=6000{4}280640XX{32}0016c7a6a9fe8bd7ac3c69b2a0126f90e8320000020405a00402080a01c2473eff{4}01030307%ST=0.47953%RT=0.480549)
        S6(P=6000{4}240640XX{32}0016c7a76d2a8034ac3c69b390126f9044520000020405a00402080a01c247a2ff{4}%ST=0.579882%RT=0.581002)
        IE1(P=6000{4}803a40XX{32}81093eafabcd00{122}%ST=0.61657%RT=0.61718)
        IE2(P=6000{4}583a40XX{32}0401400a00{3}386001234500280032XX{32}3c00010400{4}2b00010400{12}3a00010400{4}8000402fabcd0001%ST=0.666876%RT=0.668181)
        NS(P=6000{4}183affXX{32}880009df4000{3}XX{16}%ST=0.719135%RT=0.720038)
        U1(P=6000{3}01643a40XX{32}0101d53200{4}6001234501341139XX{32}c733a93d01348fec43{300}%ST=0.766442%RT=0.767309)
        TECN(P=6000{4}200640XX{32}0016c7a8d45582a8ac3c69b48052708035e80000020405a00101040201030307%ST=0.815959%RT=0.816861)
        T4(P=6000{4}140640XX{32}0016c7aba5421c1400{4}5004000093090000%ST=0.964467%RT=0.966983)
        EXTRA(FL=12345)

        -- pistol
        SCAN(V=pistol_4.0.16%E=6%D=8/19%OT=22%CT=8765%CU=9876PV=Y%DS=1%DC=D%G=Y%M=0C29%TM=68A44A76%P=RUST)
        S1(P=600{2}028640fe800{3}0XX{32}%ST=0.000578%RT=0.025954)
        S2(P=600{2}028640fe800{3}0XX{32}%ST=0.100911%RT=0.121613)
        S3(P=600{2}028640fe800{3}0XX{32}%ST=0.201081%RT=0.221879)
        S4(P=600{2}028640fe800{3}0XX{32}%ST=0.304505%RT=0.325537)
        S5(P=600{2}028640fe800{3}0XX{32}%ST=0.404598%RT=0.417561)
        S6(P=600{2}024640fe800{3}0XX{30}%ST=0.504899%RT=0.525877)
        IE1(P=600{2}0803a40fe800{3}0XX{32}00{44}%ST=0.605082%RT=0.649687)
        IE2(P=600{2}0583a40fe800{3}0XX{32}78e837a77371778c3c01400{2}2b01400{6}3a01400{2}800402fabcd01%ST=0.649706%RT=0.665666)
        NS(P=600{2}0183afffe800{3}0XX{24}%ST=3.285946%RT=3.309598)
        U1(P=600{2}1643a40fe800{3}0XX{32}78e837a77371778c84932694134553643{300}%ST=3.309699%RT=3.330450)
        TECN(P=600{2}020640fe800{3}0XX{28}%ST=3.330488%RT=3.357514)
        T4(P=600{2}014640fe800{3}0XX{22}%ST=3.558762%RT=3.578006)
        */

        let _pr = PistolRunner::init(
            PistolLogger::Debug,
            Some(String::from("os_detect6.pcapng")),
            None, // use default value
        )
        .unwrap();

        let src_addr = None;
        let dst_open_tcp_port = 22;
        let dst_closed_tcp_port = 8765;
        let dst_closed_udp_port = 9876;
        let addr1 = Ipv6Addr::from_str("fe80::78e8:37a7:7371:778c").unwrap();
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
        // let fingerprint = ret.
    }

    #[test]
    fn test_os_detect6_windows_server_2025() {
        /*
        -- nmap
        SCAN(V=7.95%E=6%D=8/19%OT=3389%CT=%CU=%PV=N%DS=1%DC=D%G=Y%M=000C29%TM=68A43D15%P=x86_64-pc-linux-gnu)
        S1(P=60029ebf00280640XX{32}0d3d99c6689af490e73b9337a012fa0052090000020405a0010303000402080a0132496eff{4}%ST=0.021405%RT=0.022599)
        S2(P=600bef1e00280640XX{32}0d3d99c7576e06a5e73b9338a012fa0050bb0000020405a0010303000402080a013249d2ff{4}%ST=0.121547%RT=0.123118)
        S3(P=60085d5d00280640XX{32}0d3d99c86fb65611e73b9339a012fa00eba10000020405a0010303000101080a01324a36ff{4}%ST=0.221461%RT=0.222517)
        S4(P=600377f700280640XX{32}0d3d99c924b05409e73b933aa012fa0035490000020405a0010303000402080a01324a9aff{4}%ST=0.321468%RT=0.322621)
        S5(P=6002f85a00280640XX{32}0d3d99ca782ca544e73b933ba012fa00902a0000020405a0010303000402080a01324aff{5}%ST=0.422417%RT=0.423493)
        S6(P=60073a4400240640XX{32}0d3d99cb694a6beae73b933c9012fa00ec080000020405a00402080a01324b62ff{4}%ST=0.521465%RT=0.522136)
        NS(P=6000{4}203affXX{32}88002df86000{3}XX{16}0201000c29fd51d5%ST=0.665484%RT=0.667043)
        TECN(P=6024d63100200640XX{32}0d3d99ccedaa00fae73b933d8052fa0031f50000020405a00103030001010402%ST=0.765114%RT=0.766728)
        EXTRA(FL=12345)

        -- pistol
        SCAN(V=pistol_4.0.16%E=6%D=8/20%OT=3389%CT=8765%CU=9876PV=Y%DS=1%DC=D%G=Y%M=0C29%TM=68A527C2%P=RUST)
        S1(P=60c7220028680fe800{3}0XX{32}%ST=0.000624%RT=0.009970)
        S2(P=60a8e56028680fe800{3}0XX{32}%ST=0.100868%RT=0.122395)
        S3(P=60c67e3028680fe800{3}0XX{32}%ST=0.201178%RT=0.218521)
        S4(P=609ca85028680fe800{3}0XX{32}%ST=0.301444%RT=0.321933)
        S5(P=609a75c028680fe800{3}0XX{32}%ST=0.401585%RT=0.418401)
        S6(P=6024033024680fe800{3}0XX{30}%ST=0.501854%RT=0.518154)
        NS(P=600{2}0203afffe800{3}0XX{28}%ST=8.470275%RT=8.498444)
        TECN(P=602447e6020680fe800{3}0XX{28}%ST=11.138252%RT=11.166179)
        EXTRA(FL=12345)
        */

        let _pr = PistolRunner::init(
            PistolLogger::Debug,
            Some(String::from("os_detect6.pcapng")),
            None, // use default value
        )
        .unwrap();

        let src_addr = None;
        let dst_open_tcp_port = 3389;
        let dst_closed_tcp_port = 8765;
        let dst_closed_udp_port = 9876;
        let addr1 = Ipv6Addr::from_str("fe80::5dd9:4cd2:82ac:d35").unwrap();
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
        // let fingerprint = ret.
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
