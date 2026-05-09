/* Remote OS Detection */
use chrono::DateTime;
use chrono::Local;
use prettytable::Cell;
use prettytable::Row;
use prettytable::Table;
use prettytable::row;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use std::io::Cursor;
use std::io::Read;
use std::net::IpAddr;
use std::sync::mpsc::channel;
use std::time::Duration;
use std::time::Instant;
use threadpool::ThreadPool;
use tracing::debug;
use tracing::error;
use tracing::warn;
use zip::ZipArchive;

use crate::NetInfo;
use crate::error::PistolError;
use crate::os::dbparser::NmapOsDb;
use crate::os::osscan::Fingerprint;
use crate::os::osscan::os_probe_thread;
use crate::os::osscan6::Fingerprint6;
use crate::os::osscan6::os_probe_thread6;
use crate::utils::time_to_string;

pub mod dbparser;
pub mod operator;
pub mod operator6;
pub mod osscan;
pub mod osscan6;
pub mod packet;
pub mod packet6;
pub mod rr;

#[derive(Debug, Clone)]
struct OsProbeState {
    retries: usize,
    recved: bool,
}

#[derive(Debug, Clone)]
pub struct OsInfo {
    pub name: String,
    pub class: Vec<String>,
    pub cpe: Vec<String>,
    pub score: usize,
    pub total: usize,
    pub db: NmapOsDb,
}

#[derive(Debug, Clone)]
pub struct OsInfo6 {
    pub name: String,
    pub class: String,
    pub cpe: String,
    pub score: f64,
    pub label: usize,
}

#[derive(Debug, Clone)]
pub struct Detect {
    pub addr: IpAddr,
    pub alive: bool,
    pub fingerprint: Fingerprint,
    pub detects: Vec<OsInfo>,
    pub layer3_cost: Duration,
    pub layer2_cost: Duration,
}

impl Detect {
    fn new_offline_host(dst_addr: IpAddr) -> Self {
        Self {
            addr: dst_addr,
            alive: false,
            fingerprint: Fingerprint::default(),
            detects: Vec::new(),
            layer3_cost: Duration::ZERO,
            layer2_cost: Duration::ZERO,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Detect6 {
    pub addr: IpAddr,
    pub alive: bool,
    pub fingerprint: Fingerprint6,
    pub detects: Vec<OsInfo6>,
    pub layer3_cost: Duration,
    pub layer2_cost: Duration,
}

impl Detect6 {
    fn new_offline_host(dst_addr: IpAddr) -> Self {
        Self {
            addr: dst_addr,
            alive: false,
            fingerprint: Fingerprint6::default(),
            detects: Vec::new(),
            layer3_cost: Duration::ZERO,
            layer2_cost: Duration::ZERO,
        }
    }
}

#[derive(Debug, Clone)]
pub enum DetectReport {
    V4(Detect),
    V6(Detect6),
}

/// Show the fingerprint in DetectReport.
impl fmt::Display for DetectReport {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DetectReport::V4(o) => write!(f, "{}", o.fingerprint),
            DetectReport::V6(o) => write!(f, "{}", o.fingerprint),
        }
    }
}

impl DetectReport {
    pub fn addr(&self) -> IpAddr {
        match self {
            DetectReport::V4(ipv4) => ipv4.addr,
            DetectReport::V6(ipv6) => ipv6.addr,
        }
    }
    fn new_offline_host(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => DetectReport::V4(Detect::new_offline_host(addr)),
            IpAddr::V6(_) => DetectReport::V6(Detect6::new_offline_host(addr)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OsDetect {
    pub layer2_cost: Duration,
    pub detect_report: Option<DetectReport>,
    pub start_time: DateTime<Local>,
    pub finish_time: DateTime<Local>,
}

impl OsDetect {
    fn new() -> Self {
        Self {
            layer2_cost: Duration::ZERO,
            detect_report: None,
            start_time: Local::now(),
            finish_time: Local::now(),
        }
    }
    fn finish(&mut self, os_detect: Option<DetectReport>) {
        self.finish_time = Local::now();
        self.detect_report = os_detect;
    }
}

#[derive(Debug, Clone)]
pub struct OsDetects {
    pub layer2_cost: Duration,
    pub detect_reports: Vec<DetectReport>,
    pub start_time: DateTime<Local>,
    pub finish_time: DateTime<Local>,
    max_retries: usize,
}

impl fmt::Display for OsDetects {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("OS Detect Results").style_spec("c").with_hspan(7),
        ]));

        table.add_row(
            row![c -> "id", c -> "addr", c -> "rank", c -> "score", c -> "os", c -> "cpe", c -> "time cost"],
        );

        // sorted
        let mut btm_addr: BTreeMap<IpAddr, DetectReport> = BTreeMap::new();
        for detect in &self.detect_reports {
            btm_addr.insert(detect.addr(), detect.clone());
        }

        let mut total_cost = 0.0;
        let mut id = 1;
        for (addr, detect) in btm_addr {
            match detect {
                DetectReport::V4(o) => {
                    let time_cost_str = time_to_string(o.layer3_cost);
                    let addr_str = format!("{}", addr);
                    total_cost += o.layer3_cost.as_secs_f32();
                    if o.alive {
                        if o.detects.len() > 0 {
                            for (i, os_info) in o.detects.iter().enumerate() {
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
                        let rank_str = format!("#{}", 1);
                        table.add_row(row![c -> id, c -> addr_str, c -> rank_str, c -> "0/0", c -> "target dead", c -> "", c -> time_cost_str]);
                        id += 1;
                    }
                }
                DetectReport::V6(o) => {
                    let time_cost_str = time_to_string(o.layer3_cost);
                    let addr_str = format!("{}", addr);
                    total_cost += o.layer3_cost.as_secs_f32();
                    if o.alive {
                        if o.detects.len() > 0 {
                            for (i, os_info6) in o.detects.iter().enumerate() {
                                let number_str = format!("#{}", i + 1);
                                let score_str = format!("{:.1}", os_info6.score);
                                let os_str = &os_info6.name;
                                let os_cpe = &os_info6.cpe;
                                table.add_row(row![c -> id, c -> addr_str, c -> number_str, c -> score_str, c -> os_str, c -> os_cpe, c -> time_cost_str]);
                                id += 1;
                            }
                        } else {
                            table.add_row(Row::new(vec![Cell::new(
                                "no results, usually caused by a novelty value greater than 15.0",
                            )
                            .with_hspan(7)]));
                        }
                    } else {
                        let rank_str = format!("#{}", 1);
                        table.add_row(row![c -> id, c -> addr_str, c -> rank_str, c -> "0.0", c -> "target dead", c -> "", c -> time_cost_str]);
                        id += 1;
                    }
                }
            }
        }
        let total_cost_str = time_to_string(Duration::from_secs_f32(total_cost));
        let summary = format!(
            "total used time: {}, max_retries: {}",
            total_cost_str, self.max_retries
        );
        table.add_row(Row::new(vec![Cell::new(&summary).with_hspan(7)]));
        write!(f, "{}", table)
    }
}

impl OsDetects {
    fn new(max_retries: usize) -> Self {
        Self {
            layer2_cost: Duration::ZERO,
            detect_reports: Vec::new(),
            start_time: Local::now(),
            finish_time: Local::now(),
            max_retries,
        }
    }
    fn finish(&mut self, os_detects: Vec<DetectReport>) {
        self.finish_time = Local::now();
        self.detect_reports = os_detects;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapJsonParameters {
    pub name: String,
    pub value: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

fn get_nmap_os_db() -> Result<Vec<NmapOsDb>, PistolError> {
    let data = include_bytes!("./db/nmap-os-db.zip");
    let reader = Cursor::new(data);
    let mut archive = ZipArchive::new(reader)?;

    if archive.len() > 0 {
        let mut file = archive.by_index(0)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let ret: Vec<NmapOsDb> = serde_json::from_str(&contents)?;
        Ok(ret)
    } else {
        Err(PistolError::ZipEmptyError)
    }
}

pub fn os_detect(
    net_infos: Vec<NetInfo>,
    threads: usize,
    timeout: Duration,
    max_retries: usize,
    top_k: usize,
) -> Result<OsDetects, PistolError> {
    let (tx, rx) = channel();
    let pool = ThreadPool::new(threads);
    let mut recv_size = 0;
    let mut ret = OsDetects::new(max_retries);
    let mut os_detects = Vec::new();

    for ni in &net_infos {
        if !ni.valid {
            let od = DetectReport::new_offline_host(ni.inferred_dst_addr);
            os_detects.push(od);
            continue;
        }

        let dst_mac = ni.inferred_dst_mac;
        let dst_addr = ni.inferred_dst_addr;
        let src_mac = ni.inferred_src_mac;

        let tx = tx.clone();
        recv_size += 1;
        match dst_addr {
            IpAddr::V4(dst_ipv4) => {
                let dst_ports = ni.dst_ports.clone();
                let src_ipv4 = match ni.inferred_src_addr {
                    IpAddr::V4(src) => src,
                    _ => {
                        return Err(PistolError::AttackAddressNotMatch {
                            addr: ni.inferred_src_addr,
                        });
                    }
                };

                let nmap_os_db = get_nmap_os_db()?;
                debug!("ipv4 nmap os db parse finish");
                let if_name = ni.if_name.clone();
                pool.execute(move || {
                    let start_time = Instant::now();
                    let detect_rets = if dst_ports.len() >= 3 {
                        let dst_open_tcp_port = dst_ports[0];
                        let dst_closed_tcp_port = dst_ports[1];
                        let dst_closed_udp_port = dst_ports[2];
                        let os_detect_ret = os_probe_thread(
                            dst_mac,
                            dst_ipv4,
                            dst_open_tcp_port,
                            dst_closed_tcp_port,
                            dst_closed_udp_port,
                            src_mac,
                            src_ipv4,
                            if_name,
                            nmap_os_db,
                            top_k,
                            timeout,
                            max_retries,
                        );
                        os_detect_ret
                    } else {
                        Err(PistolError::OsDetectPortsNotEnough)
                    };
                    let od = match detect_rets {
                        Ok(Some((fingerprint, detects))) => {
                            let o = Detect {
                                addr: dst_addr,
                                alive: true,
                                fingerprint,
                                detects,
                                layer3_cost: start_time.elapsed(),
                                layer2_cost: Duration::ZERO,
                            };
                            let od = DetectReport::V4(o);
                            Ok(Some(od))
                        }
                        Ok(None) => Ok(None),
                        Err(e) => Err(e),
                    };
                    if let Err(e) = tx.send((dst_addr, od, start_time)) {
                        error!("failed to send to tx on func os_detect: {}", e);
                    }
                });
            }
            IpAddr::V6(dst_ipv6) => {
                let dst_ports = ni.dst_ports.clone();
                let src_ipv6 = match ni.inferred_src_addr {
                    IpAddr::V6(src) => src,
                    _ => {
                        return Err(PistolError::AttackAddressNotMatch {
                            addr: ni.inferred_src_addr,
                        });
                    }
                };

                let linear = gen_linear()?;
                debug!("ipv6 gen linear parse finish");
                let if_name = ni.if_name.clone();
                pool.execute(move || {
                    let start_time = Instant::now();
                    let detect_rets = if dst_ports.len() >= 3 {
                        let dst_open_tcp_port = dst_ports[0];
                        let dst_closed_tcp_port = dst_ports[1];
                        let dst_closed_udp_port = dst_ports[2];

                        let os_detect_ret = os_probe_thread6(
                            dst_mac,
                            dst_ipv6,
                            dst_open_tcp_port,
                            dst_closed_tcp_port,
                            dst_closed_udp_port,
                            src_mac,
                            src_ipv6,
                            if_name,
                            top_k,
                            linear,
                            timeout,
                            max_retries,
                        );
                        os_detect_ret
                    } else {
                        Err(PistolError::OsDetectPortsNotEnough)
                    };
                    let od = match detect_rets {
                        Ok((fingerprint, detects)) => {
                            let o = Detect6 {
                                addr: dst_addr,
                                alive: true,
                                fingerprint,
                                detects,
                                layer3_cost: start_time.elapsed(),
                                layer2_cost: Duration::ZERO,
                            };
                            let od = DetectReport::V6(o);
                            Ok(Some(od))
                        }
                        Err(e) => Err(e),
                    };
                    if let Err(e) = tx.send((dst_addr, od, start_time)) {
                        error!("failed to send to tx on func os_detect: {}", e);
                    }
                });
            }
        }
    }

    let iter = rx.into_iter().take(recv_size);
    for (addr, r, start_time) in iter {
        match r {
            Ok(Some(od)) => {
                os_detects.push(od);
            }
            Ok(None) | Err(_) => match addr {
                IpAddr::V4(_) => {
                    let o = Detect {
                        addr,
                        alive: false,
                        fingerprint: Fingerprint::default(),
                        detects: Vec::new(),
                        layer3_cost: start_time.elapsed(),
                        layer2_cost: Duration::ZERO,
                    };
                    let od = DetectReport::V4(o);
                    os_detects.push(od);
                }
                IpAddr::V6(_) => {
                    let o = Detect6 {
                        addr,
                        alive: false,
                        fingerprint: Fingerprint6::default(),
                        detects: Vec::new(),
                        layer3_cost: start_time.elapsed(),
                        layer2_cost: Duration::ZERO,
                    };
                    let od = DetectReport::V6(o);
                    os_detects.push(od);
                }
            },
        }
    }
    ret.finish(os_detects);
    Ok(ret)
}

pub fn os_detect_raw(
    net_info: NetInfo,
    timeout: Duration,
    max_retries: usize,
    top_k: usize,
) -> Result<OsDetect, PistolError> {
    let mut os_detect = OsDetect::new();
    if !net_info.valid {
        os_detect.finish(Some(DetectReport::new_offline_host(
            net_info.inferred_dst_addr,
        )));
        return Ok(os_detect);
    }
    let start_time = Instant::now();
    let dst_mac = net_info.inferred_dst_mac;
    let dst_addr = net_info.inferred_dst_addr;
    let src_mac = net_info.inferred_src_mac;
    let src_addr = net_info.inferred_src_addr;
    let if_name = net_info.if_name.clone();

    let dst_open_tcp_port = net_info.dst_ports[0];
    let dst_closed_tcp_port = net_info.dst_ports[1];
    let dst_closed_udp_port = net_info.dst_ports[2];

    match dst_addr {
        IpAddr::V4(dst_ipv4) => {
            let src_ipv4 = match src_addr {
                IpAddr::V4(src) => src,
                _ => return Err(PistolError::CanNotFoundSrcAddress),
            };
            let nmap_os_db = get_nmap_os_db()?;
            debug!("ipv4 nmap os db parse finish");
            let nmap_os_db = nmap_os_db.to_vec();
            match os_probe_thread(
                dst_mac,
                dst_ipv4,
                dst_open_tcp_port,
                dst_closed_tcp_port,
                dst_closed_udp_port,
                src_mac,
                src_ipv4,
                if_name,
                nmap_os_db,
                top_k,
                timeout,
                max_retries,
            ) {
                Ok(Some((fingerprint, detects))) => {
                    let o = Detect {
                        addr: dst_addr,
                        alive: true,
                        fingerprint,
                        detects,
                        layer3_cost: start_time.elapsed(),
                        layer2_cost: Duration::ZERO,
                    };
                    let dr = DetectReport::V4(o);
                    os_detect.finish(Some(dr));
                    Ok(os_detect)
                }
                Ok(None) | Err(_) => {
                    let o = Detect {
                        addr: dst_addr,
                        alive: false,
                        fingerprint: Fingerprint::default(),
                        detects: Vec::new(),
                        layer3_cost: start_time.elapsed(),
                        layer2_cost: Duration::ZERO,
                    };
                    let dr = DetectReport::V4(o);
                    os_detect.finish(Some(dr));
                    Ok(os_detect)
                }
            }
        }
        IpAddr::V6(dst_ipv6) => {
            let src_ipv6 = match src_addr {
                IpAddr::V6(src) => src,
                _ => return Err(PistolError::CanNotFoundSrcAddress),
            };
            let linear = gen_linear()?;
            debug!("ipv6 gen linear parse finish");
            match os_probe_thread6(
                dst_mac,
                dst_ipv6,
                dst_open_tcp_port,
                dst_closed_tcp_port,
                dst_closed_udp_port,
                src_mac,
                src_ipv6,
                if_name,
                top_k,
                linear,
                timeout,
                max_retries,
            ) {
                Ok((fingerprint, detects)) => {
                    let o = Detect6 {
                        addr: dst_addr,
                        alive: true,
                        fingerprint,
                        detects,
                        layer3_cost: start_time.elapsed(),
                        layer2_cost: Duration::ZERO,
                    };
                    let dr = DetectReport::V6(o);
                    os_detect.finish(Some(dr));
                    Ok(os_detect)
                }
                Err(e) => {
                    warn!("os probe error: {}", e);
                    let o = Detect6 {
                        addr: dst_addr,
                        alive: false,
                        fingerprint: Fingerprint6::default(),
                        detects: Vec::new(),
                        layer3_cost: start_time.elapsed(),
                        layer2_cost: Duration::ZERO,
                    };
                    let dr = DetectReport::V6(o);
                    os_detect.finish(Some(dr));
                    Ok(os_detect)
                }
            }
        }
    }
}
