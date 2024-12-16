use log::debug;
use serde::Deserialize;
use serde::Serialize;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::time::Duration;
use std::time::Instant;
// use std::fs::File;

use super::dbparser::Match;
use super::dbparser::ProbeProtocol;
use super::dbparser::ServiceProbe;
use super::dbparser::SoftMatch;
use crate::errors::PistolErrors;
use crate::utils::random_port;
use crate::utils::vs_probe_data_to_string;

const TCP_BUFF_SIZE: usize = 4096;
const UDP_BUFF_SIZE: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchX {
    Match(Match),
    SoftMatch(SoftMatch),
}

fn tcp_null_probe(
    stream: &mut TcpStream,
    service_probes: &[ServiceProbe],
) -> Result<Vec<MatchX>, PistolErrors> {
    let mut recv_buff = [0u8; TCP_BUFF_SIZE];
    let mut recv_all_buff = Vec::new();
    loop {
        let n = match stream.read(&mut recv_buff) {
            Ok(n) => n,
            Err(_) => 0,
        };
        if n == 0 {
            break;
        } else {
            recv_all_buff.extend(recv_buff);
        }
    }

    let mut ret = Vec::new();
    if recv_all_buff.len() > 0 {
        // let recv_str = String::from_utf8_lossy(&recv_buff);
        let recv_str = vs_probe_data_to_string(&recv_buff);
        // println!("{}", recv_str);
        for s in service_probes {
            if s.probe.probename == "NULL" {
                let (ms, sms) = s.check(&recv_str);
                for m in ms {
                    let mx = MatchX::Match(m);
                    ret.push(mx);
                }
                for sm in sms {
                    let mx = MatchX::SoftMatch(sm);
                    ret.push(mx);
                }
            }
        }
    }
    Ok(ret)
}

fn tcp_continue_probe(
    stream: &mut TcpStream,
    dst_port: u16,
    only_tcp_recommended: bool,
    intensity: usize,
    service_probes: &[ServiceProbe],
) -> Result<Vec<MatchX>, PistolErrors> {
    fn run_probe(stream: &mut TcpStream, sp: &ServiceProbe) -> Result<Vec<MatchX>, PistolErrors> {
        let probestring = &sp.probe.probestring;
        stream.write(probestring)?;
        let mut recv_buff = [0u8; TCP_BUFF_SIZE];
        let mut recv_all_buff = Vec::new();
        loop {
            let n = match stream.read(&mut recv_buff) {
                Ok(n) => n,
                Err(_) => 0,
            };
            if n == 0 {
                break;
            } else {
                recv_all_buff.extend(recv_buff);
            }
        }
        if recv_all_buff.len() > 0 {
            // let recv_str = String::from_utf8_lossy(&recv_all_buff);
            let recv_str = String::from_utf8_lossy(&recv_buff);
            // println!("{}", recv_str);
            let (ms, sms) = sp.check(&recv_str);
            let mut ret = Vec::new();
            for m in ms {
                let mx = MatchX::Match(m);
                ret.push(mx);
            }
            for sm in sms {
                let mx = MatchX::SoftMatch(sm);
                ret.push(mx);
            }
            Ok(ret)
        } else {
            Ok(vec![])
        }
    }

    let mut ret = Vec::new();
    // TCP connections continue here if the NULL probe described above fails or soft-matches.
    for sp in service_probes {
        if sp.probe.probename != "NULL"
            && sp.probe.probeprotocol == ProbeProtocol::Tcp
            && intensity >= sp.rarity
        {
            // Since the reality is that most ports are used by the service they are registered to in nmap-services,
            // every probe has a list of port numbers that are considered to be most effective.
            if only_tcp_recommended {
                if sp.ports.len() > 0 && sp.ports.contains(&dst_port) {
                    let r = run_probe(stream, sp);
                    match r {
                        Ok(r) => ret.extend(r),
                        Err(e) => return Err(e.into()),
                    }
                }
            } else {
                let r = run_probe(stream, sp);
                match r {
                    Ok(r) => ret.extend(r),
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    Ok(ret)
}

fn udp_probe(
    dst_addr: IpAddr,
    dst_port: u16,
    only_udp_recommended: bool,
    intensity: usize,
    service_probes: &[ServiceProbe],
    timeout: Duration,
) -> Result<Vec<MatchX>, PistolErrors> {
    fn run_probe(socket: &UdpSocket, sp: &ServiceProbe) -> Result<Vec<MatchX>, PistolErrors> {
        let mut ret = Vec::new();
        let probestring = &sp.probe.probestring;
        socket.send(probestring)?;
        let mut recv_buff = [0u8; UDP_BUFF_SIZE];
        let n = match socket.recv(&mut recv_buff) {
            Ok(n) => n,
            Err(_) => 0,
        };
        if n > 0 {
            // let recv_str = String::from_utf8_lossy(&recv_buff);
            let recv_str = String::from_utf8_lossy(&recv_buff);
            let (ms, sms) = sp.check(&recv_str);
            for m in ms {
                let mx = MatchX::Match(m);
                ret.push(mx);
            }
            for sm in sms {
                let mx = MatchX::SoftMatch(sm);
                ret.push(mx);
            }
        }
        Ok(ret)
    }

    let random_port = random_port();
    let src_addr = match dst_addr {
        IpAddr::V4(_) => {
            let addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
            SocketAddr::new(addr, random_port)
        }
        IpAddr::V6(_) => {
            let addr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
            SocketAddr::new(addr, random_port)
        }
    };

    let dst_addr = SocketAddr::new(dst_addr, dst_port);
    let socket = UdpSocket::bind(src_addr)?;
    // let timeout = Duration::from_secs(1); // both 1 sec
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    socket.connect(dst_addr)?;

    let mut ret = Vec::new();
    for sp in service_probes {
        if sp.probe.probename != "NULL"
            && sp.probe.probeprotocol == ProbeProtocol::Udp
            && intensity >= sp.rarity
        {
            // Since the reality is that most ports are used by the service they are registered to in nmap-services,
            // every probe has a list of port numbers that are considered to be most effective.
            if only_udp_recommended {
                if sp.ports.contains(&dst_port) {
                    let r = run_probe(&socket, sp);
                    match r {
                        Ok(r) => ret.extend(r),
                        Err(e) => return Err(e.into()),
                    }
                }
            } else {
                let r = run_probe(&socket, sp);
                match r {
                    Ok(r) => ret.extend(r),
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    Ok(ret)
}

pub fn threads_vs_probe(
    dst_addr: IpAddr,
    dst_port: u16,
    only_null_probe: bool,
    only_tcp_recommended: bool,
    only_udp_recommended: bool,
    intensity: usize,
    service_probes: Vec<ServiceProbe>,
    timeout: Duration,
) -> Result<(Vec<MatchX>, Duration), PistolErrors> {
    // If the port is TCP, Nmap starts by connecting to it.
    let start_time = Instant::now();
    let tcp_dst_addr = SocketAddr::new(dst_addr, dst_port);
    match TcpStream::connect_timeout(&tcp_dst_addr, timeout) {
        Ok(mut stream) => {
            // println!("{}", tcp_dst_addr);
            // stream.set_nonblocking(false)?;
            // Once the TCP connection is made, Nmap listens for roughly five seconds.
            let five_seconds = Duration::from_secs(5);
            stream.set_read_timeout(Some(five_seconds))?;
            stream.set_write_timeout(Some(timeout))?;
            stream.set_nodelay(true).expect("set stream nodelay failed");
            stream
                .set_nonblocking(false)
                .expect("set noblocking failed");

            // If the connection succeeds and the port had been in the open|filtered state, it is changed to open.
            // Ignore this step here.
            debug!("send null probe");
            let null_probe_ret = tcp_null_probe(&mut stream, &service_probes)?;
            if null_probe_ret.len() > 0 {
                debug!("null probe work, exit");
                Ok((null_probe_ret, start_time.elapsed()))
            } else {
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                if !only_null_probe {
                    // Start TCP continue probe.
                    // println!("TCP CONTINUE PROBE");
                    debug!("send tcp continue probe");
                    let tcp_ret = tcp_continue_probe(
                        &mut stream,
                        dst_port,
                        only_tcp_recommended,
                        intensity,
                        &service_probes,
                    )?;
                    if tcp_ret.len() > 0 {
                        debug!("tcp continue probe work, exit");
                        Ok((tcp_ret, start_time.elapsed()))
                    } else {
                        // This point is where Nmap starts for UDP probes,
                        // and TCP connections continue here if the NULL probe described above fails or soft-matches.
                        debug!("send udp probe");
                        let udp_ret = udp_probe(
                            dst_addr,
                            dst_port,
                            only_udp_recommended,
                            intensity,
                            &service_probes,
                            timeout,
                        )?;
                        Ok((udp_ret, start_time.elapsed()))
                    }
                } else {
                    Ok((vec![], start_time.elapsed()))
                }
            }
        }
        Err(_) => Ok((vec![], start_time.elapsed())), // ignore closed port here
    }
}
