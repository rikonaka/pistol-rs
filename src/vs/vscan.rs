use serde::Deserialize;
use serde::Serialize;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::time::Duration;
use tracing::debug;
use tracing::error;
use tracing::warn;

use super::dbparser::Match;
use super::dbparser::ProbeProtocol;
use super::dbparser::ServiceProbe;
use super::dbparser::SoftMatch;
use crate::error::PistolError;
use crate::utils::random_port;

const TCP_BUFF_SIZE: usize = 40960;
const UDP_BUFF_SIZE: usize = 40960;

fn vs_probe_data_to_string(input: &[u8]) -> String {
    let mut ret = String::new();
    for &i in input {
        match i {
            // not convert the char below to string anymore
            10 => {
                ret += "\n";
            }
            13 => {
                ret += "\r";
            }
            9 => {
                ret += "\t";
            }
            // others
            0 => {
                ret += r"\0";
            }
            8 => {
                ret += r"\b";
            }
            11 => {
                ret += r"\v";
            }
            12 => {
                ret += r"\f";
            }
            32..=126 => {
                let s = (i as char).to_string();
                ret += &s;
            }
            _ => {
                if i > 126 {
                    let s = format!(r"\x{:02x}", i);
                    ret += &s;
                }
            }
        }
    }
    // println!(">>> {}", ret);
    ret
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchX {
    Match(Match),
    SoftMatch(SoftMatch),
}

fn tcp_null_probe(
    stream: &mut TcpStream,
    service_probes: &[ServiceProbe],
) -> Result<Vec<MatchX>, PistolError> {
    let mut total_recv_buff = Vec::new();
    loop {
        let mut recv_buff = [0u8; TCP_BUFF_SIZE];
        match stream.read(&mut recv_buff) {
            Ok(n) => {
                debug!("tcp null probe n: {}", n);
                if n == 0 {
                    break;
                } else {
                    total_recv_buff.extend(recv_buff);
                }
            }
            Err(e) => {
                warn!("tcp null probe stream read failed: {}", e);
                break;
            }
        };
    }

    let mut recv_buff = total_recv_buff;
    recv_buff.retain(|&x| x != 0);

    let mut ret = Vec::new();
    debug!("null probe recv buff len: {}", recv_buff.len());
    if recv_buff.len() > 0 {
        let recv_str = vs_probe_data_to_string(&recv_buff);
        for s in service_probes {
            if s.probe.probename == "NULL" {
                match s.check(&recv_str) {
                    Some(mx) => ret.push(mx),
                    None => (),
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
) -> Result<Vec<MatchX>, PistolError> {
    fn send_recv_match(
        stream: &mut TcpStream,
        sp: &ServiceProbe,
    ) -> Result<Vec<MatchX>, PistolError> {
        let probestring = &sp.probe.probestring;
        stream.write(probestring)?;
        let mut total_recv_buff = Vec::new();
        loop {
            let mut recv_buff = [0u8; TCP_BUFF_SIZE];
            match stream.read(&mut recv_buff) {
                Ok(n) => {
                    debug!("tcp continue probe n: {}", n);
                    if n == 0 {
                        break;
                    } else {
                        total_recv_buff.extend(recv_buff);
                    }
                }
                Err(e) => {
                    error!("tcp continue probe stream read failed: {}", e);
                    break;
                }
            };
        }
        let mut recv_buff = total_recv_buff;
        recv_buff.retain(|&x| x != 0);

        debug!("tcp continue probe recv buff len: {}", recv_buff.len());
        if recv_buff.len() > 0 {
            let recv_str = vs_probe_data_to_string(&recv_buff);
            // debug!("{}", recv_str);
            let mut ret = Vec::new();
            match sp.check(&recv_str) {
                Some(mx) => ret.push(mx),
                None => (),
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
                    let r = send_recv_match(stream, sp);
                    match r {
                        Ok(r) => ret.extend(r),
                        Err(e) => return Err(e.into()),
                    }
                }
            } else {
                let r = send_recv_match(stream, sp);
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
) -> Result<Vec<MatchX>, PistolError> {
    fn run_probe(socket: &UdpSocket, sp: &ServiceProbe) -> Result<Vec<MatchX>, PistolError> {
        let mut ret = Vec::new();
        let probestring = &sp.probe.probestring;
        socket.send(probestring)?;

        let mut total_recv_buff = Vec::new();
        loop {
            let mut recv_buff = [0u8; UDP_BUFF_SIZE];
            match socket.recv(&mut recv_buff) {
                Ok(n) => {
                    debug!("udp probe n: {}", n);
                    if n == 0 {
                        break;
                    } else {
                        total_recv_buff.extend(recv_buff);
                    }
                }
                Err(e) => {
                    error!("udp probe recv failed: {}", e);
                    break;
                }
            }
        }

        let mut recv_buff = total_recv_buff;
        recv_buff.retain(|&x| x != 0);

        if recv_buff.len() > 0 {
            let recv_str = vs_probe_data_to_string(&recv_buff);
            match sp.check(&recv_str) {
                Some(mx) => ret.push(mx),
                None => (),
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
) -> Result<Vec<MatchX>, PistolError> {
    // If the port is TCP, Nmap starts by connecting to it.
    let tcp_dst_addr = SocketAddr::new(dst_addr, dst_port);
    match TcpStream::connect_timeout(&tcp_dst_addr, timeout) {
        Ok(mut stream) => {
            // println!("{}", tcp_dst_addr);
            // stream.set_nonblocking(false)?;
            // Once the TCP connection is made, Nmap listens for roughly five seconds.
            let five_seconds = Duration::from_secs(5);
            stream.set_read_timeout(Some(five_seconds))?;
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
                match stream.shutdown(Shutdown::Both) {
                    Ok(_) => (),
                    Err(e) => error!("shutdown tcp stream failed: {}", e),
                }
                Ok(null_probe_ret)
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
                        match stream.shutdown(Shutdown::Both) {
                            Ok(_) => (),
                            Err(e) => error!("shutdown tcp stream failed: {}", e),
                        }
                        Ok(tcp_ret)
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
                        match stream.shutdown(Shutdown::Both) {
                            Ok(_) => (),
                            Err(e) => error!("shutdown tcp stream failed: {}", e),
                        }
                        Ok(udp_ret)
                    }
                } else {
                    match stream.shutdown(Shutdown::Both) {
                        Ok(_) => (),
                        Err(e) => error!("shutdown tcp stream failed: {}", e),
                    }
                    Ok(vec![])
                }
            }
        }
        Err(e) => {
            error!("connect to dst failed: {}", e);
            Ok(vec![]) // ignore closed port here
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fancy_regex::Regex as FancyRegex;
    use regex::bytes::Regex;
    #[test]
    fn test_vs_probe_to_string() {
        let regex = FancyRegex::new(r"\\0\\0\\xae\\xae").unwrap();
        let data = vec![0, 0, 0xae, 0xae];
        let data_str = vs_probe_data_to_string(&data);
        let ret = regex.is_match(&data_str).unwrap();
        println!("{}", data_str);
        println!("{}", ret);
        // let data_str = String::from_utf8_lossy(&data);
        // let ret = regex.is_match(&data_str).unwrap();
        // println!("{}", data_str);
        // println!("{}", ret);
    }
    #[test]
    fn test_xx() {
        let data: &[u8] = &[72, 101, 108, 108, 111, 0, 87, 111, 114, 108, 100]; // "Hello\0World"
        let regex = Regex::new(r"\x00").unwrap();

        if regex.is_match(data) {
            println!("XXX");
        } else {
        }
    }
}
