use anyhow::Result;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket, Ipv4Addr};
use std::time::Duration;
use std::time::Instant;

use super::dbparser::{nsp_exclued_parser, nsp_parser, Match, ProbesProtocol, ServiceProbe};
use crate::errors::{CanNotFoundNullProbe, CanNotFoundOtherProbes, CanNotFoundUdpProbes};
use crate::utils::{get_threads_pool, random_port};
use crate::TargetScanStatus;

const TCP_BUFF_SIZE: usize = 1024;

fn format_recv(buff: &[u8]) -> String {
    let mut ret_str = String::new();
    for b in buff {
        // ASCII printable characters 32-127
        if *b >= 32 && *b < 127 {
            ret_str += &format!("{}", *b as char);
        } else {
            match b {
                0 => ret_str += "\0",
                9 => ret_str += "\t",
                10 => ret_str += "\n",
                13 => ret_str += "\r",
                _ => {
                    let mut tmp = format!("{:x}", b);
                    if tmp.len() < 2 {
                        for _ in 0..(2 - tmp.len()) {
                            tmp = format!("0{}", tmp);
                        }
                    }
                    tmp = format!("\\x{}", tmp);
                    ret_str += &tmp;
                }
            }
        }
    }
    ret_str
}

fn null_probe(stream: &mut TcpStream, null_probe: &ServiceProbe) -> Result<Vec<Match>> {
    let mut recv_buff = [0u8; TCP_BUFF_SIZE];
    let n = stream.read(&mut recv_buff)?;
    if n > 0 {
        let recv_str = format_recv(&recv_buff);
        let ret = null_probe.check(&recv_str)?;
        Ok(ret)
    } else {
        Ok(vec![])
    }
}

fn continue_probe(
    stream: &mut TcpStream,
    dst_port: u16,
    service_probes: &[ServiceProbe],
) -> Result<Vec<Match>> {
    // TCP connections continue here if the NULL probe described above fails or soft-matches.
    for sp in service_probes {
        if sp.probe.protocol == ProbesProtocol::Tcp {
            match &sp.ports {
                Some(p) => {
                    // Since the reality is that most ports are used by the service they are registered to in nmap-services, every probe has a list of port numbers that are considered to be most effective.
                    if p.contains(&dst_port) {
                        let probestring = sp.probe.probestring.as_bytes();
                        stream.write(probestring)?;
                        let mut recv_buff = [0u8; TCP_BUFF_SIZE];
                        let n = stream.read(&mut recv_buff)?;
                        if n > 0 {
                            let recv_str = format_recv(&recv_buff);
                            let ret = sp.check(&recv_str)?;
                            if ret.len() > 0 {
                                return Ok(ret);
                            }
                        }
                    }
                }
                None => (),
            }
        }
    }
    Ok(vec![])
}

fn tcp_probe(
    dst_addr: IpAddr,
    dst_port: u16,
    mut status: TargetScanStatus,
    service_probes: &[ServiceProbe],
) -> Result<Vec<Match>> {
    let mut np = Vec::new();
    for s in service_probes {
        if s.probe.probename == "NULL" {
            np = vec![s];
        }
    }
    if np.len() == 0 {
        return Err(CanNotFoundNullProbe::new().into());
    }

    let mut op = Vec::new();
    for s in service_probes {
        if s.probe.probename != "NULL" {
            op.push(s);
        }
    }
    if op.len() == 0 {
        return Err(CanNotFoundOtherProbes::new().into());
    }

    // If the port is TCP, Nmap starts by connecting to it.
    let dst_addr = SocketAddr::new(dst_addr, dst_port);
    match TcpStream::connect(dst_addr) {
        Ok(mut stream) => {
            stream.set_nonblocking(false)?;
            // Once the TCP connection is made, Nmap listens for roughly five seconds.
            let dur = Duration::from_secs(5);
            stream.set_read_timeout(Some(dur))?;

            //  If the connection succeeds and the port had been in the open|filtered state, it is changed to open.
            match status {
                TargetScanStatus::OpenOrFiltered => {
                    status = TargetScanStatus::Open;
                }
                _ => (),
            }

            let null_probe_ret = null_probe(&mut stream, np[0])?;
            if null_probe_ret.len() > 0 {
                return Ok(null_probe_ret);
            }

            let ret = continue_probe(&mut stream, dst_port, service_probes)?;
        }
        Err(e) => (), // do nothing
    }
    Ok(vec![])
}

fn udp_probe(
    dst_addr: IpAddr,
    dst_port: u16,
    mut status: TargetScanStatus,
    service_probes: &[ServiceProbe],
) -> Result<Vec<Match>> {
    let mut up = Vec::new();
    for s in service_probes {
        if s.probe.protocol == ProbesProtocol::Udp {
            up.push(s);
        }
    }
    if up.len() == 0 {
        return Err(CanNotFoundUdpProbes::new().into());
    }

    let random_port = random_port();
    let src_addr_str = match dst_addr {
        IpAddr::V4(_) => format!("0.0.0.0:{}", random_port),
        IpAddr::V6(_) => format!(":::{}", random_port),
    };
    let dst_addr_str = format!("{}:{}", dst_addr, dst_port);

    let dst_addr = SocketAddr::new(dst_addr, dst_port);
    let socket = UdpSocket::bind(src_addr_str)?;
    socket.connect(dst_addr_str)?;

    Ok(vec![])
}

pub fn vs_probe(
    dst_addr: IpAddr,
    dst_port: u16,
    mut status: TargetScanStatus,
) -> Result<Option<Vec<Match>>> {
    let start = Instant::now();
    let nsp_str = include_str!("../db/nmap-service-probes");
    let nsp_lines: Vec<String> = nsp_str.split("\n").map(|s| s.to_string()).collect();
    let exclude_ports = nsp_exclued_parser(&nsp_lines)?;
    let service_probes = nsp_parser(&nsp_lines)?;
    let duration = start.elapsed();
    println!("Time elapsed is: {:?}", duration);

    // Nmap checks to see if the port is one of the ports to be excluded.
    if exclude_ports.ports.contains(&dst_port)
        || exclude_ports.tcp_ports.contains(&dst_port)
        || exclude_ports.udp_ports.contains(&dst_port)
    {
        // do nothing here
        return Ok(None);
    }

    let _ = tcp_probe(dst_addr, dst_port, status, &service_probes)?;

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    #[test]
    fn test_vscan() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 72, 134));
        let port = 22;
        let protocol = ProbesProtocol::Tcp;
        let status = TargetScanStatus::Open;
        let ret = vs_probe(addr, port, status).unwrap();
    }
}
