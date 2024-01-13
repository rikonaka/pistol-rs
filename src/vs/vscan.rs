use anyhow::Result;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::mpsc::channel;
use std::time::Duration;
use std::time::Instant;

use super::dbparser::{nsp_exclued_parser, nsp_parser, Match, ProbesProtocol, ServiceProbe};
use crate::errors::{CanNotFoundNullTcpProbe, CanNotFoundOtherTcpProbes, CanNotFoundUdpProbes};
use crate::utils::{get_threads_pool, random_port};
use crate::TargetScanStatus;

const TCP_BUFF_SIZE: usize = 4096;
const UDP_BUFF_SIZE: usize = 4096;

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

fn tcp_null_probe(stream: &mut TcpStream, null_probe: &ServiceProbe) -> Result<Vec<Match>> {
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

fn tcp_continue_probe(
    stream: &mut TcpStream,
    dst_port: u16,
    service_probes: &[ServiceProbe],
) -> Result<Vec<Match>> {
    // TCP connections continue here if the NULL probe described above fails or soft-matches.
    for sp in service_probes {
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
    Ok(vec![])
}

fn start_probe(
    dst_addr: IpAddr,
    dst_port: u16,
    service_probes: &[ServiceProbe],
) -> Result<Vec<Match>> {
    let mut np = Vec::new();
    let mut op = Vec::new();
    let mut up = Vec::new();

    for s in service_probes {
        if s.probe.probename == "NULL" {
            np = vec![s.clone()];
        } else if s.probe.probename != "NULL" {
            if s.probe.protocol == ProbesProtocol::Tcp {
                op.push(s.clone());
            } else if s.probe.protocol == ProbesProtocol::Udp {
                up.push(s.clone());
            }
        }
    }
    if np.len() == 0 {
        return Err(CanNotFoundNullTcpProbe::new().into());
    } else if op.len() == 0 {
        return Err(CanNotFoundOtherTcpProbes::new().into());
    } else if up.len() == 0 {
        return Err(CanNotFoundUdpProbes::new().into());
    }

    // If the port is TCP, Nmap starts by connecting to it.
    let tcp_dst_addr = SocketAddr::new(dst_addr, dst_port);
    match TcpStream::connect(tcp_dst_addr) {
        Ok(mut stream) => {
            stream.set_nonblocking(false)?;
            // Once the TCP connection is made, Nmap listens for roughly five seconds.
            let dur = Duration::from_secs(5);
            stream.set_read_timeout(Some(dur))?;

            // If the connection succeeds and the port had been in the open|filtered state, it is changed to open.
            // Ignore here.

            let null_probe_ret = tcp_null_probe(&mut stream, &np[0])?;
            if null_probe_ret.len() > 0 {
                return Ok(null_probe_ret);
            }

            // Start UDP and TCP continue probe here with 2 threads.
            let pool = get_threads_pool(2);
            let (tx, rx) = channel();
            let tx1 = tx.clone();
            let tx2 = tx.clone();
            pool.execute(move || {
                let tcp_ret = tcp_continue_probe(&mut stream, dst_port, &op);
                match tx1.send(tcp_ret) {
                    _ => (),
                }
            });
            pool.execute(move || {
                let udp_ret = udp_probe(dst_addr, dst_port, &up);
                match tx2.send(udp_ret) {
                    _ => (),
                }
            });

            let mut ret = Vec::new();
            let iter = rx.into_iter().take(2);
            for i in iter {
                match i {
                    Ok(r) => ret.extend(r),
                    Err(e) => return Err(e),
                }
            }

            Ok(ret)
        }
        Err(e) => Err(e.into()), // do nothing
    }
}

fn udp_probe(
    dst_addr: IpAddr,
    dst_port: u16,
    service_probes: &[ServiceProbe],
) -> Result<Vec<Match>> {
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
    let dur = Duration::from_secs(5); // both 5 sec
    socket.set_read_timeout(Some(dur))?;
    socket.set_write_timeout(Some(dur))?;
    socket.connect(dst_addr)?;

    for sp in service_probes {
        let probestring = sp.probe.probestring.as_bytes();
        socket.send(probestring)?;
        let mut recv_buff = [0u8; UDP_BUFF_SIZE];
        let n = socket.recv(&mut recv_buff)?;
        if n > 0 {
            let recv_str = format_recv(&recv_buff);
            let ret = sp.check(&recv_str)?;
            if ret.len() > 0 {
                return Ok(ret);
            }
        }
    }

    Ok(vec![])
}

pub fn vs_probe(dst_addr: IpAddr, dst_port: u16) -> Result<Vec<Match>> {
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
        return Ok(vec![]); // do nothing here
    }

    let ret = start_probe(dst_addr, dst_port, &service_probes)?;
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    #[test]
    fn test_vscan() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 72, 134));
        let port = 22;
        let ret = vs_probe(addr, port).unwrap();
        println!("{:?}", ret);
    }
}
