use anyhow::Result;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;
// use std::fs::File;

use super::dbparser::{Match, ProbesProtocol, ServiceProbe};
use crate::utils::random_port;

const TCP_BUFF_SIZE: usize = 4096;
const UDP_BUFF_SIZE: usize = 4096;

fn format_send(data: &str) -> String {
    let new_data = data.replace("\\n", "\n");
    let new_data = new_data.replace("\\r", "\r");
    let new_data = new_data.replace("\\t", "\t");
    new_data
}

fn tcp_null_probe(
    stream: &mut TcpStream,
    service_probes: &[ServiceProbe],
) -> Result<Option<Match>> {
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
        let recv_str = String::from_utf8_lossy(&recv_buff);
        // println!("{}", recv_str);
        for s in service_probes {
            if s.probe.probename == "NULL" {
                let ret = s.check(&recv_str);
                return Ok(ret);
            }
        }
    }
    Ok(None)
}

fn tcp_continue_probe(
    stream: &mut TcpStream,
    dst_port: u16,
    only_tcp_recommended: bool,
    service_probes: &[ServiceProbe],
) -> Result<Option<Match>> {
    let mut run_probe = |sp: &ServiceProbe| -> Result<Option<Match>> {
        let probestring = format_send(&sp.probe.probestring);
        stream.write(probestring.as_bytes())?;
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
            let recv_str = String::from_utf8_lossy(&recv_all_buff);
            let ret = sp.check(&recv_str);
            Ok(ret)
        } else {
            Ok(None)
        }
    };

    // TCP connections continue here if the NULL probe described above fails or soft-matches.
    for sp in service_probes {
        if sp.probe.probename != "NULL" && sp.probe.protocol == ProbesProtocol::Tcp {
            match &sp.ports {
                Some(p) => {
                    // Since the reality is that most ports are used by the service they are registered to in nmap-services,
                    // every probe has a list of port numbers that are considered to be most effective.
                    if only_tcp_recommended {
                        if p.contains(&dst_port) {
                            let ret = run_probe(sp);
                            return ret;
                        }
                    } else {
                        let ret = run_probe(sp);
                        return ret;
                    }
                }
                None => {
                    if !only_tcp_recommended {
                        let ret = run_probe(sp);
                        return ret;
                    }
                }
            }
        }
    }
    Ok(None)
}

fn udp_probe(
    dst_addr: IpAddr,
    dst_port: u16,
    only_udp_recommanded: bool,
    service_probes: &[ServiceProbe],
    timeout: Duration,
) -> Result<Option<Match>> {
    let run_probe = |socket: UdpSocket, sp: &ServiceProbe| -> Result<Option<Match>> {
        let probestring = sp.probe.probestring.as_bytes();
        socket.send(probestring)?;
        let mut recv_buff = [0u8; UDP_BUFF_SIZE];
        let n = match socket.recv(&mut recv_buff) {
            Ok(n) => n,
            Err(_) => 0,
        };
        if n > 0 {
            let recv_str = String::from_utf8_lossy(&recv_buff);
            let ret = sp.check(&recv_str);
            match ret {
                Some(r) => return Ok(Some(r)),
                None => (),
            }
        }
        Ok(None)
    };

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

    for sp in service_probes {
        if sp.probe.probename != "NULL" && sp.probe.protocol == ProbesProtocol::Udp {
            match &sp.ports {
                Some(p) => {
                    // Since the reality is that most ports are used by the service they are registered to in nmap-services,
                    // every probe has a list of port numbers that are considered to be most effective.
                    if only_udp_recommanded {
                        if p.contains(&dst_port) {
                            let ret = run_probe(socket, sp);
                            return ret;
                        }
                    } else {
                        let ret = run_probe(socket, sp);
                        return ret;
                    }
                }
                None => {
                    if !only_udp_recommanded {
                        let ret = run_probe(socket, sp);
                        return ret;
                    }
                }
            }
        }
    }
    Ok(None)
}

pub fn vs_probe(
    dst_addr: IpAddr,
    dst_port: u16,
    only_null_probe: bool,
    only_tcp_recommended: bool,
    only_udp_recommended: bool,
    service_probes: &[ServiceProbe],
    timeout: Duration,
) -> Result<Option<Match>> {
    // If the port is TCP, Nmap starts by connecting to it.
    let tcp_dst_addr = SocketAddr::new(dst_addr, dst_port);
    match TcpStream::connect_timeout(&tcp_dst_addr, timeout) {
        Ok(mut stream) => {
            // println!("{}", tcp_dst_addr);
            // stream.set_nonblocking(false)?;
            // Once the TCP connection is made, Nmap listens for roughly five seconds.
            let five_seconds = Duration::from_secs(5);
            stream.set_read_timeout(Some(five_seconds))?;
            stream.set_write_timeout(Some(timeout))?;

            // If the connection succeeds and the port had been in the open|filtered state, it is changed to open.
            // Ignore this step here.
            let null_probe_ret = tcp_null_probe(&mut stream, service_probes)?;
            match null_probe_ret {
                Some(n) => return Ok(Some(n)),
                None => {
                    if !only_null_probe {
                        // Start TCP continue probe.
                        // println!("TCP CONTINUE PROBE");
                        let tcp_ret = tcp_continue_probe(
                            &mut stream,
                            dst_port,
                            only_tcp_recommended,
                            service_probes,
                        )?;
                        match tcp_ret {
                            Some(t) => return Ok(Some(t)),
                            None => {
                                // This point is where Nmap starts for UDP probes,
                                // and TCP connections continue here if the NULL probe described above fails or soft-matches.
                                let udp_ret = udp_probe(
                                    dst_addr,
                                    dst_port,
                                    only_udp_recommended,
                                    service_probes,
                                    timeout,
                                )?;
                                Ok(udp_ret)
                            }
                        }
                    } else {
                        Ok(None)
                    }
                }
            }
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    #[test]
    fn test_tcp_connect() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 51));
        let tcp_dst_addr = SocketAddr::new(addr, 22);
        let mut stream = TcpStream::connect(tcp_dst_addr).unwrap();
        let mut buff = [0u8; 4096];
        let n = stream.read(&mut buff).unwrap();
        println!("{}", n);
        let nstr = String::from_utf8_lossy(&buff);
        println!("{}", nstr);
    }
}
