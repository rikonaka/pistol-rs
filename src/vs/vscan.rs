use anyhow::Result;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use super::dbparser::{Match, ServiceProbe};
use crate::utils::random_port;

const TCP_BUFF_SIZE: usize = 10240;
const _UDP_BUFF_SIZE: usize = 10240;

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

fn format_send(data: &str) -> String {
    let new_data = data.replace("\\n", "\n");
    let new_data = new_data.replace("\\r", "\r");
    let new_data = new_data.replace("\\t", "\t");
    new_data
}

fn tcp_null_probe(stream: &mut TcpStream, service_probes: &[ServiceProbe]) -> Result<Vec<Match>> {
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
        let recv_str = format_recv(&recv_buff);
        // println!("{}", recv_str);
        for s in service_probes {
            if s.probe.probename == "NULL" {
                let ret = s.check(&recv_str);
                return Ok(ret);
            }
        }
    }
    Ok(vec![])
}

fn tcp_continue_probe(
    stream: &mut TcpStream,
    dst_port: u16,
    service_probes: &[ServiceProbe],
) -> Result<Vec<Match>> {
    // TCP connections continue here if the NULL probe described above fails or soft-matches.
    for sp in service_probes {
        if sp.probe.probename != "NULL" {
            match &sp.ports {
                Some(p) => {
                    // Since the reality is that most ports are used by the service they are registered to in nmap-services,
                    // every probe has a list of port numbers that are considered to be most effective.
                    if p.contains(&dst_port) {
                        let probestring = format_send(&sp.probe.probestring);
                        println!("SEND {}", sp.probe.probestring);
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
                            println!("len: {}", recv_all_buff.len());
                            let recv_str = format_recv(&recv_all_buff);
                            let ret = sp.check(&recv_str);
                            if ret.len() > 0 {
                                println!("{}", ret[0].service);
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

fn _vs_probe_udp(
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
    let timeout = Duration::from_secs(1); // both 1 sec
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    socket.connect(dst_addr)?;

    for sp in service_probes {
        let probestring = sp.probe.probestring.as_bytes();
        socket.send(probestring)?;
        let mut recv_buff = [0u8; _UDP_BUFF_SIZE];
        let n = match socket.recv(&mut recv_buff) {
            Ok(n) => n,
            Err(_) => 0,
        };
        if n > 0 {
            let recv_str = format_recv(&recv_buff);
            let ret = sp.check(&recv_str);
            if ret.len() > 0 {
                return Ok(ret);
            }
        }
    }
    Ok(vec![])
}

pub fn vs_probe_tcp(
    dst_addr: IpAddr,
    dst_port: u16,
    service_probes: &[ServiceProbe],
    timeout: Duration,
) -> Result<Vec<Match>> {
    // If the port is TCP, Nmap starts by connecting to it.
    let tcp_dst_addr = SocketAddr::new(dst_addr, dst_port);
    match TcpStream::connect_timeout(&tcp_dst_addr, timeout) {
        Ok(mut stream) => {
            println!("{}", tcp_dst_addr);
            // stream.set_nonblocking(false)?;
            // Once the TCP connection is made, Nmap listens for roughly five seconds.
            let five_seconds = Duration::from_secs(5);
            let one_seconds = Duration::from_secs(1);
            stream.set_read_timeout(Some(five_seconds))?;
            stream.set_write_timeout(Some(one_seconds))?;

            // If the connection succeeds and the port had been in the open|filtered state, it is changed to open.
            // Ignore this step here.

            let null_probe_ret = tcp_null_probe(&mut stream, service_probes)?;
            if null_probe_ret.len() > 0 {
                println!("NULL PROBE");
                Ok(null_probe_ret)
            } else {
                // Start TCP continue probe.
                println!("TCP CONTINUE PROBE");
                let tcp_ret = tcp_continue_probe(&mut stream, dst_port, service_probes)?;
                Ok(tcp_ret)
            }
        }
        Err(e) => Err(e.into()), // do nothing
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
        let nstr = format_recv(&buff);
        println!("{}", nstr);
    }
}
