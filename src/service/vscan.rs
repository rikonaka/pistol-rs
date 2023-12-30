use anyhow::Result;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use super::dbparser::{nsp_exclued_parser, nsp_parser, ProbesProtocol};
use crate::TargetScanStatus;

const TCP_BUFF_SIZE: usize = 1024;

#[derive(Debug, Clone, Copy)]
pub struct ServiceScanTarget {
    addr: IpAddr,
    port: u16,
    status: TargetScanStatus,
    protocol: ProbesProtocol,
}

pub fn vs_probe(targets: &[ServiceScanTarget]) -> Result<()> {
    let nsp_str = include_str!("../db/nmap-service-probes");
    let nsp_lines: Vec<String> = nsp_str.split("\n").map(|s| s.to_string()).collect();
    let exclude_ports = nsp_exclued_parser(&nsp_lines)?;
    let service_probes = nsp_parser(&nsp_lines)?;

    // Nmap checks to see if the port is one of the ports to be excluded.
    let mut new_target = Vec::new();
    for t in targets {
        if exclude_ports.ports.contains(&t.port)
            || exclude_ports.tcp_ports.contains(&t.port)
            || exclude_ports.udp_ports.contains(&t.port)
        {
            // do nothing here
        } else {
            new_target.push(*t);
        }
    }

    // println!("{}", new_target.len());
    for mut t in new_target {
        match t.protocol {
            ProbesProtocol::Tcp => {
                // If the port is TCP, Nmap starts by connecting to it.
                let dst_addr = SocketAddr::new(t.addr, t.port);
                match TcpStream::connect(dst_addr) {
                    Ok(mut stream) => {
                        match t.status {
                            TargetScanStatus::OpenOrFiltered => {
                                //  If the connection succeeds and the port had been in the open|filtered state, it is changed to open.
                                t.status = TargetScanStatus::Open;
                            }

                            _ => (),
                        }
                        stream.set_nonblocking(false)?;
                        // Once the TCP connection is made, Nmap listens for roughly five seconds.
                        let dur = Duration::from_secs(5);
                        stream.set_read_timeout(Some(dur))?;
                        let mut buff = [0u8; TCP_BUFF_SIZE];
                        // stream.write(&[1]);
                        let n = stream.read(&mut buff)?;
                        if n > 0 {
                            // let recv_str = String::from_utf8_lossy(&buff);
                            let mut recv_str = String::new();
                            for b in buff {
                                // ASCII printable characters 32-127
                                if b >= 32 && b < 127 {
                                    recv_str += &format!("{}", b as char);
                                } else if b == 0 {
                                    recv_str += "\0";
                                } else if b == 10 {
                                    recv_str += "\\n";
                                } else if b == 13 {
                                    recv_str += "\\r";
                                } else {
                                    let mut tmp = format!("{:x}", b);
                                    if tmp.len() < 2 {
                                        for _ in 0..(2 - tmp.len()) {
                                            tmp = format!("0{}", tmp);
                                        }
                                    }
                                    tmp = format!("\\x{}", tmp);
                                    recv_str += &tmp;
                                }
                            }
                            println!("[{}]", recv_str);
                            for sp in &service_probes {
                                if sp.probe.probename == "NULL" {
                                    let ret = sp.check(&recv_str)?;
                                    println!("{}", ret.len());
                                    for r in ret {
                                        println!("{}", r.service);
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => (),
                }
            }
            ProbesProtocol::Udp => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;
    use std::net::Ipv4Addr;
    #[test]
    fn test_vscan() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 72, 134));
        let port = 22;
        let protocol = ProbesProtocol::Tcp;
        let status = TargetScanStatus::Open;
        let target = ServiceScanTarget {
            addr,
            port,
            protocol,
            status,
        };
        let targets = vec![target];
        vs_probe(&targets).unwrap();
    }
    #[test]
    fn test_regex() {
        /*
        Note:
            { => \{
            [] => [.*?]
            \1 => .*?
            [ => \[
            ?= => .*?
            ?! => .*?
            ?<= => .*?
         */

        let t = r###"^220 FTP Server\[^[.*?]* \[([\w.-]+)\]\r\n214-The following commands are recognized \(\* =>'s unimplemented\)\.\r\n USER    PASS    ACCT\*   CWD     XCWD    CDUP    XCUP    SMNT\*   \r\n QUIT    REIN\*   PORT    PASV    TYPE    STRU\*   MODE\*   RETR    \r\n STOR    STOU\*   APPE    ALLO\*   REST    RNFR    RNTO    ABOR    \r\n DELE    MDTM    RMD     XRMD    MKD     XMKD    PWD     XPWD    \r\n SIZE    LIST    NLST    SITE    SYST    STAT    HELP    NOOP    \r\n214 Direct comments to "###;
        let _re = Regex::new(&t).unwrap();
    }
    #[test]
    fn test_regex_run() {
        let nsp_str = include_str!("../db/nmap-service-probes-test");
        let nsp_lines: Vec<String> = nsp_str.split("\n").map(|s| s.to_string()).collect();
        let service_probes = nsp_parser(&nsp_lines).unwrap();

        // let recv_str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.5\r\n";
        let recv_str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.5\r\n";
        // let t = r"^SSH-([\d.]+)-OpenSSH_([\w._-]+)[ -]\{1,2}Ubuntu[ -_]([^\r\n]+)\r?\n";
        let t = r"^SSH-([\d.]+)-OpenSSH_([\w._-]+)[ -]{1,2}Ubuntu[ -_]([^\r\n]+)\r?\n";
        let re = Regex::new(t).unwrap();
        println!(">>>> {}", re.is_match(recv_str));

        for sp in &service_probes {
            if sp.probe.probename == "NULL" {
                for m in &sp.matchs {
                    // println!("{}", m.pattern);
                    let re = Regex::new(&m.pattern).unwrap();
                    if re.is_match(&recv_str) {
                        println!("match");
                    }
                }
            }
        }
    }
}
