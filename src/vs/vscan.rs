use anyhow::Result;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::time::Duration;
// use std::fs::File;

use super::dbparser::Match;
use super::dbparser::ProbesProtocol;
use super::dbparser::ServiceProbe;
use crate::utils::random_port;

const TCP_BUFF_SIZE: usize = 4096;
const UDP_BUFF_SIZE: usize = 4096;

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

    let mut ret = Vec::new();
    if recv_all_buff.len() > 0 {
        let recv_str = String::from_utf8_lossy(&recv_buff);
        // println!("{}", recv_str);
        for s in service_probes {
            if s.probe.probename == "NULL" {
                let r = s.check(&recv_str);
                ret.extend(r);
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
) -> Result<Vec<Match>> {
    let mut run_probe = |sp: &ServiceProbe| -> Result<Vec<Match>> {
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
            println!("{}", recv_str);
            let r = sp.check(&recv_str);
            Ok(r)
        } else {
            Ok(vec![])
        }
    };

    let mut ret = Vec::new();
    // TCP connections continue here if the NULL probe described above fails or soft-matches.
    for sp in service_probes {
        let rarity = match sp.rarity {
            Some(r) => r as usize,
            None => 0,
        };
        let mut ports: Vec<u16> = Vec::new();
        match &sp.ports {
            Some(p) => ports.extend(p),
            None => (),
        }
        match &sp.sslports {
            Some(s) => ports.extend(s),
            None => (),
        }
        if sp.probe.probename != "NULL"
            && sp.probe.protocol == ProbesProtocol::Tcp
            && intensity >= rarity
        {
            // Since the reality is that most ports are used by the service they are registered to in nmap-services,
            // every probe has a list of port numbers that are considered to be most effective.
            if only_tcp_recommended {
                if ports.contains(&dst_port) {
                    let r = run_probe(sp);
                    match r {
                        Ok(r) => ret.extend(r),
                        Err(e) => return Err(e.into()),
                    }
                }
            } else {
                let r = run_probe(sp);
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
) -> Result<Vec<Match>> {
    let run_probe = |socket: &UdpSocket, sp: &ServiceProbe| -> Result<Vec<Match>> {
        let mut ret = Vec::new();
        let probestring = sp.probe.probestring.as_bytes();
        socket.send(probestring)?;
        let mut recv_buff = [0u8; UDP_BUFF_SIZE];
        let n = match socket.recv(&mut recv_buff) {
            Ok(n) => n,
            Err(_) => 0,
        };
        if n > 0 {
            let recv_str = String::from_utf8_lossy(&recv_buff);
            let r = sp.check(&recv_str);
            ret.extend(r);
        }
        Ok(ret)
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

    let mut ret = Vec::new();
    for sp in service_probes {
        let rarity = match sp.rarity {
            Some(r) => r as usize,
            None => 0,
        };
        let mut ports: Vec<u16> = Vec::new();
        match &sp.ports {
            Some(p) => ports.extend(p),
            None => (),
        }
        if sp.probe.probename != "NULL"
            && sp.probe.protocol == ProbesProtocol::Udp
            && intensity >= rarity
        {
            // Since the reality is that most ports are used by the service they are registered to in nmap-services,
            // every probe has a list of port numbers that are considered to be most effective.
            if only_udp_recommended {
                if ports.contains(&dst_port) {
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

pub fn vs_probe(
    dst_addr: IpAddr,
    dst_port: u16,
    only_null_probe: bool,
    only_tcp_recommended: bool,
    only_udp_recommended: bool,
    intensity: usize,
    service_probes: &[ServiceProbe],
    timeout: Duration,
) -> Result<Vec<Match>> {
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
            if null_probe_ret.len() > 0 {
                Ok(null_probe_ret)
            } else {
                if !only_null_probe {
                    // Start TCP continue probe.
                    // println!("TCP CONTINUE PROBE");
                    let tcp_ret = tcp_continue_probe(
                        &mut stream,
                        dst_port,
                        only_tcp_recommended,
                        intensity,
                        service_probes,
                    )?;
                    if tcp_ret.len() > 0 {
                        Ok(tcp_ret)
                    } else {
                        // This point is where Nmap starts for UDP probes,
                        // and TCP connections continue here if the NULL probe described above fails or soft-matches.
                        let udp_ret = udp_probe(
                            dst_addr,
                            dst_port,
                            only_udp_recommended,
                            intensity,
                            service_probes,
                            timeout,
                        )?;
                        Ok(udp_ret)
                    }
                } else {
                    Ok(vec![])
                }
            }
        }
        Err(_) => Ok(vec![]), // ignore closed port here
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
    #[test]
    fn test_tls() {
        // use rustls;
        // use rustls::client::danger::HandshakeSignatureValid;
        // use rustls::client::danger::ServerCertVerified;
        // use rustls::client::danger::ServerCertVerifier;
        // use rustls::pki_types::CertificateDer;
        // use rustls::pki_types::ServerName;
        // use rustls::pki_types::UnixTime;
        // use rustls::DigitallySignedStruct;
        // use rustls::SignatureScheme;
        // use std::sync::Arc;
        // #[derive(Debug)]
        // struct SkipServerVerification;

        // impl SkipServerVerification {
        //     fn new() -> std::sync::Arc<Self> {
        //         std::sync::Arc::new(Self)
        //     }
        // }

        // impl ServerCertVerifier for SkipServerVerification {
        //     fn verify_server_cert(
        //         &self,
        //         _end_entity: &CertificateDer,
        //         _intermediates: &[CertificateDer],
        //         _server_name: &ServerName,
        //         _ocsp_response: &[u8],
        //         _now: UnixTime,
        //     ) -> Result<ServerCertVerified, rustls::Error> {
        //         Ok(ServerCertVerified::assertion())
        //     }
        //     fn verify_tls12_signature(
        //         &self,
        //         _message: &[u8],
        //         _cert: &CertificateDer,
        //         _dss: &DigitallySignedStruct,
        //     ) -> Result<HandshakeSignatureValid, rustls::Error> {
        //         Ok(HandshakeSignatureValid::assertion())
        //     }
        //     fn verify_tls13_signature(
        //         &self,
        //         _message: &[u8],
        //         _cert: &CertificateDer,
        //         _dss: &DigitallySignedStruct,
        //     ) -> Result<HandshakeSignatureValid, rustls::Error> {
        //         Ok(HandshakeSignatureValid::assertion())
        //     }
        //     fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        //         vec![]
        //     }
        // }

        // let config = rustls::ClientConfig::builder()
        //     .dangerous()
        //     .with_custom_certificate_verifier(SkipServerVerification::new())
        //     .with_no_client_auth();

        // let server_name = "www.rust-lang.org".try_into().unwrap();
        // let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        // let mut sock = TcpStream::connect("www.rust-lang.org:443").unwrap();
        // let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        // tls.write_all(
        //     concat!(
        //         "GET / HTTP/1.1\r\n",
        //         "Host: www.rust-lang.org\r\n",
        //         "Connection: close\r\n",
        //         "Accept-Encoding: identity\r\n",
        //         "\r\n"
        //     )
        //     .as_bytes(),
        // )
        // .unwrap();
        // let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
        // writeln!(
        //     &mut std::io::stderr(),
        //     "Current ciphersuite: {:?}",
        //     ciphersuite.suite()
        // )
        // .unwrap();
        // let mut plaintext = Vec::new();
        // tls.read_to_end(&mut plaintext).unwrap();
        // println!("{:?}", String::from_utf8_lossy(&plaintext));
    }
}
