use chrono::DateTime;
use chrono::Local;
use chrono::Utc;
use log::debug;
use pnet::datalink::MacAddr;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::mpsc::channel;
use std::thread::sleep;
use std::time::Duration;
use std::time::SystemTime;

use crate::errors::PistolErrors;
use crate::hop::ipv4_get_hops;
use crate::layers::layer3_ipv4_send;
use crate::layers::system_route;
use crate::layers::Layer3Match;
use crate::layers::Layer4MatchIcmp;
use crate::layers::Layer4MatchTcpUdp;
use crate::layers::LayersMatch;
use crate::os::OSInfo;
use crate::utils::get_threads_pool;
use crate::utils::random_port;
use crate::utils::random_port_multi;
use crate::IpCheckMethods;

use super::dbparser::NmapOSDB;
use super::operator::icmp_cd;
use super::operator::icmp_dfi;
use super::operator::tcp_a;
use super::operator::tcp_cc;
use super::operator::tcp_f;
use super::operator::tcp_gcd;
use super::operator::tcp_isr;
use super::operator::tcp_o;
use super::operator::tcp_ox;
use super::operator::tcp_q;
use super::operator::tcp_rd;
use super::operator::tcp_s;
use super::operator::tcp_sp;
use super::operator::tcp_ss;
use super::operator::tcp_ti_ci_ii;
use super::operator::tcp_ts;
use super::operator::tcp_udp_df;
use super::operator::tcp_udp_icmp_r;
use super::operator::tcp_udp_icmp_t;
use super::operator::tcp_udp_icmp_tg;
use super::operator::tcp_w;
use super::operator::tcp_wx;
use super::operator::udp_ipl;
use super::operator::udp_rid;
use super::operator::udp_ripck;
use super::operator::udp_ripl;
use super::operator::udp_ruck;
use super::operator::udp_rud;
use super::operator::udp_un;
use super::packet;
use super::rr::AllPacketRR;
use super::rr::RequestAndResponse;
use super::rr::ECNRR;
use super::rr::IERR;
use super::rr::SEQRR;
use super::rr::TXRR;
use super::rr::U1RR;

// EXAMPLE
// SCAN(V=5.05BETA1%D=8/23%OT=22%CT=1%CU=42341%PV=N%DS=0%DC=L%G=Y%TM=4A91CB90%P=i686-pc-linux-gnu)
// SEQ(SP=C9%GCD=1%ISR=CF%TI=Z%CI=Z%II=I%TS=A)
// OPS(O1=M400CST11NW5%O2=M400CST11NW5%O3=M400CNNT11NW5%O4=M400CST11NW5%O5=M400CST11NW5%O6=M400CST11)
// WIN(W1=8000%W2=8000%W3=8000%W4=8000%W5=8000%W6=8000)
// ECN(R=Y%DF=Y%T=40%W=8018%O=M400CNNSNW5%CC=N%Q=)
// T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
// T2(R=N)
// T3(R=Y%DF=Y%T=40%W=8000%S=O%A=S+%F=AS%O=M400CST11NW5%RD=0%Q=)
// T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
// T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
// T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
// T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
// U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
// IE(R=Y%DFI=N%T=40%CD=S)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetFingerprint {
    pub scan: String,
    pub seqx: SEQX,
    pub opsx: OPSX,
    pub winx: WINX,
    pub ecnx: ECNX,
    pub t1x: TXX,
    pub t2x: TXX,
    pub t3x: TXX,
    pub t4x: TXX,
    pub t5x: TXX,
    pub t6x: TXX,
    pub t7x: TXX,
    pub u1x: U1X,
    pub iex: IEX,
}

impl fmt::Display for TargetFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = format!("{}", self.scan);
        let seqx_str = format!("\n{}", self.seqx);
        let opsx_str = format!("\n{}", self.opsx);
        let winx_str = format!("\n{}", self.winx);
        let ecnx_str = format!("\n{}", self.ecnx);
        let t1x_str = format!("\n{}", self.t1x);
        let t2x_str = format!("\n{}", self.t2x);
        let t3x_str = format!("\n{}", self.t3x);
        let t4x_str = format!("\n{}", self.t4x);
        let t5x_str = format!("\n{}", self.t5x);
        let t6x_str = format!("\n{}", self.t6x);
        let t7x_str = format!("\n{}", self.t7x);
        let u1x_str = format!("\n{}", self.u1x);
        let iex_str = format!("\n{}", self.iex);
        output += &seqx_str;
        output += &opsx_str;
        output += &winx_str;
        output += &ecnx_str;
        output += &t1x_str;
        output += &t2x_str;
        output += &t3x_str;
        output += &t4x_str;
        output += &t5x_str;
        output += &t6x_str;
        output += &t7x_str;
        output += &u1x_str;
        output += &iex_str;
        write!(f, "{}", output)
    }
}

impl TargetFingerprint {
    pub fn nmap_format(&self) -> String {
        let interval = 72;
        let mut ret = String::new();
        let mut i = 0;
        let fingerprint = format!("{}", self);
        for ch in fingerprint.chars() {
            if i % interval == 0 {
                ret += "\nOS:"
            }
            if ch != '\n' {
                ret += &format!("{}", ch);
                i += 1;
            }
        }
        ret.trim().to_string()
    }
}

pub fn get_scan_line(
    dst_mac: Option<MacAddr>,
    dst_open_tcp_port: u16,
    dst_closed_tcp_port: u16,
    dst_closed_udp_port: u16,
    dst_addr: IpAddr,
    hops: u8,
    good_results: bool,
) -> String {
    // Nmap version number (V).
    let v = "PISTOL";
    // Date of scan (D) in the form month/day.
    let now: DateTime<Local> = Local::now();
    let date = format!("{}", now.format("%-m/%-d"));
    // Private IP space (PV) is Y if the target is on the 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16 private networks (RFC 1918).
    // Otherwise it is N.
    // Network distance (DS) is the network hop distance from the target. It is 0 if the target is localhost, 1 if directly connected on an ethernet network, or the exact distance if discovered by Nmap.
    // If the distance is unknown, this test is omitted.
    // The distance calculation method (DC) indicates how the network distance (DS) was calculated.
    // It can take on these values:
    // L for localhost (DS=0);
    // D for a direct subnet connection (DS=1);
    // I for a TTL calculation based on an ICMP response to the U1 OS detection probe;
    // and T for a count of traceroute hops (I don't particularly understand how this sentence is implemented).
    // This test exists because it is possible for the ICMP TTL calculation to be incorrect when intermediate machines change the TTL;
    // it distinguishes between a host that is truly directly connected and what may be just a miscalculation.
    let (pv, ds, dc) = if dst_addr.is_loopback() {
        ("Y", 0, "L")
    } else if !dst_addr.is_global_x() {
        ("Y", 1, "D")
    } else {
        ("N", hops, "I")
    };
    // Good results (G) is Y if conditions and results seem good enough to submit this fingerprint to Nmap.Org.
    // It is N otherwise. Unless you force them by enabling debugging (-d) or extreme verbosity (-vv), G=N fingerprints aren't printed by Nmap.
    let g = if good_results { "Y" } else { "N" };
    // Target MAC prefix (M) is the first six hex digits of the target MAC address, which correspond to the vendor name.
    // Leading zeros are not included. This field is omitted unless the target is on the same ethernet network (DS=1).
    let m = if ds == 1 {
        let mut dst_mac_vec: [u8; 6] = dst_mac.unwrap().octets();
        let mut dst_mac_str = String::new();
        for m in &mut dst_mac_vec[0..3] {
            dst_mac_str = format!("{}{:X}", dst_mac_str, m);
        }
        dst_mac_str
    } else {
        "".to_string()
    };
    // The OS scan time (TM) is provided in Unix time_t format (in hexadecimal).
    let now: DateTime<Utc> = Utc::now();
    let tm = format!("{:X}", now.timestamp());
    // The platform Nmap was compiled for is given in the P field.
    let p = "RUST";

    // SCAN(V=5.05BETA1%D=8/23%OT=22%CT=1%CU=42341%PV=N%DS=0%DC=L%G=Y%TM=4A91CB90%P=i686-pc-linux-gnu)
    let info_str = match dst_addr {
        IpAddr::V4(_) => {
            let info_str = if m.len() > 0 {
                format!("SCAN(V={v}%D={date}%OT={dst_open_tcp_port}%CT={dst_closed_tcp_port}%CU={dst_closed_udp_port}PV={pv}%DS={ds}%DC={dc}%G={g}%M={m}%TM={tm}%P={p})", )
            } else {
                format!("SCAN(V={v}%D={date}%OT={dst_open_tcp_port}%CT={dst_closed_tcp_port}%CU={dst_closed_udp_port}PV={pv}%DS={ds}%DC={dc}%G={g}%TM={tm}%P={p})", )
            };
            info_str
        }
        IpAddr::V6(_) => {
            let info_str = if m.len() > 0 {
                format!("SCAN(V={v}%E=6%D={date}%OT={dst_open_tcp_port}%CT={dst_closed_tcp_port}%CU={dst_closed_udp_port}PV={pv}%DS={ds}%DC={dc}%G={g}%M={m}%TM={tm}%P={p})", )
            } else {
                format!("SCAN(V={v}%E=6%D={date}%OT={dst_open_tcp_port}%CT={dst_closed_tcp_port}%CU={dst_closed_udp_port}PV={pv}%DS={ds}%DC={dc}%G={g}%TM={tm}%P={p})", )
            };
            info_str
        }
    };
    info_str
}

fn send_seq_probes(
    src_ipv4: Ipv4Addr,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_open_port: u16,
    timeout: Duration,
) -> Result<SEQRR, PistolErrors> {
    // 6 packets with 6 threads
    let pool = get_threads_pool(6);
    let (tx, rx) = channel();

    let src_ports = match src_port {
        Some(s) => vec![s; 6],
        None => random_port_multi(6),
    };

    let buff_1 = packet::seq_packet_1_layer3(src_ipv4, src_ports[0], dst_ipv4, dst_open_port)?;
    let buff_2 = packet::seq_packet_2_layer3(src_ipv4, src_ports[1], dst_ipv4, dst_open_port)?;
    let buff_3 = packet::seq_packet_3_layer3(src_ipv4, src_ports[2], dst_ipv4, dst_open_port)?;
    let buff_4 = packet::seq_packet_4_layer3(src_ipv4, src_ports[3], dst_ipv4, dst_open_port)?;
    let buff_5 = packet::seq_packet_5_layer3(src_ipv4, src_ports[4], dst_ipv4, dst_open_port)?;
    let buff_6 = packet::seq_packet_6_layer3(src_ipv4, src_ports[5], dst_ipv4, dst_open_port)?;
    let buffs = vec![buff_1, buff_2, buff_3, buff_4, buff_5, buff_6];
    // let buffs = vec![buff_4];

    let start = SystemTime::now();
    let mut i = 0;
    for buff in buffs {
        let src_port = src_ports[i];
        let layer3 = Layer3Match {
            layer2: None,
            src_addr: Some(dst_ipv4.into()),
            dst_addr: Some(src_ipv4.into()),
        };
        let layer4_tcp_udp = Layer4MatchTcpUdp {
            layer3: Some(layer3),
            src_port: Some(dst_open_port),
            dst_port: Some(src_port),
        };
        let layers_match = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp);

        let tx = tx.clone();
        pool.execute(move || {
            let ret = layer3_ipv4_send(src_ipv4, dst_ipv4, &buff, vec![layers_match], timeout);
            match tx.send((i, buff.to_vec(), ret)) {
                _ => (),
            }
        });
        // the probes are sent exactly 100 milliseconds apart so the total time taken is 500 ms
        sleep(Duration::from_millis(100));
        i += 1;
    }

    let mut seq1 = None;
    let mut seq2 = None;
    let mut seq3 = None;
    let mut seq4 = None;
    let mut seq5 = None;
    let mut seq6 = None;

    let iter = rx.into_iter().take(6);
    for (i, request, ret) in iter {
        let response = match ret? {
            (Some(r), _rtt) => r,
            (_, _) => vec![],
        };
        let rr = Some(RequestAndResponse { request, response });
        match i {
            0 => seq1 = rr,
            1 => seq2 = rr,
            2 => seq3 = rr,
            3 => seq4 = rr,
            4 => seq5 = rr,
            5 => seq6 = rr,
            _ => (),
        }
    }
    let elapsed = start.elapsed()?.as_secs_f64();

    let seqrr = SEQRR {
        seq1: seq1.unwrap(),
        seq2: seq2.unwrap(),
        seq3: seq3.unwrap(),
        seq4: seq4.unwrap(),
        seq5: seq5.unwrap(),
        seq6: seq6.unwrap(),
        elapsed,
    };

    Ok(seqrr)
}

fn send_ie_probes(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    timeout: Duration,
) -> Result<IERR, PistolErrors> {
    let (tx, rx) = channel();

    let mut rng = rand::thread_rng();
    let id_1 = rng.gen();
    // and the ICMP request ID and sequence numbers are incremented by one from the previous query values
    let id_2 = id_1 + 1;
    let buff_1 = packet::ie_packet_1_layer3(src_ipv4, dst_ipv4, id_1)?;
    let buff_2 = packet::ie_packet_2_layer3(src_ipv4, dst_ipv4, id_2)?;
    let buffs = vec![buff_1, buff_2];

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_icmp = Layer4MatchIcmp {
        layer3: Some(layer3),
        types: None,
        codes: None,
    };
    let layers_match = LayersMatch::Layer4MatchIcmp(layer4_icmp);

    let mut i = 0;
    for buff in buffs {
        i += 1;
        let tx = tx.clone();
        // For those that do not require time, process them in order.
        // Prevent the previous request from receiving response from the later request.
        // ICMPV6 is a stateless protocol, we cannot accurately know the response for each request.
        let ret = layer3_ipv4_send(src_ipv4, dst_ipv4, &buff, vec![layers_match], timeout);
        match tx.send((i, buff.to_vec(), ret)) {
            _ => (),
        }
    }

    let mut ie1 = None;
    let mut ie2 = None;

    let iter = rx.into_iter().take(2);
    for (i, request, ret) in iter {
        let response = match ret? {
            (Some(r), _rtt) => r,
            (_, _) => vec![],
        };
        let rr = Some(RequestAndResponse { request, response });
        match i {
            1 => {
                ie1 = rr;
            }
            2 => {
                ie2 = rr;
            }
            _ => (),
        }
    }

    let ie = IERR {
        ie1: ie1.unwrap(),
        ie2: ie2.unwrap(),
    };
    Ok(ie)
}

fn send_ecn_probe(
    src_ipv4: Ipv4Addr,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_open_port: u16,
    timeout: Duration,
) -> Result<ECNRR, PistolErrors> {
    let src_port = match src_port {
        Some(s) => s,
        None => random_port(),
    };

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_open_port),
        dst_port: Some(src_port),
    };
    let layers_match = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp);

    let buff = packet::ecn_packet_layer3(src_ipv4, src_port, dst_ipv4, dst_open_port)?;
    // For those that do not require time, process them in order.
    // Prevent the previous request from receiving response from the later request.
    // ICMPV6 is a stateless protocol, we cannot accurately know the response for each request.
    let ret = layer3_ipv4_send(src_ipv4, dst_ipv4, &buff, vec![layers_match], timeout);

    let response = match ret? {
        (Some(r), _rtt) => r,
        (_, _) => vec![],
    };
    let rr = RequestAndResponse {
        request: buff,
        response,
    };

    let ecn = ECNRR { ecn: rr };
    Ok(ecn)
}

fn send_tx_probes(
    src_ipv4: Ipv4Addr,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_open_port: u16,
    dst_closed_port: u16,
    timeout: Duration,
) -> Result<TXRR, PistolErrors> {
    // 6 packets with 6 threads
    let pool = get_threads_pool(6);
    let (tx, rx) = channel();
    let src_ports = match src_port {
        Some(s) => vec![s; 6],
        None => random_port_multi(6),
    };

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_tcp_udp_1 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_open_port),
        dst_port: Some(src_ports[0]),
    };
    let layer4_tcp_udp_2 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_open_port),
        dst_port: Some(src_ports[1]),
    };
    let layer4_tcp_udp_3 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_open_port),
        dst_port: Some(src_ports[2]),
    };
    let layer4_tcp_udp_4 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_closed_port),
        dst_port: Some(src_ports[3]),
    };
    let layer4_tcp_udp_5 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_closed_port),
        dst_port: Some(src_ports[4]),
    };
    let layer4_tcp_udp_6 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_closed_port),
        dst_port: Some(src_ports[5]),
    };
    let layers_match_1 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_1);
    let layers_match_2 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_2);
    let layers_match_3 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_3);
    let layers_match_4 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_4);
    let layers_match_5 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_5);
    let layers_match_6 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_6);
    let ms = vec![
        layers_match_1,
        layers_match_2,
        layers_match_3,
        layers_match_4,
        layers_match_5,
        layers_match_6,
    ];

    // T2 sends a TCP null (no flags set) packet with the IP DF bit set and a window field of 128 to an open port.
    let buff_2 = packet::t2_packet_layer3(src_ipv4, src_ports[0], dst_ipv4, dst_open_port)?;
    // T3 sends a TCP packet with the SYN, FIN, URG, and PSH flags set and a window field of 256 to an open port. The IP DF bit is not set.
    let buff_3 = packet::t3_packet_layer3(src_ipv4, src_ports[1], dst_ipv4, dst_open_port)?;
    // T4 sends a TCP ACK packet with IP DF and a window field of 1024 to an open port.
    let buff_4 = packet::t4_packet_layer3(src_ipv4, src_ports[2], dst_ipv4, dst_open_port)?;
    // T5 sends a TCP SYN packet without IP DF and a window field of 31337 to a closed port.
    let buff_5 = packet::t5_packet_layer3(src_ipv4, src_ports[3], dst_ipv4, dst_closed_port)?;
    // T6 sends a TCP ACK packet with IP DF and a window field of 32768 to a closed port.
    let buff_6 = packet::t6_packet_layer3(src_ipv4, src_ports[4], dst_ipv4, dst_closed_port)?;
    // T7 sends a TCP packet with the FIN, PSH, and URG flags set and a window field of 65535 to a closed port. The IP DF bit is not set.
    let buff_7 = packet::t7_packet_layer3(src_ipv4, src_ports[5], dst_ipv4, dst_closed_port)?;
    let buffs = vec![buff_2, buff_3, buff_4, buff_5, buff_6, buff_7];
    // let buffs = vec![buff_5];

    let mut i = 0;
    for buff in buffs {
        let tx = tx.clone();
        let m = ms[i];
        pool.execute(move || {
            let ret = layer3_ipv4_send(src_ipv4, dst_ipv4, &buff, vec![m], timeout);
            match tx.send((i, buff.to_vec(), ret)) {
                _ => (),
            }
        });
        i += 1;
    }

    let mut t2 = None;
    let mut t3 = None;
    let mut t4 = None;
    let mut t5 = None;
    let mut t6 = None;
    let mut t7 = None;

    let iter = rx.into_iter().take(6);
    for (i, request, ret) in iter {
        let response = match ret? {
            (Some(r), _rtt) => r,
            (_, _) => vec![],
        };
        let rr = Some(RequestAndResponse { request, response });
        match i {
            0 => t2 = rr,
            1 => t3 = rr,
            2 => t4 = rr,
            3 => t5 = rr,
            4 => t6 = rr,
            5 => t7 = rr,
            _ => (),
        }
    }

    let txrr = TXRR {
        t2: t2.unwrap(),
        t3: t3.unwrap(),
        t4: t4.unwrap(),
        t5: t5.unwrap(),
        t6: t6.unwrap(),
        t7: t7.unwrap(),
    };

    Ok(txrr)
}

fn send_u1_probe(
    src_ipv4: Ipv4Addr,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_closed_port: u16, //should be an closed port
    timeout: Duration,
) -> Result<U1RR, PistolErrors> {
    let src_port = match src_port {
        Some(s) => s,
        None => random_port(),
    };

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv4.into()),
        dst_addr: Some(src_ipv4.into()),
    };
    let layer4_icmp = Layer4MatchIcmp {
        layer3: Some(layer3),
        types: None,
        codes: None,
    };
    let layers_match = LayersMatch::Layer4MatchIcmp(layer4_icmp);

    let buff = packet::udp_packet_layer3(src_ipv4, src_port, dst_ipv4, dst_closed_port)?;
    // For those that do not require time, process them in order.
    // Prevent the previous request from receiving response from the later request.
    // ICMPV6 is a stateless protocol, we cannot accurately know the response for each request.
    let ret = layer3_ipv4_send(src_ipv4, dst_ipv4, &buff, vec![layers_match], timeout)?;

    let response = match ret {
        (Some(r), _rtt) => r,
        (_, _) => vec![],
    };
    let rr = RequestAndResponse {
        request: buff,
        response,
    };

    let u1 = U1RR { u1: rr };
    Ok(u1)
}

fn send_all_probes(
    src_ipv4: Ipv4Addr,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_open_tcp_port: u16,
    dst_closed_tcp_port: u16,
    dst_closed_udp_port: u16,
    timeout: Duration,
) -> Result<AllPacketRR, PistolErrors> {
    let seq = send_seq_probes(src_ipv4, src_port, dst_ipv4, dst_open_tcp_port, timeout)?;
    let ie = send_ie_probes(src_ipv4, dst_ipv4, timeout)?;
    let ecn = send_ecn_probe(src_ipv4, src_port, dst_ipv4, dst_open_tcp_port, timeout)?;
    let tx = send_tx_probes(
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_open_tcp_port,
        dst_closed_tcp_port,
        timeout,
    )?;
    let u1 = send_u1_probe(src_ipv4, src_port, dst_ipv4, dst_closed_udp_port, timeout)?;

    let ap = AllPacketRR {
        seq,
        ie,
        ecn,
        tx,
        u1,
    };

    Ok(ap)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SEQX {
    // SP, GCD, ISR, TI, CI, II, SS, and TS.
    pub sp: u32,
    pub gcd: u32,
    pub isr: u32,
    pub ti: String,
    pub ci: String,
    pub ii: String,
    pub ss: String,
    pub ts: String,
    // Fit the db file.
    pub r: String,
}

impl fmt::Display for SEQX {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.r.as_str() {
            "Y" => {
                // Do not show R if R == Y.
                let mut output =
                    format!("SEQ(SP={:X}%GCD={:X}%ISR={:X}", self.sp, self.gcd, self.isr);
                if self.ti.len() > 0 {
                    let ti_str = format!("%TI={}", self.ti);
                    output += &ti_str;
                }
                if self.ci.len() > 0 {
                    let ci_str = format!("%CI={}", self.ci);
                    output += &ci_str;
                }
                if self.ii.len() > 0 {
                    let ii_str = format!("%II={}", self.ii);
                    output += &ii_str;
                }
                if self.ss.len() > 0 {
                    let ss_str = format!("%SS={}", self.ss);
                    output += &ss_str;
                }
                if self.ts.len() > 0 {
                    let ts_str = format!("%TS={}", self.ts);
                    output += &ts_str;
                }
                output += ")";
                write!(f, "{}", output)
            }
            _ => {
                let output = format!("SEQ(R={})", self.r);
                write!(f, "{}", output)
            }
        }
    }
}

pub fn seq_fingerprint(ap: &AllPacketRR) -> Result<SEQX, PistolErrors> {
    let rynum = |rvec: Vec<String>| -> usize {
        let mut num = 0;
        for r in rvec {
            if r == "Y" {
                num += 1;
            }
        }
        num
    };
    let r1 = tcp_udp_icmp_r(&ap.seq.seq1.response)?;
    let r2 = tcp_udp_icmp_r(&ap.seq.seq2.response)?;
    let r3 = tcp_udp_icmp_r(&ap.seq.seq3.response)?;
    let r4 = tcp_udp_icmp_r(&ap.seq.seq4.response)?;
    let r5 = tcp_udp_icmp_r(&ap.seq.seq5.response)?;
    let r6 = tcp_udp_icmp_r(&ap.seq.seq6.response)?;
    let rvec = vec![r1, r2, r3, r4, r5, r6];
    let num = rynum(rvec);

    // At least four responses should be returned.
    let (r, sp, gcd, isr, ti, ci, ii, ss, ts) = if num >= 4 {
        let (gcd, diff) = tcp_gcd(&ap.seq)?; // None mean error
        let elapsed = ap.seq.elapsed / 6.0;
        let (isr, seq_rates) = tcp_isr(diff, elapsed as f32)?;
        let sp = tcp_sp(seq_rates, gcd)?;
        let (ti, ci, ii) = tcp_ti_ci_ii(&ap.seq, &ap.tx, &ap.ie)?;
        let ss = tcp_ss(&ap.seq, &ap.ie, &ti, &ii)?;
        let ts = tcp_ts(&ap.seq)?;
        let r = String::from("Y");
        (r, sp, gcd, isr, ti, ci, ii, ss, ts)
    } else {
        let r = String::from("N");
        let gcd = 0;
        let isr = 0;
        let sp = 0;
        let ti = String::new();
        let ci = String::new();
        let ii = String::new();
        let ss = String::new();
        let ts = String::new();
        (r, sp, gcd, isr, ti, ci, ii, ss, ts)
    };
    Ok(SEQX {
        sp,
        gcd,
        isr,
        ti,
        ci,
        ii,
        ss,
        ts,
        r,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OPSX {
    pub o1: String,
    pub o2: String,
    pub o3: String,
    pub o4: String,
    pub o5: String,
    pub o6: String,
    // Fit the db file.
    pub r: String,
}

impl fmt::Display for OPSX {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.r.as_str() {
            "Y" => {
                let mut first_elem = true;
                let mut output = String::from("OPS(");
                if self.o1.len() > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("O1={}", self.o1)
                    } else {
                        format!("%O1={}", self.o1)
                    };
                    output += &ox_str;
                }
                if self.o2.len() > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("O2={}", self.o2)
                    } else {
                        format!("%O2={}", self.o2)
                    };
                    output += &ox_str;
                }
                if self.o3.len() > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("O3={}", self.o3)
                    } else {
                        format!("%O3={}", self.o3)
                    };
                    output += &ox_str;
                }
                if self.o4.len() > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("O4={}", self.o4)
                    } else {
                        format!("%O4={}", self.o4)
                    };
                    output += &ox_str;
                }
                if self.o5.len() > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("O5={}", self.o5)
                    } else {
                        format!("%O5={}", self.o5)
                    };
                    output += &ox_str;
                }
                if self.o6.len() > 0 {
                    let ox_str = if first_elem {
                        // first_elem = false;
                        format!("O6={}", self.o6)
                    } else {
                        format!("%O6={}", self.o6)
                    };
                    output += &ox_str;
                }
                output += ")";
                write!(f, "{}", output)
            }
            _ => {
                let output = format!("OPS(R={})", self.r);
                write!(f, "{}", output)
            }
        }
    }
}

pub fn ops_fingerprint(ap: &AllPacketRR) -> Result<OPSX, PistolErrors> {
    let rops = |rvec: Vec<String>| -> bool {
        let mut flag = true;
        for r in rvec {
            if r == "N" {
                flag = false;
            }
        }
        flag
    };
    let r1 = tcp_udp_icmp_r(&ap.seq.seq1.response)?;
    let r2 = tcp_udp_icmp_r(&ap.seq.seq2.response)?;
    let r3 = tcp_udp_icmp_r(&ap.seq.seq3.response)?;
    let r4 = tcp_udp_icmp_r(&ap.seq.seq4.response)?;
    let r5 = tcp_udp_icmp_r(&ap.seq.seq5.response)?;
    let r6 = tcp_udp_icmp_r(&ap.seq.seq6.response)?;
    let rvec = vec![r1, r2, r3, r4, r5, r6];
    // println!("{:?}", rvec);
    let flag = rops(rvec);
    let r = if flag {
        String::from("Y")
    } else {
        String::from("N")
    };

    let (o1, o2, o3, o4, o5, o6) = tcp_ox(&ap.seq)?;

    Ok(OPSX {
        o1,
        o2,
        o3,
        o4,
        o5,
        o6,
        r,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WINX {
    pub w1: u16,
    pub w2: u16,
    pub w3: u16,
    pub w4: u16,
    pub w5: u16,
    pub w6: u16,
    // Fit.
    pub r: String,
}

impl fmt::Display for WINX {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.r.as_str() {
            "Y" => {
                let mut first_elem = true;
                let mut output = String::from("WIN(");
                if self.w1 > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("W1={:X}", self.w1)
                    } else {
                        format!("%W1={:X}", self.w1)
                    };
                    output += &ox_str;
                }
                if self.w2 > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("W2={:X}", self.w2)
                    } else {
                        format!("%W2={:X}", self.w2)
                    };
                    output += &ox_str;
                }
                if self.w3 > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("W3={:X}", self.w3)
                    } else {
                        format!("%W3={:X}", self.w3)
                    };
                    output += &ox_str;
                }
                if self.w4 > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("W4={:X}", self.w4)
                    } else {
                        format!("%W4={:X}", self.w4)
                    };
                    output += &ox_str;
                }
                if self.w5 > 0 {
                    let ox_str = if first_elem {
                        first_elem = false;
                        format!("W5={:X}", self.w5)
                    } else {
                        format!("%W5={:X}", self.w5)
                    };
                    output += &ox_str;
                }
                if self.w6 > 0 {
                    let ox_str = if first_elem {
                        // first_elem = false;
                        format!("W6={:X}", self.w6)
                    } else {
                        format!("%W6={:X}", self.w6)
                    };
                    output += &ox_str;
                }
                output += ")";
                write!(f, "{}", output)
            }
            _ => {
                let output = format!("WIN(R={})", self.r);
                write!(f, "{}", output)
            }
        }
    }
}

pub fn win_fingerprint(ap: &AllPacketRR) -> Result<WINX, PistolErrors> {
    let rwin = |rvec: Vec<String>| -> bool {
        let mut flag = true;
        for r in rvec {
            if r == "N" {
                flag = false;
            }
        }
        flag
    };
    let r1 = tcp_udp_icmp_r(&ap.seq.seq1.response)?;
    let r2 = tcp_udp_icmp_r(&ap.seq.seq2.response)?;
    let r3 = tcp_udp_icmp_r(&ap.seq.seq3.response)?;
    let r4 = tcp_udp_icmp_r(&ap.seq.seq4.response)?;
    let r5 = tcp_udp_icmp_r(&ap.seq.seq5.response)?;
    let r6 = tcp_udp_icmp_r(&ap.seq.seq6.response)?;
    let rvec = vec![r1, r2, r3, r4, r5, r6];
    let flag = rwin(rvec);
    let r = if flag {
        String::from("Y")
    } else {
        String::from("N")
    };

    let (w1, w2, w3, w4, w5, w6) = tcp_wx(&ap.seq)?;
    Ok(WINX {
        w1,
        w2,
        w3,
        w4,
        w5,
        w6,
        r,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECNX {
    // R, DF, T, TG, W, O, CC, and Q tests.
    pub r: String,
    pub df: String,
    pub t: u16,
    pub tg: u8,
    pub w: u16,
    pub o: String,
    pub cc: String,
    pub q: String,
}

impl fmt::Display for ECNX {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.r.as_str() {
            "Y" => {
                let mut first_elem = true;
                let mut output = String::from("ECN(");
                if self.r.len() > 0 {
                    let r_str = if first_elem {
                        first_elem = false;
                        format!("R={}", self.r)
                    } else {
                        format!("%R={}", self.r)
                    };
                    output += &r_str;
                }
                if self.df.len() > 0 {
                    let df_str = if first_elem {
                        first_elem = false;
                        format!("DF={}", self.df)
                    } else {
                        format!("%DF={}", self.df)
                    };
                    output += &df_str;
                }
                if self.t > 0 {
                    let t_str = if first_elem {
                        first_elem = false;
                        format!("T={:X}", self.t)
                    } else {
                        format!("%T={:X}", self.t)
                    };
                    output += &t_str;
                } else if self.tg > 0 {
                    // This TTL guess field is not printed in a subject fingerprint if the actual TTL (T) value was discovered.
                    let tg_str = if first_elem {
                        first_elem = false;
                        format!("TG={:X}", self.tg)
                    } else {
                        format!("%TG={:X}", self.tg)
                    };
                    output += &tg_str;
                }
                if self.w > 0 {
                    let w_str = if first_elem {
                        first_elem = false;
                        format!("W={:X}", self.w)
                    } else {
                        format!("%W={:X}", self.w)
                    };
                    output += &w_str;
                }
                if self.o.len() > 0 {
                    let o_str = if first_elem {
                        first_elem = false;
                        format!("O={}", self.o)
                    } else {
                        format!("%O={}", self.o)
                    };
                    output += &o_str;
                }
                if self.cc.len() > 0 {
                    let cc_str = if first_elem {
                        first_elem = false;
                        format!("CC={}", self.cc)
                    } else {
                        format!("%CC={}", self.cc)
                    };
                    output += &cc_str;
                }
                let q_str = if first_elem {
                    // first_elem = false;
                    format!("Q={}", self.q)
                } else {
                    format!("%Q={}", self.q)
                };
                output += &q_str;
                output += ")";
                write!(f, "{}", output)
            }
            _ => {
                let output = format!("ECN(R={})", self.r);
                write!(f, "{}", output)
            }
        }
    }
}

pub fn ecn_fingerprint(ap: &AllPacketRR) -> Result<ECNX, PistolErrors> {
    let r = tcp_udp_icmp_r(&ap.ecn.ecn.response)?;
    let (df, t, tg, w, o, cc, q) = match r.as_str() {
        "Y" => {
            let df = tcp_udp_df(&ap.ecn.ecn.response)?;
            let t = tcp_udp_icmp_t(&ap.ecn.ecn.response, &ap.u1)?;
            let tg = tcp_udp_icmp_tg(&ap.ecn.ecn.response)?;
            let w = tcp_w(&ap.ecn.ecn.response)?;
            let o = tcp_o(&ap.ecn.ecn.response)?;
            let cc = tcp_cc(&ap.ecn.ecn.response)?;
            let q = tcp_q(&ap.ecn.ecn.response)?;

            (df, t, tg, w, o, cc, q)
        }
        _ => {
            //  If there is no reply, remaining fields for the test are omitted.
            let df = String::new();
            let t = 0;
            let tg = 0;
            let w = 0;
            let o = String::new();
            let cc = String::new();
            let q = String::new();
            (df, t, tg, w, o, cc, q)
        }
    };

    Ok(ECNX {
        r,
        df,
        t,
        tg,
        w,
        o,
        cc,
        q,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TXX {
    pub name: String,
    // R, DF, T, TG, W, S, A, F, O, RD, and Q tests.
    pub r: String,
    pub df: String,
    pub t: u16,
    pub tg: u8,
    pub w: u16,
    pub s: String,
    pub a: String,
    pub f: String,
    pub o: String,
    pub rd: u32, // CRC32
    pub q: String,
}

impl fmt::Display for TXX {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.r.as_str() {
            "Y" => {
                let mut first_elem = true;
                let mut output = format!("{}(", self.name);
                if self.r.len() > 0 {
                    let r_str = if first_elem {
                        first_elem = false;
                        format!("R={}", self.r)
                    } else {
                        format!("%R={}", self.r)
                    };
                    output += &r_str;
                }
                if self.df.len() > 0 {
                    let df_str = if first_elem {
                        first_elem = false;
                        format!("DF={}", self.df)
                    } else {
                        format!("%DF={}", self.df)
                    };
                    output += &df_str;
                }
                if self.t > 0 {
                    let t_str = if first_elem {
                        first_elem = false;
                        format!("T={:X}", self.t)
                    } else {
                        format!("%T={:X}", self.t)
                    };
                    output += &t_str;
                } else if self.tg > 0 {
                    // This TTL guess field is not printed in a subject fingerprint if the actual TTL (T) value was discovered.
                    let tg_str = if first_elem {
                        first_elem = false;
                        format!("TG={:X}", self.tg)
                    } else {
                        format!("%TG={:X}", self.tg)
                    };
                    output += &tg_str;
                }
                if self.name != "T1" {
                    let w_str = if first_elem {
                        first_elem = false;
                        format!("W={:X}", self.w)
                    } else {
                        format!("%W={:X}", self.w)
                    };
                    output += &w_str;
                }
                if self.s.len() > 0 {
                    let s_str = if first_elem {
                        first_elem = false;
                        format!("S={}", self.s)
                    } else {
                        format!("%S={}", self.s)
                    };
                    output += &s_str;
                }
                if self.a.len() > 0 {
                    let a_str = if first_elem {
                        first_elem = false;
                        format!("A={}", self.a)
                    } else {
                        format!("%A={}", self.a)
                    };
                    output += &a_str;
                }
                if self.f.len() > 0 {
                    let f_str = if first_elem {
                        first_elem = false;
                        format!("F={}", self.f)
                    } else {
                        format!("%F={}", self.f)
                    };
                    output += &f_str;
                }
                if self.name != "T1" {
                    let o_str = if first_elem {
                        first_elem = false;
                        format!("O={}", self.o)
                    } else {
                        format!("%O={}", self.o)
                    };
                    output += &o_str;
                }
                let rd_str = if first_elem {
                    first_elem = false;
                    format!("RD={:X}", self.rd)
                } else {
                    format!("%RD={:X}", self.rd)
                };
                output += &rd_str;
                let q_str = if first_elem {
                    // first_elem = false;
                    format!("Q={}", self.q)
                } else {
                    format!("%Q={}", self.q)
                };
                output += &q_str;
                output += ")";

                write!(f, "{}", output)
            }
            _ => {
                let output = format!("{}(R={})", self.name, self.r);
                write!(f, "{}", output)
            }
        }
    }
}

fn _tx_fingerprint(tx: &RequestAndResponse, u1rr: &U1RR, name: &str) -> Result<TXX, PistolErrors> {
    let r = tcp_udp_icmp_r(&tx.response)?;
    let (df, t, tg, w, s, a, f, o, rd, q) = match r.as_str() {
        "Y" => {
            let df = tcp_udp_df(&tx.response)?;
            let t = tcp_udp_icmp_t(&tx.response, u1rr)?;
            let tg = tcp_udp_icmp_tg(&tx.response)?;
            let w = tcp_w(&tx.response)?;
            let s = tcp_s(&tx.request, &tx.response)?;
            let a = tcp_a(&tx.request, &tx.response)?;
            let f = tcp_f(&tx.response)?;
            let o = tcp_o(&tx.response)?;
            let rd = tcp_rd(&tx.response)?;
            let q = tcp_q(&tx.response)?;

            (df, t, tg, w, s, a, f, o, rd, q)
        }
        _ => {
            let df = String::new();
            let t = 0;
            let tg = 0;
            let w = 0;
            let s = String::new();
            let a = String::new();
            let f = String::new();
            let o = String::new();
            let rd = 0;
            let q = String::new();
            (df, t, tg, w, s, a, f, o, rd, q)
        }
    };

    Ok(TXX {
        name: name.to_string(),
        r,
        df,
        t,
        tg,
        w,
        s,
        a,
        f,
        o,
        rd,
        q,
    })
}

pub fn tx_fingerprint(
    ap: &AllPacketRR,
) -> Result<(TXX, TXX, TXX, TXX, TXX, TXX, TXX), PistolErrors> {
    // The final line related to these probes, T1, contains various test values for packet #1.
    let t1 = _tx_fingerprint(&ap.seq.seq1, &ap.u1, "T1")?;
    let t2 = _tx_fingerprint(&ap.tx.t2, &ap.u1, "T2")?;
    let t3 = _tx_fingerprint(&ap.tx.t3, &ap.u1, "T3")?;
    let t4 = _tx_fingerprint(&ap.tx.t4, &ap.u1, "T4")?;
    let t5 = _tx_fingerprint(&ap.tx.t5, &ap.u1, "T5")?;
    let t6 = _tx_fingerprint(&ap.tx.t6, &ap.u1, "T6")?;
    let t7 = _tx_fingerprint(&ap.tx.t7, &ap.u1, "T7")?;

    Ok((t1, t2, t3, t4, t5, t6, t7))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct U1X {
    // R, DF, T, TG, IPL, UN, RIPL, RID, RIPCK, RUCK, and RUD tests.
    pub r: String,
    pub df: String,
    pub t: u16,
    pub tg: u8,
    pub ipl: usize,
    pub un: u32,
    pub ripl: String,
    pub rid: String,
    pub ripck: String,
    pub ruck: String,
    pub rud: String,
}

impl fmt::Display for U1X {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first_elem = true;
        let mut output = String::from("U1(");
        if self.r.len() > 0 {
            let r_str = if first_elem {
                first_elem = false;
                format!("R={}", self.r)
            } else {
                format!("%R={}", self.r)
            };
            output += &r_str;
        }
        if self.df.len() > 0 {
            let df_str = if first_elem {
                first_elem = false;
                format!("DF={}", self.df)
            } else {
                format!("%DF={}", self.df)
            };
            output += &df_str;
        }
        if self.t > 0 {
            let t_str = if first_elem {
                first_elem = false;
                format!("T={:X}", self.t)
            } else {
                format!("%T={:X}", self.t)
            };
            output += &t_str;
        } else if self.tg > 0 {
            // This TTL guess field is not printed in a subject fingerprint if the actual TTL (T) value was discovered.
            let tg_str = if first_elem {
                first_elem = false;
                format!("TG={}", self.tg)
            } else {
                format!("%TG={}", self.tg)
            };
            output += &tg_str;
        }
        if self.ipl > 0 {
            let ipl_str = if first_elem {
                first_elem = false;
                format!("IPL={:X}", self.ipl)
            } else {
                format!("%IPL={:X}", self.ipl)
            };
            output += &ipl_str;
        }
        let un_str = if first_elem {
            first_elem = false;
            format!("UN={:X}", self.un)
        } else {
            format!("%UN={:X}", self.un)
        };
        output += &un_str;
        if self.ripl.len() > 0 {
            let ripl_str = if first_elem {
                first_elem = false;
                format!("RIPL={}", self.ripl)
            } else {
                format!("%RIPL={}", self.ripl)
            };
            output += &ripl_str;
        }
        if self.rid.len() > 0 {
            let rid_str = if first_elem {
                first_elem = false;
                format!("RID={}", self.rid)
            } else {
                format!("%RID={}", self.rid)
            };
            output += &rid_str;
        }
        if self.ripck.len() > 0 {
            let ripck_str = if first_elem {
                first_elem = false;
                format!("RIPCK={}", self.ripck)
            } else {
                format!("%RIPCK={}", self.ripck)
            };
            output += &ripck_str;
        }
        if self.ruck.len() > 0 {
            let ruck_str = if first_elem {
                first_elem = false;
                format!("RUCK={}", self.ruck)
            } else {
                format!("%RUCK={}", self.ruck)
            };
            output += &ruck_str;
        }
        if self.rud.len() > 0 {
            let rud_str = if first_elem {
                // first_elem = false;
                format!("RUD={}", self.rud)
            } else {
                format!("%RUD={}", self.rud)
            };
            output += &rud_str;
        }
        output += ")";
        write!(f, "{}", output)
    }
}

pub fn u1_fingerprint(ap: &AllPacketRR) -> Result<U1X, PistolErrors> {
    let r = tcp_udp_icmp_r(&ap.u1.u1.response)?;
    let (df, t, tg, ipl, un, ripl, rid, ripck, ruck, rud) = match r.as_str() {
        "Y" => {
            let df = tcp_udp_df(&ap.u1.u1.response)?;
            let t = tcp_udp_icmp_t(&ap.u1.u1.response, &ap.u1)?;
            let tg = tcp_udp_icmp_tg(&ap.u1.u1.response)?;
            let ipl = udp_ipl(&ap.u1)?;
            let un = udp_un(&ap.u1)?;
            let ripl = udp_ripl(&ap.u1)?;
            let rid = udp_rid(&ap.u1)?;
            let ripck = udp_ripck(&ap.u1)?;
            let ruck = udp_ruck(&ap.u1)?;
            let rud = udp_rud(&ap.u1)?;

            (df, t, tg, ipl, un, ripl, rid, ripck, ruck, rud)
        }
        _ => {
            let df = String::new();
            let t = 0;
            let tg = 0;
            let ipl = 0;
            let un = 0;
            let ripl = String::new();
            let rid = String::new();
            let ripck = String::new();
            let ruck = String::new();
            let rud = String::new();

            (df, t, tg, ipl, un, ripl, rid, ripck, ruck, rud)
        }
    };

    Ok(U1X {
        r,
        df,
        t,
        tg,
        ipl,
        un,
        ripl,
        rid,
        ripck,
        ruck,
        rud,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IEX {
    // R, DFI, T, TG, and CD tests.
    pub r: String,
    pub dfi: String,
    pub t: u16,
    pub tg: u8,
    pub cd: String,
}

impl fmt::Display for IEX {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first_elem = true;
        let mut output = String::from("IE(");
        if self.r.len() > 0 {
            let r_str = if first_elem {
                first_elem = false;
                format!("R={}", self.r)
            } else {
                format!("%R={}", self.r)
            };
            output += &r_str;
        }
        if self.dfi.len() > 0 {
            let dfi_str = if first_elem {
                first_elem = false;
                format!("DFI={}", self.dfi)
            } else {
                format!("%DFI={}", self.dfi)
            };
            output += &dfi_str;
        }
        if self.t > 0 {
            let t_str = if first_elem {
                first_elem = false;
                format!("T={:X}", self.t)
            } else {
                format!("%T={:X}", self.t)
            };
            output += &t_str;
        } else if self.tg > 0 {
            // This TTL guess field is not printed in a subject fingerprint if the actual TTL (T) value was discovered.
            let tg_str = if first_elem {
                first_elem = false;
                format!("TG={}", self.tg)
            } else {
                format!("%TG={}", self.tg)
            };
            output += &tg_str;
        }
        if self.cd.len() > 0 {
            let cd_str = if first_elem {
                // first_elem = false;
                format!("CD={}", self.cd)
            } else {
                format!("%CD={}", self.cd)
            };
            output += &cd_str;
        }
        output += ")";
        write!(f, "{}", output)
    }
}

pub fn ie_fingerprint(ap: &AllPacketRR) -> Result<IEX, PistolErrors> {
    let r1 = tcp_udp_icmp_r(&ap.ie.ie1.response)?;
    let r2 = tcp_udp_icmp_r(&ap.ie.ie2.response)?;
    let (r, dfi, t, tg, cd) = if r1 == "Y" && r2 == "Y" {
        // The R value is only true (Y) if both probes elicit responses.
        let r = String::from("Y");
        let dfi = icmp_dfi(&ap.ie)?;
        let t = tcp_udp_icmp_t(&ap.ie.ie1.response, &ap.u1)?;
        let tg = tcp_udp_icmp_tg(&ap.ie.ie1.response)?;
        let cd = icmp_cd(&ap.ie)?;

        (r, dfi, t, tg, cd)
    } else {
        let r = String::from("N");
        let dfi = String::new();
        let t = 0;
        let tg = 0;
        let cd = String::new();

        (r, dfi, t, tg, cd)
    };

    Ok(IEX { r, dfi, t, tg, cd })
}

fn sort_pick(arr: &[OSInfo], top_k: usize) -> Vec<OSInfo> {
    /* Insertion Sort (O(n^2) ==! anyway) */
    let mut ret = Vec::new();
    let mut arr = arr.to_vec();

    fn pick(arr: &[OSInfo]) -> (OSInfo, Vec<OSInfo>) {
        let mut max_score = 0;
        let mut max_score_loc = 0;
        let mut arr = arr.to_vec();
        let mut i = 0;
        for a in &arr {
            if a.score > max_score {
                max_score = a.score;
                max_score_loc = i;
            }
            i += 1;
        }
        let ret = arr.remove(max_score_loc);
        (ret, arr)
    }

    let mut count = top_k;
    let mut last_score = 0;
    while count > 0 {
        let (max, new_arr) = pick(&arr);
        if max.score != last_score {
            count -= 1;
            last_score = max.score;
        }
        arr = new_arr;
        ret.push(max)
    }
    ret
}

pub fn threads_os_probe(
    src_ipv4: Ipv4Addr,
    src_port: Option<u16>,
    dst_ipv4: Ipv4Addr,
    dst_open_tcp_port: u16,
    dst_closed_tcp_port: u16,
    dst_closed_udp_port: u16,
    nmap_os_db: Vec<NmapOSDB>,
    top_k: usize,
    timeout: Duration,
) -> Result<(TargetFingerprint, Vec<OSInfo>), PistolErrors> {
    debug!("send all probes now");
    let ap = send_all_probes(
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_open_tcp_port,
        dst_closed_tcp_port,
        dst_closed_udp_port,
        timeout,
    )?;

    // let hops = Some(1);
    let (dst_mac, _interface) = system_route(src_ipv4, dst_ipv4, timeout)?;

    let good_results = true;
    // form get_scan_line function
    let need_cal_hops = |dst_addr: IpAddr| -> bool {
        if dst_addr.is_loopback() {
            false
        } else if !dst_addr.is_global_x() {
            false
        } else {
            true
        }
    };

    let scan = match need_cal_hops(dst_ipv4.into()) {
        true => {
            let hops = ipv4_get_hops(src_ipv4, dst_ipv4, timeout)?;
            get_scan_line(
                Some(dst_mac),
                dst_open_tcp_port,
                dst_closed_tcp_port,
                dst_closed_udp_port,
                dst_ipv4.into(),
                hops,
                good_results,
            )
        }
        false => {
            let hops = 0;
            get_scan_line(
                Some(dst_mac),
                dst_open_tcp_port,
                dst_closed_tcp_port,
                dst_closed_udp_port,
                dst_ipv4.into(),
                hops,
                good_results,
            )
        }
    };

    // Use seq to judge target is alive or not.
    let seqx = seq_fingerprint(&ap);
    match seqx {
        Ok(seqx) => {
            let opsx = ops_fingerprint(&ap)?;
            let winx = win_fingerprint(&ap)?;
            let ecnx = ecn_fingerprint(&ap)?;
            let (t1x, t2x, t3x, t4x, t5x, t6x, t7x) = tx_fingerprint(&ap)?;
            let u1x = u1_fingerprint(&ap)?;
            let iex = ie_fingerprint(&ap)?;

            debug!("generate the fingerprint");
            let target_fingerprint = TargetFingerprint {
                scan,
                seqx,
                opsx,
                winx,
                ecnx,
                t1x,
                t2x,
                t3x,
                t4x,
                t5x,
                t6x,
                t7x,
                u1x,
                iex,
            };

            let mut sort_vec = Vec::new();
            for db in &nmap_os_db {
                let (score, total) = db.check(&target_fingerprint);
                // println!("name: {}, score: {}", &db.name, score);
                let osinfo = OSInfo {
                    name: db.name.clone(),
                    class: db.class.clone(),
                    score,
                    total,
                    db: db.clone(),
                    cpe: db.cpe.clone(),
                };
                sort_vec.push(osinfo);
            }

            let detect_rets = sort_pick(&sort_vec, top_k);
            if detect_rets.len() > 0 {
                Ok((target_fingerprint, detect_rets))
            } else {
                Err(PistolErrors::OSDetectResultsNullError)
            }
        }
        Err(e) => Err(e),
    }
}
