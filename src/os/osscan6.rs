use log::debug;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use std::iter::zip;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::sync::mpsc::channel;
use std::thread::sleep;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use crate::errors::PistolErrors;
use crate::hop::ipv6_get_hops;
use crate::layers::layer3_ipv6_send;
use crate::layers::system_route6;
use crate::layers::Layer3Match;
use crate::layers::Layer4MatchIcmpv6;
use crate::layers::Layer4MatchTcpUdp;
use crate::layers::LayersMatch;
use crate::utils::get_threads_pool;
use crate::utils::random_port;
use crate::utils::random_port_sp;
use crate::IpCheckMethods;

use super::operator6::apply_scale;
use super::operator6::vectorize;
use super::osscan::get_scan_line;
use super::packet6;
use super::rr::AllPacketRR6;
use super::rr::RequestAndResponse;
use super::rr::IERR6;
use super::rr::NXRR6;
use super::rr::SEQRR6;
use super::rr::TECNRR6;
use super::rr::TXRR6;
use super::rr::U1RR6;
use super::Linear;
use super::OSInfo6;

// EXAMPLE
// SCAN(V=5.61TEST1%E=6%D=9/27%OT=22%CT=443%CU=42192%PV=N%DS=5%DC=T%G=Y%TM=4E82908D%P=x86_64-unknown-linux-gnu)
// S1(P=6000{4}28063cXX{32}0016c1b002bbd213c57562f5a01212e0f8880000020404c40402080a5be177f2ff{4}01030307%ST=0.021271%RT=0.041661)
// S2(P=6000{4}28063cXX{32}0016c1b108d7da47c57562f6a01212e0e9d20000020404c40402080a5be17856ff{4}01030307%ST=0.121251%RT=0.144586)
// S3(P=6000{4}28063cXX{32}0016c1b21029efebc57562f7a01212e0cf630000020404c40101080a5be178ceff{4}01030307%ST=0.221232%RT=0.268086)
// S4(P=6000{4}28063cXX{32}0016c1b31553d32dc57562f8a01212e0e3a40000020404c40402080a5be1791eff{4}01030307%ST=0.321237%RT=0.340261)
// S5(P=6000{4}28063cXX{32}0016c1b41ae90087c57562f9a01212e0b04f0000020404c40402080a5be17982ff{4}01030307%ST=0.421246%RT=0.441253)
// S6(P=6000{4}24063cXX{32}0016c1b5207baa83c57562fa901212e014690000020404c40402080a5be179e6ff{4}%ST=0.521245%RT=0.541755)
// IE1(P=6000{4}803a3cXX{32}810927cbabcd00{122}%ST=0.565533%RT=0.593505)
// U1(P=6000{3}01643a3cXX{32}0104be5300{4}6001234501341131XX{32}c1a9a4d0013482ff43{300}%ST=0.713832%RT=0.734263)
// TECN(P=6000{4}20063cXX{32}0016c1b62f0c74d8c57562fb80121310241c0000020404c40101040201030307%ST=0.763567%RT=0.784838)
// T2(P=6000{4}583a3cXX{32}0101ca5600{4}6001234500280632XX{32}c1b70016c57562fb85549cefa00000808c0d000003030a0102040109080aff{4}00{4}0402%ST=0.813012%RT=0.833344)
// T3(P=6000{4}583a3cXX{32}0101ca6000{4}60012 34500280628XX{32}c1b80016c57562fc2b8e3db7a02b0100445f000003030a0102040109080aff{4}00{4}0402%ST=0.863293%RT=0.881198)
// T4(P=6000{4}14063cXX{32}0016c1b93a67fc8a00{4}500400000c7c0000%ST=0.912394%RT=0.93247)
// T5(P=6000{4}14063cXX{32}01bbc1ba00{4}c57562ff5014000019430000%ST=0.96164%RT=0.983475)
// T6(P=6000{4}14063cXX{32}01bbc1bba9e336d500{4}50040000610e0000%ST=1.01164%RT=1.03554)
// T7(P=6000{4}583a3cXX{32}0101ca5800{4}6001234500280630XX{32}c1bc01bbc5756300095eb241a029ffffec59000003030f0102040109080aff{4}00{4}0402%ST=1.06173%RT=1.07961)
// EXTRA(FL=12345)

fn p_reduce(p: &str) -> String {
    let mut new_p = String::new();
    let mut count = 0;

    let p_chars: Vec<char> = p.chars().collect();
    // println!("1 {}", p);
    let mut i = 0;

    loop {
        // 000001
        if i + 1 > p_chars.len() {
            break;
        }

        let ch_i = p_chars[i];
        let ch_i_next = if i + 1 >= p_chars.len() {
            0 as char
        } else {
            p_chars[i + 1]
        };

        let ch_i_p_2 = if i + 2 >= p_chars.len() {
            0 as char
        } else {
            p_chars[i + 2]
        };
        let ch_i_next_p_2 = if i + 3 >= p_chars.len() {
            0 as char
        } else {
            p_chars[i + 3]
        };

        if ch_i == ch_i_p_2 && ch_i_next == ch_i_next_p_2 {
            count += 1;
            i += 2;
        } else {
            if count != 0 {
                i += 2;
            } else {
                i += 1;
            }
            if count == 0 {
                new_p += &format!("{}", ch_i);
            } else {
                new_p += &format!("{}{}{{{}}}", ch_i, ch_i_next, count + 1);
            }
            count = 0;
        }
    }

    // println!("2 {}", new_p.trim());
    new_p.trim().to_string()
}

fn p_as_nmap_format(input: &[u8]) -> String {
    let mut p = String::new();
    let ip_start = 16;
    let ip_end = ip_start + 32 * 2;

    for (i, b) in input.iter().enumerate() {
        if i >= ip_start && i < ip_end {
            // The characters XX are put in place of source and destination addresses,
            // which are private and anyway not useful for training the classifier.
            p += "X";
        } else {
            p += &format!("{:x}", b);
        }
    }

    let new_p = p_reduce(&p);
    new_p
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SEQX6 {
    pub name: String,
    pub rr: RequestAndResponse,
    pub st: Duration,
    pub rt: Duration,
}

impl fmt::Display for SEQX6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = if self.rr.response.len() > 0 {
            let output = format!(
                "{}(P={}%ST={:.6}%RT={:.6})",
                self.name,
                p_as_nmap_format(&self.rr.response),
                self.st.as_secs_f32(),
                self.rt.as_secs_f32()
            );
            output
        } else {
            String::new()
        };
        write!(f, "{}", output)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IEX6 {
    pub name: String,
    pub rr: RequestAndResponse,
    pub st: Duration,
    pub rt: Duration,
}

impl fmt::Display for IEX6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = if self.rr.response.len() > 0 {
            let output = format!(
                "{}(P={}%ST={:.6}%RT={:.6})",
                self.name,
                p_as_nmap_format(&self.rr.response),
                self.st.as_secs_f32(),
                self.rt.as_secs_f32()
            );
            output
        } else {
            String::new()
        };
        write!(f, "{}", output)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NX6 {
    pub name: String,
    pub rr: RequestAndResponse,
    pub st: Duration,
    pub rt: Duration,
}

impl fmt::Display for NX6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = if self.rr.response.len() > 0 {
            let output = format!(
                "{}(P={}%ST={:.6}%RT={:.6})",
                self.name,
                p_as_nmap_format(&self.rr.response),
                self.st.as_secs_f32(),
                self.rt.as_secs_f32()
            );
            output
        } else {
            String::new()
        };
        write!(f, "{}", output)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct U1X6 {
    pub rr: RequestAndResponse,
    pub st: Duration,
    pub rt: Duration,
}

impl fmt::Display for U1X6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = if self.rr.response.len() > 0 {
            let output = format!(
                "U1(P={}%ST={:.6}%RT={:.6})",
                p_as_nmap_format(&self.rr.response),
                self.st.as_secs_f32(),
                self.rt.as_secs_f32()
            );
            output
        } else {
            String::new()
        };
        write!(f, "{}", output)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TECNX6 {
    pub rr: RequestAndResponse,
    pub st: Duration,
    pub rt: Duration,
}

impl fmt::Display for TECNX6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = if self.rr.response.len() > 0 {
            let output = format!(
                "TECN(P={}%ST={:.6}%RT={:.6})",
                p_as_nmap_format(&self.rr.response),
                self.st.as_secs_f32(),
                self.rt.as_secs_f32()
            );
            output
        } else {
            String::new()
        };
        write!(f, "{}", output)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TX6 {
    pub name: String,
    pub rr: RequestAndResponse,
    pub st: Duration,
    pub rt: Duration,
}

impl fmt::Display for TX6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = if self.rr.response.len() > 0 {
            let output = format!(
                "{}(P={}%ST={:.6}%RT={:.6})",
                self.name,
                p_as_nmap_format(&self.rr.response),
                self.st.as_secs_f32(),
                self.rt.as_secs_f32()
            );
            output
        } else {
            String::new()
        };
        write!(f, "{}", output)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetFingerprint6 {
    // Some fields just for display.
    pub scan: String,
    pub s1x: SEQX6,
    pub s2x: SEQX6,
    pub s3x: SEQX6,
    pub s4x: SEQX6,
    pub s5x: SEQX6,
    pub s6x: SEQX6,
    pub ie1x: IEX6,
    pub ie2x: IEX6,
    pub ni: NX6,
    pub ns: NX6,
    pub u1x: U1X6,
    pub tecnx: TECNX6,
    pub t2x: TX6,
    pub t3x: TX6,
    pub t4x: TX6,
    pub t5x: TX6,
    pub t6x: TX6,
    pub t7x: TX6,
    pub extra: String,
    pub novelty: f64,
    pub status: bool,
}

impl TargetFingerprint6 {
    pub fn nmap_format(&self) -> String {
        let interval = 71; // from nmap format
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

impl fmt::Display for TargetFingerprint6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = format!("{}", self.scan);
        let s1x_str = format!("\n{}", self.s1x);
        let s2x_str = format!("\n{}", self.s2x);
        let s3x_str = format!("\n{}", self.s3x);
        let s4x_str = format!("\n{}", self.s4x);
        let s5x_str = format!("\n{}", self.s5x);
        let s6x_str = format!("\n{}", self.s6x);
        let u1x_str = format!("\n{}", self.u1x);
        let tecnx_str = format!("\n{}", self.tecnx);
        let t2x_str = format!("\n{}", self.t2x);
        let t3x_str = format!("\n{}", self.t3x);
        let t4x_str = format!("\n{}", self.t4x);
        let t5x_str = format!("\n{}", self.t5x);
        let t6x_str = format!("\n{}", self.t6x);
        let t7x_str = format!("\n{}", self.t7x);
        let extra_str = format!("\nEXTRA(FL={})", self.extra);
        if s1x_str.trim().len() > 0 {
            output += &s1x_str;
        }
        if s2x_str.trim().len() > 0 {
            output += &s2x_str;
        }
        if s3x_str.trim().len() > 0 {
            output += &s3x_str;
        }
        if s4x_str.trim().len() > 0 {
            output += &s4x_str;
        }
        if s5x_str.trim().len() > 0 {
            output += &s5x_str;
        }
        if s6x_str.trim().len() > 0 {
            output += &s6x_str;
        }
        if u1x_str.trim().len() > 0 {
            output += &u1x_str;
        }
        if tecnx_str.trim().len() > 0 {
            output += &tecnx_str;
        }
        if t2x_str.trim().len() > 0 {
            output += &t2x_str;
        }
        if t3x_str.trim().len() > 0 {
            output += &t3x_str;
        }
        if t4x_str.trim().len() > 0 {
            output += &t4x_str;
        }
        if t5x_str.trim().len() > 0 {
            output += &t5x_str;
        }
        if t6x_str.trim().len() > 0 {
            output += &t6x_str;
        }
        if t7x_str.trim().len() > 0 {
            output += &t7x_str;
        }
        if extra_str.trim().len() > 0 {
            output += &extra_str;
        }
        write!(f, "{}", output)
    }
}

fn send_seq_probes(
    src_ipv6: Ipv6Addr,
    dst_ipv6: Ipv6Addr,
    dst_open_port: u16,
    timeout: Duration,
    start_time: Instant,
) -> Result<SEQRR6, PistolErrors> {
    let pool = get_threads_pool(6);
    let (tx, rx) = channel();

    let src_port_start = random_port_sp(1000, 6540);
    let mut src_ports = Vec::new();
    for i in 0..6 {
        src_ports.push(src_port_start * 10 + i);
    }
    let buff_1 = packet6::seq_packet_1_layer3(src_ipv6, src_ports[0], dst_ipv6, dst_open_port)?;
    let buff_2 = packet6::seq_packet_2_layer3(src_ipv6, src_ports[1], dst_ipv6, dst_open_port)?;
    let buff_3 = packet6::seq_packet_3_layer3(src_ipv6, src_ports[2], dst_ipv6, dst_open_port)?;
    let buff_4 = packet6::seq_packet_4_layer3(src_ipv6, src_ports[3], dst_ipv6, dst_open_port)?;
    let buff_5 = packet6::seq_packet_5_layer3(src_ipv6, src_ports[4], dst_ipv6, dst_open_port)?;
    let buff_6 = packet6::seq_packet_6_layer3(src_ipv6, src_ports[5], dst_ipv6, dst_open_port)?;
    let buffs = vec![buff_1, buff_2, buff_3, buff_4, buff_5, buff_6];

    let start = SystemTime::now();
    for (i, buff) in buffs.into_iter().enumerate() {
        let src_port = src_ports[i];
        let layer3 = Layer3Match {
            layer2: None,
            src_addr: Some(dst_ipv6.into()),
            dst_addr: Some(src_ipv6.into()),
        };
        let layer4_tcp_udp = Layer4MatchTcpUdp {
            layer3: Some(layer3),
            src_port: Some(dst_open_port),
            dst_port: Some(src_port),
        };
        let layers_match = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp);

        let tx = tx.clone();
        pool.execute(move || {
            let st = start_time.elapsed();
            let ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![layers_match], timeout);
            let rt = start_time.elapsed();
            match tx.send((i, buff.to_vec(), ret, st, rt)) {
                _ => (),
            }
        });
        // the probes are sent exactly 100 milliseconds apart so the total time taken is 500 ms
        sleep(Duration::from_millis(100));
    }

    let mut seqs = HashMap::new();
    let mut sts = HashMap::new();
    let mut rts = HashMap::new();

    let iter = rx.into_iter().take(6);
    for (i, request, ret, st, rt) in iter {
        let response = match ret? {
            (Some(r), _rtt) => r,
            (_, _) => vec![],
        };
        let rr = RequestAndResponse { request, response };
        seqs.insert(i, rr);
        sts.insert(i, st);
        rts.insert(i, rt);
    }
    let elapsed = start.elapsed()?.as_secs_f64();

    let seq1 = seqs
        .get(&0)
        .map_or(RequestAndResponse::empty(), |x| x.clone());
    let seq2 = seqs
        .get(&1)
        .map_or(RequestAndResponse::empty(), |x| x.clone());
    let seq3 = seqs
        .get(&2)
        .map_or(RequestAndResponse::empty(), |x| x.clone());
    let seq4 = seqs
        .get(&3)
        .map_or(RequestAndResponse::empty(), |x| x.clone());
    let seq5 = seqs
        .get(&4)
        .map_or(RequestAndResponse::empty(), |x| x.clone());
    let seq6 = seqs
        .get(&5)
        .map_or(RequestAndResponse::empty(), |x| x.clone());

    let st1 = sts.get(&0).map_or(Duration::new(0, 0), |x| *x);
    let st2 = sts.get(&1).map_or(Duration::new(0, 0), |x| *x);
    let st3 = sts.get(&2).map_or(Duration::new(0, 0), |x| *x);
    let st4 = sts.get(&3).map_or(Duration::new(0, 0), |x| *x);
    let st5 = sts.get(&4).map_or(Duration::new(0, 0), |x| *x);
    let st6 = sts.get(&5).map_or(Duration::new(0, 0), |x| *x);

    let rt1 = rts.get(&0).map_or(Duration::new(0, 0), |x| *x);
    let rt2 = rts.get(&1).map_or(Duration::new(0, 0), |x| *x);
    let rt3 = rts.get(&2).map_or(Duration::new(0, 0), |x| *x);
    let rt4 = rts.get(&3).map_or(Duration::new(0, 0), |x| *x);
    let rt5 = rts.get(&4).map_or(Duration::new(0, 0), |x| *x);
    let rt6 = rts.get(&5).map_or(Duration::new(0, 0), |x| *x);

    let seqrr = SEQRR6 {
        seq1,
        seq2,
        seq3,
        seq4,
        seq5,
        seq6,
        elapsed,
        st1,
        rt1,
        st2,
        rt2,
        st3,
        rt3,
        st4,
        rt4,
        st5,
        rt5,
        st6,
        rt6,
    };

    Ok(seqrr)
}

fn send_ie_probes(
    src_ipv6: Ipv6Addr,
    dst_ipv6: Ipv6Addr,
    timeout: Duration,
    start_time: Instant,
) -> Result<IERR6, PistolErrors> {
    let (tx, rx) = channel();

    let buff_1 = packet6::ie_packet_1_layer3(src_ipv6, dst_ipv6).unwrap();
    let buff_2 = packet6::ie_packet_2_layer3(src_ipv6, dst_ipv6).unwrap();
    let buffs = vec![buff_1, buff_2];
    // let match_object = MatchObject::new_layer4_icmpv6_specific(Icmpv6Types::EchoReply, Icmpv6Code(0));
    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
    };
    let layers_match = LayersMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    for (i, buff) in buffs.into_iter().enumerate() {
        let tx = tx.clone();
        // For those that do not require time, process them in order.
        // Prevent the previous request from receiving response from the later request.
        // ICMPV6 is a stateless protocol, we cannot accurately know the response for each request.
        let st = start_time.elapsed();
        let ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![layers_match], timeout);
        let rt = start_time.elapsed();
        match tx.send((i, buff.to_vec(), ret, st, rt)) {
            _ => (),
        }
    }

    let mut ies = HashMap::new();
    let mut sts = HashMap::new();
    let mut rts = HashMap::new();

    let iter = rx.into_iter().take(2);
    for (i, request, ret, st, rt) in iter {
        let response = match ret? {
            (Some(r), _rtt) => r,
            (_, _) => vec![],
        };
        let rr = RequestAndResponse { request, response };
        ies.insert(i, rr);
        sts.insert(i, st);
        rts.insert(i, rt);
    }

    let ie1 = ies
        .get(&0)
        .map_or(RequestAndResponse::empty(), |x| x.clone());
    let ie2 = ies
        .get(&1)
        .map_or(RequestAndResponse::empty(), |x| x.clone());

    let st1 = sts.get(&0).map_or(Duration::new(0, 0), |x| *x);
    let st2 = sts.get(&1).map_or(Duration::new(0, 0), |x| *x);

    let rt1 = rts.get(&0).map_or(Duration::new(0, 0), |x| *x);
    let rt2 = rts.get(&1).map_or(Duration::new(0, 0), |x| *x);

    let ie = IERR6 {
        ie1,
        ie2,
        st1,
        rt1,
        st2,
        rt2,
    };
    Ok(ie)
}

fn send_nx_probes(
    src_ipv6: Ipv6Addr,
    dst_ipv6: Ipv6Addr,
    timeout: Duration,
    start_time: Instant,
) -> Result<NXRR6, PistolErrors> {
    let (tx, rx) = channel();

    let buff_1 = packet6::ni_packet_layer3(src_ipv6, dst_ipv6).unwrap();
    let buff_2 = packet6::ns_packet_layer3(src_ipv6, dst_ipv6).unwrap();
    let buffs = vec![buff_1, buff_2];
    // let buffs = vec![buff_1];
    // let buffs = vec![buff_2];
    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
    };
    let layers_match = LayersMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    for (i, buff) in buffs.into_iter().enumerate() {
        let tx = tx.clone();
        // For those that do not require time, process them in order.
        // Prevent the previous request from receiving response from the later request.
        // ICMPV6 is a stateless protocol, we cannot accurately know the response for each request.
        let st = start_time.elapsed();
        let ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![layers_match], timeout);
        let rt = start_time.elapsed();
        match tx.send((i, buff.to_vec(), ret, st, rt)) {
            _ => (),
        }
    }

    let mut nxs = HashMap::new();
    let mut sts = HashMap::new();
    let mut rts = HashMap::new();

    let iter = rx.into_iter().take(2);
    for (i, request, ret, st, rt) in iter {
        let response = match ret? {
            (Some(r), _rtt) => r,
            (_, _) => vec![],
        };
        let rr = RequestAndResponse { request, response };
        nxs.insert(i, rr);
        sts.insert(i, st);
        rts.insert(i, rt);
    }

    let ni = nxs
        .get(&0)
        .map_or(RequestAndResponse::empty(), |x| x.clone());
    let ns = nxs
        .get(&1)
        .map_or(RequestAndResponse::empty(), |x| x.clone());

    let sti = sts.get(&0).map_or(Duration::new(0, 0), |x| *x);
    let sts = sts.get(&1).map_or(Duration::new(0, 0), |x| *x);

    let rti = rts.get(&0).map_or(Duration::new(0, 0), |x| *x);
    let rts = rts.get(&1).map_or(Duration::new(0, 0), |x| *x);

    let ns = NXRR6 {
        ni,
        ns,
        sti,
        rti,
        sts,
        rts,
    };
    Ok(ns)
}

fn send_u1_probe(
    src_ipv6: Ipv6Addr,
    dst_ipv6: Ipv6Addr,
    dst_closed_port: u16, //should be an closed udp port
    timeout: Duration,
    start_time: Instant,
) -> Result<U1RR6, PistolErrors> {
    let src_port = random_port();
    let buff = packet6::udp_packet_layer3(src_ipv6, src_port, dst_ipv6, dst_closed_port)?;
    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_icmpv6 = Layer4MatchIcmpv6 {
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
    };
    let layers_match = LayersMatch::Layer4MatchIcmpv6(layer4_icmpv6);

    // For those that do not require time, process them in order.
    // Prevent the previous request from receiving response from the later request.
    // ICMPV6 is a stateless protocol, we cannot accurately know the response for each request.
    let st = start_time.elapsed();
    let ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![layers_match], timeout)?;
    let rt = start_time.elapsed();

    let response = match ret {
        (Some(r), _rtt) => r,
        (_, _) => vec![],
    };
    let rr = RequestAndResponse {
        request: buff,
        response,
    };

    let u1 = U1RR6 { u1: rr, st, rt };
    Ok(u1)
}

fn send_tecn_probe(
    src_ipv6: Ipv6Addr,
    dst_ipv6: Ipv6Addr,
    dst_open_port: u16,
    timeout: Duration,
    start_time: Instant,
) -> Result<TECNRR6, PistolErrors> {
    let src_port = random_port();

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_open_port),
        dst_port: Some(src_port),
    };
    let layers_match = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp);

    let buff = packet6::tecn_packet_layer3(src_ipv6, src_port, dst_ipv6, dst_open_port)?;
    // For those that do not require time, process them in order.
    // Prevent the previous request from receiving response from the later request.
    // ICMPV6 is a stateless protocol, we cannot accurately know the response for each request.
    let st = start_time.elapsed();
    let ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![layers_match], timeout)?;
    let rt = start_time.elapsed();

    let response = match ret {
        (Some(r), _rtt) => r,
        (_, _) => vec![],
    };
    let rr = RequestAndResponse {
        request: buff,
        response,
    };

    let tecn = TECNRR6 { tecn: rr, st, rt };
    Ok(tecn)
}

fn send_tx_probes(
    src_ipv6: Ipv6Addr,
    dst_ipv6: Ipv6Addr,
    dst_open_port: u16,
    dst_closed_port: u16,
    timeout: Duration,
    start_time: Instant,
) -> Result<TXRR6, PistolErrors> {
    let pool = get_threads_pool(6);
    let (tx, rx) = channel();

    let src_port_start = random_port_sp(1000, 6540);
    let mut src_ports = Vec::new();
    for i in 0..6 {
        src_ports.push(src_port_start * 10 + i);
    }

    let layer3 = Layer3Match {
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };

    let layer4_tcp_udp_2 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_open_port),
        dst_port: Some(src_ports[0]),
    };
    let layer4_tcp_udp_3 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_open_port),
        dst_port: Some(src_ports[1]),
    };
    let layer4_tcp_udp_4 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_open_port),
        dst_port: Some(src_ports[2]),
    };
    let layer4_tcp_udp_5 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_closed_port),
        dst_port: Some(src_ports[3]),
    };
    let layer4_tcp_udp_6 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_closed_port),
        dst_port: Some(src_ports[4]),
    };
    let layer4_tcp_udp_7 = Layer4MatchTcpUdp {
        layer3: Some(layer3),
        src_port: Some(dst_closed_port),
        dst_port: Some(src_ports[5]),
    };
    let layers_match_2 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_2);
    let layers_match_3 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_3);
    let layers_match_4 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_4);
    let layers_match_5 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_5);
    let layers_match_6 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_6);
    let layers_match_7 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_7);
    let ms = vec![
        layers_match_2,
        layers_match_3,
        layers_match_4,
        layers_match_5,
        layers_match_6,
        layers_match_7,
    ];

    let buff_2 = packet6::t2_packet_layer3(src_ipv6, src_ports[0], dst_ipv6, dst_open_port)?;
    let buff_3 = packet6::t3_packet_layer3(src_ipv6, src_ports[1], dst_ipv6, dst_open_port)?;
    let buff_4 = packet6::t4_packet_layer3(src_ipv6, src_ports[2], dst_ipv6, dst_open_port)?;
    let buff_5 = packet6::t5_packet_layer3(src_ipv6, src_ports[3], dst_ipv6, dst_closed_port)?;
    let buff_6 = packet6::t6_packet_layer3(src_ipv6, src_ports[4], dst_ipv6, dst_closed_port)?;
    let buff_7 = packet6::t7_packet_layer3(src_ipv6, src_ports[5], dst_ipv6, dst_closed_port)?;
    let buffs = vec![buff_2, buff_3, buff_4, buff_5, buff_6, buff_7];

    for (i, buff) in buffs.into_iter().enumerate() {
        let tx = tx.clone();
        let m = ms[i];
        pool.execute(move || {
            let st = start_time.elapsed();
            let ret = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![m], timeout);
            let rt = start_time.elapsed();
            match tx.send((i, buff.to_vec(), ret, st, rt)) {
                _ => (),
            }
        });
        sleep(Duration::from_millis(100));
    }

    let mut txs = HashMap::new();
    let mut sts = HashMap::new();
    let mut rts = HashMap::new();

    let iter = rx.into_iter().take(6);
    for (i, request, ret, st, rt) in iter {
        let response = match ret? {
            (Some(r), _rtt) => r,
            (_, _) => vec![],
        };
        let rr = RequestAndResponse { request, response };
        txs.insert(i, rr);
        sts.insert(i, st);
        rts.insert(i, rt);
    }

    let t2 = txs
        .get(&0)
        .map_or(RequestAndResponse::empty(), |x| x.clone());
    let t3 = txs
        .get(&1)
        .map_or(RequestAndResponse::empty(), |x| x.clone());
    let t4 = txs
        .get(&2)
        .map_or(RequestAndResponse::empty(), |x| x.clone());
    let t5 = txs
        .get(&3)
        .map_or(RequestAndResponse::empty(), |x| x.clone());
    let t6 = txs
        .get(&4)
        .map_or(RequestAndResponse::empty(), |x| x.clone());
    let t7 = txs
        .get(&5)
        .map_or(RequestAndResponse::empty(), |x| x.clone());

    let st2 = sts.get(&0).map_or(Duration::new(0, 0), |x| *x);
    let st3 = sts.get(&1).map_or(Duration::new(0, 0), |x| *x);
    let st4 = sts.get(&2).map_or(Duration::new(0, 0), |x| *x);
    let st5 = sts.get(&3).map_or(Duration::new(0, 0), |x| *x);
    let st6 = sts.get(&4).map_or(Duration::new(0, 0), |x| *x);
    let st7 = sts.get(&5).map_or(Duration::new(0, 0), |x| *x);

    let rt2 = rts.get(&0).map_or(Duration::new(0, 0), |x| *x);
    let rt3 = rts.get(&1).map_or(Duration::new(0, 0), |x| *x);
    let rt4 = rts.get(&2).map_or(Duration::new(0, 0), |x| *x);
    let rt5 = rts.get(&3).map_or(Duration::new(0, 0), |x| *x);
    let rt6 = rts.get(&4).map_or(Duration::new(0, 0), |x| *x);
    let rt7 = rts.get(&5).map_or(Duration::new(0, 0), |x| *x);

    let txrr = TXRR6 {
        t2,
        t3,
        t4,
        t5,
        t6,
        t7,
        st2,
        rt2,
        st3,
        rt3,
        st4,
        rt4,
        st5,
        rt5,
        st6,
        rt6,
        st7,
        rt7,
    };

    Ok(txrr)
}

fn send_all_probes(
    src_ipv6: Ipv6Addr,
    dst_ipv6: Ipv6Addr,
    dst_open_tcp_port: u16,
    dst_closed_tcp_port: u16,
    dst_closed_udp_port: u16,
    timeout: Duration,
) -> Result<AllPacketRR6, PistolErrors> {
    let start_time = Instant::now();
    let seq = send_seq_probes(src_ipv6, dst_ipv6, dst_open_tcp_port, timeout, start_time)?;
    let ie = send_ie_probes(src_ipv6, dst_ipv6, timeout, start_time)?;
    let nx = send_nx_probes(src_ipv6, dst_ipv6, timeout, start_time)?;
    let u1 = send_u1_probe(src_ipv6, dst_ipv6, dst_closed_udp_port, timeout, start_time)?;
    let tecn = send_tecn_probe(src_ipv6, dst_ipv6, dst_open_tcp_port, timeout, start_time)?;
    let tx = send_tx_probes(
        src_ipv6,
        dst_ipv6,
        dst_open_tcp_port,
        dst_closed_tcp_port,
        timeout,
        start_time,
    )?;

    let ap = AllPacketRR6 {
        seq,
        ie,
        nx,
        u1,
        tecn,
        tx,
    };

    Ok(ap)
}

fn predict_value(features: &[f64], wvec: &[Vec<f64>]) -> Vec<f64> {
    /*
       features [695]
       wvec [92, 695]

    */
    let vec_time = |x: &[f64], y: &[f64]| -> f64 {
        assert_eq!(x.len(), y.len());
        let mut sum = 0.0;
        for (a, b) in zip(x, y) {
            sum += a * b;
        }
        sum
    };

    let mut dec_value = [0f64; 92];
    for (idx, w) in wvec.iter().enumerate() {
        dec_value[idx] = vec_time(features, w);
    }

    let dec_value = dec_value.map(|x| 1.0 / (1.0 + (-x as f64).exp()));
    dec_value.to_vec()
}

fn novelty_of(features: &[f64], mean: &[f64], variance: &[f64]) -> f64 {
    assert_eq!(features.len(), 695);
    assert_eq!(mean.len(), 695);
    assert_eq!(variance.len(), 695);

    let mut sum = 0.0;
    for i in 0..695 {
        let d = features[i] - mean[i];
        let mut v = variance[i];
        if v == 0.0 {
            v = 0.01;
        }
        sum += (d * d) / v;
    }

    sum.sqrt()
}

fn isort(arr: &[OSInfo6]) -> Vec<OSInfo6> {
    fn pick(arr: &[OSInfo6]) -> (OSInfo6, Vec<OSInfo6>) {
        let mut max_score = 0.0;
        let mut max_score_loc = 0;
        let mut i = 0;
        let mut arr = arr.to_vec();
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

    let mut ret = Vec::new();
    let mut arr = arr.to_vec();

    while arr.len() > 0 {
        let (r, new_arr) = pick(&arr);
        arr = new_arr;
        ret.push(r);
    }
    ret
}

pub fn threads_os_probe6(
    src_ipv6: Ipv6Addr,
    dst_ipv6: Ipv6Addr,
    dst_open_tcp_port: u16,
    dst_closed_tcp_port: u16,
    dst_closed_udp_port: u16,
    top_k: usize,
    linear: Linear,
    timeout: Duration,
) -> Result<(TargetFingerprint6, Vec<OSInfo6>), PistolErrors> {
    debug!("send all probes now");
    let ap = send_all_probes(
        src_ipv6,
        dst_ipv6,
        dst_open_tcp_port,
        dst_closed_tcp_port,
        dst_closed_udp_port,
        timeout,
    )?;

    let (dst_mac, _interface) = system_route6(src_ipv6, dst_ipv6, timeout)?;

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

    let scan = match need_cal_hops(dst_ipv6.into()) {
        true => {
            let hops = ipv6_get_hops(src_ipv6, dst_ipv6, timeout)?;
            get_scan_line(
                Some(dst_mac),
                dst_open_tcp_port,
                dst_closed_tcp_port,
                dst_closed_udp_port,
                dst_ipv6.into(),
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
                dst_ipv6.into(),
                hops,
                good_results,
            )
        }
    };

    let features = vectorize(&ap)?;
    let features = apply_scale(&features, &linear.scale);
    let predict = predict_value(&features, &linear.w);

    let mut detect_rets = Vec::new();
    for (i, (name, score)) in zip(&linear.infolist, &predict).into_iter().enumerate() {
        let class = &linear.cpe[i].osclass;
        if class.len() > 0 {
            let class = class[0].join(" | ");
            let cpe = linear.cpe[i].cpe.join(" ");
            let dr = OSInfo6 {
                name: name.to_string(),
                class,
                cpe,
                score: *score,
                label: i,
            };
            detect_rets.push(dr);
        }
    }

    let detect_rets = isort(&detect_rets);
    let mut perfect_match = 1;
    for i in 1..36 {
        if detect_rets[i].score >= 0.9 * detect_rets[0].score {
            perfect_match += 1;
        }
    }

    // println!("{}", perfect_match);
    let label = detect_rets[0].label;
    let novelty = novelty_of(&features, &linear.mean[label], &linear.variance[label]);

    let status = if perfect_match == 1 {
        const FP_NOVELTY_THRESHOLD: f64 = 15.0;
        // println!("{}", novelty);
        if novelty < FP_NOVELTY_THRESHOLD {
            true
        } else {
            false
        }
    } else {
        false
    };

    let s1x = SEQX6 {
        name: String::from("S1"),
        rr: ap.seq.seq1,
        st: ap.seq.st1,
        rt: ap.seq.rt1,
    };
    let s2x = SEQX6 {
        name: String::from("S2"),
        rr: ap.seq.seq2,
        st: ap.seq.st2,
        rt: ap.seq.rt2,
    };
    let s3x = SEQX6 {
        name: String::from("S3"),
        rr: ap.seq.seq3,
        st: ap.seq.st3,
        rt: ap.seq.rt3,
    };
    let s4x = SEQX6 {
        name: String::from("S4"),
        rr: ap.seq.seq4,
        st: ap.seq.st4,
        rt: ap.seq.rt4,
    };
    let s5x = SEQX6 {
        name: String::from("S5"),
        rr: ap.seq.seq5,
        st: ap.seq.st5,
        rt: ap.seq.rt5,
    };
    let s6x = SEQX6 {
        name: String::from("S6"),
        rr: ap.seq.seq6,
        st: ap.seq.st6,
        rt: ap.seq.rt6,
    };
    let ie1x = IEX6 {
        name: String::from("IE1"),
        rr: ap.ie.ie1,
        st: ap.ie.st1,
        rt: ap.ie.rt1,
    };
    let ie2x = IEX6 {
        name: String::from("IE2"),
        rr: ap.ie.ie2,
        st: ap.ie.st2,
        rt: ap.ie.rt2,
    };
    let ni = NX6 {
        name: String::from("NI"),
        rr: ap.nx.ni,
        st: ap.nx.sti,
        rt: ap.nx.rti,
    };
    let ns = NX6 {
        name: String::from("NS"),
        rr: ap.nx.ns,
        st: ap.nx.sts,
        rt: ap.nx.rts,
    };
    let u1x = U1X6 {
        rr: ap.u1.u1,
        st: ap.u1.st,
        rt: ap.u1.rt,
    };
    let tecnx = TECNX6 {
        rr: ap.tecn.tecn,
        st: ap.tecn.st,
        rt: ap.tecn.rt,
    };
    let t2x = TX6 {
        name: String::from("T2"),
        rr: ap.tx.t2,
        st: ap.tx.st2,
        rt: ap.tx.rt2,
    };
    let t3x = TX6 {
        name: String::from("T3"),
        rr: ap.tx.t3,
        st: ap.tx.st3,
        rt: ap.tx.rt3,
    };
    let t4x = TX6 {
        name: String::from("T4"),
        rr: ap.tx.t4,
        st: ap.tx.st4,
        rt: ap.tx.rt4,
    };
    let t5x = TX6 {
        name: String::from("T5"),
        rr: ap.tx.t5,
        st: ap.tx.st5,
        rt: ap.tx.rt5,
    };
    let t6x = TX6 {
        name: String::from("T6"),
        rr: ap.tx.t6,
        st: ap.tx.st6,
        rt: ap.tx.rt6,
    };
    let t7x = TX6 {
        name: String::from("T7"),
        rr: ap.tx.t7,
        st: ap.tx.st7,
        rt: ap.tx.rt7,
    };

    let target_fingerprint = TargetFingerprint6 {
        scan,
        s1x,
        s2x,
        s3x,
        s4x,
        s5x,
        s6x,
        ie1x,
        ie2x,
        ni,
        ns,
        u1x,
        tecnx,
        t2x,
        t3x,
        t4x,
        t5x,
        t6x,
        t7x,
        extra: String::from("12345"), // IPv6 flow label
        novelty,
        status,
    };

    let ret = if status {
        let mut count = top_k;
        let mut last_score = 0.0;
        let mut ret = Vec::new();
        let mut iter = detect_rets.into_iter();
        while count > 0 {
            let r = match iter.next() {
                Some(r) => r,
                None => break,
            };
            if last_score != r.score {
                last_score = r.score;
                count -= 1;
            }
            ret.push(r);
        }
        ret
    } else {
        let ret = vec![];
        ret
    };
    Ok((target_fingerprint, ret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{utils::find_source_addr6, TEST_IPV6_LOCAL};
    #[test]
    fn test_something() {
        let p = "000XXXXXX";
        let ret = p_reduce(p);
        println!("{}", ret);

        let p = "0000XXXXXX";
        let ret = p_reduce(p);
        println!("{}", ret);

        let p = "0000XXXXXXX";
        let ret = p_reduce(p);
        println!("{}", ret);
    }
    #[test]
    fn test_send_tx() {
        let dst_ipv6 = TEST_IPV6_LOCAL;
        let src_ipv6 = find_source_addr6(None, dst_ipv6).unwrap().unwrap();
        let dst_open_port = 22;
        let dst_closed_port = 9876;

        let src_port_start = random_port_sp(1000, 6540);
        let mut src_ports = Vec::new();
        for i in 0..6 {
            src_ports.push(src_port_start * 10 + i);
        }
        println!("src_ports: {:?}", src_ports);

        let layer3 = Layer3Match {
            layer2: None,
            src_addr: Some(dst_ipv6.into()),
            dst_addr: Some(src_ipv6.into()),
        };

        let layer4_tcp_udp_2 = Layer4MatchTcpUdp {
            layer3: Some(layer3),
            src_port: Some(dst_open_port),
            dst_port: Some(src_ports[0]),
        };
        let layer4_tcp_udp_3 = Layer4MatchTcpUdp {
            layer3: Some(layer3),
            src_port: Some(dst_open_port),
            dst_port: Some(src_ports[1]),
        };
        let layer4_tcp_udp_4 = Layer4MatchTcpUdp {
            layer3: Some(layer3),
            src_port: Some(dst_open_port),
            dst_port: Some(src_ports[2]),
        };
        let layer4_tcp_udp_5 = Layer4MatchTcpUdp {
            layer3: Some(layer3),
            src_port: Some(dst_closed_port),
            dst_port: Some(src_ports[3]),
        };
        let layer4_tcp_udp_6 = Layer4MatchTcpUdp {
            layer3: Some(layer3),
            src_port: Some(dst_closed_port),
            dst_port: Some(src_ports[4]),
        };
        let layer4_tcp_udp_7 = Layer4MatchTcpUdp {
            layer3: Some(layer3),
            src_port: Some(dst_closed_port),
            dst_port: Some(src_ports[5]),
        };
        let layers_match_2 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_2);
        let layers_match_3 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_3);
        let layers_match_4 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_4);
        let layers_match_5 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_5);
        let layers_match_6 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_6);
        let layers_match_7 = LayersMatch::Layer4MatchTcpUdp(layer4_tcp_udp_7);
        let ms = vec![
            layers_match_2,
            layers_match_3,
            layers_match_4,
            layers_match_5,
            layers_match_6,
            layers_match_7,
        ];

        let buff_2 =
            packet6::t2_packet_layer3(src_ipv6, src_ports[0], dst_ipv6, dst_open_port).unwrap();
        let buff_3 =
            packet6::t3_packet_layer3(src_ipv6, src_ports[1], dst_ipv6, dst_open_port).unwrap();
        let buff_4 =
            packet6::t4_packet_layer3(src_ipv6, src_ports[2], dst_ipv6, dst_open_port).unwrap();
        let buff_5 =
            packet6::t5_packet_layer3(src_ipv6, src_ports[3], dst_ipv6, dst_closed_port).unwrap();
        let buff_6 =
            packet6::t6_packet_layer3(src_ipv6, src_ports[4], dst_ipv6, dst_closed_port).unwrap();
        let buff_7 =
            packet6::t7_packet_layer3(src_ipv6, src_ports[5], dst_ipv6, dst_closed_port).unwrap();
        let buffs = vec![buff_2, buff_3, buff_4, buff_5, buff_6, buff_7];

        let i = 0;
        let m = ms[i];
        let buff = buffs[i].clone();
        let timeout = Duration::new(3, 0);
        let (ret, _rtt) = layer3_ipv6_send(src_ipv6, dst_ipv6, &buff, vec![m], timeout).unwrap();
        println!("ret: {}", ret.unwrap().len());
    }
}
