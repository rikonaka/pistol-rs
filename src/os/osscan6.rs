use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmpv6::Icmpv6Type;
use std::collections::HashMap;
use std::fmt;
use std::iter::zip;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::time::Instant;
use tracing::debug;
use tracing::warn;

use crate::NetInfo;
use crate::ask_runner;
use crate::error::PistolError;
use crate::get_response;
use crate::layer::Layer3Filter;
use crate::layer::Layer4FilterIcmpv6;
use crate::layer::Layer4FilterTcpUdp;
use crate::layer::PacketFilter;
use crate::os::Linear;
use crate::os::OsInfo6;
use crate::os::operator6::apply_scale;
use crate::os::operator6::vectorize;
use crate::os::osscan::get_scan_line;
use crate::os::packet6;
use crate::os::rr::AllPacketRR6;
use crate::os::rr::IERR6;
use crate::os::rr::NXRR6;
use crate::os::rr::RequestResponse;
use crate::os::rr::SEQRR6;
use crate::os::rr::TECNRR6;
use crate::os::rr::TXRR6;
use crate::os::rr::U1RR6;
use crate::trace::icmp_trace;
use crate::utils::random_port;
use crate::utils::random_port_range;

const PROBE_MAX_RETIRIES: usize = 5; // nmap default

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

#[derive(Debug, Clone)]
pub struct SEQX6 {
    pub name: String,
    pub rr: RequestResponse,
    pub st: Duration,
    pub rt: Duration,
}

impl Default for SEQX6 {
    fn default() -> Self {
        Self {
            name: String::new(),
            rr: RequestResponse::default(),
            st: Duration::new(0, 0),
            rt: Duration::new(0, 0),
        }
    }
}

impl fmt::Display for SEQX6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = if self.rr.response.len() > 0 {
            let output = format!(
                "{}(P={}%ST={:.6}%RT={:.6})",
                self.name,
                p_as_nmap_format(&self.rr.response),
                self.st.as_secs_f64(),
                self.rt.as_secs_f64()
            );
            output
        } else {
            String::new()
        };
        write!(f, "{}", output)
    }
}

#[derive(Debug, Clone)]
pub struct IEX6 {
    pub name: String,
    pub rr: RequestResponse,
    pub st: Duration,
    pub rt: Duration,
}

impl Default for IEX6 {
    fn default() -> Self {
        Self {
            name: String::new(),
            rr: RequestResponse::default(),
            st: Duration::new(0, 0),
            rt: Duration::new(0, 0),
        }
    }
}

impl fmt::Display for IEX6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = if self.rr.response.len() > 0 {
            let output = format!(
                "{}(P={}%ST={:.6}%RT={:.6})",
                self.name,
                p_as_nmap_format(&self.rr.response),
                self.st.as_secs_f64(),
                self.rt.as_secs_f64()
            );
            output
        } else {
            String::new()
        };
        write!(f, "{}", output)
    }
}

#[derive(Debug, Clone)]
pub struct NX6 {
    pub name: String,
    pub rr: RequestResponse,
    pub st: Duration,
    pub rt: Duration,
}

impl Default for NX6 {
    fn default() -> Self {
        Self {
            name: String::new(),
            rr: RequestResponse::default(),
            st: Duration::new(0, 0),
            rt: Duration::new(0, 0),
        }
    }
}

impl fmt::Display for NX6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = if self.rr.response.len() > 0 {
            let output = format!(
                "{}(P={}%ST={:.6}%RT={:.6})",
                self.name,
                p_as_nmap_format(&self.rr.response),
                self.st.as_secs_f64(),
                self.rt.as_secs_f64()
            );
            output
        } else {
            String::new()
        };
        write!(f, "{}", output)
    }
}

#[derive(Debug, Clone)]
pub struct U1X6 {
    pub rr: RequestResponse,
    pub st: Duration,
    pub rt: Duration,
}

impl Default for U1X6 {
    fn default() -> Self {
        Self {
            rr: RequestResponse::default(),
            st: Duration::new(0, 0),
            rt: Duration::new(0, 0),
        }
    }
}

impl fmt::Display for U1X6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = if self.rr.response.len() > 0 {
            let output = format!(
                "U1(P={}%ST={:.6}%RT={:.6})",
                p_as_nmap_format(&self.rr.response),
                self.st.as_secs_f64(),
                self.rt.as_secs_f64()
            );
            output
        } else {
            String::new()
        };
        write!(f, "{}", output)
    }
}

#[derive(Debug, Clone)]
pub struct TECNX6 {
    pub rr: RequestResponse,
    pub st: Duration,
    pub rt: Duration,
}

impl Default for TECNX6 {
    fn default() -> Self {
        Self {
            rr: RequestResponse::default(),
            st: Duration::new(0, 0),
            rt: Duration::new(0, 0),
        }
    }
}

impl fmt::Display for TECNX6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = if self.rr.response.len() > 0 {
            let output = format!(
                "TECN(P={}%ST={:.6}%RT={:.6})",
                p_as_nmap_format(&self.rr.response),
                self.st.as_secs_f64(),
                self.rt.as_secs_f64()
            );
            output
        } else {
            String::new()
        };
        write!(f, "{}", output)
    }
}

#[derive(Debug, Clone)]
pub struct TX6 {
    pub name: String,
    pub rr: RequestResponse,
    pub st: Duration,
    pub rt: Duration,
}

impl Default for TX6 {
    fn default() -> Self {
        Self {
            name: String::new(),
            rr: RequestResponse::default(),
            st: Duration::new(0, 0),
            rt: Duration::new(0, 0),
        }
    }
}

impl fmt::Display for TX6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = if self.rr.response.len() > 0 {
            let output = format!(
                "{}(P={}%ST={:.6}%RT={:.6})",
                self.name,
                p_as_nmap_format(&self.rr.response),
                self.st.as_secs_f64(),
                self.rt.as_secs_f64()
            );
            output
        } else {
            String::new()
        };
        write!(f, "{}", output)
    }
}

#[derive(Debug, Clone)]
pub struct Fingerprint6 {
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

impl Default for Fingerprint6 {
    fn default() -> Self {
        Self {
            scan: String::new(),
            s1x: SEQX6::default(),
            s2x: SEQX6::default(),
            s3x: SEQX6::default(),
            s4x: SEQX6::default(),
            s5x: SEQX6::default(),
            s6x: SEQX6::default(),
            ie1x: IEX6::default(),
            ie2x: IEX6::default(),
            ni: NX6::default(),
            ns: NX6::default(),
            u1x: U1X6::default(),
            tecnx: TECNX6::default(),
            t2x: TX6::default(),
            t3x: TX6::default(),
            t4x: TX6::default(),
            t5x: TX6::default(),
            t6x: TX6::default(),
            t7x: TX6::default(),
            extra: String::new(),
            novelty: 0.0,
            status: false,
        }
    }
}

impl Fingerprint6 {
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

impl fmt::Display for Fingerprint6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        let scan_str = format!("{}", self.scan);
        let s1x_str = format!("\n{}", self.s1x);
        let s2x_str = format!("\n{}", self.s2x);
        let s3x_str = format!("\n{}", self.s3x);
        let s4x_str = format!("\n{}", self.s4x);
        let s5x_str = format!("\n{}", self.s5x);
        let s6x_str = format!("\n{}", self.s6x);
        let ie1x_str = format!("\n{}", self.ie1x);
        let ie2x_str = format!("\n{}", self.ie2x);
        // let nix_str = format!("\n{}", self.ni); // ignored by nmap
        let nsx_str = format!("\n{}", self.ns);
        let u1x_str = format!("\n{}", self.u1x);
        let tecnx_str = format!("\n{}", self.tecnx);
        let t2x_str = format!("\n{}", self.t2x);
        let t3x_str = format!("\n{}", self.t3x);
        let t4x_str = format!("\n{}", self.t4x);
        let t5x_str = format!("\n{}", self.t5x);
        let t6x_str = format!("\n{}", self.t6x);
        let t7x_str = format!("\n{}", self.t7x);
        let extra_str = format!("\nEXTRA(FL={})", self.extra);
        if scan_str.trim().len() > 0 {
            output += &scan_str;
        }
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
        if ie1x_str.trim().len() > 0 {
            output += &ie1x_str;
        }
        if ie2x_str.trim().len() > 0 {
            output += &ie2x_str;
        }
        // if nix_str.trim().len() > 0 {
        //     output += &nix_str;
        // }
        if nsx_str.trim().len() > 0 {
            output += &nsx_str;
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
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_open_port: u16,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    interface: &NetworkInterface,
    timeout: Duration,
    scan_start: Instant,
) -> Result<SEQRR6, PistolError> {
    let begin = Instant::now();
    let src_port_start = random_port_range(1000, 6540);
    let mut src_ports = Vec::new();
    for i in 0..6 {
        src_ports.push(src_port_start * 10 + i);
    }
    let buff_1 = packet6::seq_packet_1_layer3(dst_ipv6, dst_open_port, src_ipv6, src_ports[0])?;
    let buff_2 = packet6::seq_packet_2_layer3(dst_ipv6, dst_open_port, src_ipv6, src_ports[1])?;
    let buff_3 = packet6::seq_packet_3_layer3(dst_ipv6, dst_open_port, src_ipv6, src_ports[2])?;
    let buff_4 = packet6::seq_packet_4_layer3(dst_ipv6, dst_open_port, src_ipv6, src_ports[3])?;
    let buff_5 = packet6::seq_packet_5_layer3(dst_ipv6, dst_open_port, src_ipv6, src_ports[4])?;
    let buff_6 = packet6::seq_packet_6_layer3(dst_ipv6, dst_open_port, src_ipv6, src_ports[5])?;
    let mut buff_hm = HashMap::new();
    buff_hm.insert(1, buff_1);
    buff_hm.insert(2, buff_2);
    buff_hm.insert(3, buff_3);
    buff_hm.insert(4, buff_4);
    buff_hm.insert(5, buff_5);
    buff_hm.insert(6, buff_6);

    let mut filter_hm = HashMap::new();
    for i in 1..=6 {
        let src_port = src_ports[i];
        let name = format!("os scan6 seq {} layer3", i + 1);
        let layer3 = Layer3Filter {
            name,
            layer2: None,
            src_addr: Some(dst_ipv6.into()),
            dst_addr: Some(src_ipv6.into()),
        };
        let name = format!("os scan6 seq {} tcp_udp", i + 1);
        let layer4_tcp_udp = Layer4FilterTcpUdp {
            name,
            layer3: Some(layer3),
            src_port: Some(dst_open_port),
            dst_port: Some(src_port),
            flag: None,
        };
        let filter = Arc::from(PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp));
        filter_hm.insert(i, filter);
    }

    let mut send_status = HashMap::new();
    for t in 1..=6 {
        // 1 means buff_1, 2 means buff_2, and so on.
        // (0, false, None, start) => (retiries, has data recved?, receiver, send probe time)
        send_status.insert(t, (0, false, None, Instant::now()));
    }

    let ether_type = EtherTypes::Ipv6;
    let iface = interface.name.clone();
    let mut seq_hm = HashMap::new();
    let mut scan_start_hm = HashMap::new();
    loop {
        let mut all_done = true;
        let mut send_status_clone = send_status.clone();
        for (i, buff) in &buff_hm {
            let filter = &filter_hm[i];
            let (retiries, recved, _receiver, _start) = &send_status[&i];
            if *retiries < PROBE_MAX_RETIRIES && !recved {
                let start = Instant::now();
                let receiver = ask_runner(
                    iface.clone(),
                    dst_mac,
                    src_mac,
                    buff.clone(),
                    ether_type,
                    vec![filter.clone()],
                    timeout,
                    0,
                )?;
                scan_start_hm.insert(i, scan_start.elapsed());
                send_status_clone.insert(*i, (retiries + 1, *recved, Some(receiver), start));
                all_done = false;
            }

            // the probes are sent exactly 100 milliseconds apart so the total time taken is 500 ms
            sleep(Duration::from_millis(100));
        }

        if all_done {
            break;
        }

        for (i, x) in send_status_clone.clone() {
            let (_retiries, _recved, receiver, start) = x;
            match receiver {
                Some(receiver) => {
                    let (eth_response, rtt) = get_response(receiver, start, timeout);
                    match EthernetPacket::new(&eth_response) {
                        Some(eth_packet) => {
                            let eth_payload = Arc::from(eth_packet.payload());
                            let request = buff_hm[&i].clone();
                            let rr = RequestResponse {
                                request,
                                response: eth_payload,
                                rtt,
                            };
                            seq_hm.insert(i, rr);
                        }
                        None => (),
                    }
                }
                None => (),
            }
        }
        send_status = send_status_clone;
    }

    let seq1: RequestResponse = seq_hm
        .get(&1)
        .map_or(RequestResponse::default(), |x| x.clone());
    let seq2 = seq_hm
        .get(&2)
        .map_or(RequestResponse::default(), |x| x.clone());
    let seq3 = seq_hm
        .get(&3)
        .map_or(RequestResponse::default(), |x| x.clone());
    let seq4 = seq_hm
        .get(&4)
        .map_or(RequestResponse::default(), |x| x.clone());
    let seq5 = seq_hm
        .get(&5)
        .map_or(RequestResponse::default(), |x| x.clone());
    let seq6 = seq_hm
        .get(&6)
        .map_or(RequestResponse::default(), |x| x.clone());

    let st1 = scan_start_hm[&1];
    let st2 = scan_start_hm[&2];
    let st3 = scan_start_hm[&3];
    let st4 = scan_start_hm[&4];
    let st5 = scan_start_hm[&5];
    let st6 = scan_start_hm[&6];

    let rt1 = st1 + seq1.rtt;
    let rt2 = st2 + seq2.rtt;
    let rt3 = st3 + seq3.rtt;
    let rt4 = st4 + seq4.rtt;
    let rt5 = st5 + seq5.rtt;
    let rt6 = st6 + seq6.rtt;

    let elapsed = begin.elapsed().as_secs_f64();
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
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    interface: &NetworkInterface,
    timeout: Duration,
    scan_start: Instant,
) -> Result<IERR6, PistolError> {
    let buff_1 = packet6::ie_packet_1_layer3(dst_ipv6, src_ipv6)?;
    let buff_2 = packet6::ie_packet_2_layer3(dst_ipv6, src_ipv6)?;
    let mut buff_hm = HashMap::new();
    buff_hm.insert(1, buff_1);
    buff_hm.insert(2, buff_2);

    let layer3 = Layer3Filter {
        name: String::from("os scan6 ie layer3"),
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    // They do, however, respond with different ICMPv6 errors with icmpv6 types 1, 2, 3, 4.
    let layer4_icmpv6_1 = Layer4FilterIcmpv6 {
        name: String::from("os scan6 ie icmpv6 type 1"),
        layer3: Some(layer3.clone()),
        icmpv6_type: Some(Icmpv6Type(1)),
        icmpv6_code: None,
        payload: None,
    };
    let layer4_icmpv6_2 = Layer4FilterIcmpv6 {
        name: String::from("os scan6 ie icmpv6 type 2"),
        layer3: Some(layer3.clone()),
        icmpv6_type: Some(Icmpv6Type(2)),
        icmpv6_code: None,
        payload: None,
    };
    let layer4_icmpv6_3 = Layer4FilterIcmpv6 {
        name: String::from("os scan6 ie icmpv6 type 3"),
        layer3: Some(layer3.clone()),
        icmpv6_type: Some(Icmpv6Type(3)),
        icmpv6_code: None,
        payload: None,
    };
    let layer4_icmpv6_4 = Layer4FilterIcmpv6 {
        name: String::from("os scan6 ie icmpv6 type 4"),
        layer3: Some(layer3),
        icmpv6_type: Some(Icmpv6Type(4)),
        icmpv6_code: None,
        payload: None,
    };
    let filter_1 = Arc::from(PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6_1));
    let filter_2 = Arc::from(PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6_2));
    let filter_3 = Arc::from(PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6_3));
    let filter_4 = Arc::from(PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6_4));
    let filters = vec![filter_1, filter_2, filter_3, filter_4];

    let mut send_status = HashMap::new();
    for t in 1..=2 {
        // 1 means buff_1, 2 means buff_2, and so on.
        // (0, false, None, start) => (retiries, has data recved?, receiver, send probe time)
        send_status.insert(t, (0, false, None, Instant::now()));
    }

    let mut ie_hm = HashMap::new();
    let mut scan_start_hm = HashMap::new();
    let ether_type = EtherTypes::Ipv6;
    let iface = interface.name.clone();
    loop {
        let mut all_done = true;
        let mut send_status_clone = send_status.clone();
        for (i, buff) in &buff_hm {
            let (retiries, recved, _receiver, _start) = &send_status[&i];
            if *retiries < PROBE_MAX_RETIRIES && !recved {
                let start = Instant::now();
                let receiver = ask_runner(
                    iface.clone(),
                    dst_mac,
                    src_mac,
                    buff.clone(),
                    ether_type,
                    filters.clone(),
                    timeout,
                    0,
                )?;
                scan_start_hm.insert(i, scan_start.elapsed());
                send_status_clone.insert(*i, (retiries + 1, *recved, Some(receiver), start));
                all_done = false;
            }
        }

        if all_done {
            break;
        }

        for (i, x) in send_status_clone.clone() {
            let (_retiries, _recved, receiver, start) = x;
            match receiver {
                Some(receiver) => {
                    let (eth_response, rtt) = get_response(receiver, start, timeout);
                    match EthernetPacket::new(&eth_response) {
                        Some(eth_packet) => {
                            let eth_payload = Arc::from(eth_packet.payload());
                            let request = buff_hm[&i].clone();
                            let rr = RequestResponse {
                                request,
                                response: eth_payload,
                                rtt,
                            };
                            ie_hm.insert(i, rr);
                        }
                        None => (),
                    }
                }
                None => (),
            }
        }
    }

    let ie1 = ie_hm
        .get(&1)
        .map_or(RequestResponse::default(), |x| x.clone());
    let ie2 = ie_hm
        .get(&2)
        .map_or(RequestResponse::default(), |x| x.clone());

    let st1 = scan_start_hm[&1];
    let st2 = scan_start_hm[&2];

    let rt1 = st1 + ie1.rtt;
    let rt2 = st2 + ie2.rtt;

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
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    interface: &NetworkInterface,
    timeout: Duration,
    scan_start: Instant,
) -> Result<NXRR6, PistolError> {
    let buff_1 = packet6::ni_packet_layer3(dst_ipv6, src_ipv6)?;
    let buff_2 = packet6::ns_packet_layer3(dst_ipv6, src_ipv6, src_mac)?;
    let mut buff_hm = HashMap::new();
    buff_hm.insert(1, buff_1);
    buff_hm.insert(2, buff_2);

    let layer3 = Layer3Filter {
        name: String::from("os scan6 nx layer3"),
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_icmpv6 = Layer4FilterIcmpv6 {
        name: String::from("os scan6 nx icmpv6"),
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
        payload: None,
    };
    let filter = Arc::from(PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6));

    let mut send_status = HashMap::new();
    for t in 1..=2 {
        // 1 means buff_1, 2 means buff_2, and so on.
        // (0, false, None, start) => (retiries, has data recved?, receiver, send probe time)
        send_status.insert(t, (0, false, None, Instant::now()));
    }

    let mut nx_hm = HashMap::new();
    let mut scan_start_hm = HashMap::new();
    let ether_type = EtherTypes::Ipv6;
    let iface = interface.name.clone();
    loop {
        let mut all_done = true;
        let mut send_status_clone = send_status.clone();
        for (i, buff) in &buff_hm {
            let (retiries, recved, _receiver, _start) = &send_status[&i];
            if *retiries < PROBE_MAX_RETIRIES && !recved {
                let start = Instant::now();
                let receiver = ask_runner(
                    iface.clone(),
                    dst_mac,
                    src_mac,
                    buff.clone(),
                    ether_type,
                    vec![filter.clone()],
                    timeout,
                    0,
                )?;
                scan_start_hm.insert(i, scan_start.elapsed());
                send_status_clone.insert(*i, (retiries + 1, *recved, Some(receiver), start));
                all_done = false;
            }
        }

        if all_done {
            break;
        }

        for (i, x) in send_status_clone.clone() {
            let (_retiries, _recved, receiver, start) = x;
            match receiver {
                Some(receiver) => {
                    let (eth_response, rtt) = get_response(receiver, start, timeout);
                    match EthernetPacket::new(&eth_response) {
                        Some(eth_packet) => {
                            let eth_payload = Arc::from(eth_packet.payload());
                            let request = buff_hm[&i].clone();
                            let rr = RequestResponse {
                                request,
                                response: eth_payload,
                                rtt,
                            };
                            nx_hm.insert(i, rr);
                        }
                        None => (),
                    }
                }
                None => (),
            }
        }
    }

    let ni = nx_hm
        .get(&0)
        .map_or(RequestResponse::default(), |x| x.clone());
    let ns = nx_hm
        .get(&1)
        .map_or(RequestResponse::default(), |x| x.clone());

    let sti = scan_start_hm[&1];
    let sts = scan_start_hm[&2];

    let rti = sti + ni.rtt;
    let rts = sts + ns.rtt;

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
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_closed_port: u16, //should be an closed udp port
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    interface: &NetworkInterface,
    timeout: Duration,
    scan_start: Instant,
) -> Result<U1RR6, PistolError> {
    let src_port = random_port();
    let buff = packet6::udp_packet_layer3(dst_ipv6, dst_closed_port, src_ipv6, src_port)?;
    let layer3 = Layer3Filter {
        name: String::from("os scan6 u1 layer3"),
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_icmpv6 = Layer4FilterIcmpv6 {
        name: String::from("os scan6 u1 icmpv6"),
        layer3: Some(layer3),
        icmpv6_type: None,
        icmpv6_code: None,
        payload: None,
    };
    let filter = Arc::from(PacketFilter::Layer4FilterIcmpv6(layer4_icmpv6));

    // For those that do not require time, process them in order.
    // Prevent the previous request from receiving response from the later request.
    // ICMPV6 is a stateless protocol, we cannot accurately know the response for each request.
    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv6;
    for _ in 0..PROBE_MAX_RETIRIES {
        let start = Instant::now();
        let st = scan_start.elapsed();
        let receiver = ask_runner(
            iface.clone(),
            dst_mac,
            src_mac,
            buff.clone(),
            ether_type,
            vec![filter.clone()],
            timeout,
            0,
        )?;
        let (eth_response, rtt) = get_response(receiver, start, timeout);
        if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
            let eth_payload: Arc<[u8]> = Arc::from(eth_packet.payload());
            if eth_payload.len() > 0 {
                let rr = RequestResponse {
                    request: buff,
                    response: eth_payload,
                    rtt,
                };
                let rt = st + rtt;
                let ecn = U1RR6 { u1: rr, st, rt };
                return Ok(ecn);
            }
        }
    }

    let rr = RequestResponse {
        request: buff,
        response: Arc::from([]),
        rtt: Duration::ZERO,
    };

    let u1 = U1RR6 {
        u1: rr,
        st: Duration::ZERO,
        rt: Duration::ZERO,
    };
    return Ok(u1);
}

fn send_tecn_probe(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_open_port: u16,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    interface: &NetworkInterface,
    timeout: Duration,
    start_time: Instant,
) -> Result<TECNRR6, PistolError> {
    let src_port = random_port();

    let layer3 = Layer3Filter {
        name: String::from("os scan6 tecn layer3"),
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };
    let layer4_tcp_udp = Layer4FilterTcpUdp {
        name: String::from("os scan6 tecn tcp_udp"),
        layer3: Some(layer3),
        src_port: Some(dst_open_port),
        dst_port: Some(src_port),
        flag: None,
    };
    let filter = Arc::from(PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp));

    let buff = packet6::tecn_packet_layer3(dst_ipv6, dst_open_port, src_ipv6, src_port)?;
    // For those that do not require time, process them in order.
    // Prevent the previous request from receiving response from the later request.
    // ICMPV6 is a stateless protocol, we cannot accurately know the response for each request.
    let st = start_time.elapsed();
    let iface = interface.name.clone();
    let ether_type = EtherTypes::Ipv6;
    let start = Instant::now();
    let receiver = ask_runner(
        iface.clone(),
        dst_mac,
        src_mac,
        buff.clone(),
        ether_type,
        vec![filter],
        timeout,
        0,
    )?;
    let (eth_response, rtt) = get_response(receiver, start, timeout);
    let rt = st + rtt;

    let rr = if let Some(eth_packet) = EthernetPacket::new(&eth_response) {
        let eth_payload = Arc::from(eth_packet.payload());
        RequestResponse {
            request: buff,
            response: eth_payload,
            rtt,
        }
    } else {
        RequestResponse {
            request: buff,
            response: Arc::from([]),
            rtt: Duration::ZERO,
        }
    };

    let tecn = TECNRR6 { tecn: rr, st, rt };
    Ok(tecn)
}

fn send_tx_probes(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_open_port: u16,
    dst_closed_port: u16,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    interface: &NetworkInterface,
    timeout: Duration,
    scan_start: Instant,
) -> Result<TXRR6, PistolError> {
    let src_port_start = random_port_range(1000, 6540);
    let mut src_ports = Vec::new();
    for i in 0..6 {
        src_ports.push(src_port_start * 10 + i);
    }

    let layer3 = Layer3Filter {
        name: String::from("os scan6 tx layer3"),
        layer2: None,
        src_addr: Some(dst_ipv6.into()),
        dst_addr: Some(src_ipv6.into()),
    };

    let layer4_tcp_udp_2 = Layer4FilterTcpUdp {
        name: String::from("os scan6 tx tcp_udp 2"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_open_port),
        dst_port: Some(src_ports[0]),
        flag: None,
    };
    let layer4_tcp_udp_3 = Layer4FilterTcpUdp {
        name: String::from("os scan6 tx tcp_udp 3"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_open_port),
        dst_port: Some(src_ports[1]),
        flag: None,
    };
    let layer4_tcp_udp_4 = Layer4FilterTcpUdp {
        name: String::from("os scan6 tx tcp_udp 4"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_open_port),
        dst_port: Some(src_ports[2]),
        flag: None,
    };
    let layer4_tcp_udp_5 = Layer4FilterTcpUdp {
        name: String::from("os scan6 tx tcp_udp 5"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_closed_port),
        dst_port: Some(src_ports[3]),
        flag: None,
    };
    let layer4_tcp_udp_6 = Layer4FilterTcpUdp {
        name: String::from("os scan6 tx tcp_udp 6"),
        layer3: Some(layer3.clone()),
        src_port: Some(dst_closed_port),
        dst_port: Some(src_ports[4]),
        flag: None,
    };
    let layer4_tcp_udp_7 = Layer4FilterTcpUdp {
        name: String::from("os scan6 tx tcp_udp 7"),
        layer3: Some(layer3),
        src_port: Some(dst_closed_port),
        dst_port: Some(src_ports[5]),
        flag: None,
    };
    let layer_match_2 = Arc::from(PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp_2));
    let layer_match_3 = Arc::from(PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp_3));
    let layer_match_4 = Arc::from(PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp_4));
    let layer_match_5 = Arc::from(PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp_5));
    let layer_match_6 = Arc::from(PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp_6));
    let layer_match_7 = Arc::from(PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp_7));
    let mut filter_hm = HashMap::new();
    filter_hm.insert(2, layer_match_2);
    filter_hm.insert(3, layer_match_3);
    filter_hm.insert(4, layer_match_4);
    filter_hm.insert(5, layer_match_5);
    filter_hm.insert(6, layer_match_6);
    filter_hm.insert(7, layer_match_7);

    let buff_2 = packet6::t2_packet_layer3(dst_ipv6, dst_open_port, src_ipv6, src_ports[0])?;
    let buff_3 = packet6::t3_packet_layer3(dst_ipv6, dst_open_port, src_ipv6, src_ports[1])?;
    let buff_4 = packet6::t4_packet_layer3(dst_ipv6, dst_open_port, src_ipv6, src_ports[2])?;
    let buff_5 = packet6::t5_packet_layer3(dst_ipv6, dst_closed_port, src_ipv6, src_ports[3])?;
    let buff_6 = packet6::t6_packet_layer3(dst_ipv6, dst_closed_port, src_ipv6, src_ports[4])?;
    let buff_7 = packet6::t7_packet_layer3(dst_ipv6, dst_closed_port, src_ipv6, src_ports[5])?;
    let mut buff_hm = HashMap::new();
    buff_hm.insert(2, buff_2);
    buff_hm.insert(3, buff_3);
    buff_hm.insert(4, buff_4);
    buff_hm.insert(5, buff_5);
    buff_hm.insert(6, buff_6);
    buff_hm.insert(7, buff_7);

    let mut send_status = HashMap::new();
    for t in 1..=6 {
        // 1 means buff_1, 2 means buff_2, and so on.
        // (0, false, None, start) => (retiries, has data recved?, receiver, send probe time)
        send_status.insert(t, (0, false, None, Instant::now()));
    }

    let ether_type = EtherTypes::Ipv6;
    let iface = interface.name.clone();
    let mut tx_hm = HashMap::new();
    let mut scan_start_hm = HashMap::new();
    loop {
        let mut all_done = true;
        let mut send_status_clone = send_status.clone();
        for (i, buff) in &buff_hm {
            let filter = &filter_hm[i];
            let (retiries, recved, _receiver, _start) = &send_status[&i];
            if *retiries < PROBE_MAX_RETIRIES && !recved {
                let start = Instant::now();
                let receiver = ask_runner(
                    iface.clone(),
                    dst_mac,
                    src_mac,
                    buff.clone(),
                    ether_type,
                    vec![filter.clone()],
                    timeout,
                    0,
                )?;
                scan_start_hm.insert(i, scan_start.elapsed());
                send_status_clone.insert(*i, (retiries + 1, *recved, Some(receiver), start));
                all_done = false;
            }
        }

        if all_done {
            break;
        }

        for (i, x) in send_status_clone.clone() {
            let (_retiries, _recved, receiver, start) = x;
            match receiver {
                Some(receiver) => {
                    let (eth_response, rtt) = get_response(receiver, start, timeout);
                    match EthernetPacket::new(&eth_response) {
                        Some(eth_packet) => {
                            let eth_payload = Arc::from(eth_packet.payload());
                            let request = buff_hm[&i].clone();
                            let rr = RequestResponse {
                                request,
                                response: eth_payload,
                                rtt,
                            };
                            tx_hm.insert(i, rr);
                        }
                        None => (),
                    }
                }
                None => (),
            }
        }
        send_status = send_status_clone;
    }

    let t2 = tx_hm
        .get(&2)
        .map_or(RequestResponse::default(), |x| x.clone());
    let t3 = tx_hm
        .get(&3)
        .map_or(RequestResponse::default(), |x| x.clone());
    let t4 = tx_hm
        .get(&4)
        .map_or(RequestResponse::default(), |x| x.clone());
    let t5 = tx_hm
        .get(&5)
        .map_or(RequestResponse::default(), |x| x.clone());
    let t6 = tx_hm
        .get(&6)
        .map_or(RequestResponse::default(), |x| x.clone());
    let t7 = tx_hm
        .get(&7)
        .map_or(RequestResponse::default(), |x| x.clone());

    let st2 = scan_start_hm[&2];
    let st3 = scan_start_hm[&3];
    let st4 = scan_start_hm[&4];
    let st5 = scan_start_hm[&5];
    let st6 = scan_start_hm[&6];
    let st7 = scan_start_hm[&7];

    let rt2 = st2 + t2.rtt;
    let rt3 = st2 + t2.rtt;
    let rt4 = st2 + t2.rtt;
    let rt5 = st2 + t2.rtt;
    let rt6 = st2 + t2.rtt;
    let rt7 = st2 + t2.rtt;

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
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_open_tcp_port: u16,
    dst_closed_tcp_port: u16,
    dst_closed_udp_port: u16,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    interface: &NetworkInterface,
    timeout: Duration,
) -> Result<AllPacketRR6, PistolError> {
    let start_time = Instant::now();
    debug!("sending SEQ probe");
    let seq = send_seq_probes(
        dst_mac,
        dst_ipv6,
        dst_open_tcp_port,
        src_mac,
        src_ipv6,
        interface,
        timeout,
        start_time,
    )?;
    debug!("sending IE probe");
    let ie = send_ie_probes(
        dst_mac, dst_ipv6, src_mac, src_ipv6, interface, timeout, start_time,
    )?;
    debug!("sending NX probe");
    let nx = send_nx_probes(
        dst_mac, dst_ipv6, src_mac, src_ipv6, interface, timeout, start_time,
    )?;
    debug!("sending U1 probe");
    let u1 = send_u1_probe(
        dst_mac,
        dst_ipv6,
        dst_closed_udp_port,
        src_mac,
        src_ipv6,
        interface,
        timeout,
        start_time,
    )?;
    debug!("sending TECN probe");
    let tecn = send_tecn_probe(
        dst_mac,
        dst_ipv6,
        dst_open_tcp_port,
        src_mac,
        src_ipv6,
        interface,
        timeout,
        start_time,
    )?;
    debug!("sending TX probe");
    let tx = send_tx_probes(
        dst_mac,
        dst_ipv6,
        dst_open_tcp_port,
        dst_closed_tcp_port,
        src_mac,
        src_ipv6,
        interface,
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
    // features [695]
    // wvec [92, 695]
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

fn isort(arr: &[OsInfo6]) -> Vec<OsInfo6> {
    fn pick(arr: &[OsInfo6]) -> (OsInfo6, Vec<OsInfo6>) {
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

pub fn os_probe_thread6(
    dst_mac: MacAddr,
    dst_ipv6: Ipv6Addr,
    dst_open_tcp_port: u16,
    dst_closed_tcp_port: u16,
    dst_closed_udp_port: u16,
    src_mac: MacAddr,
    src_ipv6: Ipv6Addr,
    interface: &NetworkInterface,
    top_k: usize,
    linear: Linear,
    timeout: Duration,
) -> Result<(Fingerprint6, Vec<OsInfo6>), PistolError> {
    debug!("send all probes now");
    let ap = send_all_probes(
        dst_mac,
        dst_ipv6,
        dst_open_tcp_port,
        dst_closed_tcp_port,
        dst_closed_udp_port,
        src_mac,
        src_ipv6,
        interface,
        timeout,
    )?;
    debug!("send all probes done");

    let good_results = true;
    let icmp_trace_net_info = NetInfo {
        dst_mac,
        src_mac,
        dst_addr: dst_ipv6.into(),
        src_addr: src_ipv6.into(),
        dst_ports: Vec::new(),
        src_port: None,
        interface: interface.clone(),
        cached: true,
        cost: Duration::ZERO,
        valid: true,
    };
    let trace = icmp_trace(icmp_trace_net_info, timeout)?;
    let hops = trace.hops;
    // form get_scan_line function
    let scan = get_scan_line(
        dst_mac,
        dst_open_tcp_port,
        dst_closed_tcp_port,
        dst_closed_udp_port,
        dst_ipv6.into(),
        hops,
        good_results,
    );

    let features = vectorize(&ap)?;
    debug!("featured vectorize done");
    let features = apply_scale(&features, &linear.scale);
    debug!("apply scale done");
    let predict = predict_value(&features, &linear.w);
    debug!("predict done");

    let mut detect_rets = Vec::new();
    for (i, (name, &score)) in zip(&linear.infolist, &predict).into_iter().enumerate() {
        let class = &linear.cpe[i].osclass;
        if class.len() > 0 {
            let class = class[0].join(" | ");
            let cpe = linear.cpe[i].cpe.join(" ");
            let dr = OsInfo6 {
                name: name.to_string(),
                class,
                cpe,
                score,
                label: i,
            };
            detect_rets.push(dr);
        }
    }
    debug!("detect rets len: {}", detect_rets.len());

    let detect_rets = isort(&detect_rets);
    let mut perfect_match = 1;
    for i in 1..36 {
        if detect_rets[i].score >= 0.9 * detect_rets[0].score {
            perfect_match += 1;
        }
    }
    debug!("prefect match: {}", perfect_match);

    let label = detect_rets[0].label;
    let novelty = novelty_of(&features, &linear.mean[label], &linear.variance[label]);
    debug!("novelty: {}", novelty);

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

    const FP_NOVELTY_THRESHOLD: f64 = 15.0;
    let status = if perfect_match == 1 {
        if novelty < FP_NOVELTY_THRESHOLD {
            true
        } else {
            false
        }
    } else {
        false
    };

    let target_fingerprint = Fingerprint6 {
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
        warn!(
            "os scan6 novelty {} > FP_NOVELTY_THRESHOLD {}, so there are no results returned",
            novelty, FP_NOVELTY_THRESHOLD
        );
        let ret = Vec::new();
        ret
    };

    debug!("ipv6 fingerprint:\n{}", target_fingerprint);
    Ok((target_fingerprint, ret))
}

/*
#[cfg(test)]
mod tests {
    use super::*;
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
    // #[should_panic]
    fn test_send_tx() {
        let dst_ipv6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0020c, 0x29ff, 0xfe2c, 0x09e4);
        let src_ipv6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0020c, 0x29ff, 0xfe2c, 0x09e4);
        let dst_open_port = 22;
        let dst_closed_port = 9876;

        let src_port_start = random_port_range(1000, 6540);
        let mut src_ports = Vec::new();
        for i in 0..6 {
            src_ports.push(src_port_start * 10 + i);
        }
        println!("src_ports: {:?}", src_ports);

        let layer3 = Layer3Filter {
            name: String::from("test layer3"),
            layer2: None,
            src_addr: Some(dst_ipv6.into()),
            dst_addr: Some(src_ipv6.into()),
        };

        let layer4_tcp_udp_2 = Layer4FilterTcpUdp {
            name: String::from("test tcp_udp 2"),
            layer3: Some(layer3),
            src_port: Some(dst_open_port),
            dst_port: Some(src_ports[0]),
        };
        let layer4_tcp_udp_3 = Layer4FilterTcpUdp {
            name: String::from("test tcp_udp 3"),
            layer3: Some(layer3),
            src_port: Some(dst_open_port),
            dst_port: Some(src_ports[1]),
        };
        let layer4_tcp_udp_4 = Layer4FilterTcpUdp {
            name: String::from("test tcp_udp 4"),
            layer3: Some(layer3),
            src_port: Some(dst_open_port),
            dst_port: Some(src_ports[2]),
        };
        let layer4_tcp_udp_5 = Layer4FilterTcpUdp {
            name: String::from("test tcp_udp 5"),
            layer3: Some(layer3),
            src_port: Some(dst_closed_port),
            dst_port: Some(src_ports[3]),
        };
        let layer4_tcp_udp_6 = Layer4FilterTcpUdp {
            name: String::from("test tcp_udp 6"),
            layer3: Some(layer3),
            src_port: Some(dst_closed_port),
            dst_port: Some(src_ports[4]),
        };
        let layer4_tcp_udp_7 = Layer4FilterTcpUdp {
            name: String::from("test tcp_udp 7"),
            layer3: Some(layer3),
            src_port: Some(dst_closed_port),
            dst_port: Some(src_ports[5]),
        };
        let filter_2 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp_2);
        let filter_3 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp_3);
        let filter_4 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp_4);
        let filter_5 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp_5);
        let filter_6 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp_6);
        let filter_7 = PacketFilter::Layer4FilterTcpUdp(layer4_tcp_udp_7);
        let filters = vec![filter_2, filter_3, filter_4, filter_5, filter_6, filter_7];

        let buff_2 =
            packet6::t2_packet_layer3(dst_ipv6, dst_open_port, src_ipv6, src_ports[0]).unwrap();
        let buff_3 =
            packet6::t3_packet_layer3(dst_ipv6, dst_open_port, src_ipv6, src_ports[1]).unwrap();
        let buff_4 =
            packet6::t4_packet_layer3(dst_ipv6, dst_open_port, src_ipv6, src_ports[2]).unwrap();
        let buff_5 =
            packet6::t5_packet_layer3(dst_ipv6, dst_closed_port, src_ipv6, src_ports[3]).unwrap();
        let buff_6 =
            packet6::t6_packet_layer3(dst_ipv6, dst_closed_port, src_ipv6, src_ports[4]).unwrap();
        let buff_7 =
            packet6::t7_packet_layer3(dst_ipv6, dst_closed_port, src_ipv6, src_ports[5]).unwrap();
        let buffs = vec![buff_2, buff_3, buff_4, buff_5, buff_6, buff_7];

        let i = 0;
        let filter = filters[i].clone();
        let buff = buffs[i].clone();
        let timeout = Duration::new(3, 0);

        let receiver = ask_runner(vec![filter]).unwrap();
        let layer3 = Layer3::new(dst_ipv6.into(), src_ipv6.into(), timeout, true);
        let start = Instant::now();
        layer3.send(&buff).unwrap();
        let eth_response = match receiver.recv_timeout(timeout) {
            Ok(b) => b,
            Err(e) => {
                debug!("{} recv icmpv6 ping response timeout: {}", dst_ipv6, e);
                Vec::new()
            }
        };
        let _rtt = start.elapsed();

        println!("eth_response len: {}", eth_response.len());
    }
}
*/
