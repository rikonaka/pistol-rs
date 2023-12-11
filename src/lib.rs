#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("lib.md")]
use pnet::datalink::MacAddr;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet_datalink::NetworkInterface;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod errors;
mod fingerprinting;
mod flood;
mod ping;
mod scan;
mod utils;

#[derive(Debug, Clone, Copy)]
pub enum PingStatus {
    Up,
    Down,
}

#[derive(Debug, Clone, Copy)]
pub struct PingResults {
    pub addr: IpAddr,
    pub status: PingStatus,
}

impl fmt::Display for PingResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ip = self.addr;
        let mut result_str = String::new();
        let str = match self.status {
            PingStatus::Up => format!("{ip} up"),
            PingStatus::Down => format!("{ip} down"),
        };
        result_str += &str;
        write!(f, "{}", result_str)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TargetScanStatus {
    Open,
    Closed,
    Filtered,
    OpenOrFiltered,
    Unfiltered,
    Unreachable,
    ClosedOrFiltered,
}

#[derive(Debug, Clone, Copy)]
pub struct IdleScanResults {
    pub zombie_ip_id_1: u16,
    pub zombie_ip_id_2: u16,
}

#[derive(Debug, Clone)]
pub struct ArpScanResults {
    pub alive_hosts_num: usize,
    pub alive_hosts: HashMap<Ipv4Addr, MacAddr>,
}

#[derive(Debug, Clone)]
pub struct TcpUdpScanResults {
    pub addr: IpAddr,
    pub results: HashMap<u16, TargetScanStatus>,
}

impl TcpUdpScanResults {
    pub fn new(addr: IpAddr) -> TcpUdpScanResults {
        let results = HashMap::new();
        TcpUdpScanResults { addr, results }
    }
}

impl fmt::Display for TcpUdpScanResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ip = self.addr;
        let mut result_str = String::new();
        for port in self.results.keys() {
            let str = match self.results.get(port).unwrap() {
                TargetScanStatus::Open => format!("{ip} {port} open"),
                TargetScanStatus::OpenOrFiltered => format!("{ip} {port} open|filtered"),
                TargetScanStatus::Filtered => format!("{ip} {port} filtered"),
                TargetScanStatus::Unfiltered => format!("{ip} {port} unfiltered"),
                TargetScanStatus::Closed => format!("{ip} {port} closed"),
                TargetScanStatus::Unreachable => format!("{ip} {port} unreachable"),
                TargetScanStatus::ClosedOrFiltered => format!("{ip} {port} closed|filtered"),
            };
            result_str += &str;
        }
        write!(f, "{}", result_str)
    }
}

#[derive(Debug, Clone)]
pub struct IpScanResults {
    pub addr: IpAddr,
    pub results: HashMap<IpNextHeaderProtocol, TargetScanStatus>,
}

impl IpScanResults {
    pub fn new(addr: IpAddr) -> IpScanResults {
        let results = HashMap::new();
        IpScanResults { addr, results }
    }
}

impl fmt::Display for IpScanResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ip = self.addr;
        let mut result_str = String::new();
        for protocol in self.results.keys() {
            let str = match self.results.get(protocol).unwrap() {
                TargetScanStatus::Open => format!("{ip} {protocol} open"),
                TargetScanStatus::OpenOrFiltered => format!("{ip} {protocol} open|filtered"),
                TargetScanStatus::Filtered => format!("{ip} {protocol} filtered"),
                TargetScanStatus::Unfiltered => format!("{ip} {protocol} unfiltered"),
                TargetScanStatus::Closed => format!("{ip} {protocol} closed"),
                TargetScanStatus::Unreachable => format!("{ip} {protocol} unreachable"),
                TargetScanStatus::ClosedOrFiltered => format!("{ip} {protocol} closed|filtered"),
            };
            result_str += &str;
        }
        write!(f, "{}", result_str)
    }
}

#[derive(Debug, Clone)]
pub struct Host {
    pub addr: Ipv4Addr,
    pub ports: Vec<u16>,
}

impl Host {
    pub fn new(addr: Ipv4Addr, ports: Option<Vec<u16>>) -> Host {
        match ports {
            Some(p) => Host { addr, ports: p },
            None => Host {
                addr,
                ports: vec![],
            },
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let result_str = format!("{} {:?}", self.addr, self.ports);
        write!(f, "{}", result_str)
    }
}

#[derive(Debug, Clone)]
pub struct Host6 {
    pub addr: Ipv6Addr,
    pub ports: Vec<u16>,
}

impl Host6 {
    pub fn new(addr: Ipv6Addr, ports: Option<Vec<u16>>) -> Host6 {
        match ports {
            Some(p) => Host6 { addr, ports: p },
            None => Host6 {
                addr,
                ports: vec![],
            },
        }
    }
}

impl fmt::Display for Host6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let result_str = format!("{} {:?}", self.addr, self.ports);
        write!(f, "{}", result_str)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TargetType {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub target_type: TargetType,
    pub hosts: Vec<Host>,
    pub hosts6: Vec<Host6>,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut result_str = format!("Type: {:?}", self.target_type);
        match self.target_type {
            TargetType::Ipv4 => {
                for host in &self.hosts {
                    let s = format!("\n      {}", host);
                    result_str += &s;
                }
            }
            TargetType::Ipv6 => {
                for host6 in &self.hosts6 {
                    let s = format!("\n      {}", host6);
                    result_str += &s;
                }
            }
        }

        write!(f, "{}", result_str)
    }
}

impl Target {
    /// Scan different ports for different targets,
    /// for example, we want to scan ports 22 and 23 of "192.168.1.1" and ports 80 and 81 of "192.168.1.2",
    /// you can define the address and port range of each host yourself.
    /// ```rust
    /// use pistol::{Host, Target};
    /// use std::net::{Ipv4Addr, Ipv6Addr};
    ///
    /// fn test() {
    ///     let host1 = Host::new(Ipv4Addr::new(192, 168, 72, 136), Some(vec![22, 23]));
    ///     let host2 = Host::new(Ipv4Addr::new(192, 168, 1, 2), Some(vec![80, 81]));
    ///     let target = Target::new(vec![host1, host2]);
    /// }
    /// ```
    pub fn new(hosts: Vec<Host>) -> Target {
        Target {
            target_type: TargetType::Ipv4,
            hosts: hosts.to_vec(),
            hosts6: vec![],
        }
    }
    /// Ipv6 version.
    pub fn new6(hosts6: Vec<Host6>) -> Target {
        Target {
            target_type: TargetType::Ipv6,
            hosts: vec![],
            hosts6: hosts6.to_vec(),
        }
    }
}

/// Bind IP address to interface.
#[derive(Debug, Clone)]
pub struct BindIp2Interface {
    pub ipv4: Ipv4Addr,
    pub interface: Option<NetworkInterface>,
}

impl BindIp2Interface {
    pub fn new(ip: Ipv4Addr, interface: Option<NetworkInterface>) -> BindIp2Interface {
        BindIp2Interface {
            ipv4: ip,
            interface,
        }
    }
}

/// Bind IP address to interface.
#[derive(Debug, Clone)]
pub struct BindIp2Interface6 {
    pub ipv6: Ipv6Addr,
    pub interface: Option<NetworkInterface>,
}

impl BindIp2Interface6 {
    pub fn new(ip: Ipv6Addr, interface: Option<NetworkInterface>) -> BindIp2Interface6 {
        BindIp2Interface6 {
            ipv6: ip,
            interface,
        }
    }
}

/* Scan */

/// ARP Scan.
/// This will sends ARP packets to hosts on the local network and displays any responses that are received.
/// The network interface to use can be specified with the `interface` option.
/// If this option is not present, program will search the system interface list for `subnet` user provided, configured up interface (excluding loopback).
/// By default, the ARP packets are sent to the Ethernet broadcast address, ff:ff:ff:ff:ff:ff, but that can be changed with the `destaddr` option.
/// When `threads_num` is 0, means that automatic threads pool mode is used.
pub use scan::arp_scan;

/// TCP Connect() Scan.
/// This is the most basic form of TCP scanning.
/// The connect() system call provided by your operating system is used to open a connection to every interesting port on the machine.
/// If the port is listening, connect() will succeed, otherwise the port isn't reachable.
/// One strong advantage to this technique is that you don't need any special privileges.
/// Any user on most UNIX boxes is free to use this call.
/// Another advantage is speed.
/// While making a separate connect() call for every targeted port in a linear fashion would take ages over a slow connection,
/// you can hasten the scan by using many sockets in parallel.
/// Using non-blocking I/O allows you to set a low time-out period and watch all the sockets at once.
/// This is the fastest scanning method supported by nmap, and is available with the -t (TCP) option.
/// The big downside is that this sort of scan is easily detectable and filterable.
/// The target hosts logs will show a bunch of connection and error messages for the services which take the connection and then have it immediately shutdown.
pub use scan::tcp_connect_scan;
/// Ipv6 version.
pub use scan::tcp_connect_scan6;

/// TCP SYN Scan.
/// This technique is often referred to as "half-open" scanning, because you don't open a full TCP connection.
/// You send a SYN packet, as if you are going to open a real connection and wait for a response.
/// A SYN|ACK indicates the port is listening.
/// A RST is indicative of a non-listener.
/// If a SYN|ACK is received, you immediately send a RST to tear down the connection (actually the kernel does this for us).
/// The primary advantage to this scanning technique is that fewer sites will log it.
/// Unfortunately you need root privileges to build these custom SYN packets.
/// SYN scan is the default and most popular scan option for good reason.
/// It can be performed quickly,
/// scanning thousands of ports per second on a fast network not hampered by intrusive firewalls.
/// SYN scan is relatively unobtrusive and stealthy, since it never completes TCP connections.
pub use scan::tcp_syn_scan;
/// Ipv6 version.
pub use scan::tcp_syn_scan6;

/// TCP FIN Scan.
/// There are times when even SYN scanning isn't clandestine enough.
/// Some firewalls and packet filters watch for SYNs to an unallowed port,
/// and programs like synlogger and Courtney are available to detect these scans.
/// FIN packets, on the other hand, may be able to pass through unmolested.
/// This scanning technique was featured in detail by Uriel Maimon in Phrack 49, article 15.
/// The idea is that closed ports tend to reply to your FIN packet with the proper RST.
/// Open ports, on the other hand, tend to ignore the packet in question.
/// This is a bug in TCP implementations and so it isn't 100% reliable
/// (some systems, notably Micro$oft boxes, seem to be immune).
/// When scanning systems compliant with this RFC text,
/// any packet not containing SYN, RST, or ACK bits will result in a returned RST if the port is closed and no response at all if the port is open.
/// As long as none of those three bits are included, any combination of the other three (FIN, PSH, and URG) are OK.
pub use scan::tcp_fin_scan;
/// Ipv6 version.
pub use scan::tcp_fin_scan6;

/// TCP ACK Scan.
/// This scan is different than the others discussed so far in that it never determines open (or even open|filtered) ports.
/// It is used to map out firewall rulesets, determining whether they are stateful or not and which ports are filtered.
/// When scanning unfiltered systems, open and closed ports will both return a RST packet.
/// We then labels them as unfiltered, meaning that they are reachable by the ACK packet, but whether they are open or closed is undetermined.
/// Ports that don't respond, or send certain ICMP error messages back, are labeled filtered.
pub use scan::tcp_ack_scan;
/// Ipv6 version.
pub use scan::tcp_ack_scan6;

/// TCP Null Scan.
/// Does not set any bits (TCP flag header is 0).
/// When scanning systems compliant with this RFC text,
/// any packet not containing SYN, RST, or ACK bits will result in a returned RST if the port is closed and no response at all if the port is open.
/// As long as none of those three bits are included, any combination of the other three (FIN, PSH, and URG) are OK.
pub use scan::tcp_null_scan;
/// Ipv6 version.
pub use scan::tcp_null_scan6;

/// TCP Xmas Scan.
/// Sets the FIN, PSH, and URG flags, lighting the packet up like a Christmas tree.
/// When scanning systems compliant with this RFC text,
/// any packet not containing SYN, RST, or ACK bits will result in a returned RST if the port is closed and no response at all if the port is open.
/// As long as none of those three bits are included, any combination of the other three (FIN, PSH, and URG) are OK.
pub use scan::tcp_xmas_scan;
/// Ipv6 version.
pub use scan::tcp_xmas_scan6;

/// TCP Window Scan.
/// Window scan is exactly the same as ACK scan except that it exploits an implementation detail of certain systems to differentiate open ports from closed ones,
/// rather than always printing unfiltered when a RST is returned.
/// It does this by examining the TCP Window value of the RST packets returned.
/// On some systems, open ports use a positive window size (even for RST packets) while closed ones have a zero window.
/// Window scan sends the same bare ACK probe as ACK scan.
pub use scan::tcp_window_scan;
/// Ipv6 version.
pub use scan::tcp_window_scan6;

/// TCP Maimon Scan.
/// The Maimon scan is named after its discoverer, Uriel Maimon.
/// He described the technique in Phrack Magazine issue #49 (November 1996).
/// This technique is exactly the same as NULL, FIN, and Xmas scan, except that the probe is FIN/ACK.
/// According to RFC 793 (TCP), a RST packet should be generated in response to such a probe whether the port is open or closed.
/// However, Uriel noticed that many BSD-derived systems simply drop the packet if the port is open.
pub use scan::tcp_maimon_scan;
/// Ipv6 version.
pub use scan::tcp_maimon_scan6;

/// TCP Idle Scan.
/// In 1998, security researcher Antirez (who also wrote the hping2 tool used in parts of this book) posted to the Bugtraq mailing list an ingenious new port scanning technique.
/// Idle scan, as it has become known, allows for completely blind port scanning.
/// Attackers can actually scan a target without sending a single packet to the target from their own IP address!
/// Instead, a clever side-channel attack allows for the scan to be bounced off a dumb "zombie host".
/// Intrusion detection system (IDS) reports will finger the innocent zombie as the attacker.
/// Besides being extraordinarily stealthy, this scan type permits discovery of IP-based trust relationships between machines.
pub use scan::tcp_idle_scan;

/// UDP Scan.
/// While most popular services on the Internet run over the TCP protocol, UDP services are widely deployed.
/// DNS, SNMP, and DHCP (registered ports 53, 161/162, and 67/68) are three of the most common.
/// Because UDP scanning is generally slower and more difficult than TCP, some security auditors ignore these ports.
/// This is a mistake, as exploitable UDP services are quite common and attackers certainly don't ignore the whole protocol.
/// UDP scan works by sending a UDP packet to every targeted port.
/// For most ports, this packet will be empty (no payload), but for a few of the more common ports a protocol-specific payload will be sent.
/// Based on the response, or lack thereof, the port is assigned to one of four states.
pub use scan::udp_scan;
/// Ipv6 version.
pub use scan::udp_scan6;

/// IP Protocol Scan.
/// IP protocol scan allows you to determine which IP protocols (TCP, ICMP, IGMP, etc.) are supported by target machines.
/// This isn't technically a port scan, since it cycles through IP protocol numbers rather than TCP or UDP port numbers.
pub use scan::ip_procotol_scan;

/// General scan function.
pub use scan::scan;
/// Ipv6 version.
pub use scan::scan6;

/* Ping */

/// TCP SYN Ping.
/// The function send an empty TCP packet with the SYN flag set.
/// The destination port an alternate port can be specified as a parameter.
/// A list of ports may be specified (e.g. 22-25,80,113,1050,35000), in which case probes will be attempted against each port in parallel.
pub use ping::tcp_syn_ping;
/// Ipv6 version.
pub use ping::tcp_syn_ping6;

/// TCP ACK Ping.
/// The TCP ACK ping is quite similar to the SYN ping.
/// The difference, as you could likely guess, is that the TCP ACK flag is set instead of the SYN flag.
/// Such an ACK packet purports to be acknowledging data over an established TCP connection, but no such connection exists.
/// So remote hosts should always respond with a RST packet, disclosing their existence in the process.
pub use ping::tcp_ack_ping;
/// Ipv6 version.
pub use ping::tcp_ack_ping6;

/// UDP Ping.
/// Another host discovery option is the UDP ping, which sends a UDP packet to the given ports.
/// If no ports are specified, the default is 125.
/// A highly uncommon port is used by default because sending to open ports is often undesirable for this particular scan type.
pub use ping::udp_ping;
/// Ipv6 version.
pub use ping::udp_ping6;

/// ICMP Ping.
/// In addition to the unusual TCP and UDP host discovery types discussed previously, we can send the standard packets sent by the ubiquitous ping program.
/// We sends an ICMP type 8 (echo request) packet to the target IP addresses, expecting a type 0 (echo reply) in return from available hosts.
/// As noted at the beginning of this chapter, many hosts and firewalls now block these packets, rather than responding as required by RFC 1122.
/// For this reason, ICMP-only scans are rarely reliable enough against unknown targets over the Internet.
/// But for system administrators monitoring an internal network, this can be a practical and efficient approach.
pub use ping::icmp_ping;
/// Ipv6 version.
pub use ping::icmp_ping6;

/* Flood */

/// An Internet Control Message Protocol (ICMP) flood DDoS attack, also known as a Ping flood attack,
/// is a common Denial-of-Service (DoS) attack in which an attacker attempts to overwhelm a targeted device with ICMP echo-requests (pings).
/// Normally, ICMP echo-request and echo-reply messages are used to ping a network device in order to diagnose the health and connectivity of the device and the connection between the sender and the device.
/// By flooding the target with request packets, the network is forced to respond with an equal number of reply packets. This causes the target to become inaccessible to normal traffic.
pub use flood::icmp_flood;
/// Ipv6 version.
pub use flood::icmp_flood6;

/// TCP ACK flood, or 'ACK Flood' for short, is a network DDoS attack comprising TCP ACK packets.
/// The packets will not contain a payload but may have the PSH flag enabled.
/// In the normal TCP, the ACK packets indicate to the other party that the data have been received successfully.
/// ACK packets are very common and can constitute 50% of the entire TCP packets.
/// The attack will typically affect stateful devices that must process each packet and that can be overwhelmed.
/// ACK flood is tricky to mitigate for several reasons. It can be spoofed;
/// the attacker can easily generate a high rate of attacking traffic,
/// and it is very difficult to distinguish between a Legitimate ACK and an attacking ACK, as they look the same.
pub use flood::tcp_ack_flood;
/// Ipv6 version.
pub use flood::tcp_ack_flood6;

/// TCP ACK flood with PSH flag set.
pub use flood::tcp_ack_psh_flood;
/// Ipv6 version.
pub use flood::tcp_ack_psh_flood6;

/// In a TCP SYN Flood attack, the malicious entity sends a barrage of SYN requests to a target server but intentionally avoids sending the final ACK.
/// This leaves the server waiting for a response that never comes, consuming resources for each of these half-open connections.
pub use flood::tcp_syn_flood;
/// Ipv6 version.
pub use flood::tcp_syn_flood6;

/// In a UDP Flood attack, the attacker sends a massive number of UDP packets to random ports on the target host.
/// This barrage of packets forces the host to:
/// Check for applications listening at each port.
/// Realize that no application is listening at many of these ports.
/// Respond with an Internet Control Message Protocol (ICMP) Destination Unreachable packet.
pub use flood::udp_flood;
/// Ipv6 version.
pub use flood::udp_flood6;

/* Finger Printing */

/// Nmap OS DB Parser.
/// Process standard nmap-os-db files and return a structure that can be processed by the program.
pub use fingerprinting::dbparser::nmap_os_db_parser;

/// Load our processed files `nmap-os-db.pistol`.
pub use fingerprinting::dbparser::nmap_os_db_pistol_load;

/// Detect target machine OS.
pub use fingerprinting::osscan::os_detect;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use subnetwork::Ipv4Pool;
    #[test]
    fn test_target_print() {
        let host1 = Host::new(Ipv4Addr::new(192, 168, 72, 136), Some(vec![22, 23]));
        let host2 = Host::new(Ipv4Addr::new(192, 168, 1, 2), Some(vec![80, 81]));
        let target = Target::new(vec![host1, host2]);
        println!("{}", target);
    }
    #[test]
    fn test_arp_scan_subnet() {
        let interface: Option<&str> = Some("ens33");
        let subnet: Ipv4Pool = Ipv4Pool::from("192.168.72.0/24").unwrap();
        let mut hosts = vec![];
        for ip in subnet {
            let host = Host::new(ip, None);
            hosts.push(host);
        }
        let target: Target = Target::new(hosts);
        let dst_mac = None;
        let threads_num = 16;
        let max_loop = Some(8);
        let print_result = true;
        // let print_result = false;
        let rets: ArpScanResults = match arp_scan(
            target,
            dst_mac,
            interface,
            threads_num,
            print_result,
            max_loop,
        ) {
            Ok(r) => r,
            Err(e) => panic!("{}", e),
        };
        println!("{:?}", rets);
    }
    #[test]
    fn test_tcp_connect_scan() {
        let src_ipv4: Option<Ipv4Addr> = Some(Ipv4Addr::new(192, 168, 72, 128));
        let src_port: Option<u16> = None;
        let dst_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 72, 136);
        // let interface: Option<&str> = Some("eno1");
        let interface: Option<&str> = None;
        let print_result: bool = true;
        let threads_num: usize = 8;
        let timeout: Option<Duration> = Some(Duration::from_secs_f32(0.5));
        let max_loop: Option<usize> = Some(8);
        let host = Host::new(dst_ipv4, Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let ret: HashMap<IpAddr, TcpUdpScanResults> = match tcp_connect_scan(
            target,
            src_ipv4,
            src_port,
            interface,
            print_result,
            threads_num,
            timeout,
            max_loop,
        ) {
            Ok(r) => r,
            Err(e) => panic!("{}", e),
        };
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_syn_scan() {
        let src_ipv4: Option<Ipv4Addr> = Some(Ipv4Addr::new(192, 168, 72, 128));
        let src_port: Option<u16> = None;
        let dst_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 72, 136);
        // let interface: Option<&str> = Some("eno1");
        let interface: Option<&str> = None;
        let print_result: bool = true;
        let threads_num: usize = 8;
        let timeout: Option<Duration> = Some(Duration::from_secs_f32(0.5));
        let max_loop: Option<usize> = Some(8);
        let host = Host::new(dst_ipv4, Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let ret: HashMap<IpAddr, TcpUdpScanResults> = match tcp_syn_scan(
            target,
            src_ipv4,
            src_port,
            interface,
            print_result,
            threads_num,
            timeout,
            max_loop,
        ) {
            Ok(r) => r,
            Err(e) => panic!("{}", e),
        };
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_fin_scan() {
        let src_ipv4: Option<Ipv4Addr> = Some(Ipv4Addr::new(192, 168, 72, 128));
        let src_port: Option<u16> = None;
        let dst_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 72, 136);
        // let interface: Option<&str> = Some("eno1");
        let interface: Option<&str> = None;
        let print_result: bool = true;
        let threads_num: usize = 8;
        let timeout: Option<Duration> = Some(Duration::from_secs_f32(0.5));
        let max_loop: Option<usize> = Some(8);
        let host = Host::new(dst_ipv4, Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let ret: HashMap<IpAddr, TcpUdpScanResults> = match tcp_fin_scan(
            target,
            src_ipv4,
            src_port,
            interface,
            print_result,
            threads_num,
            timeout,
            max_loop,
        ) {
            Ok(r) => r,
            Err(e) => panic!("{}", e),
        };
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_ack_scan() {
        let src_ipv4: Option<Ipv4Addr> = Some(Ipv4Addr::new(192, 168, 72, 128));
        let src_port: Option<u16> = None;
        let dst_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 72, 136);
        // let interface: Option<&str> = Some("eno1");
        let interface: Option<&str> = None;
        let print_result: bool = true;
        let threads_num: usize = 8;
        let timeout: Option<Duration> = Some(Duration::from_secs_f32(0.5));
        let max_loop: Option<usize> = Some(8);
        let host = Host::new(dst_ipv4, Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let ret: HashMap<IpAddr, TcpUdpScanResults> = match tcp_ack_scan(
            target,
            src_ipv4,
            src_port,
            interface,
            print_result,
            threads_num,
            timeout,
            max_loop,
        ) {
            Ok(r) => r,
            Err(e) => panic!("{}", e),
        };
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_null_scan() {
        let src_ipv4: Option<Ipv4Addr> = Some(Ipv4Addr::new(192, 168, 72, 128));
        let src_port: Option<u16> = None;
        let dst_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 72, 136);
        // let interface: Option<&str> = Some("eno1");
        let interface: Option<&str> = None;
        let print_result: bool = true;
        let threads_num: usize = 8;
        let timeout: Option<Duration> = Some(Duration::from_secs_f32(0.5));
        let max_loop: Option<usize> = Some(8);
        let host = Host::new(dst_ipv4, Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let ret: HashMap<IpAddr, TcpUdpScanResults> = match tcp_null_scan(
            target,
            src_ipv4,
            src_port,
            interface,
            print_result,
            threads_num,
            timeout,
            max_loop,
        ) {
            Ok(r) => r,
            Err(e) => panic!("{}", e),
        };
        println!("{:?}", ret);
    }
    #[test]
    fn test_udp_scan() {
        let src_ipv4: Option<Ipv4Addr> = Some(Ipv4Addr::new(192, 168, 72, 128));
        let src_port: Option<u16> = None;
        let dst_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 72, 136);
        // let interface: Option<&str> = Some("eno1");
        let interface: Option<&str> = None;
        let print_result: bool = true;
        let threads_num: usize = 8;
        let timeout: Option<Duration> = Some(Duration::from_secs_f32(0.5));
        let max_loop: Option<usize> = Some(8);
        let host = Host::new(dst_ipv4, Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let ret: HashMap<IpAddr, TcpUdpScanResults> = match udp_scan(
            target,
            src_ipv4,
            src_port,
            interface,
            print_result,
            threads_num,
            timeout,
            max_loop,
        ) {
            Ok(r) => r,
            Err(e) => panic!("{}", e),
        };
        println!("{:?}", ret);
    }
    #[test]
    fn test_ip_scan() {
        use pnet::packet::ip::IpNextHeaderProtocols;
        let protocol = Some(IpNextHeaderProtocols::Udp);

        let src_ipv4: Option<Ipv4Addr> = Some(Ipv4Addr::new(192, 168, 72, 128));
        let src_port: Option<u16> = None;
        let dst_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 72, 136);
        // let interface: Option<&str> = Some("eno1");
        let interface: Option<&str> = None;
        let print_result: bool = true;
        let threads_num: usize = 8;
        let timeout: Option<Duration> = Some(Duration::from_secs_f32(0.5));
        let max_loop: Option<usize> = Some(8);
        let host = Host::new(dst_ipv4, Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let ret: HashMap<IpAddr, IpScanResults> = match ip_procotol_scan(
            target,
            src_ipv4,
            src_port,
            protocol,
            interface,
            print_result,
            threads_num,
            timeout,
            max_loop,
        ) {
            Ok(r) => r,
            Err(e) => panic!("{}", e),
        };
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_syn_ping() {
        let src_ipv4: Option<Ipv4Addr> = Some(Ipv4Addr::new(192, 168, 72, 128));
        let src_port: Option<u16> = None;
        let dst_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 72, 136);
        // let interface: Option<&str> = Some("eno1");
        let interface: Option<&str> = None;
        let print_result: bool = true;
        let threads_num: usize = 8;
        let timeout: Option<Duration> = Some(Duration::from_secs_f32(0.5));
        let max_loop: Option<usize> = Some(8);
        let host = Host::new(dst_ipv4, Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let ret = match tcp_syn_ping(
            target,
            src_ipv4,
            src_port,
            interface,
            threads_num,
            print_result,
            timeout,
            max_loop,
        ) {
            Ok(r) => r,
            Err(e) => panic!("{}", e),
        };
        println!("{:?}", ret);
    }
    #[test]
    fn test_icmp_ping() {
        let src_ipv4: Option<Ipv4Addr> = Some(Ipv4Addr::new(192, 168, 72, 128));
        let src_port: Option<u16> = None;
        let dst_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 72, 136);
        // let interface: Option<&str> = Some("eno1");
        let interface: Option<&str> = None;
        let print_result: bool = true;
        let threads_num: usize = 8;
        let timeout: Option<Duration> = Some(Duration::from_secs_f32(0.5));
        let max_loop: Option<usize> = Some(8);
        let host = Host::new(dst_ipv4, Some(vec![22, 99]));
        let target: Target = Target::new(vec![host]);
        let ret = match icmp_ping(
            target,
            src_ipv4,
            src_port,
            interface,
            threads_num,
            print_result,
            timeout,
            max_loop,
        ) {
            Ok(r) => r,
            Err(e) => panic!("{}", e),
        };
        println!("{:?}", ret);
    }
}
