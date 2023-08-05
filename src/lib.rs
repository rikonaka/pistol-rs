#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("lib.md")]
use pnet::datalink::MacAddr;
use pnet::packet::ip::IpNextHeaderProtocol;
use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;

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
    pub addr: Ipv4Addr,
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
pub enum IpScanStatus {
    Open,
    Closed,
    Filtered,
    OpenOrFiltered,
}

#[derive(Debug, Clone, Copy)]
pub enum TcpScanStatus {
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

#[derive(Debug, Clone, Copy)]
pub enum UdpScanStatus {
    Open,
    Closed,
    Filtered,
    OpenOrFiltered,
}

#[derive(Debug, Clone)]
pub struct ArpScanResults {
    pub alive_hosts_num: usize,
    pub alive_hosts: HashMap<Ipv4Addr, Option<MacAddr>>,
}

#[derive(Debug, Clone)]
pub struct TcpScanResults {
    pub addr: Ipv4Addr,
    pub results: HashMap<u16, TcpScanStatus>,
}

impl TcpScanResults {
    pub fn new(addr: Ipv4Addr) -> TcpScanResults {
        let results = HashMap::new();
        TcpScanResults { addr, results }
    }
}

impl fmt::Display for TcpScanResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ip = self.addr;
        let mut result_str = String::new();
        for port in self.results.keys() {
            let str = match self.results.get(port).unwrap() {
                TcpScanStatus::Open => format!("{ip} {port} open"),
                TcpScanStatus::OpenOrFiltered => format!("{ip} {port} open|filtered"),
                TcpScanStatus::Filtered => format!("{ip} {port} filtered"),
                TcpScanStatus::Unfiltered => format!("{ip} {port} unfiltered"),
                TcpScanStatus::Closed => format!("{ip} {port} closed"),
                TcpScanStatus::Unreachable => format!("{ip} {port} unreachable"),
                TcpScanStatus::ClosedOrFiltered => format!("{ip} {port} closed|filtered"),
            };
            result_str += &str;
        }
        write!(f, "{}", result_str)
    }
}

#[derive(Debug, Clone)]
pub struct IpScanResults {
    pub addr: Ipv4Addr,
    pub results: HashMap<IpNextHeaderProtocol, IpScanStatus>,
}

impl IpScanResults {
    pub fn new(addr: Ipv4Addr) -> IpScanResults {
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
                IpScanStatus::Open => format!("{ip} {protocol} open"),
                IpScanStatus::Filtered => format!("{ip} {protocol} filtered"),
                IpScanStatus::OpenOrFiltered => format!("{ip} {protocol} open|filtered"),
                IpScanStatus::Closed => format!("{ip} {protocol} closed"),
            };
            result_str += &str;
        }
        write!(f, "{}", result_str)
    }
}

#[derive(Debug, Clone)]
pub struct UdpScanResults {
    pub addr: Ipv4Addr,
    pub results: HashMap<u16, UdpScanStatus>,
}

impl UdpScanResults {
    pub fn new(addr: Ipv4Addr) -> UdpScanResults {
        let results = HashMap::new();
        UdpScanResults { addr, results }
    }
}

impl fmt::Display for UdpScanResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ip = self.addr;
        let mut result_str = String::new();
        for port in self.results.keys() {
            let str = match self.results.get(port).unwrap() {
                UdpScanStatus::Open => format!("{ip} {port} open"),
                UdpScanStatus::OpenOrFiltered => format!("{ip} {port} open|filtered"),
                UdpScanStatus::Filtered => format!("{ip} {port} filtered"),
                UdpScanStatus::Closed => format!("{ip} {port} closed"),
            };
            result_str += &str;
        }
        write!(f, "{}", result_str)
    }
}

/* Scan */

/// ARP Scan.
/// This will sends ARP packets to hosts on the local network and displays any responses that are received.
/// The network interface to use can be specified with the `interface` option.
/// If this option is not present, program will search the system interface list for `subnet` user provided, configured up interface (excluding loopback).
/// By default, the ARP packets are sent to the Ethernet broadcast address, ff:ff:ff:ff:ff:ff, but that can be changed with the `destaddr` option.
/// When `threads_num` is 0, means that automatic threads pool mode is used.
pub use scan::arp_scan_subnet;

pub use scan::tcp_connect_scan_range_port;
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
pub use scan::tcp_connect_scan_single_port;
pub use scan::tcp_connect_scan_subnet;

pub use scan::tcp_syn_scan_range_port;
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
pub use scan::tcp_syn_scan_single_port;
pub use scan::tcp_syn_scan_subnet;

pub use scan::tcp_fin_scan_range_port;
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
pub use scan::tcp_fin_scan_single_port;
pub use scan::tcp_fin_scan_subnet;

pub use scan::tcp_ack_scan_range_port;
/// TCP ACK Scan.
/// This scan is different than the others discussed so far in that it never determines open (or even open|filtered) ports.
/// It is used to map out firewall rulesets, determining whether they are stateful or not and which ports are filtered.
/// When scanning unfiltered systems, open and closed ports will both return a RST packet.
/// We then labels them as unfiltered, meaning that they are reachable by the ACK packet, but whether they are open or closed is undetermined.
/// Ports that don't respond, or send certain ICMP error messages back, are labeled filtered.
pub use scan::tcp_ack_scan_single_port;
pub use scan::tcp_ack_scan_subnet;

pub use scan::tcp_null_scan_range_port;
/// TCP Null Scan.
/// Does not set any bits (TCP flag header is 0).
/// When scanning systems compliant with this RFC text,
/// any packet not containing SYN, RST, or ACK bits will result in a returned RST if the port is closed and no response at all if the port is open.
/// As long as none of those three bits are included, any combination of the other three (FIN, PSH, and URG) are OK.
pub use scan::tcp_null_scan_single_port;
pub use scan::tcp_null_scan_subnet;

pub use scan::tcp_xmas_scan_range_port;
/// TCP Xmas Scan.
/// Sets the FIN, PSH, and URG flags, lighting the packet up like a Christmas tree.
/// When scanning systems compliant with this RFC text,
/// any packet not containing SYN, RST, or ACK bits will result in a returned RST if the port is closed and no response at all if the port is open.
/// As long as none of those three bits are included, any combination of the other three (FIN, PSH, and URG) are OK.
pub use scan::tcp_xmas_scan_single_port;
pub use scan::tcp_xmas_scan_subnet;

pub use scan::tcp_window_scan_range_port;
/// TCP Window Scan.
/// Window scan is exactly the same as ACK scan except that it exploits an implementation detail of certain systems to differentiate open ports from closed ones,
/// rather than always printing unfiltered when a RST is returned.
/// It does this by examining the TCP Window value of the RST packets returned.
/// On some systems, open ports use a positive window size (even for RST packets) while closed ones have a zero window.
/// Window scan sends the same bare ACK probe as ACK scan.
pub use scan::tcp_window_scan_single_port;
pub use scan::tcp_window_scan_subnet;

pub use scan::tcp_maimon_scan_range_port;
/// TCP Maimon Scan.
/// The Maimon scan is named after its discoverer, Uriel Maimon.
/// He described the technique in Phrack Magazine issue #49 (November 1996).
/// This technique is exactly the same as NULL, FIN, and Xmas scan, except that the probe is FIN/ACK.
/// According to RFC 793 (TCP), a RST packet should be generated in response to such a probe whether the port is open or closed.
/// However, Uriel noticed that many BSD-derived systems simply drop the packet if the port is open.
pub use scan::tcp_maimon_scan_single_port;
pub use scan::tcp_maimon_scan_subnet;

pub use scan::tcp_idle_scan_range_port;
/// TCP Idle Scan.
/// In 1998, security researcher Antirez (who also wrote the hping2 tool used in parts of this book) posted to the Bugtraq mailing list an ingenious new port scanning technique.
/// Idle scan, as it has become known, allows for completely blind port scanning.
/// Attackers can actually scan a target without sending a single packet to the target from their own IP address!
/// Instead, a clever side-channel attack allows for the scan to be bounced off a dumb "zombie host".
/// Intrusion detection system (IDS) reports will finger the innocent zombie as the attacker.
/// Besides being extraordinarily stealthy, this scan type permits discovery of IP-based trust relationships between machines.
pub use scan::tcp_idle_scan_single_port;
pub use scan::tcp_idle_scan_subnet;

pub use scan::udp_scan_range_port;
/// UDP Scan.
/// While most popular services on the Internet run over the TCP protocol, UDP services are widely deployed.
/// DNS, SNMP, and DHCP (registered ports 53, 161/162, and 67/68) are three of the most common.
/// Because UDP scanning is generally slower and more difficult than TCP, some security auditors ignore these ports.
/// This is a mistake, as exploitable UDP services are quite common and attackers certainly don't ignore the whole protocol.
/// UDP scan works by sending a UDP packet to every targeted port.
/// For most ports, this packet will be empty (no payload), but for a few of the more common ports a protocol-specific payload will be sent.
/// Based on the response, or lack thereof, the port is assigned to one of four states.
pub use scan::udp_scan_single_port;
pub use scan::udp_scan_subnet;

pub use scan::ip_procotol_scan_subnet;
/// IP Protocol Scan.
/// IP protocol scan allows you to determine which IP protocols (TCP, ICMP, IGMP, etc.) are supported by target machines.
/// This isn't technically a port scan, since it cycles through IP protocol numbers rather than TCP or UDP port numbers.
pub use scan::ip_protocol_scan_host;

/* Ping */

/// TCP SYN Ping.
/// The function send an empty TCP packet with the SYN flag set.
/// The destination port an alternate port can be specified as a parameter.
/// A list of ports may be specified (e.g. 22-25,80,113,1050,35000), in which case probes will be attempted against each port in parallel.
pub use ping::tcp_syn_ping_host;
pub use ping::tcp_syn_ping_subnet;

/// TCP ACK Ping.
/// The TCP ACK ping is quite similar to the SYN ping.
/// The difference, as you could likely guess, is that the TCP ACK flag is set instead of the SYN flag.
/// Such an ACK packet purports to be acknowledging data over an established TCP connection, but no such connection exists.
/// So remote hosts should always respond with a RST packet, disclosing their existence in the process.
pub use ping::tcp_ack_ping_host;
pub use ping::tcp_ack_ping_subnet;

/// UDP Ping.
/// Another host discovery option is the UDP ping, which sends a UDP packet to the given ports.
/// If no ports are specified, the default is 125.
/// A highly uncommon port is used by default because sending to open ports is often undesirable for this particular scan type.
pub use ping::udp_ping_host;
pub use ping::udp_ping_subnet;

/// ICMP Ping.
/// In addition to the unusual TCP and UDP host discovery types discussed previously, we can send the standard packets sent by the ubiquitous ping program.
/// We sends an ICMP type 8 (echo request) packet to the target IP addresses, expecting a type 0 (echo reply) in return from available hosts.
/// As noted at the beginning of this chapter, many hosts and firewalls now block these packets, rather than responding as required by RFC 1122.
/// For this reason, ICMP-only scans are rarely reliable enough against unknown targets over the Internet.
/// But for system administrators monitoring an internal network, this can be a practical and efficient approach.
pub use ping::icmp_ping_host;
pub use ping::icmp_ping_subnet;

/* Flood */

pub use flood::icmp_flood_host;
pub use flood::tcp_ack_flood_host;
pub use flood::tcp_syn_flood_host;
pub use flood::udp_flood_host;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use subnetwork::Ipv4Pool;
    #[test]
    fn test_arp_scan_subnet() {
        let interface = Some("ens33");
        let subnet = Ipv4Pool::new("192.168.72.0/24").unwrap();
        let rets = arp_scan_subnet(subnet, None, interface, 0, true, None).unwrap();
        println!("{:?}", rets);
    }
    #[test]
    fn test_tcp_connect_scan_single_port() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let src_port = None;
        let dst_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 72, 136);
        let dst_port: u16 = 80;
        // let interface: Option<&str> = Some("eno1");
        let interface: Option<&str> = None;
        let print_result: bool = true;
        let ret = tcp_connect_scan_single_port(
            src_ipv4,
            src_port,
            dst_ipv4,
            dst_port,
            interface,
            print_result,
            None,
            None,
        )
        .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_connect_scan_range_port() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let src_port = None;
        let dst_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 3);
        let start_port: u16 = 1;
        let end_port: u16 = 100;
        // let interface: Option<&str> = Some("eno1");
        let interface = None;
        let threads_num = 0;
        let print_result: bool = true;
        let max_loop = Some(8);
        let ret = tcp_connect_scan_range_port(
            src_ipv4,
            src_port,
            dst_ipv4,
            start_port,
            end_port,
            interface,
            threads_num,
            print_result,
            None,
            max_loop,
        )
        .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_connect_scan_subnet() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let src_port = None;
        let subnet: Ipv4Pool = Ipv4Pool::new("192.168.1.0/30").unwrap();
        let start_port: u16 = 80;
        let end_port: u16 = 82;
        // let interface: Option<&str> = Some("eno1");
        let interface = None;
        let threads_num: usize = 0;
        let print_result: bool = true;
        let max_loop = Some(8);
        let ret = tcp_connect_scan_subnet(
            src_ipv4,
            src_port,
            subnet,
            start_port,
            end_port,
            interface,
            threads_num,
            print_result,
            None,
            max_loop,
        )
        .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_syn_scan_single_port() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let src_port = None;
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        // let i = Some("eno1");
        let i = None;
        let max_loop = Some(64);
        let ret =
            tcp_syn_scan_single_port(src_ipv4, src_port, dst_ipv4, 80, i, true, None, max_loop)
                .unwrap();
        println!("{:?}", ret);
        let ret =
            tcp_syn_scan_single_port(src_ipv4, src_port, dst_ipv4, 9999, i, true, None, max_loop)
                .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_syn_scan_range_port() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let src_port = None;
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        // let i = Some("eno1");
        let i = None;
        let ret =
            tcp_syn_scan_range_port(src_ipv4, src_port, dst_ipv4, 22, 90, i, 0, true, None, None)
                .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_syn_scan_subnet() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let src_port = None;
        let subnet = Ipv4Pool::new("192.168.1.0/30").unwrap();
        // let i = Some("eno1");
        let i = None;
        let max_loop = Some(64);
        let ret = tcp_syn_scan_subnet(
            src_ipv4, src_port, subnet, 80, 82, i, 0, true, None, max_loop,
        )
        .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_fin_scan_single_port() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let src_port = None;
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        // let i = Some("eno1");
        let i = None;
        let ret = tcp_fin_scan_single_port(src_ipv4, src_port, dst_ipv4, 80, i, true, None, None)
            .unwrap();
        println!("{:?}", ret);
        let ret = tcp_fin_scan_single_port(src_ipv4, src_port, dst_ipv4, 9999, i, true, None, None)
            .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_fin_scan_range_port() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let src_port = None;
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        // let i = Some("eno1");
        let i = None;
        let ret =
            tcp_fin_scan_range_port(src_ipv4, src_port, dst_ipv4, 22, 90, i, 0, true, None, None)
                .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_fin_scan_subnet() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let src_port = None;
        let subnet = Ipv4Pool::new("192.168.1.0/30").unwrap();
        // let i = Some("eno1");
        let i = None;
        let max_loop = Some(64);
        let ret = tcp_fin_scan_subnet(
            src_ipv4, src_port, subnet, 80, 82, i, 0, true, None, max_loop,
        )
        .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_ack_scan_single_port() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let src_port = None;
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        // let i = Some("eno1");
        let i = None;
        let ret = tcp_ack_scan_single_port(src_ipv4, src_port, dst_ipv4, 80, i, true, None, None)
            .unwrap();
        println!("{:?}", ret);
        let ret = tcp_ack_scan_single_port(src_ipv4, src_port, dst_ipv4, 9999, i, true, None, None)
            .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_ack_scan_range_port() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let src_port = None;
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        // let i = Some("eno1");
        let i = None;
        let ret =
            tcp_ack_scan_range_port(src_ipv4, src_port, dst_ipv4, 22, 90, i, 0, true, None, None)
                .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_ack_scan_subnet() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let src_port = None;
        let subnet = Ipv4Pool::new("192.168.1.0/30").unwrap();
        // let i = Some("eno1");
        let i = None;
        let max_loop = Some(64);
        let ret = tcp_ack_scan_subnet(
            src_ipv4, src_port, subnet, 80, 82, i, 0, true, None, max_loop,
        )
        .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_null_scan_single_port() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let src_port = None;
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        // let i = Some("eno1");
        let i = None;
        let ret = tcp_null_scan_single_port(src_ipv4, src_port, dst_ipv4, 81, i, true, None, None)
            .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_null_scan_range_port() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let src_port = None;
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        // let i = Some("eno1");
        let i = None;
        let ret =
            tcp_null_scan_range_port(src_ipv4, src_port, dst_ipv4, 22, 90, i, 0, true, None, None)
                .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_null_scan_subnet() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let src_port = None;
        let subnet = Ipv4Pool::new("192.168.1.0/30").unwrap();
        // let i = Some("eno1");
        let i = None;
        let max_loop = Some(64);
        let ret = tcp_null_scan_subnet(
            src_ipv4, src_port, subnet, 80, 82, i, 0, true, None, max_loop,
        )
        .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_udp_scan_single_port() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let src_port = None;
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        // let i = Some("eno1");
        let i = None;
        let ret =
            udp_scan_single_port(src_ipv4, src_port, dst_ipv4, 53, i, true, None, None).unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_udp_scan_range_port() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let src_port = None;
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        // let i = Some("eno1");
        let i = None;
        let ret = udp_scan_range_port(src_ipv4, src_port, dst_ipv4, 22, 90, i, 0, true, None, None)
            .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_udp_scan_subnet() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let src_port = None;
        let subnet = Ipv4Pool::new("192.168.1.0/30").unwrap();
        // let i = Some("eno1");
        let i = None;
        let max_loop = Some(64);
        let ret = udp_scan_subnet(
            src_ipv4, src_port, subnet, 80, 82, i, 0, true, None, max_loop,
        )
        .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_ip_scan_host() {
        use pnet::packet::ip::IpNextHeaderProtocols;
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        // let i = Some("eno1");
        let i = None;
        let max_loop = None;
        let protocol = IpNextHeaderProtocols::Udp;
        let ret =
            ip_protocol_scan_host(src_ipv4, dst_ipv4, protocol, i, true, None, max_loop).unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_syn_ping_host() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        let i = None;
        let max_loop = None;
        let ret =
            tcp_syn_ping_host(src_ipv4, None, dst_ipv4, None, i, true, None, max_loop).unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_tcp_syn_ping_subnet() {
        let src_ipv4 = None;
        let subnet = Ipv4Pool::new("192.168.1.0/29").unwrap();
        let i = Some("ens33");
        let max_loop = Some(16);
        let ret =
            tcp_syn_ping_subnet(src_ipv4, None, None, subnet, i, 0, true, None, max_loop).unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_icmp_ping_host() {
        let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
        let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
        let i = None;
        let max_loop = None;
        let ret = icmp_ping_host(src_ipv4, None, dst_ipv4, None, i, true, None, max_loop).unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_icmp_ping_subnet() {
        let src_ipv4 = None;
        let subnet = Ipv4Pool::new("192.168.1.0/24").unwrap();
        let i = Some("ens33");
        let timeout = Some(Duration::from_secs_f32(0.5));
        let max_loop = Some(4);
        let ret =
            icmp_ping_subnet(src_ipv4, None, None, subnet, i, 32, true, timeout, max_loop).unwrap();
        println!("{:?}", ret);
    }
}
