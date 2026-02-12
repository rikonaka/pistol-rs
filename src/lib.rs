#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("lib.md")]
use bitcode::Decode;
use bitcode::Encode;
use chrono::DateTime;
use chrono::Local;
use crossbeam::channel::Receiver;
use crossbeam::channel::Sender;
use crossbeam::channel::unbounded;
use dns_lookup::lookup_host;
use pcapture::Capture;
#[cfg(feature = "scan")]
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::datalink::interfaces;
#[cfg(feature = "debug")]
use pnet::packet::Packet;
#[cfg(feature = "debug")]
use pnet::packet::ethernet::EtherType;
#[cfg(feature = "debug")]
use pnet::packet::ethernet::EtherTypes;
#[cfg(feature = "debug")]
use pnet::packet::ethernet::EthernetPacket;
#[cfg(feature = "debug")]
use pnet::packet::ip::IpNextHeaderProtocols;
#[cfg(feature = "debug")]
use pnet::packet::ipv4::Ipv4Packet;
#[cfg(feature = "debug")]
use pnet::packet::ipv6::Ipv6Packet;
#[cfg(feature = "debug")]
use pnet::packet::tcp::TcpPacket;
#[cfg(feature = "debug")]
use pnet::packet::udp::UdpPacket;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::net::IpAddr;
#[cfg(feature = "os")]
use std::net::Ipv4Addr;
#[cfg(feature = "os")]
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use subnetwork::Ipv4Pool;
use subnetwork::Ipv6Pool;
use tracing::Level;
use tracing::debug;
use tracing::error;
use tracing::warn;
use tracing_subscriber::FmtSubscriber;

mod error;
mod flood;
mod layer;
mod os;
mod ping;
mod route;
mod scan;
mod trace;
mod utils;
mod vs;

use crate::error::PistolError;
#[cfg(feature = "flood")]
use crate::flood::PistolFloods;
use crate::layer::PacketFilter;
#[cfg(feature = "os")]
use crate::os::OsDetect;
#[cfg(feature = "os")]
use crate::os::PistolOsDetects;
#[cfg(feature = "os")]
use crate::os::dbparser::NmapOsDb;
#[cfg(feature = "ping")]
use crate::ping::HostPings;
#[cfg(feature = "ping")]
use crate::ping::PingStatus;
use crate::route::SystemNetCache;
use crate::route::infer_addr;
use crate::route::infer_mac;
#[cfg(feature = "scan")]
use crate::scan::MacScans;
#[cfg(feature = "scan")]
use crate::scan::PortScan;
#[cfg(feature = "scan")]
use crate::scan::PortScans;
#[cfg(feature = "vs")]
use crate::vs::PistolVsScans;
#[cfg(feature = "vs")]
use crate::vs::PortService;

pub type Result<T, E = error::PistolError> = std::result::Result<T, E>;

/// In order to reduce multiple neighbor detection in a multi-threaded environment.
static NEIGHBOR_DETECT_MUTEX: LazyLock<Arc<Mutex<HashMap<IpAddr, Arc<Mutex<()>>>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

/// Cache the network information of the program runtime process to avoid repeated calculations.
static GLOBAL_NET_CACHES: LazyLock<Arc<Mutex<NetCache>>> = LazyLock::new(|| {
    debug!("create a new network cache");
    let nc = match NetCache::load() {
        Some(nc) => {
            debug!("load network cache from file: {:?}", nc);
            nc
        }
        None => {
            debug!("create a new network cache");
            NetCache {
                system_network_cache: SystemNetCache::init()
                    .expect("can not init the system net cache"),
                created_at: Local::now(),
            }
        }
    };
    Arc::new(Mutex::new(nc))
});

const NETWORK_CACHE_PATH: &str = ".plnetcache";
// When the cache is created more than 1 hour ago,
// it will be considered expired and will be deleted.
const NETWORK_CACHE_EXPIRE_HOURS: i64 = 1;

/// Cache the network information of the program runtime process to avoid repeated calculations.
#[derive(Debug, Clone, Deserialize, Serialize)]
struct NetCache {
    system_network_cache: SystemNetCache,
    created_at: DateTime<Local>,
}

impl NetCache {
    pub(crate) fn load() -> Option<Self> {
        let nc_bytes = match fs::read(NETWORK_CACHE_PATH) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!(
                    "failed to read network cache from file, create a new one: {}",
                    e
                );
                return None;
            }
        };

        let nc: NetCache = match bitcode::deserialize(&nc_bytes) {
            Ok(v) => v,
            Err(e) => {
                debug!("failed to parse network cache from file: {}, delete it", e);
                fs::remove_file(NETWORK_CACHE_PATH).expect("delete invalid network cache failed");
                return None;
            }
        };

        let now = Local::now();
        let duration = now - nc.created_at;
        if duration.num_hours() < NETWORK_CACHE_EXPIRE_HOURS {
            debug!("load network cache from file: {:?}", nc);
            Some(nc)
        } else {
            debug!("network cache is expired, delete it");
            fs::remove_file(NETWORK_CACHE_PATH).expect("delete expired network cache failed");
            None
        }
    }
}

/// debug code
#[cfg(feature = "debug")]
fn debug_show_packet(ethernet_packet: &[u8], show_ether_type: Option<EtherType>) {
    let ethernet_packet = match EthernetPacket::new(&ethernet_packet) {
        Some(ethernet_packet) => ethernet_packet,
        None => return,
    };
    let ether_type = ethernet_packet.get_ethertype();
    let show_flag = match show_ether_type {
        Some(t) => {
            if t == ether_type {
                true
            } else {
                false
            }
        }
        None => true,
    };
    if show_flag {
        match ether_type {
            EtherTypes::Ipv4 => {
                let ipv4_packet = match Ipv4Packet::new(ethernet_packet.payload()) {
                    Some(i) => i,
                    None => return,
                };
                let ip_payload = ipv4_packet.payload();
                match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp_packet = match TcpPacket::new(ip_payload) {
                            Some(tcp_packet) => tcp_packet,
                            None => return,
                        };
                        println!(
                            "[PACKET] {}, {}:{} -> {}:{}, len {}",
                            ether_type.to_string().to_lowercase(),
                            ipv4_packet.get_source(),
                            tcp_packet.get_source(),
                            ipv4_packet.get_destination(),
                            tcp_packet.get_destination(),
                            ethernet_packet.packet().len(),
                        );
                    }
                    IpNextHeaderProtocols::Udp => {
                        let udp_packet = match UdpPacket::new(ip_payload) {
                            Some(udp_packet) => udp_packet,
                            None => return,
                        };
                        println!(
                            "[PACKET] {}, {}:{} -> {}:{}, len {}",
                            ether_type.to_string().to_lowercase(),
                            ipv4_packet.get_source(),
                            udp_packet.get_source(),
                            ipv4_packet.get_destination(),
                            udp_packet.get_destination(),
                            ethernet_packet.packet().len(),
                        );
                    }
                    _ => return,
                }
            }
            EtherTypes::Ipv6 => {
                let ipv6_packet = match Ipv6Packet::new(ethernet_packet.payload()) {
                    Some(i) => i,
                    None => return,
                };
                let ip_payload = ipv6_packet.payload();
                match ipv6_packet.get_next_header() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp_packet = match TcpPacket::new(ip_payload) {
                            Some(tcp_packet) => tcp_packet,
                            None => return,
                        };
                        println!(
                            "[PACKET] {}, {}:{} -> {}:{}, len {}",
                            ether_type.to_string().to_lowercase(),
                            ipv6_packet.get_source(),
                            tcp_packet.get_source(),
                            ipv6_packet.get_destination(),
                            tcp_packet.get_destination(),
                            ethernet_packet.packet().len(),
                        );
                    }
                    IpNextHeaderProtocols::Udp => {
                        let udp_packet = match UdpPacket::new(ip_payload) {
                            Some(udp_packet) => udp_packet,
                            None => return,
                        };
                        println!(
                            "[PACKET] {}, {}:{} -> {}:{}, len {}",
                            ether_type.to_string().to_lowercase(),
                            ipv6_packet.get_source(),
                            udp_packet.get_source(),
                            ipv6_packet.get_destination(),
                            udp_packet.get_destination(),
                            ethernet_packet.packet().len(),
                        );
                    }
                    _ => return,
                }
            }
            EtherTypes::Arp => {
                // only show arp packet with non-broadcast destination mac address
                if ethernet_packet.get_destination() != MacAddr::broadcast() {
                    println!(
                        "[PACKET] {}, {} -> {}, len {}",
                        ether_type.to_string().to_lowercase(),
                        ethernet_packet.get_source(),
                        ethernet_packet.get_destination(),
                        ethernet_packet.packet().len(),
                    )
                }
            }
            _ => println!(
                "[PACKET] {}, len {}",
                ether_type,
                ethernet_packet.packet().len(),
            ),
        }
    }
}

// sec
const ATTACK_DEFAULT_TIMEOUT: f32 = 1.0;

pub const TOP_100_PORTS: [u16; 100] = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143,
    144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646,
    873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190,
    5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
    8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
];

pub const TOP_1000_PORTS: [u16; 1000] = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70,
    79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139,
    143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311,
    340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512,
    513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636,
    646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783,
    787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992,
    993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026,
    1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042,
    1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058,
    1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074,
    1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090,
    1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108,
    1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137,
    1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175,
    1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244,
    1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334,
    1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580,
    1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755,
    1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947,
    1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
    2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046,
    2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135,
    2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366,
    2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605,
    2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910,
    2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052,
    3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323,
    3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527,
    3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827,
    3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998,
    4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321,
    4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002,
    5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120,
    5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440,
    5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801,
    5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906,
    5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989,
    5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106,
    6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666,
    6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001,
    7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512,
    7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002,
    8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254,
    8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701,
    8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080,
    9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418,
    9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900,
    9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010,
    10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628,
    10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783,
    14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012,
    16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283,
    19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939,
    23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715, 28201,
    30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775,
    32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571,
    34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100,
    48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165,
    49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500,
    50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555,
    55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623,
    64680, 65000, 65129, 65389,
];

pub const TOP_100_TCP_PORTS: [u16; 100] = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143,
    144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646,
    873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190,
    5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
    8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
];

pub const TOP_1000_TCP_PORTS: [u16; 1000] = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70,
    79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139,
    143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311,
    340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512,
    513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636,
    646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783,
    787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992,
    993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026,
    1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042,
    1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058,
    1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074,
    1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090,
    1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108,
    1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137,
    1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175,
    1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244,
    1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334,
    1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580,
    1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755,
    1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947,
    1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
    2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046,
    2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135,
    2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366,
    2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605,
    2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910,
    2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052,
    3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323,
    3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527,
    3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827,
    3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998,
    4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321,
    4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002,
    5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120,
    5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440,
    5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801,
    5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906,
    5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989,
    5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106,
    6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666,
    6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001,
    7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512,
    7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002,
    8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254,
    8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701,
    8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080,
    9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418,
    9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900,
    9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010,
    10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628,
    10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783,
    14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012,
    16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283,
    19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939,
    23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715, 28201,
    30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775,
    32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571,
    34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100,
    48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165,
    49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500,
    50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555,
    55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623,
    64680, 65000, 65129, 65389,
];

pub const TOP_100_UDP_PORTS: [u16; 100] = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143,
    144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646,
    873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190,
    5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
    8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
];

pub const TOP_1000_UDP_PORTS: [u16; 1000] = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70,
    79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139,
    143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311,
    340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512,
    513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636,
    646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783,
    787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992,
    993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026,
    1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042,
    1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058,
    1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074,
    1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090,
    1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108,
    1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137,
    1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175,
    1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244,
    1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334,
    1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580,
    1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755,
    1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947,
    1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
    2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046,
    2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135,
    2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366,
    2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605,
    2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910,
    2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052,
    3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323,
    3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527,
    3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827,
    3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998,
    4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321,
    4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002,
    5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120,
    5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440,
    5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801,
    5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906,
    5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989,
    5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106,
    6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666,
    6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001,
    7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512,
    7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002,
    8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254,
    8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701,
    8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080,
    9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418,
    9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900,
    9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010,
    10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628,
    10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783,
    14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012,
    16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283,
    19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939,
    23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715, 28201,
    30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775,
    32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571,
    34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100,
    48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165,
    49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500,
    50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555,
    55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623,
    64680, 65000, 65129, 65389,
];

#[derive(Debug, Clone)]
pub(crate) struct RunnerMsg {
    pub filters: Vec<PacketFilter>,     // runner receive filters to match
    pub packet_sender: Sender<Vec<u8>>, // then send matched packets back to threads
    pub start_time: Instant,            // start time, used to drop if exceed timeout
    pub elapsed: Duration,              // elapsed
}

impl RunnerMsg {
    pub fn check_packet(&self, packet: &[u8]) -> bool {
        for filter in &self.filters {
            if filter.check(packet) {
                debug!("layer2 recv matched filter: {}", filter.name());
                return true;
            }
        }
        false
    }
    pub fn send_packet_back(&self, packet: &[u8]) {
        if let Err(e) = self.packet_sender.send(packet.to_vec()) {
            error!("failed to send matched packet: {}", e);
        }
    }
}

pub(crate) static RUNNER_COMMUNICATION_CHANNEL: LazyLock<
    Arc<HashMap<String, CommunicationChannel>>,
> = LazyLock::new(|| {
    let ifaces: Vec<String> = interfaces()
        .iter()
        .map(|iface| iface.name.clone())
        .collect();
    let mut hm = HashMap::new();
    for iface in ifaces {
        let (filter_sender, filter_receiver) = unbounded::<RunnerMsg>();
        let cc = CommunicationChannel {
            filter_sender,
            filter_receiver,
        };
        hm.insert(iface, cc);
    }
    Arc::new(hm)
});

#[derive(Debug, Clone)]
pub(crate) struct CommunicationChannel {
    pub filter_sender: Sender<RunnerMsg>,
    pub filter_receiver: Receiver<RunnerMsg>,
}

impl CommunicationChannel {
    /// Returns a receiver to get matched packets from the runner.
    pub(crate) fn send_filters(
        &self,
        filters: Vec<PacketFilter>,
        elapsed: Duration,
    ) -> Receiver<Vec<u8>> {
        let (packet_sender, packet_receiver) = unbounded::<Vec<u8>>();
        let runner_msg = RunnerMsg {
            filters,
            packet_sender,
            start_time: Instant::now(),
            elapsed,
        };
        let _ = self.filter_sender.send(runner_msg);
        packet_receiver
    }
}

pub(crate) fn ask_runner(
    iface: String,
    filters: Vec<PacketFilter>,
    elapsed: Duration,
) -> Result<Receiver<Vec<u8>>, PistolError> {
    let hm = RUNNER_COMMUNICATION_CHANNEL.clone();
    let rcc = match hm.get(&iface) {
        Some(rcc) => rcc,
        None => return Err(PistolError::CanNotFoundInterfaceFilterChannel { i: iface }),
    };

    let packet_receiver = rcc.send_filters(filters, elapsed);
    Ok(packet_receiver)
}

#[derive(Debug, Clone)]
pub struct NetInfo {
    pub dst_mac: MacAddr,
    pub src_mac: MacAddr,
    /// User input destination IP address.
    pub ori_dst_addr: IpAddr,
    /// Inferred destination IP address.
    pub dst_addr: IpAddr,
    /// If user did not specify source IP address, we will use the IP address of the selected interface.
    pub src_addr: IpAddr,
    /// User input destination ports.
    pub dst_ports: Vec<u16>,
    /// User input source port.
    pub src_port: Option<u16>,
    pub interface: NetworkInterface,
}

impl NetInfo {
    pub fn new(
        dst_addr: IpAddr,
        dst_ports: Vec<u16>,
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<Self, PistolError> {
        let ori_dst_addr = dst_addr;
        debug!("infer: dst_addr({}) - src_addr({:?})", dst_addr, src_addr);
        let (dst_addr, src_addr) = match infer_addr(dst_addr, src_addr)? {
            Some(ret) => ret,
            None => return Err(PistolError::CanNotFoundSrcAddress),
        };
        debug!("inferred: dst_addr({}) src_addr({})", dst_addr, src_addr);

        // use a small timeout to infer mac address,
        // since the target is on localnet and may not exist or may not respond to ARP requests,
        // and we don't want to wait too long for the response.
        let infer_mac_timeout = Duration::from_secs_f32(0.5);
        let (dst_mac, interface) = infer_mac(dst_addr, src_addr, infer_mac_timeout)?;
        if dst_mac == MacAddr::zero() {
            return Err(PistolError::CanNotFoundDstMacAddress);
        } else {
            match interface.mac {
                Some(src_mac) => Ok(NetInfo {
                    dst_mac,
                    src_mac,
                    ori_dst_addr,
                    dst_addr,
                    src_addr,
                    dst_ports,
                    src_port,
                    interface,
                }),
                None => Err(PistolError::CanNotFoundSrcMacAddress),
            }
        }
    }
}

const MAX_HISTORY_PACKETS: usize = 10_000_000;

#[derive(Debug, Clone)]
pub struct Pistol {
    if_name: Option<String>,
    log_level: Option<String>,
    timeout: Duration,
    threads: usize,
    max_attempts: usize,
}

impl Default for Pistol {
    fn default() -> Self {
        Pistol {
            if_name: None,
            log_level: None,
            timeout: Duration::from_secs_f32(ATTACK_DEFAULT_TIMEOUT),
            threads: 8,      // default 8 threads
            max_attempts: 2, // default 2 max_attempts
        }
    }
}

impl Drop for Pistol {
    fn drop(&mut self) {
        debug!("save network cache");
        let gncs = match GLOBAL_NET_CACHES.lock() {
            Ok(gncs) => gncs.clone(),
            Err(e) => {
                error!("failed to lock program network cache: {}", e);
                return;
            }
        };
        // serde cs and save to file
        let nc_bytes = bitcode::serialize(&gncs).expect("convert network cache to bytes failed");
        fs::write(NETWORK_CACHE_PATH, nc_bytes).expect("write network cache to file failed");
    }
}

impl Pistol {
    /// Create a new Pistol instance with default settings.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set the interface name for sending and receiving data.
    /// If not set, the program will try to automatically select an appropriate interface.
    pub fn set_if_name(&mut self, if_name: &str) {
        self.if_name = Some(if_name.to_string());
    }
    /// Get the interface name for sending and receiving data.
    pub fn get_if_name(&self) -> Option<String> {
        self.if_name.clone()
    }
    /// Set log level for tracing.
    pub fn set_log_level(&mut self, log_level: &str) {
        self.log_level = Some(log_level.to_string());
    }
    /// Get log level for tracing.      
    pub fn get_log_level(&self) -> Option<String> {
        self.log_level.clone()
    }
    /// Set the timeout (sec) value for receiving and sending packets.
    pub fn set_timeout(&mut self, timeout: f32) {
        self.timeout = Duration::from_secs_f32(timeout);
    }
    /// Get the timeout (sec) value for receiving and sending packets.
    pub fn get_timeout(&self) -> Duration {
        self.timeout
    }
    /// Set the number of threads to use for scanning.
    pub fn set_threads(&mut self, threads: usize) {
        self.threads = threads;
    }
    /// Get the number of threads to use for scanning.
    pub fn get_threads(&self) -> usize {
        self.threads
    }
    /// Set the maximum number of max_attempts to send packets to each target.
    pub fn set_max_attempts(&mut self, max_attempts: usize) {
        if max_attempts > 0 {
            self.max_attempts = max_attempts;
        } else {
            warn!("max_attempts must be greater than 0, set it to default value 2 now");
            self.max_attempts = 2;
        }
    }
    /// Get the maximum number of max_attempts to send packets to each target.
    pub fn get_max_attempts(&self) -> usize {
        self.max_attempts
    }
    /// Initialize the Pistol instance with the given parameters.
    fn init(&mut self) -> Result<(), PistolError> {
        fn set_logger(level: Level) -> Result<(), PistolError> {
            let subscriber = FmtSubscriber::builder().with_max_level(level).finish();
            let _ = tracing::subscriber::set_global_default(subscriber)?;
            Ok(())
        }

        if let Some(log_level) = &self.log_level {
            let log_level = log_level.to_lowercase();
            match log_level.as_str() {
                "debug" => set_logger(Level::DEBUG)?,
                "warn" => set_logger(Level::WARN)?,
                "info" => set_logger(Level::INFO)?,
                "none" => (),
                _ => eprintln!("unknown log_level: {}, set it to 'none' now", log_level),
            }
        }

        Ok(())
    }
    fn recver(iface: String) -> Result<(), PistolError> {
        debug!("start runner for iface: {}", iface);
        let mut cap = Capture::new(&iface)?;
        cap.set_timeout(50);
        cap.set_promiscuous_mode(true);
        // cap.set_immediate_mode(true);

        let hm = RUNNER_COMMUNICATION_CHANNEL.clone();
        let rcc = match hm.get(&iface) {
            Some(rcc) => rcc,
            None => return Err(PistolError::CanNotFoundInterfaceFilterChannel { i: iface }),
        };
        // very small timeout to check new filters
        let timeout_1ms = Duration::from_millis(1);

        // The history_packets is used to store recently received packets,
        // which will be matched with new filters when they arrive.
        // This is to avoid missing packets that arrive before filters,
        // since libpcap will not loss any packets,
        // we can store all received packets in memory and match them with new filters when they arrive.
        let mut history_packets: Vec<Arc<[u8]>> = Vec::new();
        let mut runner_msgs: Vec<RunnerMsg> = Vec::new();
        loop {
            #[cfg(feature = "debug")]
            let loop_start = Instant::now();

            // Fetch packets first, then check if there are new filters to match,
            // this can avoid missing packets that arrive before filters.
            let packets = cap.fetch_as_vec()?;
            debug!("layer2 recv {} packets", packets.len());

            for packet in packets {
                // #[cfg(feature = "debug")]
                // debug_show_packet(packet, None);
                // #[cfg(feature = "debug")]
                // debug_show_packet(packet, Some(EtherTypes::Arp));
                history_packets.push(Arc::from(packet));
            }

            if history_packets.len() > MAX_HISTORY_PACKETS {
                // remove old packets to avoid memory overflow, keep the latest MAX_HISTORY_PACKETS packets
                history_packets =
                    history_packets.split_off(history_packets.len() - MAX_HISTORY_PACKETS);
            }

            loop {
                // recv all msg except timeout, since we need to check all filters for each packet,
                // we can not block here for too long, otherwise we may miss some packets that arrive before filters.
                match rcc.filter_receiver.recv_timeout(timeout_1ms) {
                    Ok(msg) => runner_msgs.push(msg),
                    Err(_) => break,
                }
            }

            for packet in &history_packets {
                let mut drop_idx = 0;
                let mut need_drop = false;
                #[cfg(feature = "debug")]
                debug_show_packet(packet, Some(EtherTypes::Arp));
                for (i, msg) in runner_msgs.iter().enumerate() {
                    if msg.check_packet(packet) {
                        // send matched packet back to thread
                        debug!("matched packet [{}]", packet.len());
                        msg.send_packet_back(packet);
                        need_drop = true;
                        drop_idx = i;
                        break;
                    }
                }
                if need_drop {
                    let _droped_msg = runner_msgs.swap_remove(drop_idx);
                }
            }

            let mut drop_idxs = Vec::new();
            let mut need_drop = false;
            for (i, msg) in runner_msgs.iter().enumerate() {
                if msg.start_time.elapsed() > msg.elapsed * 3 {
                    // timeout, remove this msg
                    drop_idxs.push(i);
                    need_drop = true;
                }
            }
            if need_drop {
                debug!(
                    "layer2 runner {} has {} expired msgs to drop",
                    iface,
                    drop_idxs.len()
                );
                for &drop_idx in drop_idxs.iter().rev() {
                    let _droped_msg = runner_msgs.swap_remove(drop_idx);
                }
            }

            debug!(
                "layer2 runner {} has {} msgs to process",
                iface,
                runner_msgs.len()
            );

            #[cfg(feature = "debug")]
            println!(
                "runner loop cost: {:.3} ms",
                loop_start.elapsed().as_secs_f64() * 1000.0
            );
        }
    }
    /// Initialize multiple runners for multiple targets without source address info.
    /// For mac scan like function which does not need mac info.
    fn init_recvers_without_net_infos(&mut self) -> Result<(), PistolError> {
        self.init()?;
        // spawn a runner thread for each interface we need
        for ni in interfaces() {
            let _ = thread::spawn(move || Self::recver(ni.name));
        }
        Ok(())
    }
    /// Initialize multiple runners for multiple targets.
    fn init_recvers(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<(Vec<NetInfo>, Duration), PistolError> {
        let now = Instant::now();
        self.init()?;
        // start runners and listen on all interfaces,
        // since we don't know which interface will be used for each target,
        // we need to listen on all interfaces.
        for ni in interfaces() {
            let _ = thread::spawn(move || Self::recver(ni.name));
        }

        let mut net_infos = Vec::new();
        for t in targets {
            let dst_addr = t.addr;
            let dst_ports = t.ports.clone();
            let net_info = match NetInfo::new(dst_addr, dst_ports, src_addr, src_port) {
                Ok(ni) => ni,
                Err(e) => match e {
                    PistolError::CanNotFoundDstMacAddress => {
                        warn!("can not found MAC address for target {}, skip it", dst_addr);
                        continue;
                    }
                    _ => return Err(e),
                },
            };
            net_infos.push(net_info);
        }

        Ok((net_infos, now.elapsed()))
    }
    /// Initialize a single runner for a single target.
    fn init_recver(
        &mut self,
        dst_addr: IpAddr,
        dst_ports: Vec<u16>,
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<(NetInfo, Duration), PistolError> {
        let now = Instant::now();
        self.init()?;
        // start runners and listen on all interfaces,
        // since we don't know which interface will be used for each target,
        // we need to listen on all interfaces.
        for ni in interfaces() {
            let _ = thread::spawn(move || Self::recver(ni.name));
        }
        let net_info = NetInfo::new(dst_addr, dst_ports, src_addr, src_port)?;
        Ok((net_info, now.elapsed()))
    }
    /* Scan */
    /// ARP Scan (IPv4) or NDP NS Scan (IPv6).
    /// This will sends ARP packet or NDP NS packet to hosts on the local network and displays any responses that are received.
    /// It is similar to the `arp-scan` tool.
    /// ```rust
    /// use pistol::PistolRunner;
    /// use pistol::PistolLogger;
    /// use pistol::Target;
    ///
    /// fn main() {
    ///     let mut pistol = Pistol::new();
    ///     pistol.set_threads(8);
    ///     pistol.init().unwrap();
    ///
    ///     let targets = Target::from_subnet("192.168.5.0/24", None).unwrap();
    ///     // set the timeout same as `arp-scan`
    ///     let timeout = Some(Duration::from_secs_f64(0.5));
    ///     let src_ipv4 = None;
    ///     let threads = Some(512);
    ///     let max_attempts = 2;
    ///
    ///     let mut p = Pistol::new();
    ///     p.set_timeout(self.timeout);
    ///     p.set_threads(threads);
    ///     p.set_max_attempts(max_attempts);
    ///
    ///     let ret = p.mac_scan(&targets, src_ipv4).unwrap();
    ///     println!("{}", ret);
    /// }
    /// ```
    /// Compare the speed with arp-scan.
    /// pistol:
    /// ```
    /// +--------+---------------+-------------------+--------+-----------+
    /// |                    Mac Scans (max_attempts:2)                   |
    /// +--------+---------------+-------------------+--------+-----------+
    /// |  seq   |     addr      |        mac        |  oui   |    rtt    |
    /// +--------+---------------+-------------------+--------+-----------+
    /// |   1    |  192.168.5.1  | 00:50:56:c0:00:08 | VMware | 76.720 ms |
    /// +--------+---------------+-------------------+--------+-----------+
    /// |   2    |  192.168.5.2  | 00:50:56:e6:2f:9d | VMware | 76.693 ms |
    /// +--------+---------------+-------------------+--------+-----------+
    /// |   3    | 192.168.5.77  | 00:0c:29:c5:f6:99 | VMware | 66.379 ms |
    /// +--------+---------------+-------------------+--------+-----------+
    /// |   4    | 192.168.5.254 | 00:50:56:e2:f6:79 | VMware | 16.302 ms |
    /// +--------+---------------+-------------------+--------+-----------+
    /// | total cost: 1.206s, avg cost: 0.005s, alive hosts: 4            |
    /// +--------+---------------+-------------------+--------+-----------+
    /// ```
    /// arp-scan:
    /// ```
    /// ➜  pistol-rs git:(main) ✗ sudo arp-scan 192.168.5.0/24
    /// Interface: ens33, type: EN10MB, MAC: 00:0c:29:ec:d0:37, IPv4: 192.168.5.3
    /// Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
    /// 192.168.5.1     00:50:56:c0:00:08       VMware, Inc.
    /// 192.168.5.2     00:50:56:e6:2f:9d       VMware, Inc.
    /// 192.168.5.77    00:0c:29:c5:f6:99       VMware, Inc.
    /// 192.168.5.254   00:50:56:e0:d3:bb       VMware, Inc.
    ///
    /// 8 packets received by filter, 0 packets dropped by kernel
    /// Ending arp-scan 1.10.0: 256 hosts scanned in 2.071 seconds (123.61 hosts/sec). 4 responded
    /// ```
    #[cfg(feature = "scan")]
    pub fn mac_scan(&mut self, targets: &[Target]) -> Result<MacScans, PistolError> {
        self.init_recvers_without_net_infos()?;
        scan::mac_scan(targets, self.timeout, self.threads, self.max_attempts)
    }
    /// The raw version of arp_scan function.
    /// It sends an ARP request to the target IPv4 address and waits for a reply.
    /// If a reply is received within the specified timeout, it returns the MAC address of the target and the duration taken for the scan.
    #[cfg(feature = "scan")]
    pub fn arp_scan_raw(
        &mut self,
        dst_ipv4: Ipv4Addr,
    ) -> Result<(Option<MacAddr>, Duration), PistolError> {
        self.init_recvers_without_net_infos()?;
        scan::arp_scan_raw(dst_ipv4, self.timeout)
    }
    /// The raw version of ndp_ns_scan function.
    /// It sends an NDP Neighbor Solicitation to the target IPv6 address and waits for a reply.
    /// If a reply is received within the specified timeout,
    /// it returns the MAC address of the target and the duration taken for the scan.
    #[cfg(feature = "scan")]
    pub fn ndp_ns_scan_raw(
        &mut self,
        dst_ipv6: Ipv6Addr,
    ) -> Result<(Option<MacAddr>, Duration), PistolError> {
        self.init_recvers_without_net_infos()?;
        scan::ndp_ns_scan_raw(dst_ipv6, self.timeout)
    }
    /// TCP ACK Scan.
    /// This scan is different than the others discussed so far in
    /// that it never determines open (or even open|filtered) ports.
    /// It is used to map out firewall rulesets,
    /// determining whether they are stateful or not and which ports are filtered.
    /// When scanning unfiltered systems, open and closed ports will both return a RST packet.
    /// We then labels them as unfiltered, meaning that they are reachable by the ACK packet,
    /// but whether they are open or closed is undetermined.
    /// Ports that don't respond, or send certain ICMP error messages back, are labeled filtered.
    #[cfg(feature = "scan")]
    pub fn tcp_ack_scan(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<PortScans, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        let mut ret = scan::tcp_ack_scan(net_infos, self.threads, self.timeout, self.max_attempts)?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /// The raw version of tcp_ack_scan function.
    /// It sends a TCP ACK packet to the target IP address and port, and waits for a response.
    /// Based on the response received (or lack thereof),
    /// it determines the port status (Open, Closed, Filtered, Unfiltered)
    /// and the duration taken for the scan.
    #[cfg(feature = "scan")]
    pub fn tcp_ack_scan_raw(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<PortScan, PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![dst_port], src_addr, src_port)?;
        let mut ret = scan::tcp_ack_scan_raw(net_info, self.timeout, self.max_attempts)?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /// TCP Connect() Scan.
    /// This is the most basic form of TCP scanning.
    /// The connect() system call provided by your operating system
    /// is used to open a connection to every interesting port on the machine.
    /// If the port is listening, connect() will succeed, otherwise the port isn't reachable.
    /// One strong advantage to this technique is that you don't need any special privileges.
    /// Any user on most UNIX boxes is free to use this call.
    /// Another advantage is speed.
    /// While making a separate connect() call for every targeted port
    /// in a linear fashion would take ages over a slow connection,
    /// you can hasten the scan by using many sockets in parallel.
    /// Using non-blocking I/O allows you to set a low time-out period and watch all the sockets at once.
    /// This is the fastest scanning method supported by nmap, and is available with the -t (TCP) option.
    /// The big downside is that this sort of scan is easily detectable and filterable.
    /// The target hosts logs will show a bunch of connection and error messages
    /// for the services which take the connection and then have it immediately shutdown.
    #[cfg(feature = "scan")]
    pub fn tcp_connect_scan(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<PortScans, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        let mut ret =
            scan::tcp_connect_scan(net_infos, self.threads, self.timeout, self.max_attempts)?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /// The raw version of tcp_connect_scan function.
    /// It max_attempts to establish a TCP connection to the specified destination address and port.
    /// If the connection is successful, it indicates that the port is open.
    /// If the connection is refused, it indicates that the port is closed.
    /// If there is no response within the specified timeout, it indicates that the port is filtered
    #[cfg(feature = "scan")]
    pub fn tcp_connect_scan_raw(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<PortScan, PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![dst_port], src_addr, src_port)?;
        let mut ret = scan::tcp_connect_scan_raw(net_info, self.timeout, self.max_attempts)?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
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
    /// any packet not containing SYN, RST,
    /// or ACK bits will result in a returned RST
    /// if the port is closed and no response at all if the port is open.
    /// As long as none of those three bits are included,
    /// any combination of the other three (FIN, PSH, and URG) are OK.
    #[cfg(feature = "scan")]
    pub fn tcp_fin_scan(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<PortScans, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        let mut ret = scan::tcp_fin_scan(net_infos, self.threads, self.timeout, self.max_attempts)?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /// The raw version of tcp_fin_scan function.
    /// It sends a TCP FIN packet to the target IP address and port, and waits for a response.
    /// Based on the response received (or lack thereof),
    /// it determines the port status (Open, Closed, Filtered) and the duration taken for the scan.
    #[cfg(feature = "scan")]
    pub fn tcp_fin_scan_raw(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<PortScan, PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![dst_port], src_addr, src_port)?;
        let mut ret = scan::tcp_fin_scan_raw(net_info, self.timeout, self.max_attempts)?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /// TCP Idle Scan.
    /// In 1998, security researcher Antirez (who also wrote the hping2 tool used in parts of this book)
    /// posted to the Bugtraq mailing list an ingenious new port scanning technique.
    /// Idle scan, as it has become known, allows for completely blind port scanning.
    /// Attackers can actually scan a target
    /// without sending a single packet to the target from their own IP address!
    /// Instead, a clever side-channel attack allows for the scan to be bounced off a dumb "zombie host".
    /// Intrusion detection system (IDS) reports will finger the innocent zombie as the attacker.
    /// Besides being extraordinarily stealthy,
    /// this scan type permits discovery of IP-based trust relationships between machines.
    #[cfg(feature = "scan")]
    pub fn tcp_idle_scan(
        &mut self,
        targets: &[Target],
        src_ipv4: Option<Ipv4Addr>,
        src_port: Option<u16>,
        zombie_ipv4: Ipv4Addr,
        zombie_port: u16,
    ) -> Result<PortScans, PistolError> {
        let src_addr = match src_ipv4 {
            Some(ipv4) => Some(IpAddr::V4(ipv4)),
            None => None,
        };
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        let zommbie_net_info =
            NetInfo::new(zombie_ipv4.into(), vec![zombie_port], src_addr, src_port)?;
        let zombie_mac = zommbie_net_info.dst_mac;
        let mut ret = scan::tcp_idle_scan(
            net_infos,
            Some(zombie_mac),
            Some(zombie_ipv4),
            Some(zombie_port),
            self.threads,
            self.timeout,
            self.max_attempts,
        )?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /// The raw version of tcp_idle_scan function.
    /// It performs a TCP idle scan on the specified destination address and port using a zombie host.
    /// The function sends packets to the zombie host to determine the port status of the target host
    /// without directly interacting with the target host.
    #[cfg(feature = "scan")]
    pub fn tcp_idle_scan_raw(
        &mut self,
        dst_ipv4: Ipv4Addr,
        dst_port: u16,
        src_ipv4: Option<Ipv4Addr>,
        src_port: Option<u16>,
        zombie_ipv4: Ipv4Addr,
        zombie_port: u16,
    ) -> Result<PortScan, PistolError> {
        let dst_addr = IpAddr::V4(dst_ipv4);
        let src_addr = match src_ipv4 {
            Some(ipv4) => Some(IpAddr::V4(ipv4)),
            None => None,
        };
        let (net_info, dur) = self.init_recver(dst_addr, vec![dst_port], src_addr, src_port)?;
        let zombie_net_info =
            NetInfo::new(zombie_ipv4.into(), vec![zombie_port], src_addr, src_port)?;
        let zombie_mac = zombie_net_info.dst_mac;
        let mut ret = scan::tcp_idle_scan_raw(
            net_info,
            Some(zombie_mac),
            Some(zombie_ipv4),
            Some(zombie_port),
            self.timeout,
            self.max_attempts,
        )?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /// TCP Maimon Scan.
    /// The Maimon scan is named after its discoverer, Uriel Maimon.
    /// He described the technique in Phrack Magazine issue #49 (November 1996).
    /// This technique is exactly the same as NULL, FIN, and Xmas scan, except that the probe is FIN/ACK.
    /// According to RFC 793 (TCP),
    /// a RST packet should be generated in response to such a probe whether the port is open or closed.
    /// However, Uriel noticed that many BSD-derived systems simply drop the packet if the port is open.
    #[cfg(feature = "scan")]
    pub fn tcp_maimon_scan(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<PortScans, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        let mut ret =
            scan::tcp_maimon_scan(net_infos, self.threads, self.timeout, self.max_attempts)?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /// The raw version of tcp_maimon_scan function.
    /// It sends a TCP Maimon packet (FIN/ACK) to the target IP address and port,
    /// and waits for a response. Based on the response received (or lack thereof),
    /// it determines the port status (Open, Closed, Filtered) and the duration taken for the scan.
    #[cfg(feature = "scan")]
    pub fn tcp_maimon_scan_raw(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<PortScan, PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![dst_port], src_addr, src_port)?;
        let mut ret = scan::tcp_maimon_scan_raw(net_info, self.timeout, self.max_attempts)?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /// TCP Null Scan.
    /// Does not set any bits (TCP flag header is 0).
    /// When scanning systems compliant with this RFC text,
    /// any packet not containing SYN, RST,
    /// or ACK bits will result in a returned RST if the port is closed
    /// and no response at all if the port is open.
    /// As long as none of those three bits are included,
    /// any combination of the other three (FIN, PSH, and URG) are OK.
    #[cfg(feature = "scan")]
    pub fn tcp_null_scan(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<PortScans, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        let mut ret =
            scan::tcp_null_scan(net_infos, self.threads, self.timeout, self.max_attempts)?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /// The raw version of tcp_null_scan function.
    /// It sends a TCP Null packet (no flags set) to the target IP address and port,
    /// and waits for a response. Based on the response received (or lack thereof),
    /// it determines the port status (Open, Closed, Filtered) and the duration taken for the scan.
    #[cfg(feature = "scan")]
    pub fn tcp_null_scan_raw(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<PortScan, PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![dst_port], src_addr, src_port)?;
        let mut ret = scan::tcp_null_scan_raw(net_info, self.timeout, self.max_attempts)?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /// TCP SYN Scan.
    /// This technique is often referred to as "half-open" scanning,
    /// because you don't open a full TCP connection.
    /// You send a SYN packet, as if you are going to open a real connection and wait for a response.
    /// A SYN|ACK indicates the port is listening.
    /// A RST is indicative of a non-listener.
    /// If a SYN|ACK is received,
    /// you immediately send a RST to tear down the connection (actually the kernel does this for us).
    /// The primary advantage to this scanning technique is that fewer sites will log it.
    /// Unfortunately you need root privileges to build these custom SYN packets.
    /// SYN scan is the default and most popular scan option for good reason.
    /// It can be performed quickly,
    /// scanning thousands of ports per second on a fast network not hampered by intrusive firewalls.
    /// SYN scan is relatively unobtrusive and stealthy, since it never completes TCP connections.
    #[cfg(feature = "scan")]
    pub fn tcp_syn_scan(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<PortScans, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        let mut ret = scan::tcp_syn_scan(net_infos, self.threads, self.timeout, self.max_attempts)?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /// The raw version of tcp_syn_scan function.
    /// It sends a TCP SYN packet to the target IP address and port, and waits for a response.
    /// Based on the response received (or lack thereof),
    /// it determines the port status (Open, Closed, Filtered) and the duration taken for the scan.
    #[cfg(feature = "scan")]
    pub fn tcp_syn_scan_raw(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<PortScan, PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![dst_port], src_addr, src_port)?;
        let mut ret = scan::tcp_syn_scan_raw(net_info, self.timeout, self.max_attempts)?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /// TCP Window Scan.
    /// Window scan is exactly the same as ACK scan except
    /// that it exploits an implementation detail of certain systems
    /// to differentiate open ports from closed ones,
    /// rather than always printing unfiltered when a RST is returned.
    /// It does this by examining the TCP Window value of the RST packets returned.
    /// On some systems, open ports use a positive window size (even for RST packets)
    /// while closed ones have a zero window.
    /// Window scan sends the same bare ACK probe as ACK scan.
    #[cfg(feature = "scan")]
    pub fn tcp_window_scan(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<PortScans, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        let mut ret =
            scan::tcp_window_scan(net_infos, self.threads, self.timeout, self.max_attempts)?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /// The raw version of tcp_window_scan function.
    /// It sends a TCP Window packet to the target IP address and port, and waits for a response.
    /// Based on the response received (or lack thereof),
    /// it determines the port status (Open, Closed, Filtered) and the duration taken for the scan.
    #[cfg(feature = "scan")]
    pub fn tcp_window_scan_raw(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<PortScan, PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![dst_port], src_addr, src_port)?;
        let mut ret = scan::tcp_window_scan_raw(net_info, self.timeout, self.max_attempts)?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /// TCP Xmas Scan.
    /// Sets the FIN, PSH, and URG flags, lighting the packet up like a Christmas tree.
    /// When scanning systems compliant with this RFC text,
    /// any packet not containing SYN, RST, or ACK bits will result in a returned RST
    /// if the port is closed and no response at all if the port is open.
    /// As long as none of those three bits are included,
    /// any combination of the other three (FIN, PSH, and URG) are OK.
    #[cfg(feature = "scan")]
    pub fn tcp_xmas_scan(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<PortScans, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        let mut ret =
            scan::tcp_xmas_scan(net_infos, self.threads, self.timeout, self.max_attempts)?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /// The raw version of tcp_xmas_scan function.
    /// It sends a TCP Xmas packet (FIN, PSH, URG flags set) to the target IP address and port,
    /// and waits for a response. Based on the response received (or lack thereof),
    /// it determines the port status (Open, Closed, Filtered) and the duration taken for the scan.
    #[cfg(feature = "scan")]
    pub fn tcp_xmas_scan_raw(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<PortScan, PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![dst_port], src_addr, src_port)?;
        let mut ret = scan::tcp_xmas_scan_raw(net_info, self.timeout, self.max_attempts)?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /// UDP Scan.
    /// While most popular services on the Internet run over the TCP protocol,
    /// UDP services are widely deployed.
    /// DNS, SNMP, and DHCP (registered ports 53, 161/162, and 67/68) are three of the most common.
    /// Because UDP scanning is generally slower and more difficult than TCP,
    /// some security auditors ignore these ports.
    /// This is a mistake, as exploitable UDP services are quite common
    /// and attackers certainly don't ignore the whole protocol.
    /// UDP scan works by sending a UDP packet to every targeted port.
    /// For most ports, this packet will be empty (no payload),
    /// but for a few of the more common ports a protocol-specific payload will be sent.
    /// Based on the response, or lack thereof, the port is assigned to one of four states.
    #[cfg(feature = "scan")]
    pub fn udp_scan(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<PortScans, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        let mut ret = scan::udp_scan(net_infos, self.threads, self.timeout, self.max_attempts)?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /// The raw version of udp_scan function.
    /// It sends a UDP packet to the target IP address and port, and waits for a response.
    /// Based on the response received (or lack thereof),
    /// it determines the port status (Open, Closed, Filtered, Unfiltered)
    /// and the duration taken for the scan.
    #[cfg(feature = "scan")]
    pub fn udp_scan_raw(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<PortScan, PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![dst_port], src_addr, src_port)?;
        let mut ret = scan::udp_scan_raw(net_info, self.timeout, self.max_attempts)?;
        ret.layer2_cost = dur;
        Ok(ret)
    }
    /* Ping */
    /// ICMP Ping (Address Mask Request).
    /// (Note: in my local test, this request did not return any reply).
    /// While echo request is the standard ICMP ping query, Nmap does not stop there.
    /// The ICMP standards (RFC 792 and RFC 950 ) also specify timestamp request,
    /// information request, and address mask request packets as codes 13, 15, and 17,
    /// respectively. While the ostensible purpose for these queries is to learn information such
    /// as address masks and current times, they can easily be used for host discovery.
    /// A system that replies is up and available.
    /// Nmap does not currently implement information request packets,
    /// as they are not widely supported. RFC 1122 insists that "a host SHOULD NOT implement these messages".
    /// Timestamp and address mask queries can be sent with the -PP and -PM options, respectively.
    /// A timestamp reply (ICMP code 14) or address mask reply (code 18) discloses
    /// that the host is available.
    /// These two queries can be valuable when administrators specifically block echo request packets
    /// while forgetting that other ICMP queries can be used for the same purpose.
    #[cfg(feature = "ping")]
    pub fn icmp_address_mask_ping(
        &mut self,
        targets: &[Target],
        src_ipv4: Option<Ipv4Addr>,
        src_port: Option<u16>,
    ) -> Result<HostPings, PistolError> {
        let src_addr = match src_ipv4 {
            Some(ipv4) => Some(IpAddr::V4(ipv4)),
            None => None,
        };
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        ping::icmp_address_mask_ping(net_infos, self.threads, self.timeout, self.max_attempts)
    }
    /// The raw version of icmp_address_mask_ping function.
    /// It sends an ICMP Address Mask Request to the target IP address
    /// and waits for a reply. If a reply is received within the specified timeout,
    /// it returns the PingStatus indicating whether the host is reachable.
    #[cfg(feature = "ping")]
    pub fn icmp_address_mask_ping_raw(
        &mut self,
        dst_ipv4: Ipv4Addr,
        src_ipv4: Option<Ipv4Addr>,
    ) -> Result<(PingStatus, Duration), PistolError> {
        let dst_addr = IpAddr::V4(dst_ipv4);
        let src_addr = match src_ipv4 {
            Some(ipv4) => Some(IpAddr::V4(ipv4)),
            None => None,
        };
        let (net_info, dur) = self.init_recver(dst_addr, vec![], src_addr, None)?;
        ping::icmp_address_mask_ping_raw(net_info, self.timeout)
    }
    /// ICMP Ping (Standard Echo Request).
    /// In addition to the unusual TCP and UDP host discovery types discussed previously,
    /// we can send the standard packets sent by the ubiquitous ping program.
    /// We sends an ICMP type 8 (echo request) packet to the target IP addresses,
    /// expecting a type 0 (echo reply) in return from available hosts.
    /// As noted at the beginning of this chapter, many hosts and firewalls now block these packets,
    /// rather than responding as required by RFC 1122.
    /// For this reason, ICMP-only scans are rarely reliable enough against unknown targets over the Internet.
    /// But for system administrators monitoring an internal network,
    /// this can be a practical and efficient approach.
    #[cfg(feature = "ping")]
    pub fn icmp_echo_ping(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<HostPings, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        ping::icmp_echo_ping(net_infos, self.threads, self.timeout, self.max_attempts)
    }
    /// The raw version of icmp_echo_ping function.
    /// It sends an ICMP Echo Request to the target IP address
    /// and waits for a reply. If a reply is received within the specified timeout,
    /// it returns the PingStatus indicating whether the host is reachable.
    #[cfg(feature = "ping")]
    pub fn icmp_echo_ping_raw(
        &mut self,
        dst_addr: IpAddr,
        src_addr: Option<IpAddr>,
    ) -> Result<(PingStatus, Duration), PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![], src_addr, None)?;
        ping::icmp_echo_ping_raw(net_info, self.timeout)
    }
    /// ICMP Ping (Timestamp Request).
    /// While echo request is the standard ICMP ping query, Nmap does not stop there.
    /// The ICMP standards (RFC 792 and RFC 950 ) also specify timestamp request,
    /// information request, and address mask request packets as codes 13, 15, and 17,
    /// respectively. While the ostensible purpose for these queries is to learn information such
    /// as address masks and current times, they can easily be used for host discovery.
    /// A system that replies is up and available.
    /// Nmap does not currently implement information request packets,
    /// as they are not widely supported. RFC 1122 insists that "a host SHOULD NOT implement these messages".
    /// Timestamp and address mask queries can be sent with the -PP and -PM options, respectively.
    /// A timestamp reply (ICMP code 14) or address mask reply (code 18) discloses that the host is available.
    /// These two queries can be valuable when administrators specifically block echo request packets
    /// while forgetting that other ICMP queries can be used for the same purpose.
    #[cfg(feature = "ping")]
    pub fn icmp_timestamp_ping(
        &mut self,
        targets: &[Target],
        src_ipv4: Option<Ipv4Addr>,
        src_port: Option<u16>,
    ) -> Result<HostPings, PistolError> {
        let src_addr = match src_ipv4 {
            Some(ipv4) => Some(IpAddr::V4(ipv4)),
            None => None,
        };
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        ping::icmp_timestamp_ping(net_infos, self.threads, self.timeout, self.max_attempts)
    }
    /// The raw version of icmp_timestamp_ping function.
    /// It sends an ICMP Timestamp Request to the target IP address
    /// and waits for a reply. If a reply is received within the specified timeout,
    /// it returns the PingStatus indicating whether the host is reachable.
    #[cfg(feature = "ping")]
    pub fn icmp_timestamp_ping_raw(
        &mut self,
        dst_ipv4: Ipv4Addr,
        src_ipv4: Option<Ipv4Addr>,
    ) -> Result<(PingStatus, Duration), PistolError> {
        let dst_addr = IpAddr::V4(dst_ipv4);
        let src_addr = match src_ipv4 {
            Some(ipv4) => Some(IpAddr::V4(ipv4)),
            None => None,
        };
        let (net_info, dur) = self.init_recver(dst_addr, vec![], src_addr, None)?;
        ping::icmp_timestamp_ping_raw(net_info, self.timeout)
    }
    /// The raw version of icmp ping.
    /// It sends an ICMP Echo Request to the target IP address
    /// and waits for a reply. If a reply is received within the specified timeout,
    /// it returns the PingStatus indicating whether the host is reachable,
    /// along with the duration taken for the ping.
    #[cfg(feature = "ping")]
    pub fn icmp_ping_raw(
        &mut self,
        dst_addr: IpAddr,
        src_addr: Option<IpAddr>,
    ) -> Result<(PingStatus, Duration), PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![], src_addr, None)?;
        ping::icmp_ping_raw(net_info, self.timeout)
    }
    /// ICMPv6 Ping (Standard Echo Request).
    /// Sends an ICMPv6 type 128 (echo request) packet (IPv6).
    /// In addition to the unusual TCP and UDP host discovery types discussed previously,
    /// we can send the standard packets sent by the ubiquitous ping program.
    /// We sends an ICMPv6 type 128 (echo request) packet to the target IP addresses,
    /// expecting a type 129 (echo reply) in return from available hosts.
    /// As noted at the beginning of this chapter, many hosts and firewalls now block these packets,
    /// rather than responding as required by RFC 4443.
    /// For this reason, ICMPv6-only scans are rarely reliable enough against unknown targets over the Internet.
    /// But for system administrators monitoring an internal network,
    /// this can be a practical and efficient approach.
    #[cfg(feature = "ping")]
    pub fn icmpv6_ping(
        &mut self,
        targets: &[Target],
        src_ipv6: Option<Ipv6Addr>,
        src_port: Option<u16>,
    ) -> Result<HostPings, PistolError> {
        let src_addr = match src_ipv6 {
            Some(ipv6) => Some(IpAddr::V6(ipv6)),
            None => None,
        };
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        ping::icmpv6_ping(net_infos, self.threads, self.timeout, self.max_attempts)
    }
    /// TCP ACK Ping.
    /// This ping probe stays away from being similar to a ACK port scan, and to keep the probe stealthy,
    /// we chose to have the user manually provide a port number
    /// that is open on the target machine instead of traversing all ports.
    #[cfg(feature = "ping")]
    pub fn tcp_ack_ping(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<HostPings, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        ping::tcp_ack_ping(net_infos, self.threads, self.timeout, self.max_attempts)
    }
    /// The raw version of tcp_ack_ping function.
    /// It sends a TCP ACK packet to the target IP address and port, and waits for a response.
    /// Based on the response received (or lack thereof),
    /// it determines the ping status (Success, Timeout, Unreachable)
    /// and the duration taken for the ping.
    #[cfg(feature = "ping")]
    pub fn tcp_ack_ping_raw(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<(PingStatus, Duration), PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![dst_port], src_addr, src_port)?;
        ping::tcp_ack_ping_raw(net_info, self.timeout)
    }
    /// TCP SYN Ping.
    /// This ping probe stays away from being similar to a SYN port scan, and to keep the probe stealthy,
    /// we chose to have the user manually provide a port number
    /// that is open on the target machine instead of traversing all ports.
    #[cfg(feature = "ping")]
    pub fn tcp_syn_ping(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<HostPings, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        ping::tcp_syn_ping(net_infos, self.threads, self.timeout, self.max_attempts)
    }
    /// The raw version of tcp_syn_ping function.
    /// It sends a TCP SYN packet to the target IP address and port, and waits for a response.
    /// Based on the response received (or lack thereof),
    /// it determines the ping status (Success, Timeout, Unreachable)
    /// and the duration taken for the ping.
    #[cfg(feature = "ping")]
    pub fn tcp_syn_ping_raw(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<(PingStatus, Duration), PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![dst_port], src_addr, src_port)?;
        ping::tcp_syn_ping_raw(net_info, self.timeout)
    }
    /// UDP Ping.
    /// This ping probe stays away from being similar to a UDP port scan, and to keep the probe stealthy,
    /// we chose to have the user manually provide a port number
    /// that is open on the target machine instead of traversing all ports.
    #[cfg(feature = "ping")]
    pub fn udp_ping(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<HostPings, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        ping::udp_ping(net_infos, self.threads, self.timeout, self.max_attempts)
    }
    /// The raw version of udp_ping function.
    /// It sends a UDP packet to the target IP address and port, and waits for a response.
    /// Based on the response received (or lack thereof),
    /// it determines the ping status (Success, Timeout, Unreachable)
    /// and the duration taken for the ping.
    #[cfg(feature = "ping")]
    pub fn udp_ping_raw(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<(PingStatus, Duration), PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![dst_port], src_addr, src_port)?;
        ping::udp_ping_raw(net_info, self.timeout)
    }
    /* Trace */
    /// ICMP Trace.
    /// Sends ICMP Echo Request packets with incrementally increasing TTL values
    /// to discover the path to the destination.
    /// The recommended timeout value is 5 seconds,
    /// which is consistent with the default value of traceroute.
    #[cfg(feature = "trace")]
    pub fn icmp_trace(
        &mut self,
        dst_addr: IpAddr,
        src_addr: Option<IpAddr>,
    ) -> Result<u8, PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![], src_addr, None)?;
        trace::icmp_trace(net_info, self.timeout)
    }
    /// TCP SYN Trace.
    /// Sends TCP SYN packets with incrementally increasing TTL values
    /// to discover the path to the destination.
    /// The recommended timeout value is 5 seconds,
    /// which is consistent with the default value of traceroute.
    #[cfg(feature = "trace")]
    pub fn syn_trace(
        &mut self,
        dst_addr: IpAddr,
        dst_port: Option<u16>, // default is 80
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
    ) -> Result<u8, PistolError> {
        let dst_port = dst_port.unwrap_or(80);
        let (net_info, dur) = self.init_recver(dst_addr, vec![dst_port], src_addr, src_port)?;
        trace::syn_trace(net_info, self.timeout)
    }
    /// UDP Trace.
    /// Sends UDP packets with incrementally increasing TTL values
    /// to discover the path to the destination.
    /// The recommended timeout value is 5 seconds,
    /// which is consistent with the default value of traceroute.
    #[cfg(feature = "trace")]
    pub fn udp_trace(
        &mut self,
        dst_addr: IpAddr,
        src_addr: Option<IpAddr>,
    ) -> Result<u8, PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![], src_addr, None)?;
        trace::udp_trace(net_info, self.timeout)
    }
    /* Flood */
    /// Perform an ICMP flood DDoS attack on the specified targets.
    /// An Internet Control Message Protocol (ICMP) flood DDoS attack,
    /// also known as a Ping flood attack,
    /// is a common Denial-of-Service (DoS) attack in
    /// which an attacker max_attempts to overwhelm a targeted device with ICMP echo-requests (pings).
    /// Normally, ICMP echo-request and echo-reply messages are used to ping a network device
    /// in order to diagnose the health and connectivity of the device and the connection
    /// between the sender and the device.
    /// By flooding the target with request packets,
    /// the network is forced to respond with an equal number of reply packets.
    /// This causes the target to become inaccessible to normal traffic.
    /// Total number of packets sent = retransmit x threads.
    #[cfg(feature = "flood")]
    pub fn icmp_flood(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
        retransmit: usize,
        repeat: usize,
        fake_src: bool,
    ) -> Result<PistolFloods, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        flood::icmp_flood(net_infos, self.threads, retransmit, repeat, fake_src)
    }
    /// The raw version of icmp_flood function.
    /// It performs an ICMP flood attack on the specified destination address.
    #[cfg(feature = "flood")]
    pub fn icmp_flood_raw(
        &mut self,
        dst_addr: IpAddr,
        src_addr: Option<IpAddr>,
        retransmit: usize,
        repeat: usize,
        fake_src: bool,
    ) -> Result<usize, PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![], src_addr, None)?;
        flood::icmp_flood_raw(net_info, retransmit, repeat, fake_src)
    }
    /// TCP ACK flood, or 'ACK Flood' for short, is a network DDoS attack comprising TCP ACK packets.
    /// The packets will not contain a payload but may have the PSH flag enabled.
    /// In the normal TCP, the ACK packets indicate to the other party
    /// that the data have been received successfully.
    /// ACK packets are very common and can constitute 50% of the entire TCP packets.
    /// The attack will typically affect stateful devices
    /// that must process each packet and that can be overwhelmed.
    /// ACK flood is tricky to mitigate for several reasons.
    /// It can be spoofed the attacker can easily generate a high rate of attacking traffic,
    /// and it is very difficult to distinguish between a Legitimate ACK and an attacking ACK,
    /// as they look the same.
    /// Total number of packets sent = retransmit x threads.
    #[cfg(feature = "flood")]
    pub fn tcp_ack_flood(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
        threads: usize,
        retransmit: usize,
        repeat: usize,
        fake_src: bool,
    ) -> Result<PistolFloods, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        flood::tcp_ack_flood(net_infos, threads, retransmit, repeat, fake_src)
    }
    /// The raw version of tcp_ack_flood function.
    /// It performs a TCP ACK flood attack on the specified destination address and port.
    #[cfg(feature = "flood")]
    pub fn tcp_ack_flood_raw(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
        retransmit: usize,
        repeat: usize,
        fake_src: bool,
    ) -> Result<usize, PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![dst_port], src_addr, src_port)?;
        flood::tcp_ack_flood_raw(net_info, retransmit, repeat, fake_src)
    }
    /// TCP ACK flood with PSH flag set.
    /// Perform a TCP ACK flood with PSH flag set DDoS attack on the specified targets.
    /// An Internet Control Message Protocol (ICMP) flood DDoS attack,
    /// also known as a Ping flood attack,
    /// is a common Denial-of-Service (DoS) attack in
    /// which an attacker max_attempts to overwhelm a targeted device with ICMP echo-requests (pings).
    /// Normally, ICMP echo-request and echo-reply messages are used to ping a network device
    /// in order to diagnose the health and connectivity of the device and the connection
    /// between the sender and the device.
    /// By flooding the target with request packets,
    /// the network is forced to respond with an equal number of reply packets.
    /// This causes the target to become inaccessible to normal traffic.
    /// Total number of packets sent = retransmit x threads.
    #[cfg(feature = "flood")]
    pub fn tcp_ack_psh_flood(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
        threads: usize,
        retransmit: usize,
        repeat: usize,
        fake_src: bool,
    ) -> Result<PistolFloods, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        flood::tcp_ack_psh_flood(net_infos, threads, retransmit, repeat, fake_src)
    }
    /// The raw version of tcp_ack_psh_flood function.
    /// It performs a TCP ACK flood with PSH flag set attack
    /// on the specified destination address and port.
    #[cfg(feature = "flood")]
    pub fn tcp_ack_psh_flood_raw(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
        retransmit: usize,
        repeat: usize,
        fake_src: bool,
    ) -> Result<usize, PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![dst_port], src_addr, src_port)?;
        flood::tcp_ack_psh_flood_raw(net_info, retransmit, repeat, fake_src)
    }
    /// In a TCP SYN Flood attack, the malicious entity sends a barrage of
    /// SYN requests to a target server but intentionally avoids sending the final ACK.
    /// This leaves the server waiting for a response that never comes,
    /// consuming resources for each of these half-open connections.
    /// Total number of packets sent = retransmit x threads.
    #[cfg(feature = "flood")]
    pub fn tcp_syn_flood(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
        threads: usize,
        retransmit: usize,
        repeat: usize,
        fake_src: bool,
    ) -> Result<PistolFloods, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        flood::tcp_syn_flood(net_infos, threads, retransmit, repeat, fake_src)
    }
    /// The raw version of tcp_syn_flood function.
    /// It performs a TCP SYN flood attack on the specified destination address and port.
    #[cfg(feature = "flood")]
    pub fn tcp_syn_flood_raw(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
        retransmit: usize,
        repeat: usize,
        fake_src: bool,
    ) -> Result<usize, PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![dst_port], src_addr, src_port)?;
        flood::tcp_syn_flood_raw(net_info, retransmit, repeat, fake_src)
    }
    /// In a UDP Flood attack,
    /// the attacker sends a massive number of UDP packets to random ports on the target host.
    /// This barrage of packets forces the host to:
    /// Check for applications listening at each port.
    /// Realize that no application is listening at many of these ports.
    /// Respond with an Internet Control Message Protocol (ICMP) Destination Unreachable packet.
    #[cfg(feature = "flood")]
    pub fn udp_flood(
        &mut self,
        targets: &[Target],
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
        threads: usize,
        retransmit: usize,
        repeat: usize,
        fake_src: bool,
    ) -> Result<PistolFloods, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, src_addr, src_port)?;
        flood::udp_flood(net_infos, threads, retransmit, repeat, fake_src)
    }
    /// The raw version of udp_flood function.
    /// It performs a UDP flood attack on the specified destination address and port.
    #[cfg(feature = "flood")]
    pub fn udp_flood_raw(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        src_addr: Option<IpAddr>,
        src_port: Option<u16>,
        retransmit: usize,
        repeat: usize,
        fake_src: bool,
    ) -> Result<usize, PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![dst_port], src_addr, src_port)?;
        flood::udp_flood_raw(net_info, retransmit, repeat, fake_src)
    }
    /* OS Detect */
    /// Parse Nmap OS database file lines.
    /// This function takes lines from an Nmap OS database file
    /// and parses them into a structured format.
    /// Each entry in the database is represented as an NmapOsDb struct,
    /// which contains information about a specific operating system fingerprint.
    #[cfg(feature = "os")]
    pub fn nmap_os_db_parser(lines: Vec<String>) -> Result<Vec<NmapOsDb>, PistolError> {
        os::dbparser::nmap_os_db_parser(lines)
    }
    /// Detect target machine OS on IPv4 and IPv6.
    /// This function uses a combination of TCP, UDP, and ICMP probes
    /// to gather information about the target system's network stack behavior.
    /// By analyzing the responses to these probes,
    /// it max_attempts to identify the operating system running on the target machine.
    #[cfg(feature = "os")]
    pub fn os_detect(
        &mut self,
        targets: &[Target],
        top_k: usize,
    ) -> Result<PistolOsDetects, PistolError> {
        let (net_infos, dur) = self.init_recvers(targets, None, None)?;
        os::os_detect(net_infos, self.threads, self.timeout, top_k)
    }
    /// The raw version of os_detect function.
    /// It sends a series of TCP, UDP, and ICMP probes to the target IP address
    /// using the specified open and closed ports.
    /// By analyzing the responses to these probes,
    /// it max_attempts to identify the operating system running on the target machine.
    #[cfg(feature = "os")]
    pub fn os_detect_raw(
        &mut self,
        dst_addr: IpAddr,
        dst_open_tcp_port: u16,
        dst_closed_tcp_port: u16,
        dst_closed_udp_port: u16,
        top_k: usize,
    ) -> Result<OsDetect, PistolError> {
        let (net_info, dur) = self.init_recver(dst_addr, vec![], None, None)?;
        let dst_mac = net_info.dst_mac;
        let dst_addr = net_info.dst_addr;
        let ori_dst_addr = dst_addr;
        let src_mac = net_info.src_mac;
        let src_addr = net_info.src_addr;
        let interface = &net_info.interface;
        os::os_detect_raw(
            dst_mac,
            dst_addr,
            ori_dst_addr,
            dst_open_tcp_port,
            dst_closed_tcp_port,
            dst_closed_udp_port,
            src_mac,
            src_addr,
            interface,
            self.timeout,
            top_k,
        )
    }
    /* Service Detect */
    /// Detect target port service.
    /// This function sends various probes to the target ports
    /// to identify the services running on them.
    /// By analyzing the responses to these probes,
    /// it max_attempts to determine the service type and version.
    #[cfg(feature = "vs")]
    pub fn vs_scan(
        &self,
        targets: &[Target],
        only_null_probe: bool,
        only_tcp_recommended: bool,
        only_udp_recommended: bool,
        intensity: usize,
    ) -> Result<PistolVsScans, PistolError> {
        vs::vs_scan(
            targets,
            self.threads,
            only_null_probe,
            only_tcp_recommended,
            only_udp_recommended,
            intensity,
            self.timeout,
        )
    }
    /// The raw version of vs_scan function.
    /// It sends various probes to the target IP address and port
    /// to identify the service running on that port.
    /// By analyzing the responses to these probes,
    /// it max_attempts to determine the service type and version.
    #[cfg(feature = "vs")]
    pub fn vs_scan_raw(
        &self,
        dst_addr: IpAddr,
        dst_port: u16,
        only_null_probe: bool,
        only_tcp_recommended: bool,
        only_udp_recommended: bool,
        intensity: usize,
    ) -> Result<PortService, PistolError> {
        vs::vs_scan_raw(
            dst_addr,
            dst_port,
            only_null_probe,
            only_tcp_recommended,
            only_udp_recommended,
            intensity,
            self.timeout,
        )
    }
}

/// Queries the IP address of a domain name and returns.
/// If multiple IP addresses are found, all are returned.
pub fn dns_query(hostname: &str) -> Result<Vec<IpAddr>, PistolError> {
    let ips = lookup_host(hostname)?;
    let mut ret = Vec::new();
    for ip in ips {
        ret.push(ip);
    }
    Ok(ret)
}

#[cfg(feature = "os")]
trait Ipv6CheckMethods {
    fn is_global_x(&self) -> bool;
}

#[cfg(feature = "os")]
impl Ipv6CheckMethods for Ipv6Addr {
    fn is_global_x(&self) -> bool {
        let ip = self;
        let segments = ip.segments();

        // Unspecified (::/128)
        if ip.is_unspecified() {
            return false;
        }

        // Loopback (::1/128)
        if ip.is_loopback() {
            return false;
        }

        // Unique local (fc00::/7)
        if (segments[0] & 0xfe00) == 0xfc00 {
            return false;
        }

        // Link-local (fe80::/10)
        if ip.is_unicast_link_local() {
            return false;
        }

        // Multicast (ff00::/8)
        if ip.is_multicast() {
            return false;
        }

        // IPv4-mapped (::ffff:0:0/96)
        if segments[0] == 0
            && segments[1] == 0
            && segments[2] == 0
            && segments[3] == 0
            && segments[4] == 0
            && segments[5] == 0xffff
        {
            return false;
        }

        // IPv4-compatible (::/96) — deprecated
        if segments[0] == 0
            && segments[1] == 0
            && segments[2] == 0
            && segments[3] == 0
            && segments[4] == 0
            && segments[5] == 0
        {
            return false;
        }

        // 2001:db8::/32 documentation
        if (segments[0] == 0x2001) && (segments[1] == 0x0db8) {
            return false;
        }

        // 2001:10::/28 ORCHIDv2
        if (segments[0] & 0xfff0) == 0x2001 && (segments[1] >> 12) == 0x0001 {
            return false;
        }

        // 64:ff9b::/96 IPv4/IPv6 translation
        if segments[0] == 0x64 && segments[1] == 0xff9b {
            return false;
        }

        // If none of the exclusions matched, it's global
        true
    }
}

#[cfg(feature = "os")]
trait Ipv4CheckMethods {
    fn is_global_x(&self) -> bool;
}

#[cfg(feature = "os")]
impl Ipv4CheckMethods for Ipv4Addr {
    fn is_global_x(&self) -> bool {
        let ip = self;
        let octets = ip.octets();

        // RFC 1918 private
        if ip.is_private() {
            return false;
        }

        // 127.0.0.0/8 loopback
        if ip.is_loopback() {
            return false;
        }

        // 169.254.0.0/16 link-local
        if ip.is_link_local() {
            return false;
        }

        // 255.255.255.255 broadcast
        if ip.is_broadcast() {
            return false;
        }

        // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 documentation
        if ip.is_documentation() {
            return false;
        }

        // 0.0.0.0/8 unspecified
        if ip.is_unspecified() {
            return false;
        }

        // 224.0.0.0/4 multicast
        if ip.is_multicast() {
            return false;
        }

        // 240.0.0.0/4 reserved
        if octets[0] >= 240 {
            return false;
        }

        // 100.64.0.0/10 shared address space (RFC 6598)
        if octets[0] == 100 && (octets[1] & 0b1100_0000) == 64 {
            return false;
        }

        // 192.0.0.0/24 IETF protocol assignments
        if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
            return false;
        }

        // 198.18.0.0/15 benchmarking
        if octets[0] == 198 && (octets[1] & 0b1111_1110) == 18 {
            return false;
        }

        true
    }
}

/// Ipv4Addr::is_global() and Ipv6Addr::is_global() is a nightly-only experimental API,
/// use this trait instead until its become stable function.
#[cfg(feature = "os")]
trait IpCheckMethods {
    fn is_global_x(&self) -> bool;
}

#[cfg(feature = "os")]
impl IpCheckMethods for IpAddr {
    fn is_global_x(&self) -> bool {
        match self {
            IpAddr::V4(ipv4) => ipv4.is_global_x(),
            IpAddr::V6(ipv6) => ipv6.is_global_x(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Target {
    addr: IpAddr,
    ports: Vec<u16>,
    // stores user input for non-IP addresses, such as domain names or subnets
    origin: Option<String>,
}

impl Target {
    pub fn new(addr: IpAddr, ports: Option<Vec<u16>>) -> Target {
        let h = match ports {
            Some(p) => Target {
                addr,
                ports: p,
                origin: None,
            },
            None => Target {
                addr,
                ports: vec![],
                origin: None,
            },
        };
        h
    }
    /// Only supported the IPv4 target (by default, network address and broadcast address addresses are ignored).
    pub fn from_subnet(subnet: &str, ports: Option<Vec<u16>>) -> Result<Vec<Target>, PistolError> {
        let ip_pool = Ipv4Pool::from_str(subnet)?;
        let mut targets = Vec::new();

        let ports = match ports {
            Some(p) => p,
            None => Vec::new(),
        };

        let last = ip_pool.len();
        for (i, ip) in ip_pool.into_iter().enumerate() {
            if i == 0 || (last > 0 && i == last - 1) {
                continue;
            } else {
                let target = Target {
                    addr: ip.into(),
                    ports: ports.clone(),
                    origin: Some(subnet.to_string()),
                };
                targets.push(target);
            }
        }
        Ok(targets)
    }
    /// Only supported the IPv6 target (by default, network address and broadcast address addresses are ignored).
    pub fn from_subnet6(subnet: &str, ports: Option<Vec<u16>>) -> Result<Vec<Target>, PistolError> {
        let ip_pool = Ipv6Pool::from_str(subnet)?;
        let mut targets = Vec::new();

        let ports = match ports {
            Some(p) => p,
            None => Vec::new(),
        };

        let last = ip_pool.len();
        for (i, ip) in ip_pool.into_iter().enumerate() {
            if i == 0 || (last > 0 && i == last - 1) {
                continue;
            } else {
                let target = Target {
                    addr: ip.into(),
                    ports: ports.clone(),
                    origin: Some(subnet.to_string()),
                };
                targets.push(target);
            }
        }
        Ok(targets)
    }
    /// If possible, convert the domain name to an IPv4 address, otherwise return an error (returns all IPv4 addresses).
    pub fn from_domain(domain: &str, ports: Option<Vec<u16>>) -> Result<Vec<Target>, PistolError> {
        let ips = dns_query(domain)?;
        let mut ret = Vec::new();

        let ports = match ports {
            Some(p) => p,
            None => Vec::new(),
        };

        for ip in ips {
            if ip.is_ipv4() {
                let target = Target {
                    addr: ip,
                    ports: ports.clone(),
                    origin: Some(domain.to_string()),
                };
                ret.push(target);
            }
        }
        Ok(ret)
    }
    /// If possible, convert the domain name to an IPv6 address, otherwise return an error (returns all IPv6 addresses).
    pub fn from_domain6(domain: &str, ports: Option<Vec<u16>>) -> Result<Vec<Target>, PistolError> {
        let ips = dns_query(domain)?;
        let mut ret = Vec::new();

        let ports = match ports {
            Some(p) => p,
            None => Vec::new(),
        };

        for ip in ips {
            if ip.is_ipv6() {
                let target = Target {
                    addr: ip,
                    ports: ports.clone(),
                    origin: Some(domain.to_string()),
                };
                ret.push(target);
            }
        }
        Ok(ret)
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output_str = format!("{} {:?}", self.addr, self.ports);
        write!(f, "{}", output_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "scan")]
    use chrono::Local;
    #[cfg(any(feature = "scan", feature = "os", feature = "vs"))]
    use std::net::Ipv4Addr;
    #[cfg(feature = "scan")]
    use subnetwork::CrossIpv4Pool;
    #[test]
    fn test_dns_query() {
        let hostname = "ipv6.sjtu.edu.cn";
        let ret = dns_query(hostname).unwrap();
        println!("{:?}", ret);
    }
    /// for parsing nmap --top-ports output
    fn simple_top_ports_parser(ports_str: &str) -> Result<Vec<u16>, PistolError> {
        let mut ret = Vec::new();
        let ports_str_split: Vec<&str> = ports_str.split(",").collect();
        for p in ports_str_split {
            if p.contains("-") {
                let p_split: Vec<&str> = p.split("-").collect();
                if p_split.len() == 2 {
                    let start: u16 = p_split[0].parse()?;
                    let end: u16 = p_split[1].parse()?;
                    if start < end {
                        for v in start..=end {
                            ret.push(v);
                        }
                    } else {
                        panic!("start({start}) > end({end})");
                    }
                } else {
                    panic!("p_split.len() not enough: {}", p_split.len());
                }
            } else {
                let v: u16 = p.parse()?;
                ret.push(v);
            }
        }
        Ok(ret)
    }
    #[test]
    fn test_top_ports() {
        // command: nmap -oX - --top-ports 100 x
        let top_100_ports_str = "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157";
        let top_100_ports = match simple_top_ports_parser(top_100_ports_str) {
            Ok(t) => t,
            Err(e) => panic!("top_100_ports parser error: {e}"),
        };
        println!("{}", top_100_ports.len());
        // println!("{:?}", top_100_ports);

        // command: nmap -oX - --top-ports 1000 x
        let top_1000_ports_str = "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389";
        let top_1000_ports = match simple_top_ports_parser(top_1000_ports_str) {
            Ok(t) => t,
            Err(e) => panic!("top_1000_ports parser error: {e}"),
        };
        println!("{}", top_1000_ports.len());
        // println!("{:?}", top_1000_ports);

        // command: nmap -sT --top-ports 100 -v -oG -
        let top_100_tcp_ports_str = "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157";
        let top_100_tcp_ports = match simple_top_ports_parser(top_100_tcp_ports_str) {
            Ok(t) => t,
            Err(e) => panic!("top_1000_tcp_ports parser error: {e}"),
        };
        println!("{}", top_100_tcp_ports.len());
        // println!("{:?}", top_100_tcp_ports);

        // command: nmap -sT --top-ports 1000 -v -oG -
        let top_1000_tcp_ports_str = "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389";
        let top_1000_tcp_ports = match simple_top_ports_parser(top_1000_tcp_ports_str) {
            Ok(t) => t,
            Err(e) => panic!("top_1000_tcp_ports parser error: {e}"),
        };
        println!("{}", top_1000_tcp_ports.len());
        // println!("{:?}", top_1000_tcp_ports);

        // command: nmap -sU --top-ports 100 -v -oG -
        let top_100_udp_ports_str = "7,9,17,19,49,53,67-69,80,88,111,120,123,135-139,158,161-162,177,427,443,445,497,500,514-515,518,520,593,623,626,631,996-999,1022-1023,1025-1030,1433-1434,1645-1646,1701,1718-1719,1812-1813,1900,2000,2048-2049,2222-2223,3283,3456,3703,4444,4500,5000,5060,5353,5632,9200,10000,17185,20031,30718,31337,32768-32769,32771,32815,33281,49152-49154,49156,49181-49182,49185-49186,49188,49190-49194,49200-49201,65024";
        let top_100_udp_ports = match simple_top_ports_parser(top_100_udp_ports_str) {
            Ok(t) => t,
            Err(e) => panic!("top_1000_udp_ports parser error: {e}"),
        };
        println!("{}", top_100_udp_ports.len());
        // println!("{:?}", top_100_tcp_ports);

        // command: nmap -sU --top-ports 1000 -v -oG -
        let top_1000_udp_ports_str = "2-3,7,9,13,17,19-23,37-38,42,49,53,67-69,80,88,111-113,120,123,135-139,158,161-162,177,192,199,207,217,363,389,402,407,427,434,443,445,464,497,500,502,512-515,517-518,520,539,559,593,623,626,631,639,643,657,664,682-689,764,767,772-776,780-782,786,789,800,814,826,829,838,902-903,944,959,965,983,989-990,996-1001,1007-1008,1012-1014,1019-1051,1053-1060,1064-1070,1072,1080-1081,1087-1088,1090,1100-1101,1105,1124,1200,1214,1234,1346,1419,1433-1434,1455,1457,1484-1485,1524,1645-1646,1701,1718-1719,1761,1782,1804,1812-1813,1885-1886,1900-1901,1993,2000,2002,2048-2049,2051,2148,2160-2161,2222-2223,2343,2345,2362,2967,3052,3130,3283,3296,3343,3389,3401,3456-3457,3659,3664,3702-3703,4000,4008,4045,4444,4500,4666,4672,5000-5003,5010,5050,5060,5093,5351,5353,5355,5500,5555,5632,6000-6002,6004,6050,6346-6347,6970-6971,7000,7938,8000-8001,8010,8181,8193,8900,9000-9001,9020,9103,9199-9200,9370,9876-9877,9950,10000,10080,11487,16086,16402,16420,16430,16433,16449,16498,16503,16545,16548,16573,16674,16680,16697,16700,16708,16711,16739,16766,16779,16786,16816,16829,16832,16838-16839,16862,16896,16912,16918-16919,16938-16939,16947-16948,16970,16972,16974,17006,17018,17077,17091,17101,17146,17184-17185,17205,17207,17219,17236-17237,17282,17302,17321,17331-17332,17338,17359,17417,17423-17424,17455,17459,17468,17487,17490,17494,17505,17533,17549,17573,17580,17585,17592,17605,17615-17616,17629,17638,17663,17673-17674,17683,17726,17754,17762,17787,17814,17823-17824,17836,17845,17888,17939,17946,17989,18004,18081,18113,18134,18156,18228,18234,18250,18255,18258,18319,18331,18360,18373,18449,18485,18543,18582,18605,18617,18666,18669,18676,18683,18807,18818,18821,18830,18832,18835,18869,18883,18888,18958,18980,18985,18987,18991,18994,18996,19017,19022,19039,19047,19075,19096,19120,19130,19140-19141,19154,19161,19165,19181,19193,19197,19222,19227,19273,19283,19294,19315,19322,19332,19374,19415,19482,19489,19500,19503-19504,19541,19600,19605,19616,19624-19625,19632,19639,19647,19650,19660,19662-19663,19682-19683,19687,19695,19707,19717-19719,19722,19728,19789,19792,19933,19935-19936,19956,19995,19998,20003-20004,20019,20031,20082,20117,20120,20126,20129,20146,20154,20164,20206,20217,20249,20262,20279,20288,20309,20313,20326,20359-20360,20366,20380,20389,20409,20411,20423-20425,20445,20449,20464-20465,20518,20522,20525,20540,20560,20665,20678-20679,20710,20717,20742,20752,20762,20791,20817,20842,20848,20851,20865,20872,20876,20884,20919,21000,21016,21060,21083,21104,21111,21131,21167,21186,21206-21207,21212,21247,21261,21282,21298,21303,21318,21320,21333,21344,21354,21358,21360,21364,21366,21383,21405,21454,21468,21476,21514,21524-21525,21556,21566,21568,21576,21609,21621,21625,21644,21649,21655,21663,21674,21698,21702,21710,21742,21780,21784,21800,21803,21834,21842,21847,21868,21898,21902,21923,21948,21967,22029,22043,22045,22053,22055,22105,22109,22123-22124,22341,22692,22695,22739,22799,22846,22914,22986,22996,23040,23176,23354,23531,23557,23608,23679,23781,23965,23980,24007,24279,24511,24594,24606,24644,24854,24910,25003,25157,25240,25280,25337,25375,25462,25541,25546,25709,25931,26407,26415,26720,26872,26966,27015,27195,27444,27473,27482,27707,27892,27899,28122,28369,28465,28493,28543,28547,28641,28840,28973,29078,29243,29256,29810,29823,29977,30263,30303,30365,30544,30656,30697,30704,30718,30975,31059,31073,31109,31189,31195,31335,31337,31365,31625,31681,31731,31891,32345,32385,32528,32768-32780,32798,32815,32818,32931,33030,33249,33281,33354-33355,33459,33717,33744,33866,33872,34038,34079,34125,34358,34422,34433,34555,34570,34577-34580,34758,34796,34855,34861-34862,34892,35438,35702,35777,35794,36108,36206,36384,36458,36489,36669,36778,36893,36945,37144,37212,37393,37444,37602,37761,37783,37813,37843,38037,38063,38293,38412,38498,38615,39213,39217,39632,39683,39714,39723,39888,40019,40116,40441,40539,40622,40708,40711,40724,40732,40805,40847,40866,40915,41058,41081,41308,41370,41446,41524,41638,41702,41774,41896,41967,41971,42056,42172,42313,42431,42434,42508,42557,42577,42627,42639,43094,43195,43370,43514,43686,43824,43967,44101,44160,44179,44185,44190,44253,44334,44508,44923,44946,44968,45247,45380,45441,45685,45722,45818,45928,46093,46532,46836,47624,47765,47772,47808,47915,47981,48078,48189,48255,48455,48489,48761,49152-49163,49165-49182,49184-49202,49204-49205,49207-49216,49220,49222,49226,49259,49262,49306,49350,49360,49393,49396,49503,49640,49968,50099,50164,50497,50612,50708,50919,51255,51456,51554,51586,51690,51717,51905,51972,52144,52225,52503,53006,53037,53571,53589,53838,54094,54114,54281,54321,54711,54807,54925,55043,55544,55587,56141,57172,57409-57410,57813,57843,57958,57977,58002,58075,58178,58419,58631,58640,58797,59193,59207,59765,59846,60172,60381,60423,61024,61142,61319,61322,61370,61412,61481,61550,61685,61961,62154,62287,62575,62677,62699,62958,63420,63555,64080,64481,64513,64590,64727,65024";
        let top_1000_udp_ports = match simple_top_ports_parser(top_1000_udp_ports_str) {
            Ok(t) => t,
            Err(e) => panic!("top_1000_udp_ports parser error: {e}"),
        };
        println!("{}", top_1000_udp_ports.len());
        // println!("{:?}", top_1000_tcp_ports);
    }
    #[cfg(feature = "scan")]
    #[test]
    fn test_mac_scan() {
        let mut pistol = Pistol::new();
        pistol.set_threads(8);
        // pistol.set_log_level("debug");
        pistol.set_max_attempts(2);
        pistol.set_threads(8);
        pistol.set_timeout(2.5);

        let targets = vec![Target::new(Ipv4Addr::new(192, 168, 5, 254).into(), None)];
        let ret = pistol.mac_scan(&targets).unwrap();
        println!("{}", ret);
    }
    #[cfg(feature = "scan")]
    #[test]
    fn test_tcp_syn_scan() {
        let mut pistol = Pistol::new();
        pistol.set_threads(8);
        pistol.set_log_level("debug");
        pistol.set_max_attempts(2);
        pistol.set_threads(8);
        pistol.set_timeout(2.5);

        let src_ipv4 = None;
        let src_port = None;
        let targets = vec![Target::new(
            Ipv4Addr::new(192, 168, 5, 77).into(),
            Some(vec![22]),
        )];
        let ret = pistol.tcp_syn_scan(&targets, src_ipv4, src_port).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn test_load_cache() {
        let nc = NetCache::load();
        if let Some(nc) = nc {
            println!("{:?}", nc);
        } else {
            println!("no cache file found");
        }
    }
    #[cfg(feature = "scan")]
    #[test]
    fn example_mac_scan() {
        let mut pistol = Pistol::new();
        pistol.set_threads(512);
        // set the timeout same as `arp-scan`
        pistol.set_timeout(0.5);
        pistol.set_max_attempts(2);
        // pistol.set_log_level("debug");

        let targets = Target::from_subnet("192.168.5.0/24", None).unwrap();
        let ret = pistol.mac_scan(&targets).unwrap();
        println!("{}", ret);
    }
    #[cfg(feature = "scan")]
    #[test]
    fn example_tcp_syn_scan() {
        let mut pistol = Pistol::new();
        pistol.set_threads(16);
        pistol.set_timeout(1.0);
        // Number of max_attempts, it can also be understood as the maximum number of unsuccessful retries.
        // For example, here, 2 means that after the first detection the target port is closed, then an additional detection will be performed.
        pistol.set_max_attempts(2);

        // When using scanning, please use a real local address to get the return packet.
        // And for flood attacks, please consider using a fake address.
        // If the value here is None, the programme will automatically look up the available addresses from the existing interfaces on the device.
        // In some complex network environments, if the program cannot automatically identify the source IP address, you can set the source IP address manually here.
        let src_addr = None;
        // If the value of `source port` is `None`, the program will generate the source port randomly.
        let src_port = None;
        let start = Ipv4Addr::new(192, 168, 5, 1);
        let end = Ipv4Addr::new(192, 168, 5, 10);
        // The destination address is from 192.168.5.1 to 192.168.5.10.
        let subnet = CrossIpv4Pool::new(start, end).unwrap();
        let mut targets = vec![];
        for ip in subnet {
            // Test with a example port `22`
            let host = Target::new(ip.into(), Some(vec![22]));
            targets.push(host);
        }
        let ret = pistol.tcp_syn_scan(&targets, src_addr, src_port).unwrap();
        println!("{}", ret);
    }
    #[cfg(feature = "os")]
    #[test]
    fn example_os_detect() {
        let mut pistol = Pistol::new();
        pistol.set_threads(8);
        pistol.set_max_attempts(2);
        pistol.set_timeout(2.5);

        let dst_ipv4 = Ipv4Addr::new(192, 168, 5, 5);
        // `dst_open_tcp_port` must be a certain open tcp port.
        let dst_open_tcp_port = 22;
        // `dst_closed_tcp_port` must be a certain closed tcp port.
        let dst_closed_tcp_port = 8765;
        // `dst_closed_udp_port` must be a certain closed udp port.
        let dst_closed_udp_port = 9876;
        let target = Target::new(
            dst_ipv4.into(),
            Some(vec![
                dst_open_tcp_port, // The order of these three ports cannot be disrupted.
                dst_closed_tcp_port,
                dst_closed_udp_port,
            ]),
        );
        let top_k = 3;

        // The `fingerprint` is the obtained fingerprint of the target OS.
        // Return the `top_k` best results (the number of os detect result may not equal to `top_k`), sorted by score.
        let ret = pistol.os_detect(&[target], top_k).unwrap();
        println!("{}", ret);
    }
    #[cfg(feature = "os")]
    #[test]
    fn example_os_detect_ipv6() {
        let mut pistol = Pistol::new();
        pistol.set_threads(8);
        pistol.set_timeout(2.5);

        let dst_ipv6 = Ipv6Addr::from_str("fe80::20c:29ff:fe2c:9e4").unwrap();
        let dst_open_tcp_port = 22;
        let dst_closed_tcp_port = 8765;
        let dst_closed_udp_port = 9876;
        let target = Target::new(
            dst_ipv6.into(),
            Some(vec![
                dst_open_tcp_port,
                dst_closed_tcp_port,
                dst_closed_udp_port,
            ]),
        );

        let top_k = 3;
        let ret = pistol.os_detect(&[target], top_k).unwrap();
        println!("{}", ret);
    }
    #[cfg(feature = "vs")]
    #[test]
    fn example_vs_scan() {
        let mut pistol = Pistol::new();
        pistol.set_threads(8);
        pistol.set_max_attempts(2);
        pistol.set_timeout(2.5);

        let dst_addr = Ipv4Addr::new(192, 168, 5, 5);
        let target = Target::new(dst_addr.into(), Some(vec![22, 80, 8080]));
        // only_null_probe = true, only_tcp_recommended = any, only_udp_recomended = any: only try the NULL probe (for TCP)
        // only_tcp_recommended = true: only try the tcp probe recommended port
        // only_udp_recommended = true: only try the udp probe recommended port
        let (only_null_probe, only_tcp_recommended, only_udp_recommended) = (false, true, true);
        let intensity = 7; // nmap default
        let ret = pistol
            .vs_scan(
                &[target],
                only_null_probe,
                only_tcp_recommended,
                only_udp_recommended,
                intensity,
            )
            .unwrap();
        println!("{}", ret);
    }
}
