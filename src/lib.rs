#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("lib.md")]
use crate::datalink::Channel::Ethernet;
use dns_lookup::lookup_host;
use pcapture::pcapng::PcapNg;
use pnet::datalink;
use std::fmt;
use std::fs::File;
use std::net::IpAddr;
#[cfg(feature = "os")]
use std::net::Ipv6Addr;
use std::result;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;
use subnetwork::Ipv4Pool;
use subnetwork::Ipv6Pool;
use tracing::Level;
use tracing::error;
use tracing::warn;
use tracing_subscriber::FmtSubscriber;
use uuid::Uuid;

pub mod error;
pub mod flood;
pub mod hop;
pub mod layer;
pub mod os;
pub mod ping;
pub mod route;
pub mod scan;
pub mod utils;
pub mod vs;

use crate::error::PistolError;
use crate::layer::LayerMatch;
use crate::layer::layer2_capture;
use crate::route::SystemNetCache;

pub type Result<T, E = error::PistolError> = result::Result<T, E>;

static SYSTEM_NET_CACHE: LazyLock<Arc<Mutex<SystemNetCache>>> = LazyLock::new(|| {
    let snc = SystemNetCache::init().expect("can not init the system net cache");
    Arc::new(Mutex::new(snc))
});

static UNIFIED_RECV_MATCHS: LazyLock<Arc<Mutex<Vec<PistolChannel>>>> = LazyLock::new(|| {
    let v = Vec::new();
    Arc::new(Mutex::new(v))
});

static PISTOL_RUNNER_IS_RUNNING: LazyLock<Arc<Mutex<bool>>> =
    LazyLock::new(|| Arc::new(Mutex::new(false)));

#[derive(Debug, Clone)]
struct PistolChannel {
    uuid: Uuid, // identified this PC
    channel: Sender<Vec<u8>>,
    layer_matchs: Vec<LayerMatch>,
}

pub struct PistolRunner {
    pub capture: Option<PistolCapture>,
}

// sec
const RUNNER_DEFAULT_TIMEOUT: f64 = 0.001;

impl PistolRunner {
    fn get_global_layer_matchs() -> Result<Vec<PistolChannel>, PistolError> {
        match UNIFIED_RECV_MATCHS.lock() {
            Ok(urm) => Ok(urm.clone()),
            Err(e) => Err(PistolError::TryLockGlobalVarFailed {
                var_name: String::from("UNIFIED_RECV_MATCHS"),
                e: e.to_string(),
            }),
        }
    }
    fn init_runner(timeout: Option<Duration>) -> Result<(), PistolError> {
        // This timeout can be set very small,
        // because even if no data packet is received before the timeout expires,
        // the next cycle of the loop will continue to receive data packets.
        // That is, We can speed up the loop by setting a very small timeout.
        let timeout = match timeout {
            Some(t) => t,
            None => Duration::from_secs_f64(RUNNER_DEFAULT_TIMEOUT),
        };

        let config = datalink::Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
            read_timeout: Some(timeout),
            write_timeout: Some(timeout),
            channel_type: datalink::ChannelType::Layer2,
            bpf_fd_attempts: 1000,
            linux_fanout: None,
            promiscuous: false,
            socket_fd: None,
        };
        // listen all interface
        for interface in datalink::interfaces() {
            let (_, mut receiver) = match datalink::channel(&interface, config) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => return Err(PistolError::CreateDatalinkChannelFailed),
                Err(e) => return Err(e.into()),
            };
            thread::spawn(move || {
                loop {
                    // append this packet to global vec
                    match receiver.next() {
                        Ok(ethernet_packet) => {
                            // capture the recved packet and save it into file
                            match layer2_capture(ethernet_packet) {
                                Ok(_) => (),
                                Err(e) => error!("capture recv packet failed: {}", e),
                            }
                            let pistol_channels = match Self::get_global_layer_matchs() {
                                Ok(pcs) => pcs,
                                Err(e) => {
                                    error!("get global layer matchs failed: {}", e);
                                    continue;
                                }
                            };
                            for pc in pistol_channels {
                                // if any matchs just return
                                for lm in pc.layer_matchs {
                                    if lm.do_match(ethernet_packet) {
                                        // send the matched result to user thread
                                        match pc.channel.send(ethernet_packet.to_vec()) {
                                            Ok(_) => (),
                                            Err(e) => {
                                                error!("try return data to sender failed: {}", e)
                                            }
                                        };
                                    }
                                }
                            }
                        }
                        Err(e) => warn!("layer2 recv failed: {}", e), // many timeout error
                    }
                }
            });
        }
        // set PISTOL_RUNNER_IS_RUNNING = ture
        match PISTOL_RUNNER_IS_RUNNING.lock() {
            Ok(mut r) => *r = true,
            Err(e) => {
                return Err(PistolError::TryLockGlobalVarFailed {
                    var_name: String::from("PISTOL_RUNNER_IS_RUNNING"),
                    e: e.to_string(),
                });
            }
        }
        Ok(())
    }
    pub fn init(
        logger: PistolLogger,
        capture: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<PistolRunner, PistolError> {
        match logger {
            PistolLogger::Debug => PistolLogger::set_level(Level::DEBUG)?,
            PistolLogger::Warn => PistolLogger::set_level(Level::WARN)?,
            PistolLogger::Info => PistolLogger::set_level(Level::INFO)?,
            PistolLogger::None => (),
        }

        let capture = match capture {
            Some(filename) => Some(PistolCapture::init(&filename)?),
            None => None,
        };

        let _ = Self::init_runner(timeout)?;
        Ok(PistolRunner { capture })
    }
}

// sec
const DEFAULT_TIMEOUT: f64 = 1.0;

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

static PISTOL_PCAPNG: LazyLock<Arc<Mutex<PcapNg>>> =
    LazyLock::new(|| Arc::new(Mutex::new(PcapNg::new_fake())));

static PISTOL_PCAPNG_FLAG: LazyLock<Arc<Mutex<bool>>> =
    LazyLock::new(|| Arc::new(Mutex::new(false)));

/// Save the sent traffic locally in pcapng format.
/// Note that this method does not read the traffic from the network card,
/// but to save the traffic before the it is sent.
pub struct PistolCapture {
    fs: File,
}

impl PistolCapture {
    fn init(filename: &str) -> Result<PistolCapture, PistolError> {
        match PISTOL_PCAPNG_FLAG.lock() {
            Ok(mut ppf) => {
                *ppf = true;
                let fs = File::create(filename)?;
                Ok(PistolCapture { fs })
            }
            Err(e) => Err(PistolError::InitCaptureError { e: e.to_string() }),
        }
    }
    /// The program will automatically call this module when the function ends, without manual setting.
    fn save_to_file(&mut self) -> Result<(), PistolError> {
        match PISTOL_PCAPNG_FLAG.lock() {
            Ok(ppf) => {
                if *ppf {
                    match PISTOL_PCAPNG.lock() {
                        Ok(pp) => {
                            (*pp).write(&mut self.fs)?;
                            Ok(())
                        }
                        Err(e) => Err(PistolError::SaveCaptureError { e: e.to_string() }),
                    }
                } else {
                    warn!("the capture function is disabled");
                    Ok(())
                }
            }
            Err(e) => Err(PistolError::SaveCaptureError { e: e.to_string() }),
        }
    }
}

impl Drop for PistolCapture {
    fn drop(&mut self) {
        self.save_to_file().expect("auto save to file failed");
    }
}

pub enum PistolLogger {
    Debug,
    Warn,
    Info,
    None,
}

impl PistolLogger {
    fn set_level(level: Level) -> Result<(), PistolError> {
        let subscriber = FmtSubscriber::builder().with_max_level(level).finish();
        let _ = tracing::subscriber::set_global_default(subscriber)?;
        Ok(())
    }
}

#[cfg(feature = "os")]
trait Ipv6CheckMethods {
    fn is_global_x(&self) -> bool;
}

/// Ipv4Addr::is_global() and Ipv6Addr::is_global() is a nightly-only experimental API,
/// use this trait instead until its become stable function.
#[cfg(feature = "os")]
impl Ipv6CheckMethods for Ipv6Addr {
    fn is_global_x(&self) -> bool {
        let octets = self.octets();
        let is_local = if octets[0] == 0b11111110 && octets[1] >> 6 == 0b00000010 {
            true
        } else {
            false
        };
        !is_local
    }
}

#[cfg(feature = "os")]
trait IpCheckMethods {
    fn is_global_x(&self) -> bool;
}

#[cfg(feature = "os")]
impl IpCheckMethods for IpAddr {
    fn is_global_x(&self) -> bool {
        match self {
            IpAddr::V4(ipv4) => !ipv4.is_private(),
            IpAddr::V6(ipv6) => ipv6.is_global_x(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Target {
    pub addr: IpAddr,
    pub ports: Vec<u16>,
    pub origin: Option<String>, // stores user input for non-IP addresses, such as domain names or subnets
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

/* Scan */
#[cfg(feature = "scan")]
pub use scan::arp_scan_raw;
#[cfg(feature = "scan")]
pub use scan::mac_scan;
#[cfg(feature = "scan")]
pub use scan::ndp_ns_scan_raw;
#[cfg(feature = "scan")]
pub use scan::tcp_ack_scan;
#[cfg(feature = "scan")]
pub use scan::tcp_ack_scan_raw;
#[cfg(feature = "scan")]
pub use scan::tcp_connect_scan;
#[cfg(feature = "scan")]
pub use scan::tcp_connect_scan_raw;
#[cfg(feature = "scan")]
pub use scan::tcp_fin_scan;
#[cfg(feature = "scan")]
pub use scan::tcp_fin_scan_raw;
#[cfg(feature = "scan")]
pub use scan::tcp_idle_scan;
#[cfg(feature = "scan")]
pub use scan::tcp_idle_scan_raw;
#[cfg(feature = "scan")]
pub use scan::tcp_maimon_scan;
#[cfg(feature = "scan")]
pub use scan::tcp_maimon_scan_raw;
#[cfg(feature = "scan")]
pub use scan::tcp_null_scan;
#[cfg(feature = "scan")]
pub use scan::tcp_null_scan_raw;
#[cfg(feature = "scan")]
pub use scan::tcp_syn_scan;
#[cfg(feature = "scan")]
pub use scan::tcp_syn_scan_raw;
#[cfg(feature = "scan")]
pub use scan::tcp_window_scan;
#[cfg(feature = "scan")]
pub use scan::tcp_window_scan_raw;
#[cfg(feature = "scan")]
pub use scan::tcp_xmas_scan;
#[cfg(feature = "scan")]
pub use scan::tcp_xmas_scan_raw;
#[cfg(feature = "scan")]
pub use scan::udp_scan;
#[cfg(feature = "scan")]
pub use scan::udp_scan_raw;

/* Ping */

#[cfg(feature = "ping")]
pub use ping::icmp_ping;
#[cfg(feature = "ping")]
pub use ping::icmp_ping_raw;
#[cfg(feature = "ping")]
pub use ping::tcp_ack_ping;
#[cfg(feature = "ping")]
pub use ping::tcp_ack_ping_raw;
#[cfg(feature = "ping")]
pub use ping::tcp_syn_ping;
#[cfg(feature = "ping")]
pub use ping::tcp_syn_ping_raw;
#[cfg(feature = "ping")]
pub use ping::udp_ping;
#[cfg(feature = "ping")]
pub use ping::udp_ping_raw;

/* Flood */

#[cfg(feature = "flood")]
pub use flood::flood_raw;
#[cfg(feature = "flood")]
pub use flood::icmp_flood;
#[cfg(feature = "flood")]
pub use flood::icmp_flood_raw;
#[cfg(feature = "flood")]
pub use flood::tcp_ack_flood;
#[cfg(feature = "flood")]
pub use flood::tcp_ack_flood_raw;
#[cfg(feature = "flood")]
pub use flood::tcp_ack_psh_flood;
#[cfg(feature = "flood")]
pub use flood::tcp_ack_psh_flood_raw;
#[cfg(feature = "flood")]
pub use flood::tcp_syn_flood;
#[cfg(feature = "flood")]
pub use flood::tcp_syn_flood_raw;
#[cfg(feature = "flood")]
pub use flood::udp_flood;
#[cfg(feature = "flood")]
pub use flood::udp_flood_raw;

/* OS Detect */

#[cfg(feature = "os")]
pub use os::os_detect;
#[cfg(feature = "os")]
pub use os::os_detect_raw;

/* Service Detect */

#[cfg(feature = "vs")]
pub use vs::vs_scan;
#[cfg(feature = "vs")]
pub use vs::vs_scan_raw;

/// Queries the IP address of a domain name and returns.
pub fn dns_query(hostname: &str) -> Result<Vec<IpAddr>, PistolError> {
    let ips: Vec<IpAddr> = lookup_host(hostname)?;
    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use subnetwork::CrossIpv4Pool;
    #[test]
    fn test_dns_query() {
        let hostname = "ipv6.sjtu.edu.cn";
        let ret = dns_query(hostname).unwrap();
        println!("{:?}", ret);
    }
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
    #[test]
    fn example_tcp_syn_scan() {
        // Initialize and run the Runner thread.
        // This step is required for all other functions except service detection.
        let _pr = PistolRunner::init(
            PistolLogger::None,                        // logger level settings
            Some(String::from("tcp_syn_scan.pcapng")), // capture pistol traffic for debugging
            None, // timeout settings, unless there is a clear reason, use the default here
        )
        .unwrap();

        // When using scanning, please use a real local address to get the return packet.
        // And for flood attacks, please consider using a fake address.
        // If the value here is None, the programme will automatically look up the available addresses from the existing interfaces on the device.
        // In some complex network environments, if the program cannot automatically identify the source IP address, you can set the source IP address manually here.
        let src_ipv4 = None;
        // If the value of `source port` is `None`, the program will generate the source port randomly.
        let src_port = None;
        let timeout = Some(Duration::new(1, 0));
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
        // Number of attempts, it can also be understood as the maximum number of unsuccessful retries.
        // For example, here, 2 means that after the first detection the target port is closed, then an additional detection will be performed.
        let max_attempts = 2;
        let num_threads = Some(8);
        let ret = tcp_syn_scan(
            &targets,
            num_threads,
            src_ipv4,
            src_port,
            timeout,
            max_attempts,
        )
        .unwrap();
        println!("{}", ret);
    }
    #[test]
    fn example_os_detect() {
        // Initialize and run the Runner thread.
        // This step is required for all other functions except service detection.
        let _pr = PistolRunner::init(
            PistolLogger::None,                     // logger level settings
            Some(String::from("os_detect.pcapng")), // capture pistol traffic for debugging
            None, // timeout settings, unless there is a clear reason, use the default here
        )
        .unwrap();

        // If the value of `src_ipv4` is `None`, the program will find it auto.
        let src_ipv4 = None;
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
        let timeout = Some(Duration::from_secs_f64(0.5));
        let top_k = 3;
        let num_threads = Some(8);

        // The `fingerprint` is the obtained fingerprint of the target OS.
        // Return the `top_k` best results (the number of os detect result may not equal to `top_k`), sorted by score.
        let ret = os_detect(&[target], num_threads, src_ipv4, top_k, timeout).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn example_os_detect_ipv6() {
        // Initialize and run the Runner thread.
        // This step is required for all other functions except service detection.
        let _pr = PistolRunner::init(
            PistolLogger::None,                          // logger level settings
            Some(String::from("os_detect_ipv6.pcapng")), // capture pistol traffic for debugging
            None, // timeout settings, unless there is a clear reason, use the default here
        )
        .unwrap();

        let src_ipv6 = None;
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

        let timeout = Some(Duration::from_secs_f64(0.5));
        let top_k = 3;
        let num_threads = Some(8);
        let ret = os_detect(&[target], num_threads, src_ipv6, top_k, timeout).unwrap();
        println!("{}", ret);
    }
    #[test]
    fn example_vs_scan() {
        // Initialize and run the Runner thread.
        // This step is required for all other functions except service detection.
        let _pr = PistolRunner::init(
            PistolLogger::None, // logger level settings
            None,               // this capture will not work for vs scan, so just set it to None
            None, // timeout settings, unless there is a clear reason, use the default here
        )
        .unwrap();

        let dst_addr = Ipv4Addr::new(192, 168, 5, 5);
        let target = Target::new(dst_addr.into(), Some(vec![22, 80, 8080]));
        let timeout = Some(Duration::from_secs_f64(0.5));
        // only_null_probe = true, only_tcp_recommended = any, only_udp_recomended = any: only try the NULL probe (for TCP)
        // only_tcp_recommended = true: only try the tcp probe recommended port
        // only_udp_recommended = true: only try the udp probe recommended port
        let (only_null_probe, only_tcp_recommended, only_udp_recommended) = (false, true, true);
        let intensity = 7; // nmap default
        let num_threads = Some(8);
        let ret = vs_scan(
            &[target],
            num_threads,
            only_null_probe,
            only_tcp_recommended,
            only_udp_recommended,
            intensity,
            timeout,
        )
        .unwrap();
        println!("{}", ret);
    }
}
