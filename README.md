# pistol-rs

The library must be run as root (Linux, *BSD) or administrator (Windows), the `stable` version of rust is recommended.

[![Rust](https://github.com/rikonaka/pistol-rs/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/rikonaka/pistol-rs/actions/workflows/rust.yml)

## Import from crates.io

```toml
[dependencies]
pistol = "^3"
```

On Windows, download `winpcap` [here](https://www.winpcap.org/install/) or `npcap` [here](https://npcap.com/#download) SDK, then place `Packet.lib` from the `Lib/x64` folder in your root of code (Note: the `npcap` did not test by libpnet according to the doc of libpnet).

## Cross Platform Support

| Platform           | Note                         |
| :----------------- | :--------------------------- |
| Linux              | supported                    |
| Unix (*BSD, MacOS) | supported                    |
| Windows            | supported (winpcap or npcap) |

## Cargo Feature Flags

Since version v3.2.0, features fields are supported, including `scan`, `ping`, `flood`, `os`, `vs`.

## Bugs About libpnet

**libpnet bug on Windows**

Bug issues: https://github.com/libpnet/libpnet/issues/707, the `libpnet` cannot get IPv6 address on Windows.

Therefore, until `libpnet` fixes this bug, IPv6 on Windows is not supported yet.

**libpnet bug on rust nightly version**

Bug issue: https://github.com/libpnet/libpnet/issues/686

## Host Discovery (Ping Scanning)

The implementation of the `pistol` host discovery according to the nmap [documentation](https://nmap.org/book/host-discovery.html).

| Method               | Detailed Documentation                                                                         | Note                            |
| :------------------- | :--------------------------------------------------------------------------------------------- | :------------------------------ |
| [x] TCP SYN Ping     | [nmap reference](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PS)       | IPv4 & IPv6                     |
| [x] TCP ACK Ping     | [nmap reference](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PA)       | IPv4 & IPv6                     |
| [x] UDP Ping         | [nmap reference](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PU)       | IPv4 & IPv6                     |
| [x] ICMP Ping        | [nmap reference](https://nmap.org/book/host-discovery-techniques.html#host-discovery-icmpping) | IPv4 & IPv6 (ICMP, ICMPv6)      |
| [x] ARP Scan         | [nmap reference](https://nmap.org/book/host-discovery-techniques.html#arp-scan)                | IPv4                            |
| [ ] IP Protocol Ping | [nmap reference](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PO)       | Complicated and not very useful |

## Port Scanning Techniques and Algorithms

The implementation of the `pistol` port scan according to the nmap [pdf](https://nmap.org/nmap_doc.html) and [documentation](https://nmap.org/book/scan-methods.html).

Additionally, since version `v3.1.6`, pistol has compiled 100 and 1000 commonly used ports (`TOP_100_PORTS`, `TOP_1000_PORTS`, `TOP_100_TCP_PORTS`, `TOP_1000_TCP_PORTS`, `TOP_100_UDP_PORTS`,`TOP_1000_UDP_PORTS`) in nmap to speed up scanning.


| Method                  | Detailed Documentation                                                       | Note                                    |
| :---------------------- | :--------------------------------------------------------------------------- | :-------------------------------------- |
| [x] TCP SYN Scan        | [nmap reference](https://nmap.org/book/synscan.html)                         | IPv4 & IPv6                             |
| [x] TCP Connect() Scan  | [nmap reference](https://nmap.org/book/scan-methods-connect-scan.html)       | IPv4 & IPv6                             |
| [x] TCP FIN Scan        | [nmap reference](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html) | IPv4 & IPv6                             |
| [x] TCP Null Scan       | [nmap reference](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html) | IPv4 & IPv6                             |
| [x] TCP Xmas Scan       | [nmap reference](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html) | IPv4 & IPv6                             |
| [x] TCP ACK Scan        | [nmap reference](https://nmap.org/book/scan-methods-ack-scan.html)           | IPv4 & IPv6                             |
| [x] TCP Window Scan     | [nmap reference](https://nmap.org/book/scan-methods-window-scan.html)        | IPv4 & IPv6                             |
| [x] TCP Maimon Scan     | [nmap reference](https://nmap.org/book/scan-methods-maimon-scan.html)        | IPv4 & IPv6                             |
| [x] UDP Scan            | [nmap reference](https://nmap.org/book/scan-methods-udp-scan.html)           | IPv4 & IPv6                             |
| [x] TCP Idle Scan       | [nmap reference](https://nmap.org/book/idlescan.html)                        | IPv4                                    |
| [ ] IP Protocol Scan    | [nmap reference](https://nmap.org/book/scan-methods-ip-protocol-scan.html)   | Complicated and not very useful         |
| [ ] TCP FTP Bounce Scan | [nmap reference](https://nmap.org/book/scan-methods-ftp-bounce-scan.html)    | The bugs exploited have long been fixed |

## Flood Attack

| Method                | Note                               |
| :-------------------- | :--------------------------------- |
| [x] TCP SYN Flood     | IPv4 & IPv6 support                |
| [x] TCP ACK Flood     | IPv4 & IPv6 support                |
| [x] TCP ACK PSH Flood | IPv4 & IPv6 support                |
| [x] UDP Flood         | IPv4 & IPv6 support                |
| [x] ICMP Flood        | IPv4 & IPv6 support (ICMP, ICMPv6) |

## Remote OS Detection

| Method             | Detailed Documentation                                             | Note                                           |
| :----------------- | :----------------------------------------------------------------- | :--------------------------------------------- |
| [x] IPv4 OS Detect | [nmap reference](https://nmap.org/book/osdetect-methods.html)      | Print fingerprint as nmap format now supported |
| [x] IPv6 OS Detect | [nmap reference](https://nmap.org/book/osdetect-ipv6-methods.html) | Print fingerprint as nmap format now supported |


### OS Detection on IPv6?

On ipv6, the fingerprints are unreadable and meaningless to humans, see [here](https://nmap.org/book/osdetect-fingerprint-format.html#osdetect-ex-typical-reference-fprint-ipv6) for details, and nmap uses logistic regression to match target OS on ipv6, but the matching algorithm is quite outdated with confusing design logic.

The first is about the `ST`, `RT` and `EXTRA` metrics in fingerprints in detection on [ipv6](https://nmap.org/book/osdetect-fingerprint-format.html), these three metrics are not used at all in the code, at the same time, there is no detailed description of how `ST` and `RT` are calculated, I don't know why nmap would keep them in the final fingerprint.

The second is `NI` probes. In the relevant [document](https://nmap.org/book/osdetect-ipv6-methods.html#osdetect-features-ipv6) of nmap, it describes the specific structure of `NI` probe, but I don't see anything about it in the code, and it seems to completely ignore this probe when do predict use logistic regression.

Furthermore, for the current mainstream operating systems, ipv6 fingerprint support is not as rich as ipv4, so try the ipv4 first.

## Service and Application Version Detection

| Methods               | Detailed Documentation                                       |
| :-------------------- | :----------------------------------------------------------- |
| [x] IPv4 Service Scan | [nmap reference](https://nmap.org/book/vscan-technique.html) |
| [x] IPv6 Service Scan | [nmap reference](https://nmap.org/book/vscan-technique.html) |

When implementing this module, I found that the biggest problem was that Rust's `Regex` library (including `FancyRegex`) could not perfectly adapt to nmap's regular expressions. The `PCRE` regular expression engine is used in the original C++ code of nmap, so that it can match non-ASCII printable characters like `\0` (the value is `0u8`). 

```c
#include <stdio.h>
#include <pcre.h>

int main() {
    const char *pattern = "\x00";
    const char *subject = "abc\0def";

    pcre *re = pcre_compile(pattern, 0, NULL, NULL, NULL);
    if (re == NULL) {
        printf("Regex compile failed\n");
        return 1;
    }

    int ovector[30];
    int rc = pcre_exec(re, NULL, subject, strlen(subject) + 1, 0, 0, ovector, 30);
    if (rc >= 0) {
        printf("Match found at position %d\n", ovector[0]);
    } else {
        printf("No match found\n");
    }

    pcre_free(re);
    return 0;
}

```

But in Rust, it is impossible to include any special characters like `\0` in `&str` or `String`, and the existing regular expression engine is based on `&str` matching (not `&[8]`), so I can only make some trade-offs and changes to build a bridge between nmap's original regular expression and the Rust regular expression engine.

I replaced the `\0` in the nmap regular expression with `\\0`, and then replaced the `0u8` in the received buff with the `\\0` string. Although this can perfectly solve the above problems in most cases, I found some unsolvable [problems](https://github.com/fancy-regex/fancy-regex/issues/149) in the process of replacing `\r` and `\n`, so the processing of `\r` and `\n` is to keep their original values ​​unchanged.

The existing method can only keep the regular expressions of nmap basically usable to a certain extent. Because there are many regular expressions of nmap, it is difficult to check them one by one. Therefore, when matching some services, the results may be different from the original nmap results. If so, please submit these services to issues for subsequent improvements.

## Debugs

### Show Logging Infomations

```rust
use pistol::Logger;

fn main() {
    let _ = Logger::init_debug_logging();
    // let _ = Logger::init_warn_logging();
    // your code below
}
```

### Capture and Analyse All Traffic

This method is used to capture all packets sent and recv by pistol into pcapng format (which means you can open it with Wireshark).

```rust
use pistol::TrafficSaver;

fn main() {
    let _ts = TrafficSaver::init("pistol.pcapng").unwrap();
    // your scan or ping code
}
```

## Examples

### 0. Create the Target

Now you can include both IPv4 and IPv6 addresses in the `Target` when create the scan target, and `pistol` will automatically invoke the corresponding algorithm to handle it.

However, please note that some algorithms can only work with certain protocols, e.g. Idel scan can only be used with IPv4, if it is used with IPv6 it will do nothing and show a warning message.

```rust
use pistol::Target;
use pistol::Host;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

fn main() {
    let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 134);
    let host1 = Host::new(dst_ipv4.into(), Some(vec![22, 99]));
    let dst_ipv6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x020c, 0x29ff, 0xfeb6, 0x8d99);
    let host2 = Host::new(dst_ipv6.into(), Some(vec![443, 8080]));
    let target = Target::new(vec![host1, host2]);
    // your code below
    ...
}
```

If you don't want to use `Target`, you can also use the `_raw` functions we provide, for example, the corresponding raw function for `tcp_syn_scan` is `tcp_syn_scan_raw`.

| Rich Function     | Raw Function          |
| :---------------- | :-------------------- |
| arp_scan          | arp_scan_raw          |
| tcp_syn_scan      | tcp_syn_scan_raw      |
| tcp_ack_scan      | tcp_ack_scan_raw      |
| tcp_connect_scan  | tcp_connect_scan_raw  |
| tcp_fin_scan      | tcp_fin_scan_raw      |
| tcp_idle_scan     | tcp_idle_scan_raw     |
| tcp_maimon_scan   | tcp_maimon_scan_raw   |
| tcp_null_scan     | tcp_null_scan_raw     |
| tcp_window_scan   | tcp_window_scan_raw   |
| tcp_xmas_scan     | tcp_xmas_scan_raw     |
| udp_scan          | udp_scan_raw          |
| icmp_ping         | icmp_ping_raw         |
| tcp_ack_ping      | tcp_ack_ping_raw      |
| tcp_syn_ping      | tcp_syn_ping_raw      |
| udp_ping          | udp_ping_raw          |
| icmp_flood        | icmp_flood_raw        |
| tcp_ack_flood     | tcp_ack_flood_raw     |
| tcp_ack_psh_flood | tcp_ack_psh_flood_raw |
| tcp_syn_flood     | tcp_syn_flood_raw     |
| udp_flood         | udp_flood_raw         |
| os_detect         | os_detect_raw         |
| vs_scan           | vs_scan_raw           |

**Note that the `_raw` function is blocking.**

### 1. SYN Port Scan Example

```rust
use pistol::scan::tcp_syn_scan;
use pistol::Target;
use pistol::Host;
use std::net::Ipv4Addr;
use std::time::Duration;
use subnetwork::CrossIpv4Pool;

fn main() {
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
    let mut hosts = vec![];
    for ip in subnet {
        // Test with a example port `22`
        let host = Host::new(ip.into(), Some(vec![22]));
        hosts.push(host);
    }
    let target = Target::new(hosts);
    // Number of tests, it can also be understood as the maximum number of unsuccessful retries.
    // For example, here, 2 means that after the first detection the target port is closed, then an additional detection will be performed.
    let tests = 2;
    let threads_num = Some(8);
    let ret = tcp_syn_scan(
        target,
        threads_num,
        src_ipv4,
        src_port,
        timeout,
        tests
    ).unwrap();
    println!("{}", ret);
}
```

### Output

```
+-----------+--------------+-----------+-------------------------------------------+-----------+
|                                    Scan Results (tests:2)                                    |
+-----------+--------------+-----------+-------------------------------------------+-----------+
|    id     |     addr     |   port    |                  status                   | avg cost  |
+-----------+--------------+-----------+-------------------------------------------+-----------+
|     1     | 192.168.5.1  |    22     | O(0)OF(0)F(2)UF(0)C(0)UR(0)CF(0)E(0)OL(0) | 1061.39ms |
+-----------+--------------+-----------+-------------------------------------------+-----------+
|     2     | 192.168.5.2  |    22     | O(0)OF(0)F(0)UF(0)C(2)UR(0)CF(0)E(0)OL(0) |  74.26ms  |
+-----------+--------------+-----------+-------------------------------------------+-----------+
|     3     | 192.168.5.3  |    22     | O(0)OF(0)F(0)UF(0)C(0)UR(0)CF(0)E(0)OL(2) | 1079.59ms |
+-----------+--------------+-----------+-------------------------------------------+-----------+
|     4     | 192.168.5.4  |    22     | O(0)OF(0)F(0)UF(0)C(0)UR(0)CF(0)E(0)OL(2) | 1077.55ms |
+-----------+--------------+-----------+-------------------------------------------+-----------+
|     5     | 192.168.5.5  |    22     | O(0)OF(0)F(0)UF(0)C(0)UR(0)CF(0)E(0)OL(2) | 1094.39ms |
+-----------+--------------+-----------+-------------------------------------------+-----------+
|     6     | 192.168.5.6  |    22     | O(0)OF(0)F(0)UF(0)C(0)UR(0)CF(0)E(0)OL(2) | 1093.97ms |
+-----------+--------------+-----------+-------------------------------------------+-----------+
|     7     | 192.168.5.7  |    22     | O(0)OF(0)F(0)UF(0)C(0)UR(0)CF(0)E(0)OL(2) | 1093.10ms |
+-----------+--------------+-----------+-------------------------------------------+-----------+
|     8     | 192.168.5.8  |    22     | O(0)OF(0)F(0)UF(0)C(0)UR(0)CF(0)E(0)OL(2) | 1093.42ms |
+-----------+--------------+-----------+-------------------------------------------+-----------+
|     9     | 192.168.5.9  |    22     | O(0)OF(0)F(0)UF(0)C(0)UR(0)CF(0)E(0)OL(2) | 1090.77ms |
+-----------+--------------+-----------+-------------------------------------------+-----------+
|    10     | 192.168.5.10 |    22     | O(0)OF(0)F(0)UF(0)C(0)UR(0)CF(0)E(0)OL(2) | 1089.91ms |
+-----------+--------------+-----------+-------------------------------------------+-----------+
| NOTE:                                                                                        |
| O: OPEN, OF: OPEN_OR_FILTERED, F: FILTERED,                                                  |
| UF: UNFILTERED, C: CLOSED, UR: UNREACHABLE,                                                  |
| CF: CLOSE_OF_FILTERED, E: ERROR, OL: OFFLINE.                                                |
+-----------+--------------+-----------+-------------------------------------------+-----------+
| total used time: 1177.12ms                                                                   |
| avg time cost: 984.83ms                                                                      |
| open ports: 0                                                                                |
+-----------+--------------+-----------+-------------------------------------------+-----------+
```

Or

```rust
use pistol::scan::tcp_syn_scan_raw;
use std::net::Ipv4Addr;
use std::time::Duration;

fn main() {
    let dst_ipv4 = Ipv4Addr::new(192, 168, 5, 1);
    let dst_port = 80;
    let src_ipv4 = None;
    let src_port = None;
    let timeout = Some(Duration::new(1, 0));
    let (port_status, _time_cost) = tcp_syn_scan_raw(dst_ipv4.into(), dst_port, src_ipv4, src_port, timeout).unwrap();
    println!("{:?}", port_status);
}
```

### 2. Remote OS Detect Example

The test target server is ubuntu 22.04 server.

```rust
use pistol::os::os_detect;
use pistol::Target;
use pistol::Host;
use std::net::Ipv4Addr;
use std::time::Duration;

fn main() {
    // If the value of `src_ipv4` is `None`, the program will find it auto.
    let src_ipv4 = None;
    let dst_ipv4 = Ipv4Addr::new(192, 168, 5, 133);
    // `dst_open_tcp_port` must be a certain open tcp port.
    let dst_open_tcp_port = 22;
    // `dst_closed_tcp_port` must be a certain closed tcp port.
    let dst_closed_tcp_port = 8765;
    // `dst_closed_udp_port` must be a certain closed udp port.
    let dst_closed_udp_port = 9876;
    let host = Host::new(
        dst_ipv4.into(),
        Some(vec![
            dst_open_tcp_port,   // The order of these three ports cannot be disrupted.
            dst_closed_tcp_port,
            dst_closed_udp_port,
        ]),
    );
    let target = Target::new(vec![host]);
    let timeout = Some(Duration::new(3, 0));
    let top_k = 3;
    let threads_num = Some(8);

    // The `fingerprint` is the obtained fingerprint of the target OS.
    // Return the `top_k` best results (the number of os detect result may not equal to `top_k`), sorted by score.
    let ret = os_detect(
        target,
        threads_num,
        src_ipv4,
        top_k,
        timeout,
    ).unwrap();
    println!("{}", ret);
}
```

### output

```
+------+---------------+------+--------+-----------------------+-------------------------------------------------------------------+
|                                                        OS Detect Results                                                         |
+------+---------------+------+--------+-----------------------+-------------------------------------------------------------------+
|  id  |     addr      | rank | score  |        details        |                                cpe                                |
+------+---------------+------+--------+-----------------------+-------------------------------------------------------------------+
|  1   | 192.168.5.133 |  #1  | 75/101 |   Linux 4.15 - 5.6    | cpe:/o:linux:linux_kernel:4 auto|cpe:/o:linux:linux_kernel:5 auto |
+------+---------------+------+--------+-----------------------+-------------------------------------------------------------------+
|  2   | 192.168.5.133 |  #2  | 75/101 |    Linux 5.0 - 5.3    |                 cpe:/o:linux:linux_kernel:5 auto                  |
+------+---------------+------+--------+-----------------------+-------------------------------------------------------------------+
|  3   | 192.168.5.133 |  #3  | 74/101 |       Linux 5.4       |                cpe:/o:linux:linux_kernel:5.4 auto                 |
+------+---------------+------+--------+-----------------------+-------------------------------------------------------------------+
|  4   | 192.168.5.133 |  #4  | 68/101 | Linux 2.6.24 - 2.6.36 |                cpe:/o:linux:linux_kernel:2.6 auto                 |
+------+---------------+------+--------+-----------------------+-------------------------------------------------------------------+
| total used time: 8638.91ms                                                                                                       |
| avg time cost: 8583.76ms                                                                                                         |
+------+---------------+------+--------+-----------------------+-------------------------------------------------------------------+
```


### 3. Remote OS Detect Example on IPv6

The test target server is ubuntu 22.04 server.

```rust
use pistol::os::os_detect;
use pistol::Target;
use pistol::Host;
use std::net::Ipv4Addr;
use std::time::Duration;

fn main() {
    let src_ipv6 = None;
    let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:fe2c:9e4".parse().unwrap();
    let dst_open_tcp_port = 22;
    let dst_closed_tcp_port = 8765;
    let dst_closed_udp_port = 9876;
    let host = Host::new(
        dst_ipv6.into(),
        Some(vec![
            dst_open_tcp_port,
            dst_closed_tcp_port,
            dst_closed_udp_port,
        ]),
    );

    let target = Target::new(vec![host]);
    let timeout = Some(Duration::new(3, 0));
    let top_k = 3;
    let threads_num = Some(8);
    let ret = os_detect(target, threads_num, src_ipv6, top_k, timeout).unwrap();
    println!("{}", ret);
}
```

### Output

```
+------+-------------------------+------+-------+--------------------------+---------------------------------------------------------+
|                                                         OS Detect Results                                                          |
+------+-------------------------+------+-------+--------------------------+---------------------------------------------------------+
|  id  |          addr           | rank | score |         details          |                           cpe                           |
+------+-------------------------+------+-------+--------------------------+---------------------------------------------------------+
|  1   | fe80::20c:29ff:fe2c:9e4 |  #1  |  0.9  |        Linux 4.19        |             cpe:/o:linux:linux_kernel:4.19              |
+------+-------------------------+------+-------+--------------------------+---------------------------------------------------------+
|  2   | fe80::20c:29ff:fe2c:9e4 |  #2  |  0.5  |     Linux 3.13 - 4.6     | cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 |
+------+-------------------------+------+-------+--------------------------+---------------------------------------------------------+
|  3   | fe80::20c:29ff:fe2c:9e4 |  #3  |  0.0  | Android 7.1 (Linux 3.18) |                                                         |
+------+-------------------------+------+-------+--------------------------+---------------------------------------------------------+
| total used time: 10476.07ms                                                                                                        |
| avg time cost: 10474.73ms                                                                                                          |
+------+-------------------------+------+-------+--------------------------+---------------------------------------------------------+
```

According to the nmap [documentation](https://nmap.org/book/osdetect-guess.html#osdetect-guess-ipv6), the `novelty` value (third column in the table) must be less than `15` for the probe result to be meaningful, so when this value is greater than `15`, an empty list is returned. Same when the two highest OS classes have scores that differ by less than `10%`, the classification is considered ambiguous and not a successful match.


### 3. Remote Service Detect Example

* 192.168.5.133 - Debian 12 (ssh: 22, apache httpd: 80, apache tomcat: 8080)

```rust
use pistol::vs::vs_scan;
use pistol::Target;
use pistol::Host;
use std::net::Ipv4Addr;
use std::time::Duration;

fn main() {
    let dst_addr = Ipv4Addr::new(192, 168, 5, 133);
    let host = Host::new(dst_addr.into(), Some(vec![22, 80, 8080]));
    let target = Target::new(vec![host]);
    let timeout = Some(Duration::new(1, 0));
    // only_null_probe = true, only_tcp_recommended = any, only_udp_recomended = any: only try the NULL probe (for TCP)
    // only_tcp_recommended = true: only try the tcp probe recommended port
    // only_udp_recommended = true: only try the udp probe recommended port
    let (only_null_probe, only_tcp_recommended, only_udp_recomended) = (false, true, true);
    let intensity = 7; // nmap default
    let threads_num = Some(8);
    let ret = vs_scan(
        target,
        threads_num,
        only_null_probe,
        only_tcp_recommended,
        only_udp_recommended,
        intensity,
        timeout,
    )..unwrap();
    println!("{}", ret);
}
```

### Output

```
+-------+---------------+-------+---------+----------------------------------+
|                            Service Scan Results                            |
+-------+---------------+-------+---------+----------------------------------+
|  id   |     addr      | port  | service |           versioninfo            |
+-------+---------------+-------+---------+----------------------------------+
|   1   | 192.168.5.133 |  22   |   ssh   |            p:OpenSSH             |
|       |               |       |         |     v:9.2p1 Debian 2+deb12u3     |
|       |               |       |         |          i:protocol 2.0          |
|       |               |       |         |             o:Linux              |
|       |               |       |         |   cpe:/a:openbsd:openssh:9.2p1   |
+-------+---------------+-------+---------+----------------------------------+
|   2   | 192.168.5.133 |  80   |  http   |          p:Apache httpd          |
|       |               |       |         |             v:2.4.62             |
|       |               |       |         |            i:(Debian)            |
|       |               |       |         | cpe:/a:apache:http_server:2.4.62 |
+-------+---------------+-------+---------+----------------------------------+
|   3   | 192.168.5.133 | 8080  |  http   |         p:Apache Tomcat          |
|       |               |       |         |       cpe:/a:apache:tomcat       |
+-------+---------------+-------+---------+----------------------------------+
| total used time: 18800 ms                                                  |
| avg time cost: 6266.67 ms                                                  |
+-------+---------------+-------+---------+----------------------------------+
```
