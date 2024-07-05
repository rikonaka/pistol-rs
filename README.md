# pistol-rs

The library must be run as root (Linux, *BSD) or administrator (Windows), the `stable` version of rust is recommended.

## Import from crates.io

```toml
[dependencies]
pistol = "^1"
```

On Windows, download `winpcap` [here](https://www.winpcap.org/install/), then place `Packet.lib` from the x64 folder in your root of code. The other lib like `npcap` did not test by libpnet.

## Cross Platform Support

| Platform           | Note                             |
| :----------------- | :------------------------------- |
| Linux              | supported                        |
| Unix (*BSD, MacOS) | supported                        |
| ~~Windows~~        | ~~supported (winpcap or npcap)~~ |

### libpnet bug on Windows

Bug issues: https://github.com/libpnet/libpnet/issues/707, the `libpnet` cannot get IPv6 address on Windows.

Therefore, until `libpnet` fixes this bug, Windows is not supported yet.

### libpnet bug on rust nightly version

Bug issue: https://github.com/libpnet/libpnet/issues/686

## Host Discovery (Ping Scanning)

The implementation of the `pistol' host discovery according to the nmap [documentation](https://nmap.org/book/host-discovery.html).

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

| Method            | Note                               |
| :---------------- | :--------------------------------- |
| [x] TCP SYN Flood | IPv4 & IPv6 support                |
| [x] TCP ACK Flood | IPv4 & IPv6 support                |
| [x] UDP Flood     | IPv4 & IPv6 support                |
| [x] ICMP Flood    | IPv4 & IPv6 support (ICMP, ICMPv6) |

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

## Debugs

```rust
use pistol::Logger;

fn main() -> Result<()> {
    Logger::init_debug_logging()?;
    // your code below
    ...
}
```

## Examples

### 1. SYN Port Scan Example

```rust
use pistol::scan::tcp_syn_scan;
use pistol::Target;
use pistol::Host;
use std::net::Ipv4Addr;
use std::time::Duration;
use anyhow::Result;

fn main() -> Result<()> {
    // When using scanning, please use a real local address to get the return packet.
    // And for flood attacks, please consider using a fake address.
    // If the value here is None, the programme will automatically look up the available addresses from the existing interfaces on the device.
    let src_ipv4 = None;
    // If the value of `source port` is `None`, the program will generate the source port randomly.
    let src_port = None;
    // The destination address is required.
    let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 51);
    let threads_num = 8;
    let timeout = Some(Duration::new(1, 0));
    // Test with an open port `22` and a closed port `99`.
    let host = Host::new(dst_ipv4, Some(vec![22, 99]));
    // Users should build the `target` themselves.
    let target = Target::new(vec![host]);
    let ret = tcp_syn_scan(
        target,
        src_ipv4,
        src_port,
        threads_num,
        timeout,
    ).unwrap();
    println!("{}", ret);
    Ok(())
}
```

### Output

```
+--------------+------+--------+
|         Scan Results         |
+--------------+------+--------+
| 192.168.1.51 |  22  |  open  |
+--------------+------+--------+
| 192.168.1.51 |  99  | closed |
+--------------+------+--------+
| Summary:                     |
| avg rtt 0.004                |
| open ports: 1                |
+--------------+------+--------+
```

### 2. Remote OS Detect Example

The test target server is ubuntu 22.04 server.

```rust
use pistol::os::os_detect;
use pistol::Target;
use pistol::Host;
use std::net::Ipv4Addr;
use std::time::Duration;
use anyhow::Result;

fn main() -> Result<()> {
    // If the value of `src_ipv4` is `None`, the program will find it auto.
    let src_ipv4 = None;
    // If the value of `src_port` is `None`, the program will generate it randomly.
    let src_port = None;
    let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 129);
    // `dst_open_tcp_port` must be a certain open tcp port.
    let dst_open_tcp_port = 22;
    // `dst_closed_tcp_port` must be a certain closed tcp port.
    let dst_closed_tcp_port = 8765;
    // `dst_closed_udp_port` must be a certain closed udp port.
    let dst_closed_udp_port = 9876;
    let host1 = Host::new(
        dst_ipv4,
        Some(vec![
            dst_open_tcp_port,   // The order of these three ports cannot be disrupted.
            dst_closed_tcp_port,
            dst_closed_udp_port,
        ]),
    );
    let target = Target::new(vec![host1, host2]);
    let timeout = Some(Duration::new(3, 0));
    let top_k = 3;
    let threads_num = 8;

    // The `fingerprint` is the obtained fingerprint of the target OS.
    // Return the `top_k` best results (the number of os detect result may not equal to `top_k`), sorted by score.
    let ret = os_detect(
        target,
        src_ipv4,
        src_port,
        top_k,
        threads_num,
        timeout,
    )?;
    println!("{}", ret);
    Ok(())
}
```

### output

```
+--------------+------+--------+-------------------------------------------------------------------------------------------------------------------------------------+
|                                                                         OS Detect Results                                                                          |
+--------------+------+--------+-------------------------------------------------------------------------------------------------------------------------------------+
| 192.168.1.51 |  #1  | 81/101 |                 # Linux 5.0.0-23-generic #24-Ubuntu SMP Mon Jul 29 15:36:44 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux                 |
|              |      |        |                                            # Linux 5.3.0-24-generic x86_64 Ubuntu 19.10                                             |
|              |      |        |                         # Linux 5.3.9-sunxi (root@builder) (gcc version 7.4.1 20181213 [linaro-7.4-2019.02                          |
+--------------+------+--------+-------------------------------------------------------------------------------------------------------------------------------------+
| 192.168.1.51 |  #2  | 80/101 |                # Linux 5.4.0-1008-raspi #8-Ubuntu SMP Wed Apr 8 11:13:06 UTC 2020 aarch64 aarch64 aarch64 GNU/Linux                 |
+--------------+------+--------+-------------------------------------------------------------------------------------------------------------------------------------+
| 192.168.1.51 |  #3  | 75/101 |             # Atmel Network Gateway Kit (NGW100) running Linux 2.6.22.atmel.4 kernel (compiled myself; not default one)             |
|              |      |        |  # Linux 2.6.22.9-aldebaran-rt #1 PREEMPT RT Mon Nov 3 16:21:22 CET 2008 i586 unknown (Nao robot produced by Aldebaran Robotics).   |
|              |      |        |                                       # Linux version 2.6.22-XR100-v1.1.6 (rdiouskine@ubuntu)                                       |
|              |      |        |                        # Belkin Router Model F9K1103 v1 (01A) Firmware Version 1.00.37 (2011/5/24 11:55:14)                         |
|              |      |        |                                   # CentOS release 5.7 (Final) 2.6.18-274.17.1.el5 i386 GNU/Linux                                   |
|              |      |        |                     # Debian Linux 5.0 - 2.6.26-2-686-bigmem #1 SMP Wed Sep 21 05:29:18 UTC 2011 i686 GNU/Linux                     |
|              |      |        | # 2.6.32.54-0.3-default #1 SMP 2012-01-27 17:38:56 +0100 x86_64 x86_64 x86_64 GNU/Linux, SUSE Linux Enterprise Server 11 SP1 x86_64 |
|              |      |        |                                                # TufinOS (TSS); accessed VM console                                                 |
+--------------+------+--------+-------------------------------------------------------------------------------------------------------------------------------------+
```


### 3. Remote OS Detect Example on IPv6

The test target server is ubuntu 22.04 server.

```rust
use pistol::os_detect6;
use pistol::Target;
use pistol::Host;
use std::net::Ipv4Addr;
use std::time::Duration;
use anyhow::Result;

fn main() -> Result<()> {
    let src_ipv6 = None;
    let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:feb6:8d99".parse().unwrap();
    let dst_open_tcp_port = 22;
    let dst_closed_tcp_port = 8765;
    let dst_closed_udp_port = 9876;
    let host = Host6::new(
        dst_ipv6,
        Some(vec![
            dst_open_tcp_port,
            dst_closed_tcp_port,
            dst_closed_udp_port,
        ]),
    );

    let target = Target::new6(vec![host]);
    let src_port = None;
    let timeout = Some(Duration::new(3, 0));
    let top_k = 3;
    let threads_num = 8;
    let ret = os_detect6(target, src_ipv6, src_port, top_k, threads_num, timeout)?;
    println!("{}", ret);
    Ok(())
}
```

### Output

```
+---------------- ---------+------+------+--------------------------+
|                       OS Detect Results                           |
+--------------------------+------+------+--------------------------+
| fe80::20c:29ff:feb6:8d99 |  #1  | 0.9  |        Linux 4.19        |
+--------------------------+------+------+--------------------------+
| fe80::20c:29ff:feb6:8d99 |  #2  | 0.7  |     Linux 3.13 - 4.6     |
+--------------------------+------+------+--------------------------+
| fe80::20c:29ff:feb6:8d99 |  #3  | 0.0  | Android 7.1 (Linux 3.18) |
+--------------------------+------+------+--------------------------+
```

According to the nmap [documentation](https://nmap.org/book/osdetect-guess.html#osdetect-guess-ipv6), the `novelty` value (third column in the table) must be less than `15` for the probe result to be meaningful, so when this value is greater than `15`, an empty list is returned. Same when the two highest OS classes have scores that differ by less than `10%`, the classification is considered ambiguous and not a successful match.


### 3. Remote Service Detect Example

* 192.168.1.51 - Ubuntu 22.04 (ssh: 22, httpd: 80)

```rust
use pistol::vs::vs_scan;
use pistol::vs::dbparser::ExcludePorts;
use pistol::Target;
use pistol::Host;
use std::net::Ipv4Addr;
use std::time::Duration;
use anyhow::Result;

fn main() -> Result<()> {
    let dst_addr = Ipv4Addr::new(192, 168, 1, 51);
    let host = Host::new(dst_addr, Some(vec![22, 80]));
    let target = Target::new(vec![host]);
    let threads_num = 8;
    let timeout = Some(Duration::new(1, 0));
    // only_null_probe = true, only_tcp_recommended = any, only_udp_recomended = any: only try the NULL probe (for TCP)
    // only_tcp_recommended = true: only try the tcp probe recommended port
    // only_udp_recommended = true: only try the udp probe recommended port
    let (only_null_probe, only_tcp_recommended, only_udp_recomended) = (false, true, true);
    let exclude_ports = Some(ExcludePorts::new(vec![51, 52]));
    let intensity = 7; // nmap default
    let ret = vs_scan(
        target,
        only_null_probe,
        only_tcp_recommended,
        only_udp_recommended,
        exclude_ports,
        intensity,
        threads_num,
        timeout,
    )?;
    println!("{}", ret);
    Ok(())
}
```

### Output

```
+--------------+--------+--------+
|      Service Scan Results      |
+--------------+--------+--------+
| 192.168.1.51 |   22   |  ssh   |
+--------------+--------+--------+
| 192.168.1.51 |   80   |  http  |
+--------------+--------+--------+
| Summary:                       |
| avg rtt: 20.973s               |
+--------------+--------+--------+
```
