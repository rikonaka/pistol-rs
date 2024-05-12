# pistol-rs

The library must be run as root (Linux) or administrator (Windows), other systems are not supported, and the `stable` version of rust is recommended.

## libpnet bug on rust nightly version

Bug issue: https://github.com/libpnet/libpnet/issues/686

Cause the pull request to fix a bug I submitted to the upstream `libpnet` has not yet been merged into the mainline https://github.com/libpnet/libpnet/pull/640, so this library cannot be used as `crate` yet, but you can add this library through git.

```toml
[dependencies]
pistol = { git = "https://github.com/rikonaka/pistol-rs.git" }
```

On Windows, download `winpcap` [here](https://www.winpcap.org/install/), then place `Packet.lib` from the x64 folder in your root of code. The other lib like `npcap` did not test by libpnet.

## Host Discovery (Ping Scanning)

I implement `pistol` host discovery according to the nmap [documentation](https://nmap.org/book/host-discovery.html).

| Method               | Detailed Documentation                                                                          | Note                               |
| :------------------- | :---------------------------------------------------------------------------------------------- | :--------------------------------- |
| [x] TCP SYN Ping     | [nmap references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PS)       | IPv4 & IPv6 support                |
| [x] TCP ACK Ping     | [nmap references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PA)       | IPv4 & IPv6 support                |
| [x] UDP Ping         | [nmap references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PU)       | IPv4 & IPv6 support                |
| [x] ICMP Ping        | [nmap references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-icmpping) | IPv4 & IPv6 support (ICMP, ICMPv6) |
| [x] ARP Scan         | [nmap references](https://nmap.org/book/host-discovery-techniques.html#arp-scan)                | IPv4 support                       |
| [ ] IP Protocol Ping | [nmap references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PO)       | Complicated and not very useful    |

## Port Scanning Techniques and Algorithms

I implement `pistol` port scan according to the nmap [pdf](https://nmap.org/nmap_doc.html) and [documentation](https://nmap.org/book/scan-methods.html).

| Method                  | Detailed Documentation                                                        | Note                                    |
| :---------------------- | :---------------------------------------------------------------------------- | :-------------------------------------- |
| [x] TCP SYN Scan        | [nmap references](https://nmap.org/book/synscan.html)                         | IPv4 & IPv6 support                     |
| [x] TCP Connect() Scan  | [nmap references](https://nmap.org/book/scan-methods-connect-scan.html)       | IPv4 & IPv6 support                     |
| [x] TCP FIN Scan        | [nmap references](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html) | IPv4 & IPv6 support                     |
| [x] TCP Null Scan       | [nmap references](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html) | IPv4 & IPv6 support                     |
| [x] TCP Xmas Scan       | [nmap references](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html) | IPv4 & IPv6 support                     |
| [x] TCP ACK Scan        | [nmap references](https://nmap.org/book/scan-methods-ack-scan.html)           | IPv4 & IPv6 support                     |
| [x] TCP Window Scan     | [nmap references](https://nmap.org/book/scan-methods-window-scan.html)        | IPv4 & IPv6 support                     |
| [x] TCP Maimon Scan     | [nmap references](https://nmap.org/book/scan-methods-maimon-scan.html)        | IPv4 & IPv6 support                     |
| [x] UDP Scan            | [nmap references](https://nmap.org/book/scan-methods-udp-scan.html)           | IPv4 & IPv6 support                     |
| [x] TCP Idle Scan       | [nmap references](https://nmap.org/book/idlescan.html)                        | IPv4 support                            |
| [x] IP Protocol Scan    | [nmap references](https://nmap.org/book/scan-methods-ip-protocol-scan.html)   | IPv4 support                            |
| [ ] TCP FTP Bounce Scan | [nmap references](https://nmap.org/book/scan-methods-ftp-bounce-scan.html)    | The bugs exploited have long been fixed |

## Flood Attack

| Method            | Note                               |
| :---------------- | :--------------------------------- |
| [x] TCP SYN Flood | IPv4 & IPv6 support                |
| [x] TCP ACK Flood | IPv4 & IPv6 support                |
| [x] UDP Flood     | IPv4 & IPv6 support                |
| [x] ICMP Flood    | IPv4 & IPv6 support (ICMP, ICMPv6) |

## Remote OS Detection

| Method             | Detailed Documentation                                              | Note                                           |
| :----------------- | :------------------------------------------------------------------ | :--------------------------------------------- |
| [x] IPv4 OS Detect | [nmap references](https://nmap.org/book/osdetect-methods.html)      | Print fingerprint as nmap format now supported |
| [x] IPv6 OS Detect | [nmap references](https://nmap.org/book/osdetect-ipv6-methods.html) | Print fingerprint as nmap format now supported |


### OS Detection on IPv6?

On ipv6, the fingerprints are unreadable and meaningless to humans, see [here](https://nmap.org/book/osdetect-fingerprint-format.html#osdetect-ex-typical-reference-fprint-ipv6) for details, and nmap uses logistic regression to match target OS on ipv6, but the matching algorithm is quite outdated with confusing design logic.

The first is about the `ST`, `RT` and `EXTRA` metrics in fingerprints in detection on [ipv6](https://nmap.org/book/osdetect-fingerprint-format.html), these three metrics are not used at all in the code, at the same time, there is no detailed description of how `ST` and `RT` are calculated, I don't know why nmap would keep them in the final fingerprint.

The second is `NI` probes. In the relevant [document](https://nmap.org/book/osdetect-ipv6-methods.html#osdetect-features-ipv6) of nmap, it describes the specific structure of `NI` probe, but I don't see anything about it in the code, and it seems to completely ignore this probe when do predict use logistic regression.

Furthermore, for the current mainstream operating systems, ipv6 fingerprint support is not as rich as ipv4, so try the ipv4 first.

## Service and Application Version Detection

| Methods               | Detailed Documentation                                        |
| :-------------------- | :------------------------------------------------------------ |
| [x] IPv4 Service Scan | [nmap references](https://nmap.org/book/vscan-technique.html) |
| [x] IPv6 Service Scan | [nmap references](https://nmap.org/book/vscan-technique.html) |

## Examples

### 1. SYN Port Scan Example

```rust
use pistol::{tcp_syn_scan, Host, Target};
use std::net::Ipv4Addr;
use std::time::Duration;
use anyhow::Result;

fn main() -> Result<()> {
    // When using scanning, please use a real local address to get the return packet.
    // And for flood attacks, please consider using a fake address.
    // If the value here is None, the programme will automatically look up the available addresses from the existing interfaces on the device.
    let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 128));
    // If the value of `source port` is `None`, the program will generate the source port randomly.
    let src_port = None;
    // The destination address is required.
    let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
    let threads_num = 8;
    let timeout = Some(Duration::new(3, 0));
    // Test with an open port `22` and a closed port `99`.
    let host = Host::new(dst_ipv4, Some(vec![22, 99]))?;
    /// Users should build the `target` themselves.
    let target = Target::new(vec![host]);
    let ret = tcp_syn_scan(
        target,
        src_ipv4,
        src_port,
        threads_num,
        timeout,
    ).unwrap();
    for (_ip, r) in ret {
        println!("{}", r);
    }
    Ok(())
}
```

### Output

```bash
192.168.72.136 99 closed
192.168.72.136 22 open
```

### 2. Remote OS Detect Example

* 192.168.72.129 - CentOS 7
* 192.168.72.136 - Ubuntu 22.04

```rust
use pistol::{os_detect, Host, Target};
use std::net::Ipv4Addr;
use std::time::Duration;
use anyhow::Result;

fn main() -> Result<()> {
    // If the value of `src_ipv4` is `None`, the program will find it auto.
    let src_ipv4 = None;
    // If the value of `src_port` is `None`, the program will generate it randomly.
    let src_port = None;
    let dst_ipv4_1 = Ipv4Addr::new(192, 168, 72, 129);
    // `dst_open_tcp_port` must be a certain open tcp port.
    let dst_open_tcp_port_1 = 22;
    // `dst_closed_tcp_port` must be a certain closed tcp port.
    let dst_closed_tcp_port_1 = 8765;
    // `dst_closed_udp_port` must be a certain closed udp port.
    let dst_closed_udp_port_1 = 9876;
    let host1 = Host::new(
        dst_ipv4_1,
        Some(vec![
            dst_open_tcp_port_1,   // The order of these three ports cannot be disrupted.
            dst_closed_tcp_port_1,
            dst_closed_udp_port_1,
        ]),
    )?;
    let dst_ipv4_2 = Ipv4Addr::new(192, 168, 72, 136);
    let dst_open_tcp_port_2 = 22;
    let dst_closed_tcp_port_2 = 8765;
    let dst_closed_udp_port_2 = 9876;
    let host2 = Host::new(
        dst_ipv4_2,
        Some(vec![
            dst_open_tcp_port_2,
            dst_closed_tcp_port_2,
            dst_closed_udp_port_2,
        ]),
    )?;
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

    for (ip, (fingerprint, detect_ret)) in ret {
        println!(">>> IP:\n{}", ip);
        println!(">>> Pistol fingerprint:\n{}", fingerprint);
        println!(">>> Details:");
        for d in detect_ret {
            println!("{}", d);
        }
    }
    Ok(())
}
```

### Output

#### Ubuntu 22.04

```
>>> IP:
192.168.72.136
>>> Pistol fingerprint:
SCAN(V=PISTOL%D=12/14%OT=22%CT=8765%CU=9876PV=Y%DS=1%DC=D%G=Y%M=0C29%TM=657B21AA%P=RUST)
SEQ(SP=107%GCD=1%ISR=105%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B4ST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
ECN(R=Y%DF=Y%TG=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%TG=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%TG=40%CD=S)
>>> Details:
>>> Score:
83/101
>>> Info:
Linux 4.15.0-88-generic #88~16.04.1-Ubuntu SMP Wed Feb 12 04:19:15 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
Linux 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64 GNU/Linux
Linux 5.0.0-32-generic #34~18.04.2-Ubuntu SMP Thu Oct 10 10:36:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
Linux 5.2.10-yocto-standard #1 SMP PREEMPT Fri Oct 4 11:58:01 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
Linux 5.3.0-kali3-amd64
Linux 5.3.16-200.fc30.x86_64 #1 SMP Fri Dec 13 17:48:38 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
Linux 5.4.6-amd64.gbcm #3 SMP Thu Dec 26 13:55:41 -03 2019 x86_64 GNU/Linux
Linux 5.6.15-arch1-1 #1 SMP PREEMPT Wed, 27 May 2020 23:42:26 +0000 x86_64 GNU/Linux
Linux 5.2.11-arch1-1-ARCH
Linux 5.4.0-1012-raspi #12-Ubuntu SMP Wed May 27 04:08:35 UTC 2020 aarch64 aarch64 aarch64 GNU/Linux
>>> Fingerprint:
Linux 4.15 - 5.6
>>> Class:
Linux | Linux | 4.X | general purpose
Linux | Linux | 5.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:4 auto
cpe:/o:linux:linux_kernel:5 auto
...
```

#### CentOS 7

```
>>> IP:
192.168.72.129
>>> Pistol fingerprint:
SCAN(V=PISTOL%D=12/14%OT=22%CT=54532%CU=34098PV=Y%DS=1%DC=D%G=Y%M=0C29%TM=657B21AA%P=RUST)
SEQ(SP=103%GCD=1%ISR=101%TI=Z%II=I%TS=A)
OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B4ST11)
WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)
ECN(R=Y%DF=Y%TG=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=N)
T6(R=N)
T7(R=N)
U1(R=Y%DF=N%TG=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%TG=40%CD=S)
>>> Details:
>>> Score:
55/101
>>> Info:
Linux 3.10.0-327.13.1.el7.x86_64
Linux 3.12.5-200.fc19.i686 #1 SMP Tue Dec 17 22:46:33 UTC 2013 i686 i686 i386 GNU/Linux
Linux 3.13.5-200.fc20.x86_64 #1 SMP Mon Feb 24 16:51:35 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
Linux 3.11.0-17-generic #31-Ubuntu SMP Mon Feb 3 21:52:43 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
Linux 3.13.0-19-generic #40-Ubuntu SMP Mon Mar 24 02:36:06 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
Linux 3.14.3-1-ARCH #1 SMP PREEMPT Tue May 6 22:44:19 CEST 2014 x86_64 GNU/Linux
Linux 3.12.21-gentoo-r1 #1 SMP PREEMPT x86_64
Linux 3.12.28-1-ARCH #1 PREEMPT Tue Sep 9 12:57:11 MDT 2014 armv6l GNU/Linux
Linux 3.19.2-1-ARCH #1 SMP PREEMPT Wed Mar 18 16:36:01 CET 2015 i686 GNU/Linux
Linux 3.10.72 #10878 Thu Mar 19 04:41:15 CET 2015 mips GNU/Linux
Linux raspberrypi 4.1.7+ #817 PREEMPT Sat Sep 19 15:25:36 BST 2015 armv6l GNU/Linux
Linux 3.18.26 #8771 Fri Feb 5 03:08:28 CET 2016 mips
Linux 3.18.31 DD-WRT
Linux  4.2.0-27-generic #32~14.04.1-Ubuntu SMP Fri Jan 22 15:32:26 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
4.8.6-201.fc24.x86_64 #1 SMP Thu Nov 3 14:38:57 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
Linux 4.11.6-3-ARCH #1 SMP PREEMPT Thu Jun 22 12:21:46 CEST 2017 x86_64 GNU/Linux
>>> Fingerprint:
Linux 3.10 - 4.11
>>> Class:
Linux | Linux | 3.X | general purpose
Linux | Linux | 4.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:3 auto
cpe:/o:linux:linux_kernel:4 auto
...
```

### 3. Remote OS Detect Example on IPv6

* fe80::6445:b9f8:cc82:3015 - CentOS 7
* fe80::20c:29ff:feb6:8d99 - Ubuntu 22.04

```rust
use pistol::{os_detect6, Host, Target};
use std::net::Ipv4Addr;
use std::time::Duration;
use anyhow::Result;

fn main() -> Result<()> {
    let src_ipv6 = None;
    let dst_ipv6: Ipv6Addr = "fe80::20c:29ff:feb6:8d99".parse().unwrap();
    let dst_open_tcp_port_1 = 22;
    let dst_closed_tcp_port_1 = 8765;
    let dst_closed_udp_port_1 = 9876;
    let host1 = Host6::new(
        dst_ipv6,
        Some(vec![
            dst_open_tcp_port_1,
            dst_closed_tcp_port_1,
            dst_closed_udp_port_1,
        ]),
    )?;

    let dst_ipv6: Ipv6Addr = "fe80::6445:b9f8:cc82:3015".parse().unwrap();
    let dst_open_tcp_port_2 = 22;
    let dst_closed_tcp_port_2 = 8765;
    let dst_closed_udp_port_2 = 9876;
    let host2 = Host6::new(
        dst_ipv6,
        Some(vec![
            dst_open_tcp_port_2,
            dst_closed_tcp_port_2,
            dst_closed_udp_port_2,
        ]),
    )?;

    let target = Target::new6(vec![host1, host2]);

    // let dst_ipv6: Ipv6Addr = "fe80::6445:b9f8:cc82:3015".parse().unwrap();
    let src_port = None;
    let timeout = Some(Duration::new(3, 0));
    let top_k = 3;
    let threads_num = 8;

    let ret = os_detect6(target, src_ipv6, src_port, top_k, threads_num, timeout)?;
    for (i, (fingerprint, detect_ret)) in ret {
        println!(">>> IP:\n{}", i);
        println!(">>> Novelty:\n{}", fingerprint.novelty);
        for d in detect_ret {
            println!("{}", d);
        }
    }
    Ok(())
}
```


### Output

#### CentOS 7

```
>>> IP:
fe80::6445:b9f8:cc82:3015
>>> Novelty:
18.900423183803554
```

According to the nmap [documentation](https://nmap.org/book/osdetect-guess.html#osdetect-guess-ipv6), the `novelty` value must be less than `15` for the probe result to be meaningful, so when this value is greater than `15`, an empty list is returned. Same when the two highest OS classes have scores that differ by less than `10%`, the classification is considered ambiguous and not a successful match.

#### Ubuntu 22.04

```
>>> IP:
fe80::20c:29ff:feb6:8d99
>>> Novelty:
8.970839832634503
>>> Score:
92.00%
>>> Fingerprint:
Linux 4.19
>>> Class:
Linux | Linux | 4.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:4.19
>>> Score:
71.04%
>>> Fingerprint:
Linux 3.13 - 4.6
>>> Class:
Linux | Linux | 3.X | general purpose
Linux | Linux | 4.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:3
cpe:/o:linux:linux_kernel:4
>>> Score:
1.93%
>>> Fingerprint:
Android 7.1 (Linux 3.18)
>>> Class:
Google | Android | 7.X | phone
>>> CPE:
```


### 3. Remote Service Detect Example

* 192.168.1.51 - Ubuntu 22.04 (ssh: 22, httpd: 80)

```rust
use pistol::{vs_scan, Host, Target};
use pistol::vs::dbparser::ExcludePorts;
use std::net::Ipv4Addr;
use std::time::Duration;
use anyhow::Result;

fn main() -> Result<()> {
    let dst_addr = Ipv4Addr::new(192, 168, 1, 51);
    let host = Host::new(dst_addr, Some(vec![22, 80]))?;
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
    for r in ret {
        println!("{}", r);
    }
    Ok(())
}
```

### Output

```
>>> port:
22
>>> services:
ssh
>>> versioninfo:
p/OpenSSH/ v/8.9p1 Ubuntu 3ubuntu0.7/ i/Ubuntu Linux; protocol 2.0/ o/Linux/ cpe:/a:openbsd:openssh:8.9p1/ cpe:/o:canonical:ubuntu_linux/ cpe:/o:linux:linux_kernel/
>>> port:
80
>>> services:
http
>>> versioninfo:
p/Apache httpd/ v/2.4.52/ i/(Ubuntu)/ cpe:/a:apache:http_server:2.4.52/
```