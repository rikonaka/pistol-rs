# pistol-rs

The library must be run as root (Linux) or administrator (Windows).

## Example

### SYN port scan

```rust
use pistol::tcp_syn_scan;
use std::net::Ipv4Addr;

fn main() {
    // If you don't want to provide the `source address`, you can provide the `interface` for the program to infer.
    let src_ipv4: Option<Ipv4Addr> = Some(Ipv4Addr::new(192, 168, 72, 128));
    // If the value of `source port` is `None`, the program will generate the source port randomly.
    let src_port: Option<u16> = None;
    // The destination address is required.
    let dst_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 72, 136);
    // The source address and interface must provide at least one.
    let interface: Option<&str> = None;
    // let interface: Option<&str> = Some("ens33");
    // If set to True, scan result will be printed in real time during the scanning process.
    let print_result: bool = true;
    let threads_num: usize = 8;
    // The timeout for the program to read the package.
    // It is recommended to set it to twice the RTT.
    let timeout: Option<Duration> = Some(Duration::from_secs_f32(0.2));
    // `max_loop` indicates the maximum number of loops that the program will wait for the target packet.
    // The larger the value, the longer the wait time for the program to scan.
    // The smaller the value, the less reliable the scan results will be.
    let max_loop: Option<usize> = Some(32);
    // Test with an open port `22` and a closed port `99`.
    let host = Host::new(dst_ipv4, Some(vec![22, 99]));
    /// Users should build the `target` themselves.
    let target: Target = Target::new(vec![host]);
    let ret: HashMap<IpAddr, TcpUdpScanResults> = tcp_syn_scan(
        target,
        src_ipv4,
        src_port,
        interface,
        print_result,
        threads_num,
        timeout,
        max_loop,
    ).unwrap();
    for (_ip, r) in ret {
        println!("{}", r);
    }
}
```

#### Output

```bash
192.168.72.136 99 closed
192.168.72.136 22 open
```

### OS detect

```rust
fn main() {
    // The source and destination address is required.
    let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
    let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
    // If the value of `source port` is `None`, the program will generate the source port randomly.
    let src_port = None;
    // `dst_open_tcp_port` must be a certain open tcp port.
    let dst_open_tcp_port = 22;
    // `dst_closed_tcp_port` must be a certain closed tcp port.
    let dst_closed_tcp_port = 8765;
    // `dst_closed_udp_port` must be a certain closed udp port.
    let dst_closed_udp_port = 9876;
    // Same as above.
    let max_loop = 8;
    // The timeout for the program to read the package.
    // It is recommended to set it to twice the RTT.
    let read_timeout = Duration::from_secs_f32(0.2);
    let nmap_os_db_file_path = "./nmap-os-db";
    let top_k = 3;

    // The `fingerprint` is the obtained fingerprint of the target OS.
    // Return the `top_k` best results (the number of os detect result may not equal to `top_k`), sorted by score.
    let (fingerprint, detect_ret) = os_detect(
        src_ipv4,
        src_port,
        dst_ipv4,
        dst_open_tcp_port,
        dst_closed_tcp_port,
        dst_closed_udp_port,
        nmap_os_db_file_path,
        top_k,
        max_loop,
        read_timeout,
    )
    .unwrap();

    println!("{}\n", fingerprint);
    for r in detect_ret {
        println!("{}", r);
    }
}
```

#### Output (target os is ubuntu 22.04 desktop)

```bash
SCAN(V=PISTOL%D=12/12%OT=22%CT=8765%CU=9876PV=Y%DS=1%DC=D%G=Y%M=0C29%TM=6578A740%P=RUST)
SEQ(SP=106%GCD=1%ISR=105%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B4ST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

>>> Score: 83/101
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

>>> Score: 81/101
>>> Info:
Linux 5.0.0-23-generic #24-Ubuntu SMP Mon Jul 29 15:36:44 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
Linux 5.3.0-24-generic x86_64 Ubuntu 19.10
Linux 5.3.9-sunxi (root@builder) (gcc version 7.4.1 20181213 [linaro-7.4-2019.02
>>> Fingerprint:
Linux 5.0 - 5.3
>>> Class:
Linux | Linux | 5.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:5 auto

>>> Score: 80/101
>>> Info:
Linux 5.4.0-1008-raspi #8-Ubuntu SMP Wed Apr 8 11:13:06 UTC 2020 aarch64 aarch64 aarch64 GNU/Linux
>>> Fingerprint:
Linux 5.4
>>> Class:
Linux | Linux | 5.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:5.4 auto
```

## Host discovery (Ping Scanning)

I implement `pistol` host discovery according to the nmap [documentation](https://nmap.org/book/host-discovery.html).

| Methods              | Detailed Documentation                                                                          | Notes                           |
| :------------------- | :---------------------------------------------------------------------------------------------- | :------------------------------ |
| [x] TCP SYN Ping     | [nmap references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PS)       | IPv4 & IPv6 support             |
| [x] TCP ACK Ping     | [nmap references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PA)       | IPv4 & IPv6 support             |
| [x] UDP Ping         | [nmap references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PU)       | IPv4 & IPv6 support             |
| [x] ICMP Ping        | [nmap references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-icmpping) | IPv4 & IPv6 support (ICMPv6)    |
| [x] ARP Scan         | [nmap references](https://nmap.org/book/host-discovery-techniques.html#arp-scan)                | IPv4 support                    |
| [ ] IP Protocol Ping | [nmap references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PO)       | Complicated and not very useful |

## Port Scanning Techniques and Algorithms

I implement `pistol` transport layer scan according to the nmap [pdf](https://nmap.org/nmap_doc.html) and [documentation](https://nmap.org/book/scan-methods.html).

| Methods                 | Detailed Documentation                                                        | Notes                                   |
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

## Flood attack

| Methods           | Notes                        |
| :---------------- | :--------------------------- |
| [x] TCP SYN Flood | IPv4 & IPv6 support          |
| [x] TCP ACK Flood | IPv4 & IPv6 support          |
| [x] UDP Flood     | IPv4 & IPv6 support          |
| [x] ICMP Flood    | IPv4 & IPv6 support (ICMPv6) |

## Operating system detect

| Methods            | Detailed Documentation                                              |
| :----------------- | :------------------------------------------------------------------ |
| [x] IPv4 OS detect | [nmap references](https://nmap.org/book/osdetect-methods.html)      |
| [] IPv6 OS detect  | [nmap references](https://nmap.org/book/osdetect-ipv6-methods.html) |

## CLI program

I also implement a demo [code](https://github.com/rikonaka/pistol_cli-rs) here.
