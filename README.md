# pistol-rs

The library must be run as root (Linux) or administrator (Windows).

## Example

### SYN Port Scan

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

### OS Detect

See OS detect example [here](./src/fingerprint.md).

## Host Discovery (Ping Scanning)

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

## Flood Attack

| Methods           | Notes                        |
| :---------------- | :--------------------------- |
| [x] TCP SYN Flood | IPv4 & IPv6 support          |
| [x] TCP ACK Flood | IPv4 & IPv6 support          |
| [x] UDP Flood     | IPv4 & IPv6 support          |
| [x] ICMP Flood    | IPv4 & IPv6 support (ICMPv6) |

## Remote OS Detection

| Methods            | Detailed Documentation                                              | Notes           |
| :----------------- | :------------------------------------------------------------------ | :-------------- |
| [x] IPv4 OS detect | [nmap references](https://nmap.org/book/osdetect-methods.html)      |                 |
| [ ] IPv6 OS detect | [nmap references](https://nmap.org/book/osdetect-ipv6-methods.html) | Not implemented |


### Why not IPv6?

First, it is also the most important reason, the `libpnet` doesn't have good support for IPv6 (the transport layer `libpnet` are well supported, but only using the transport layer protocol cannot realize Nmap's system detection in the [IPv6 environment](https://nmap.org/book/osdetect-ipv6-methods.html), such as `IE1` probe, it requires modifying the IPv6 header and populating the extension headers), which mean I can't modify, send and recv any IPv6 packets. I tried to bypass the limitations of `libpnet` and send data directly using the datalink layer, but I found that this method is too cumbersome and complicated in engineering practice.

Second, at the same time, according to Nmap's [documentation](https://nmap.org/book/osdetect-guess.html#osdetect-guess-ipv6), Nmap abandoned the `nmap-os-db` file and related matching technology originally used in IPv4, and instead used machine learning methods for fingerprint matching in IPv6. However, Nmap does not provide any OS data files that other programs can parse, and instead writes all fingerprint information into `FPModel.cc` file, which makes it extremely complicated for me to obtain and process these fingerprints.

To sum up, unless there is substantial progress in the above two conditions, OS detection in the IPv6 environment will be suspended indefinitely.

## Service and Application Version Detection

TODO.

## CLI program

I also implement a demo [code](https://github.com/rikonaka/pistol_cli-rs) here.
