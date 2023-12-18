A rust implemented nmap library.

## SYN Port Scan Example

```rust
use pistol::{tcp_syn_scan, Host, Target};
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
        max_loop,
    ).unwrap();
    for (_ip, r) in ret {
        println!("{}", r);
    }
}
```

### Output

```bash
192.168.72.136 99 closed
192.168.72.136 22 open
```