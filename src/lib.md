An implementation of a subset of the nmap scanning tool.

## Simple example

```rust
use pistol::tcp_syn_scan_single_port;
use std::net::Ipv4Addr;

fn main() {
    // If you don't want to provide the `source address`, you can provide the `interface` for the program to infer.
    let src_ipv4 = Some(Ipv4Addr::new(192, 168, 72, 130));
    // If the value of `source port` is `None`, the program will randomly generate the source port.
    let src_port = None;
    // The destination address is required.
    let dst_ipv4 = Ipv4Addr::new(192, 168, 72, 136);
    // The source address and interface must provide at least one
    let i = None; // let i = Some("ens33");
    // `max_loop` indicates the maximum number of loops that the program will wait for the target packet in a loop.
    // The larger the value, the longer the wait time for the program to scan.
    // And the smaller the value, the more unreliable the program's scanning results increases.
    let max_loop = Some(32);
    // Test with an open port `80`.
    let ret = tcp_syn_scan_single_port(src_ipv4, src_port, dst_ipv4, 80, i, true, None, max_loop).unwrap();
    println!("{:?}", ret);
    // Test with an closed port `9999`.
    let ret = tcp_syn_scan_single_port(src_ipv4, src_port, dst_ipv4, 9999, i, true, None, max_loop).unwrap();
    println!("{:?}", ret);
}
```

**Output**
```bash
192.168.72.136 80 open
TcpScanResults { addr: 192.168.72.136, results: {80: Open} }
192.168.72.136 9999 closed
TcpScanResults { addr: 192.168.72.136, results: {9999: Closed} }
```