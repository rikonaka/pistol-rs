A Rust Library about Cybersecurity.

## SYN Port Scan Example

```rust
use pistol::Host;
use pistol::Target;
use pistol::scan::tcp_syn_scan;
use std::net::Ipv4Addr;
use std::time::Duration;

fn main() {
    // When using scanning, please use a real local address to get the return packet.
    // And for flood attacks, please consider using a fake address.
    // If the value here is None, the programme will automatically look up the available addresses from the existing interfaces on the device.
    let src_ipv4 = None;
    // If the value of `source port` is `None`, the program will generate the source port randomly.
    let src_port = None;
    // The destination address is required.
    let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 51);
    let timeout = Some(Duration::new(3, 0));
    // Test with an open port `22` and a closed port `99`.
    let host = Host::new(dst_ipv4.into(), Some(vec![22, 99]));
    // Users should build the `target` themselves.
    let target = Target::new(vec![host]);
    // Number of tests
    let tests = 4;
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