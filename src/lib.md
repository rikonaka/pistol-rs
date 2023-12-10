An implementation of a subset of the nmap scanning tool.

## Simple example

```rust
use pistol::tcp_syn_scan_single_port;
use std::net::Ipv4Addr;

fn main() {
    // If you don't want to provide the `source address`, you can provide the `interface` for the program to infer.
    let src_ipv4: Option<Ipv4Addr> = Some(Ipv4Addr::new(192, 168, 72, 128));
    // If the value of `source port` is `None`, the program will randomly generate the source port.
    let src_port: Option<u16> = None;
    // The destination address is required.
    let dst_ipv4: Ipv4Addr = Ipv4Addr::new(192, 168, 72, 136);
    // The source address and interface must provide at least one.
    let interface: Option<&str> = None;
    // let interface: Option<&str> = Some("eno1");
    let print_result: bool = true;
    let threads_num: usize = 8;
    let timeout: Option<Duration> = Some(Duration::from_secs_f32(0.5));
    // `max_loop` indicates the maximum number of loops that the program will wait for the target packet.
    // The larger the value, the longer the wait time for the program to scan.
    // And the smaller the value, the more unreliable the program's scanning results increases.
    let max_loop: Option<usize> = Some(8);
    // Test with an open port `22` and closed port `99`.
    let target: Target = Target::new_static_port(&vec![dst_ipv4], &vec![22, 99]);
    let ret: HashMap<IpAddr, TcpUdpScanResults> = match tcp_syn_scan(
        target,
        src_ipv4,
        src_port,
        interface,
        print_result,
        threads_num,
        timeout,
        max_loop,
    ) {
        Ok(r) => r,
        Err(e) => panic!("{}", e),
    };
    println!("{:?}", ret);
}
```