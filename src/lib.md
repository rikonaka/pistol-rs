A rust implemented nmap library.

## SYN Port Scan Example

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