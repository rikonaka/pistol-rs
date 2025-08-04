use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::time::Duration;
use tracing::debug;

use crate::error::PistolError;
use crate::utils::random_port_range;

pub mod udp;
pub mod udp6;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HopStatus {
    TimeExceeded,
    Unreachable,
    Open,
}

pub fn ipv4_get_hops(
    dst_ipv4: Ipv4Addr,
    src_ipv4: Ipv4Addr,
    timeout: Option<Duration>,
) -> Result<u8, PistolError> {
    for ttl in 1..=30 {
        println!("ttl: {}", ttl);
        let random_src_port = random_port_range(1000, 65535);
        let dst_port = 33433 + ttl as u16;
        let ret = udp::send_udp_trace_packet(
            dst_ipv4,
            dst_port,
            src_ipv4,
            random_src_port,
            ttl,
            timeout,
        )?;
        if ret {
            debug!("ipv4 get hops: {}", ttl);
            return Ok(ttl);
        }
    }
    Ok(0)
}

pub fn ipv6_get_hops(
    dst_ipv6: Ipv6Addr,
    src_ipv6: Ipv6Addr,
    timeout: Option<Duration>,
) -> Result<u8, PistolError> {
    for ttl in 1..=30 {
        let ret = send_icmpv6_ping_packet(dst_ipv6, src_ipv6, ttl, timeout)?;
        if ret {
            debug!("ipv6 get hops: {}", ttl);
            return Ok(ttl);
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PistolLogger;
    use crate::PistolRunner;
    #[test]
    fn test_get_hops() {
        let _pr = PistolRunner::init(
            PistolLogger::None,
            None,
            None, // use default value
        )
        .unwrap();

        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 3);
        let src_ipv4 = Ipv4Addr::new(192, 168, 5, 3);
        let timeout = Some(Duration::from_secs_f64(0.5));
        let hops = ipv4_get_hops(dst_ipv4, src_ipv4, timeout).unwrap();
        println!("{}", hops);
    }
    #[test]
    fn test_get_hops6() {
        let src_ipv6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0020c, 0x29ff, 0xfe2c, 0x09e4);
        let dst_ipv6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0020c, 0x29ff, 0xfe2c, 0x09e4);
        let timeout = Some(Duration::new(1, 0));
        let hops = ipv6_get_hops(dst_ipv6, src_ipv6, timeout).unwrap();
        println!("{}", hops);
    }
}
