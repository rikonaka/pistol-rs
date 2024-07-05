use anyhow::Result;
use log::debug;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::time::Duration;

use crate::hop::icmp::send_icmp_ping_packet;
use crate::hop::icmpv6::send_icmpv6_ping_packet;

pub mod icmp;
pub mod icmpv6;

pub fn ipv4_get_hops(src_ipv4: Ipv4Addr, dst_ipv4: Ipv4Addr, timeout: Duration) -> Result<u8> {
    debug!("30 hops max");
    for ttl in 1..=30 {
        let ret = send_icmp_ping_packet(src_ipv4, dst_ipv4, ttl, timeout)?;
        debug!("ttl: {} = {}", ttl, ret);
        if ret {
            debug!("ipv4 get hops: {}", ttl);
            return Ok(ttl);
        }
    }
    Ok(0)
}

pub fn ipv6_get_hops(src_ipv6: Ipv6Addr, dst_ipv6: Ipv6Addr, timeout: Duration) -> Result<u8> {
    debug!("30 hops max");
    for ttl in 1..=30 {
        let ret = send_icmpv6_ping_packet(src_ipv6, dst_ipv6, ttl, timeout)?;
        debug!("ttl: {} = {}", ttl, ret);
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
    use crate::DST_IPV6_REMOTE;
    #[test]
    fn test_get_hops() -> Result<()> {
        let src_ipv6: Ipv6Addr = "240e:34c:8e:3ae0:5054:ff:fe6b:1338".parse()?;
        let dst_ipv6 = DST_IPV6_REMOTE;
        let timeout = Duration::new(1, 0);
        let hops = ipv6_get_hops(src_ipv6, dst_ipv6, timeout)?;
        println!("{}", hops);
        Ok(())
    }
}
