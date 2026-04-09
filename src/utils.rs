use rand::RngExt;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::time::Duration;
use tracing::warn;

use crate::error::PistolError;

/// Returns the random port from 10000 to 65535.
pub fn random_port() -> u16 {
    let mut rng = rand::rng();
    rng.random_range(10000..=65535)
}

/// Returns the random ipv4 addr.
pub fn random_ipv4_addr() -> Ipv4Addr {
    let mut rng = rand::rng();
    let x0 = rng.random_range(0..=255);
    let x1 = rng.random_range(0..=255);
    let x2 = rng.random_range(0..=255);
    let x3 = rng.random_range(0..=255);
    Ipv4Addr::new(x0, x1, x2, x3)
}

/// Returns the random ipv6 addr.
pub fn random_ipv6_addr() -> Ipv6Addr {
    let mut rng = rand::rng();
    let a = rng.random_range(0..=65535);
    let b = rng.random_range(0..=65535);
    let c = rng.random_range(0..=65535);
    let d = rng.random_range(0..=65535);
    let e = rng.random_range(0..=65535);
    let f = rng.random_range(0..=65535);
    let g = rng.random_range(0..=65535);
    let h = rng.random_range(0..=65535);
    Ipv6Addr::new(a, b, c, d, e, f, g, h)
}

/// Returns the random port with range from start to end.
pub fn random_port_range(start: u16, end: u16) -> u16 {
    let mut rng = rand::rng();
    rng.random_range(start..=end)
}

/// Returns the random id.
pub(crate) fn random_request_id() -> u64 {
    let mut rng = rand::rng();
    let id: u64 = rng.random();
    id
}

pub(crate) fn time_to_string(cost: Duration) -> String {
    if cost.as_secs_f32() > 1.0 {
        format!("{:.2}s", cost.as_secs_f32())
    } else {
        format!("{:.2}ms", cost.as_secs_f32() * 1000.0)
    }
}

/// Big endian, convert 4 bytes to u32.
pub(crate) fn vec_to_u32(input: &[u8]) -> u32 {
    if input.len() > 4 {
        warn!("input length should be less than or equal to 4");
    }

    let mut sum = 0;
    for (i, it) in input.iter().rev().enumerate() {
        if i >= 4 {
            break;
        }
        sum += (*it as u32) << (i * 8);
    }

    sum
}

pub(crate) struct PistolHex {
    pub(crate) hex: String, // hex => dec
}

impl PistolHex {
    pub(crate) fn new_hex(hex_str: &str) -> PistolHex {
        let hex_str_len = hex_str.len();
        let after_fix = if hex_str_len % 2 == 1 {
            format!("0{}", hex_str)
        } else {
            hex_str.to_string()
        };
        PistolHex { hex: after_fix }
    }

    pub(crate) fn decode_as_u32(&self) -> Result<u32, PistolError> {
        match hex::decode(&self.hex) {
            Ok(d) => {
                let v = vec_to_u32(&d);
                Ok(v)
            }
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::datalink::interfaces;
    #[test]
    fn test_convert() {
        let v = [1, 1, 1, 1];
        let r = vec_to_u32(&v);
        assert_eq!(r, 16843009);

        let s = "51E80C";
        let h = PistolHex::new_hex(s);
        let r = h.decode_as_u32().unwrap();
        assert_eq!(r, 5367820);

        let s = "1C";
        let h = PistolHex::new_hex(s);
        let r = h.decode_as_u32().unwrap();
        assert_eq!(r, 28);

        let s = "A";
        let h = PistolHex::new_hex(s);
        let r = h.decode_as_u32().unwrap();
        assert_eq!(r, 10);
    }
    #[test]
    fn interface_loopback() {
        for interface in interfaces() {
            if interface.is_loopback() {
                println!("{} is loopback interface", interface);
            }
        }
    }
    #[test]
    fn interface_list() {
        for interface in interfaces() {
            println!("list interface: {}, {:?}", interface.name, interface.ips);
        }
    }
}
