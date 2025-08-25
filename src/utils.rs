use num_cpus;
use pnet::datalink::MacAddr;
use rand::Rng;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::time::Duration;
use threadpool::ThreadPool;
use tracing::warn;

use crate::DEFAULT_TIMEOUT;
use crate::SYSTEM_NET_CACHE;
use crate::error::PistolError;

const MAX_THREADS: usize = 1000;

pub fn time_sec_to_string(cost: Duration) -> String {
    if cost.as_secs_f64() > 1.0 {
        format!("{:.3}s", cost.as_secs_f64())
    } else {
        format!("{:.3} ms", cost.as_secs_f64() * 1000.0)
    }
}

pub fn num_threads_check(num_threads: usize) -> usize {
    let mut num_threads = num_threads;
    if num_threads > MAX_THREADS {
        warn!(
            "system try to create too many threads (current threads num: {}, fixed threads num: {}))",
            num_threads, MAX_THREADS
        );
        num_threads = MAX_THREADS;
    }
    num_threads
}

pub fn neigh_cache_update(addr: IpAddr, mac: MacAddr) -> Result<(), PistolError> {
    // release the lock when leaving the function
    let mut snc = match SYSTEM_NET_CACHE.lock() {
        Ok(snc) => snc,
        Err(e) => {
            return Err(PistolError::TryLockGlobalVarFailed {
                var_name: String::from("SYSTEM_NET_CACHE"),
                e: e.to_string(),
            });
        }
    };
    Ok(snc.update_neighbor_cache(addr, mac))
}

/// Returns the random port
pub fn random_port() -> u16 {
    let mut rng = rand::rng();
    rng.random_range(10000..=65535)
}

/// Returns the random ipv4 addr
pub fn random_ipv4_addr() -> Ipv4Addr {
    let mut rng = rand::rng();
    let x0 = rng.random_range(0..=255);
    let x1 = rng.random_range(0..=255);
    let x2 = rng.random_range(0..=255);
    let x3 = rng.random_range(0..=255);
    Ipv4Addr::new(x0, x1, x2, x3)
}

/// Returns the random ipv6 addr
pub fn random_ipv6_addr() -> Ipv6Addr {
    let mut rng = rand::rng();
    let x0 = rng.random_range(0..=65535);
    let x1 = rng.random_range(0..=65535);
    let x2 = rng.random_range(0..=65535);
    let x3 = rng.random_range(0..=65535);
    let x4 = rng.random_range(0..=65535);
    let x5 = rng.random_range(0..=65535);
    let x6 = rng.random_range(0..=65535);
    let x7 = rng.random_range(0..=65535);
    Ipv6Addr::new(x0, x1, x2, x3, x4, x5, x6, x7)
}

/// Returns the random port with range
pub fn random_port_range(start: u16, end: u16) -> u16 {
    let mut rng = rand::rng();
    rng.random_range(start..=end)
}

/// Returns the number of CPUs in the machine
pub fn get_cpu_num() -> usize {
    num_cpus::get()
}

pub fn get_threads_pool(num_threads: usize) -> ThreadPool {
    let pool = if num_threads > 0 {
        ThreadPool::new(num_threads)
    } else {
        let cpus = get_cpu_num();
        ThreadPool::new(cpus)
    };
    pool
}

pub fn get_default_timeout() -> Duration {
    Duration::from_secs_f64(DEFAULT_TIMEOUT)
}

pub struct PistolHex {
    pub hex: String, // hex => dec
}

impl PistolHex {
    pub fn new_hex(hex_str: &str) -> PistolHex {
        let hex_str_len = hex_str.len();
        let after_fix = if hex_str_len % 2 == 1 {
            format!("0{}", hex_str)
        } else {
            hex_str.to_string()
        };
        PistolHex { hex: after_fix }
    }
    pub fn be_vec_to_u32(input: &[u8]) -> Result<u32, PistolError> {
        if input.len() <= 4 {
            let padding_size = 4 - input.len();
            let mut after_padding = vec![0; padding_size];
            for &i in input {
                after_padding.push(i as u32);
            }
            let a = after_padding[0] << 24;
            let b = after_padding[1] << 16;
            let c = after_padding[2] << 8;
            let d = after_padding[3];
            Ok(a + b + c + d)
        } else {
            let v = format!("{:?}", input);
            Err(PistolError::InputTooLoog { v })
        }
    }
    pub fn decode_as_u32(&self) -> Result<u32, PistolError> {
        match hex::decode(&self.hex) {
            Ok(d) => Self::be_vec_to_u32(&d),
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
        let v: Vec<u8> = vec![1, 1, 1, 1];
        let r = PistolHex::be_vec_to_u32(&v).unwrap();
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
    fn test_get_cpus() {
        let cpus = get_cpu_num();
        println!("{}", cpus);
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
