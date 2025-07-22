use num_cpus;
use pnet::datalink::MacAddr;
use rand::Rng;
use std::net::IpAddr;
use std::time::Duration;
use threadpool::ThreadPool;
use tracing::warn;

use crate::DEFAULT_TIMEOUT;
use crate::SYSTEM_NET_CACHE;

use crate::error::PistolError;

const MAX_THREADS_NUM: usize = 1000;

pub fn rtt_to_string(rtt: Duration) -> String {
    if rtt.as_secs_f32() > 1.0 {
        format!("{:.3} s", rtt.as_secs_f32())
    } else {
        format!("{:.3} ms", rtt.as_secs_f32() * 1000.0)
    }
}

pub fn threads_num_check(threads_num: usize) -> usize {
    let mut threads_num = threads_num;
    if threads_num > MAX_THREADS_NUM {
        warn!(
            "system try to create too many threads (current threads num: {}, fixed threads num: {}), consider set the `threads_num` manual",
            threads_num, MAX_THREADS_NUM
        );
        threads_num = MAX_THREADS_NUM;
    }
    threads_num
}

pub fn arp_cache_update(addr: IpAddr, mac: MacAddr) -> Result<(), PistolError> {
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

/// Returns the random port with range
pub fn random_port_range(start: u16, end: u16) -> u16 {
    let mut rng = rand::rng();
    rng.random_range(start..=end)
}

/// Returns the number of CPUs in the machine
pub fn get_cpu_num() -> usize {
    num_cpus::get()
}

pub fn get_threads_pool(threads_num: usize) -> ThreadPool {
    let pool = if threads_num > 0 {
        ThreadPool::new(threads_num)
    } else {
        let cpus = get_cpu_num();
        ThreadPool::new(cpus)
    };
    pool
}

pub fn get_default_timeout() -> Duration {
    Duration::from_secs_f32(DEFAULT_TIMEOUT)
}

pub struct SpHex {
    pub hex: Option<String>, // hex => dec
}

impl SpHex {
    pub fn new_hex(hex_str: &str) -> SpHex {
        SpHex {
            hex: Some(SpHex::length_completion(hex_str).to_string()),
        }
    }
    pub fn length_completion(hex_str: &str) -> String {
        let hex_str_len = hex_str.len();
        if hex_str_len % 2 == 1 {
            format!("0{}", hex_str)
        } else {
            hex_str.to_string()
        }
    }
    pub fn vec_4u8_to_u32(input: &[u8]) -> u32 {
        let mut ret = 0;
        let mut i = input.len();
        for v in input {
            let mut new_v = *v as u32;
            i -= 1;
            new_v <<= i * 8;
            ret += new_v;
        }
        ret
    }
    pub fn decode(&self) -> Result<u32, PistolError> {
        match &self.hex {
            Some(hex_str) => match hex::decode(hex_str) {
                Ok(d) => Ok(SpHex::vec_4u8_to_u32(&d)),
                Err(e) => Err(e.into()),
            },
            None => panic!("set value before decode!"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::datalink::interfaces;
    #[test]
    fn test_convert() {
        let v: Vec<u8> = vec![1, 1];
        let r = SpHex::vec_4u8_to_u32(&v);
        assert_eq!(r, 257);

        let s = "51E80C";
        let h = SpHex::new_hex(s);
        let r = h.decode().unwrap();
        assert_eq!(r, 5367820);

        let s = "1C";
        let h = SpHex::new_hex(s);
        let r = h.decode().unwrap();
        assert_eq!(r, 28);

        let s = "A";
        let h = SpHex::new_hex(s);
        let r = h.decode().unwrap();
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
}
