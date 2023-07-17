use subnetwork::Ipv4Pool;

mod arp;
mod tcp_syn;
mod utils;

use arp::run_arp_scan;
use arp::ArpScanResults;

pub async fn arp_scan(subnet: &str) -> Option<ArpScanResults> {
    let mut subnet = Ipv4Pool::new(subnet).unwrap();
    run_arp_scan(&mut subnet).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_arp_scan() {
        match arp_scan("192.168.1.0/24").await {
            Some(rets) => {
                println!("{}", rets.alive_hosts);
                for i in rets.alive_hosts_info {
                    println!("{}, {}", i.host_ip, i.host_mac);
                }
            }
            _ => (),
        }
    }
    #[tokio::test]
    async fn test_tokio() {
        let mut handles = Vec::new();
        for i in 1..10 {
            let r = tokio::spawn(async move {
                println!("hi number {} from the spawned thread!", i);
                let _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                // thread::sleep(Duration::from_secs(1));
                println!("bye number {} from the spawned thread!", i);
            });
            handles.push(r);
        }

        // let _ = tokio::join!(r);
        for i in handles {
            i.await.unwrap();
            // tokio::join!(i);
        }
    }
    #[test]
    fn test_thread() {
        use std::thread;
        use std::time::Duration;

        let _ = thread::spawn(|| {
            for i in 1..10 {
                println!("hi number {} from the spawned thread!", i);
                thread::sleep(Duration::from_millis(i - 1));
                println!("bye number {} from the spawned thread!", i);
            }
        });

        // handle.join().unwrap();

        for i in 1..5 {
            println!("hi number {} from the main thread!", i);
            thread::sleep(Duration::from_millis(1));
        }
    }
}
