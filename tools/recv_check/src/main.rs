use ctrlc;
use pcapture::Capture;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

fn main() {
    println!("running...");
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("error setting Ctrl-C handler");

    let mut cap = Capture::new("ens33").expect("failed to create capture");
    cap.set_buffer_size(8192);
    // only capture tcp syn packets to avoid too much packets
    // cap.set_filter("host 192.168.5.3 and tcp and tcp[13] & 2 != 0 and tcp[13] & 16 == 0");
    cap.set_filter("host 192.168.5.3 and tcp and tcp[13] & 2 != 0 and (dst port 22 or dst port 80 or dst port 8080)");

    let mut recv_count = 0;
    println!("start receiving packets...");
    while running.load(Ordering::SeqCst) {
        let packets = cap.fetch_as_vec().expect("failed to fetch packets");
        recv_count += packets.len();
        println!("total received {} packets", recv_count);
    }

    println!("exit");
}
