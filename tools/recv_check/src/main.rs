use ctrlc;
use pcapture::Capture;

fn main() {
    let mut recv_count = 0;
    ctrlc::set_handler(move || {
        println!("recv_count: {}", recv_count);
        std::process::exit(0);
    })
    .expect("error setting Ctrl-C handler");

    let mut cap = Capture::new("ens33").expect("failed to create capture");
    cap.set_filter("host 192.168.5.3");

    loop {
        let packets = cap.fetch_as_vec().expect("failed to fetch packets");
        recv_count += packets.len();
    }
}
