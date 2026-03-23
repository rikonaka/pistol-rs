use pistol::Pistol;
use pistol::Target;

fn main() {
    let mut pistol = Pistol::new();
    pistol.set_max_retries(2);
    pistol.set_timeout(0.5);
    // pistol.set_log_level("debug");

    let targets = Target::from_subnet("192.168.5.0/24", None).unwrap();
    let ret = pistol.mac_scan(&targets).unwrap();
    println!("{}", ret);
}
