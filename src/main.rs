use clap::Parser;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::sync::Arc;
use std::sync::LazyLock;

/// Rust implementation of nmap.
#[derive(Parser, Debug)]
#[command(author = "RikoNaka", version, about, long_about = None)]
struct Args {
    /// Input from list of hosts/networks (same as nmap -iL parameter)
    #[arg(long, default_value = "")]
    filename: String,

    /// The tcp listen port
    #[arg(short, long, default_value = "")]
    tcp: String,

    /// The udp listen port
    #[arg(short, long, default_value = "")]
    udp: String,

    /// When receiving data, return the data set in this parameter
    #[arg(short, long, default_value = "null", default_missing_value = "", num_args(0..2))]
    need_return: String,
}

static IPV4_IEGAL_CHARS: LazyLock<Arc<Vec<char>>> = LazyLock::new(|| {
    let mut ipv4_legal_chars = Vec::new();
    for c in '0'..='9' {
        ipv4_legal_chars.push(c);
    }
    ipv4_legal_chars.push('.');
    Arc::new(ipv4_legal_chars)
});

static IPV6_IEGAL_CHARS: LazyLock<Arc<Vec<char>>> = LazyLock::new(|| {
    let mut ipv6_legal_chars = Vec::new();
    for c in '0'..='f' {
        ipv6_legal_chars.push(c);
    }
    ipv6_legal_chars.push(':');
    Arc::new(ipv6_legal_chars)
});

fn target_parser(target: &str) {
    let mut is_ipv4 = true;
    let mut is_ipv6 = true;
}

fn get_target_from_file(filename: &str) {
    let fp = File::open(filename).expect(&format!("can not open file [{}]", filename));
    let reader = BufReader::new(fp);
    for line in reader.lines() {
        let line = line.expect("can not read line");
        println!("{}", line);
    }
}

fn main() {
    let args = Args::parse();
    if args.filename.len() > 0 {
        get_target_from_file(&args.filename);
    }
}
