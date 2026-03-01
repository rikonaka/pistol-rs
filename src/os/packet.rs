use pnet::packet::icmp;
use pnet::packet::icmp::IcmpCode;
use pnet::packet::icmp::IcmpType;
use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::Ipv4Flags;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpOption;
use pnet::packet::udp;
use pnet::packet::udp::MutableUdpPacket;
use rand::RngExt;
use std::net::Ipv4Addr;
use std::panic::Location;
use std::sync::Arc;

use crate::error::PistolError;
use crate::layer::ICMP_HEADER_SIZE;
use crate::layer::IPV4_HEADER_SIZE;
use crate::layer::TCP_HEADER_SIZE;
use crate::layer::UDP_HEADER_SIZE;

// 8 options:
// 0~5: six options for SEQ/OPS/WIN/T1 probes.
// 6:   ECN probe.
// 7-12:   T2~T7 probes.//
// option 0: WScale (10), Nop, MSS (1460), Timestamp, SackP
// option 1: MSS (1400), WScale (0), SackP, T(0xFFFFFFFF,0x0), EOL
// option 2: T(0xFFFFFFFF, 0x0), Nop, Nop, WScale (5), Nop, MSS (640)
// option 3: SackP, T(0xFFFFFFFF,0x0), WScale (10), EOL
// option 4: MSS (536), SackP, T(0xFFFFFFFF,0x0), WScale (10), EOL
// option 5: MSS (265), SackP, T(0xFFFFFFFF,0x0)
// option 6: WScale (10), Nop, MSS (1460), SackP, Nop, Nop
// option 7-11: WScale (10), Nop, MSS (265), T(0xFFFFFFFF,0x0), SackP
// option 12: WScale (15), Nop, MSS (265), T(0xFFFFFFFF,0x0), SackP
const PRB_OPT: [[u8; 20]; 13] = [
    [
        0x03, 0x03, 0x0A, 0x01, 0x02, 0x04, 0x05, 0xb4, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x02, // 0
    ],
    [
        0x02, 0x04, 0x05, 0x78, 0x03, 0x03, 0x00, 0x04, 0x02, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, // 1
    ],
    [
        0x08, 0x0A, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x03, 0x03, 0x05,
        0x01, 0x02, 0x04, 0x02, 0x80, // 2
    ],
    [
        0x04, 0x02, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03, 0x0A,
        0x00, 0x00, 0x00, 0x00, 0x00, // 3
    ],
    [
        0x02, 0x04, 0x02, 0x18, 0x04, 0x02, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
        0x00, 0x03, 0x03, 0x0A, 0x00, // 4
    ],
    [
        0x02, 0x04, 0x01, 0x09, 0x04, 0x02, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, // 5
    ],
    [
        0x03, 0x03, 0x0A, 0x01, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, // 6
    ],
    [
        0x03, 0x03, 0x0A, 0x01, 0x02, 0x04, 0x01, 0x09, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x02, // 7
    ],
    [
        0x03, 0x03, 0x0A, 0x01, 0x02, 0x04, 0x01, 0x09, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x02, // 8
    ],
    [
        0x03, 0x03, 0x0A, 0x01, 0x02, 0x04, 0x01, 0x09, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x02, // 9
    ],
    [
        0x03, 0x03, 0x0A, 0x01, 0x02, 0x04, 0x01, 0x09, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x02, // 10
    ],
    [
        0x03, 0x03, 0x0A, 0x01, 0x02, 0x04, 0x01, 0x09, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x02, // 11
    ],
    [
        0x03, 0x03, 0x0f, 0x01, 0x02, 0x04, 0x01, 0x09, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x02, // 12
    ],
];

// TCP window sizes, numbering is the same as for prbOpts[]
const PRB_WINDOW_SZ: [u16; 13] = [1, 63, 4, 4, 16, 512, 3, 128, 256, 1024, 31337, 32768, 65535];

// TCP options size
const NOP_SIZE: usize = 1;
const MSS_SIZE: usize = 4;
const WSCALE_SIZE: usize = 3;
const TIMESTAMP_SIZE: usize = 10;
const SACK_PERM_SIZE: usize = 2;
const TTL: u8 = 64;

pub fn seq_packet_1_layer3(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<Arc<[u8]>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize =
        WSCALE_SIZE + NOP_SIZE + MSS_SIZE + TIMESTAMP_SIZE + SACK_PERM_SIZE;

    let mut buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    // ip header
    let mut ip_header = match MutableIpv4Packet::new(&mut buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE) as u16,
    );
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.random();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.random();
    tcp_header.set_acknowledgement(acknowledgement);
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    // The window field is 1.
    tcp_header.set_window(PRB_WINDOW_SZ[0]);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_data_offset(10); // 4 * 10 = 40

    // Packet #1: window scale (10), NOP, MSS (1460), timestamp (TSval: 0xFFFFFFFF; TSecr: 0), SACK permitted.
    tcp_header.set_options(&vec![
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::mss(1460),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
        TcpOption::sack_perm(),
    ]);
    let opt = tcp_header.get_options_raw();
    assert_eq!(opt, PRB_OPT[0]);

    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    Ok(Arc::new(buff))
}

pub fn seq_packet_2_layer3(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<Arc<[u8]>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize = MSS_SIZE + WSCALE_SIZE + 1 + SACK_PERM_SIZE + TIMESTAMP_SIZE;

    let mut buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    // ip header
    let mut ip_header = match MutableIpv4Packet::new(&mut buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE) as u16,
    );
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.random();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.random();
    tcp_header.set_acknowledgement(acknowledgement);
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    // The window field is 63.
    tcp_header.set_window(PRB_WINDOW_SZ[1]);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_data_offset(10); // 4 * 10 = 40

    // Packet #2: MSS (1400), window scale (0), SACK permitted, timestamp (TSval: 0xFFFFFFFF; TSecr: 0), EOL.
    tcp_header.set_options(&vec![
        TcpOption::mss(1400),
        TcpOption::wscale(0),
        TcpOption::sack_perm(),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
    ]);
    let opt = tcp_header.get_options_raw();
    assert_eq!(opt, PRB_OPT[1]);

    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    Ok(Arc::new(buff))
}

pub fn seq_packet_3_layer3(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<Arc<[u8]>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize =
        TIMESTAMP_SIZE + NOP_SIZE + NOP_SIZE + WSCALE_SIZE + NOP_SIZE + MSS_SIZE;

    let mut buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    // ip header
    let mut ip_header = match MutableIpv4Packet::new(&mut buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE) as u16,
    );
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.random();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.random();
    tcp_header.set_acknowledgement(acknowledgement);
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    // The window field is 4.
    tcp_header.set_window(PRB_WINDOW_SZ[2]);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_data_offset(10); // 4 * 10 = 40

    // Packet #3: Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), NOP, NOP, window scale (5), NOP, MSS (640).
    tcp_header.set_options(&vec![
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
        TcpOption::nop(),
        TcpOption::nop(),
        TcpOption::wscale(5),
        TcpOption::nop(),
        TcpOption::mss(640),
    ]);
    let opt = tcp_header.get_options_raw();
    assert_eq!(opt, PRB_OPT[2]);

    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    Ok(Arc::new(buff))
}

pub fn seq_packet_4_layer3(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<Arc<[u8]>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize = SACK_PERM_SIZE + 3 + TIMESTAMP_SIZE + WSCALE_SIZE + 3;

    let mut buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    // ip header
    let mut ip_header = match MutableIpv4Packet::new(&mut buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE) as u16,
    );
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.random();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.random();
    tcp_header.set_acknowledgement(acknowledgement);
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    // The window field is 4.
    tcp_header.set_window(PRB_WINDOW_SZ[3]);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_data_offset(10); // 4 * 10 = 40

    // Packet #4: SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), window scale (10), EOL.
    tcp_header.set_options(&vec![
        TcpOption::sack_perm(),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
        TcpOption::wscale(10),
    ]);
    let opt = tcp_header.get_options_raw();
    assert_eq!(opt, PRB_OPT[3]);

    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    Ok(Arc::new(buff))
}

pub fn seq_packet_5_layer3(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<Arc<[u8]>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize = MSS_SIZE + SACK_PERM_SIZE + TIMESTAMP_SIZE + WSCALE_SIZE + 1;

    let mut buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    // ip header
    let mut ip_header = match MutableIpv4Packet::new(&mut buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE) as u16,
    );
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.random();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.random();
    tcp_header.set_acknowledgement(acknowledgement);
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    // The window field is 16.
    tcp_header.set_window(PRB_WINDOW_SZ[4]);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_data_offset(10); // 4 * 10 = 40

    // Packet #5: MSS (536), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), window scale (10), EOL.
    tcp_header.set_options(&vec![
        TcpOption::mss(536),
        TcpOption::sack_perm(),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
        TcpOption::wscale(10),
    ]);
    let opt = tcp_header.get_options_raw();
    assert_eq!(opt, PRB_OPT[4]);

    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    Ok(Arc::new(buff))
}

pub fn seq_packet_6_layer3(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<Arc<[u8]>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize = MSS_SIZE + 1 + SACK_PERM_SIZE + 3 + TIMESTAMP_SIZE;

    let mut buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    // ip header
    let mut ip_header = match MutableIpv4Packet::new(&mut buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE) as u16,
    );
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.random();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.random();
    tcp_header.set_acknowledgement(acknowledgement);
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    // The window field is 512.
    tcp_header.set_window(PRB_WINDOW_SZ[5]);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_data_offset(10); // 4 * 10 = 40

    // Packet #6: MSS (265), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0).
    tcp_header.set_options(&vec![
        TcpOption::mss(265),
        TcpOption::sack_perm(),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
    ]);
    let opt = tcp_header.get_options_raw();
    assert_eq!(opt, PRB_OPT[5]);

    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    Ok(Arc::new(buff))
}

pub fn ie_packet_1_layer3(
    dst_ipv4: Ipv4Addr,
    src_ipv4: Ipv4Addr,
    idtf: u16,
) -> Result<Arc<[u8]>, PistolError> {
    let mut rng = rand::rng();
    const ICMP_DATA_SIZE: usize = 120; // and 120 bytes of 0x00 for the data payload

    let mut buff = [0u8; IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE];
    // ip header
    let mut ip_header = match MutableIpv4Packet::new(&mut buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE) as u16);
    // a random IP ID and ICMP request identifier
    let id = rng.random();
    ip_header.set_identification(id);
    // the first one has the IP DF bit set
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    // a type-of-service (TOS) byte value of zero
    ip_header.set_dscp(0);
    ip_header.set_ecn(0);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // icmp header
    let mut icmp_header = match MutableEchoRequestPacket::new(&mut buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    // a code of nine (even though it should be zero)
    icmp_header.set_icmp_code(IcmpCode(9));
    icmp_header.set_icmp_type(IcmpType(8));
    // the sequence number 295
    icmp_header.set_sequence_number(295);
    // a random IP ID and ICMP request identifier
    icmp_header.set_identifier(idtf);
    let icmp_data: Vec<u8> = vec![0x00; ICMP_DATA_SIZE];
    icmp_header.set_payload(&icmp_data);

    let mut icmp_header = match MutableIcmpPacket::new(&mut buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    let checksum = icmp::checksum(&icmp_header.to_immutable());
    icmp_header.set_checksum(checksum);
    Ok(Arc::new(buff))
}

pub fn ie_packet_2_layer3(
    dst_ipv4: Ipv4Addr,
    src_ipv4: Ipv4Addr,
    idtf: u16,
) -> Result<Arc<[u8]>, PistolError> {
    // 150 bytes of data is sent
    let mut rng = rand::rng();
    const ICMP_DATA_SIZE: usize = 150; // 150 bytes of data is sent

    let mut buff = [0u8; IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE];
    // ip header
    let mut ip_header = match MutableIpv4Packet::new(&mut buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE) as u16);
    let id = rng.random();
    ip_header.set_identification(id);
    // the first one has the IP DF bit set
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(TTL);
    // a TOS of four (IP_TOS_RELIABILITY) is used
    // 000001|00
    ip_header.set_dscp(1);
    ip_header.set_ecn(0);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // icmp header
    let mut icmp_header = match MutableEchoRequestPacket::new(&mut buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    // the code is zero
    icmp_header.set_icmp_code(IcmpCode(0));
    icmp_header.set_icmp_type(IcmpType(8));
    icmp_header.set_sequence_number(296);
    // and the ICMP request ID and sequence numbers are incremented by one from the previous query values
    icmp_header.set_identifier(idtf);
    let icmp_data: Vec<u8> = vec![0x00; ICMP_DATA_SIZE];
    icmp_header.set_payload(&icmp_data);

    let mut icmp_header = match MutableIcmpPacket::new(&mut buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    let checksum = icmp::checksum(&icmp_header.to_immutable());
    icmp_header.set_checksum(checksum);
    Ok(Arc::new(buff))
}

pub fn ecn_packet_layer3(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<Arc<[u8]>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize = WSCALE_SIZE
        + 1
        + NOP_SIZE
        + 3
        + MSS_SIZE
        + SACK_PERM_SIZE
        + 2
        + NOP_SIZE
        + 1
        + NOP_SIZE
        + 1;

    let mut buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    // ip header
    let mut ip_header = match MutableIpv4Packet::new(&mut buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE) as u16,
    );
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_ttl(TTL);
    ip_header.set_ecn(0);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    // Sequence number is random.
    let sequence = rng.random();
    tcp_header.set_sequence(sequence);
    // The acknowledgment number is zero.
    tcp_header.set_acknowledgement(0);
    // The reserved bit which immediately precedes the CWR bit is set.
    tcp_header.set_reserved(8);
    // Nmap tests this by sending a SYN packet which also has the ECN CWR and ECE congestion control flags set.
    tcp_header.set_flags(TcpFlags::CWR | TcpFlags::ECE | TcpFlags::SYN);
    // Window size field is three.
    tcp_header.set_window(PRB_WINDOW_SZ[6]);
    // For an unrelated (to ECN) test, the urgent field value of 0xF7F5 is used even though the urgent flag is not set.
    tcp_header.set_urgent_ptr(0xF7F5);
    tcp_header.set_data_offset(10); // 4 * 10 = 40

    // TCP options are WScale (10), NOP, MSS (1460), SACK permitted, NOP, NOP.
    tcp_header.set_options(&vec![
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::mss(1460),
        TcpOption::sack_perm(),
        TcpOption::nop(),
        TcpOption::nop(),
    ]);
    let opt = tcp_header.get_options_raw();
    assert_eq!(opt, PRB_OPT[6]);

    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    Ok(Arc::new(buff))
}

pub fn t2_packet_layer3(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<Arc<[u8]>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize =
        WSCALE_SIZE + NOP_SIZE + MSS_SIZE + TIMESTAMP_SIZE + SACK_PERM_SIZE;

    let mut buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    // ip header
    let mut ip_header = match MutableIpv4Packet::new(&mut buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE) as u16,
    );
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    ip_header.set_ttl(TTL);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.random();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.random();
    tcp_header.set_acknowledgement(acknowledgement);
    // T2 sends a TCP null (no flags set) packet with the IP DF bit set and a window field of 128 to an open port.
    tcp_header.set_flags(0);
    tcp_header.set_window(PRB_WINDOW_SZ[7]);
    tcp_header.set_data_offset(10); // 5 (header: 5 * 4 = 20) + 5 (options: 5 * 4 = 20)

    // Those 20 bytes correspond to window scale (10), NOP, MSS (265), Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), then SACK permitted.
    tcp_header.set_options(&vec![
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::mss(265),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
        TcpOption::sack_perm(),
    ]);
    let opt = tcp_header.get_options_raw();
    assert_eq!(opt, PRB_OPT[7]);

    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    Ok(Arc::new(buff))
}

pub fn t3_packet_layer3(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<Arc<[u8]>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize =
        WSCALE_SIZE + NOP_SIZE + MSS_SIZE + TIMESTAMP_SIZE + SACK_PERM_SIZE;

    let mut buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    // ip header
    let mut ip_header = match MutableIpv4Packet::new(&mut buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE) as u16,
    );
    let id = rng.random();
    ip_header.set_identification(id);
    // ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF not set
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    ip_header.set_ttl(TTL);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.random();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.random();
    tcp_header.set_acknowledgement(acknowledgement);
    // T3 sends a TCP packet with the SYN, FIN, URG, and PSH flags set and a window field of 256 to an open port. The IP DF bit is not set.
    tcp_header.set_flags(TcpFlags::SYN | TcpFlags::FIN | TcpFlags::URG | TcpFlags::PSH);
    tcp_header.set_window(PRB_WINDOW_SZ[8]);
    tcp_header.set_data_offset(10); // 4 * 10 = 40

    // Those 20 bytes correspond to window scale (10), NOP, MSS (265), Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), then SACK permitted.
    tcp_header.set_options(&vec![
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::mss(265),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
        TcpOption::sack_perm(),
    ]);
    let opt = tcp_header.get_options_raw();
    assert_eq!(opt, PRB_OPT[8]);

    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    Ok(Arc::new(buff))
}

pub fn t4_packet_layer3(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<Arc<[u8]>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize =
        WSCALE_SIZE + NOP_SIZE + MSS_SIZE + TIMESTAMP_SIZE + SACK_PERM_SIZE;

    let mut buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    // ip header
    let mut ip_header = match MutableIpv4Packet::new(&mut buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE) as u16,
    );
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    ip_header.set_ttl(TTL);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.random();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.random();
    tcp_header.set_acknowledgement(acknowledgement);
    // T4 sends a TCP ACK packet with IP DF and a window field of 1024 to an open port.
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_window(PRB_WINDOW_SZ[9]);
    tcp_header.set_data_offset(10); // 4 * 10 = 40

    // Those 20 bytes correspond to window scale (10), NOP, MSS (265), Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), then SACK permitted.
    tcp_header.set_options(&vec![
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::mss(265),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
        TcpOption::sack_perm(),
    ]);
    let opt = tcp_header.get_options_raw();
    assert_eq!(opt, PRB_OPT[9]);

    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    Ok(Arc::new(buff))
}

pub fn t5_packet_layer3(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<Arc<[u8]>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize =
        WSCALE_SIZE + NOP_SIZE + MSS_SIZE + TIMESTAMP_SIZE + SACK_PERM_SIZE;

    let mut buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    // ip header
    let mut ip_header = match MutableIpv4Packet::new(&mut buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE) as u16,
    );
    let id = rng.random();
    ip_header.set_identification(id);
    // ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF not set
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    ip_header.set_ttl(TTL);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.random();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.random();
    tcp_header.set_acknowledgement(acknowledgement);
    // T5 sends a TCP SYN packet without IP DF and a window field of 31337 to a closed port.
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_window(PRB_WINDOW_SZ[10]);
    tcp_header.set_data_offset(10); // 4 * 10 = 40

    // Those 20 bytes correspond to window scale (10), NOP, MSS (265), Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), then SACK permitted.
    tcp_header.set_options(&vec![
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::mss(265),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
        TcpOption::sack_perm(),
    ]);
    let opt = tcp_header.get_options_raw();
    assert_eq!(opt, PRB_OPT[10]);

    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    Ok(Arc::new(buff))
}

pub fn t6_packet_layer3(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<Arc<[u8]>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize =
        WSCALE_SIZE + NOP_SIZE + MSS_SIZE + TIMESTAMP_SIZE + SACK_PERM_SIZE;

    let mut buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    // ip header
    let mut ip_header = match MutableIpv4Packet::new(&mut buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE) as u16,
    );
    let id = rng.random();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    ip_header.set_ttl(TTL);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.random();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.random();
    tcp_header.set_acknowledgement(acknowledgement);
    // T6 sends a TCP ACK packet with IP DF and a window field of 32768 to a closed port.
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_window(PRB_WINDOW_SZ[11]);
    tcp_header.set_data_offset(10); // 4 * 10 = 40

    // Those 20 bytes correspond to window scale (10), NOP, MSS (265), Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), then SACK permitted.
    tcp_header.set_options(&vec![
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::mss(265),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
        TcpOption::sack_perm(),
    ]);
    let opt = tcp_header.get_options_raw();
    assert_eq!(opt, PRB_OPT[11]);

    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    Ok(Arc::new(buff))
}

pub fn t7_packet_layer3(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<Arc<[u8]>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize =
        WSCALE_SIZE + NOP_SIZE + MSS_SIZE + TIMESTAMP_SIZE + SACK_PERM_SIZE;

    let mut buff = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    // ip header
    let mut ip_header = match MutableIpv4Packet::new(&mut buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE) as u16,
    );
    let id = rng.random();
    ip_header.set_identification(id);
    // ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF not set
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    ip_header.set_ttl(TTL);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.random();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.random();
    tcp_header.set_acknowledgement(acknowledgement);
    // T7 sends a TCP packet with the FIN, PSH, and URG flags set and a window field of 65535 to a closed port.
    // The IP DF bit is not set.
    tcp_header.set_flags(TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG);
    tcp_header.set_window(PRB_WINDOW_SZ[12]);
    tcp_header.set_data_offset(10); // 4 * 10 = 40

    // Those 20 bytes correspond to window scale (10), NOP, MSS (265), Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), then SACK permitted.
    // The exception is that T7 uses a Window scale value of 15 rather than 10.
    tcp_header.set_options(&vec![
        TcpOption::wscale(15),
        TcpOption::nop(),
        TcpOption::mss(265),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
        TcpOption::sack_perm(),
    ]);
    let opt = tcp_header.get_options_raw();
    assert_eq!(opt, PRB_OPT[12]);

    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    Ok(Arc::new(buff))
}

pub fn udp_packet_layer3(
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
    src_ipv4: Ipv4Addr,
    src_port: u16,
) -> Result<Arc<[u8]>, PistolError> {
    const UDP_DATA_SIZE: usize = 300;
    let mut buff = [0u8; IPV4_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE];
    // ip header
    let mut ip_header = match MutableIpv4Packet::new(&mut buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE) as u16);
    // The IP ID value is set to 0x1042 for operating systems which allow us to set this.
    ip_header.set_identification(0x1042);
    // ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF not set
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip_header.set_source(src_ipv4);
    ip_header.set_ttl(TTL);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // udp header
    let mut udp_header = match MutableUdpPacket::new(&mut buff[IPV4_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    udp_header.set_source(src_port);
    udp_header.set_destination(dst_port);
    udp_header.set_length((UDP_HEADER_SIZE + UDP_DATA_SIZE) as u16);
    // The character 'C' (0x43) is repeated 300 times for the data field.
    let udp_data: Vec<u8> = vec![0x43; 300];
    assert_eq!(udp_data.len(), 300);
    udp_header.set_payload(&udp_data);
    let checksum = udp::ipv4_checksum(&udp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    udp_header.set_checksum(checksum);
    Ok(Arc::new(buff))
}
