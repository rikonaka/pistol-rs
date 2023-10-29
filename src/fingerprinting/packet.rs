use anyhow::Result;
use pnet::packet::icmp;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::icmp::{IcmpCode, IcmpType};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption};
use pnet::packet::udp;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::Packet;
use rand::Rng;
use std::net::Ipv4Addr;

use crate::utils::ICMP_HEADER_LEN;
use crate::utils::IPV4_HEADER_LEN;
use crate::utils::IP_TTL;
use crate::utils::TCP_DATA_LEN;
use crate::utils::UDP_HEADER_LEN;

const TCP_PROBE_HEADER_WITH_OPTIONS_LEN: usize = 40; // 20 + 20 (options)
const ICMP_PROBE_DATA_LEN: usize = 120; // and 120 bytes of 0x00 for the data payload
const UDP_PROBE_DATA_LEN: usize = 300;

/* 8 options:
*  0~5: six options for SEQ/OPS/WIN/T1 probes.
*  6:   ECN probe.
*  7-12:   T2~T7 probes.
*
* option 0: WScale (10), Nop, MSS (1460), Timestamp, SackP
* option 1: MSS (1400), WScale (0), SackP, T(0xFFFFFFFF,0x0), EOL
* option 2: T(0xFFFFFFFF, 0x0), Nop, Nop, WScale (5), Nop, MSS (640)
* option 3: SackP, T(0xFFFFFFFF,0x0), WScale (10), EOL
* option 4: MSS (536), SackP, T(0xFFFFFFFF,0x0), WScale (10), EOL
* option 5: MSS (265), SackP, T(0xFFFFFFFF,0x0)
* option 6: WScale (10), Nop, MSS (1460), SackP, Nop, Nop
* option 7-11: WScale (10), Nop, MSS (265), T(0xFFFFFFFF,0x0), SackP
* option 12: WScale (15), Nop, MSS (265), T(0xFFFFFFFF,0x0), SackP
*/
pub const PRB_OPT: [[u8; 20]; 13] = [
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

/* TCP Window sizes. Numbering is the same as for prbOpts[] */
pub const PRB_WINDOW_SZ: [u16; 13] = [1, 63, 4, 4, 16, 512, 3, 128, 256, 1024, 31337, 32768, 65535];

pub fn seq_packet_1_layer3(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16,
    );
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_ttl(IP_TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_buff = [0u8; TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.gen();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.gen();
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
    ip_header.set_payload(tcp_header.packet());

    Ok(ip_buff.to_vec())
}

pub fn seq_packet_2_layer3(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16,
    );
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_ttl(IP_TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_buff = [0u8; TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.gen();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.gen();
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
    ip_header.set_payload(tcp_header.packet());

    Ok(ip_buff.to_vec())
}

pub fn seq_packet_3_layer3(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16,
    );
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_ttl(IP_TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_buff = [0u8; TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.gen();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.gen();
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
    ip_header.set_payload(tcp_header.packet());

    Ok(ip_buff.to_vec())
}

pub fn seq_packet_4_layer3(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16,
    );
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_ttl(IP_TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_buff = [0u8; TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.gen();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.gen();
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
    ip_header.set_payload(tcp_header.packet());

    Ok(ip_buff.to_vec())
}

pub fn seq_packet_5_layer3(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16,
    );
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_ttl(IP_TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_buff = [0u8; TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.gen();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.gen();
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
    ip_header.set_payload(tcp_header.packet());

    Ok(ip_buff.to_vec())
}

pub fn seq_packet_6_layer3(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16,
    );
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_ttl(IP_TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_buff = [0u8; TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.gen();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.gen();
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
    ip_header.set_payload(tcp_header.packet());

    Ok(ip_buff.to_vec())
}

pub fn ie_packet_1_layer3(src_ipv4: Ipv4Addr, dst_ipv4: Ipv4Addr, idtf: u16) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PROBE_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PROBE_DATA_LEN) as u16);
    // a random IP ID and ICMP request identifier
    let id = rng.gen();
    ip_header.set_identification(id);
    // the first one has the IP DF bit set
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(IP_TTL);
    // a type-of-service (TOS) byte value of zero
    ip_header.set_dscp(0);
    ip_header.set_ecn(0);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    let mut icmp_buff = [0u8; ICMP_HEADER_LEN + ICMP_PROBE_DATA_LEN];
    let mut icmp_header = MutableEchoRequestPacket::new(&mut icmp_buff[..]).unwrap();
    // a code of nine (even though it should be zero)
    icmp_header.set_icmp_code(IcmpCode(9));
    icmp_header.set_icmp_type(IcmpType(8));
    // the sequence number 295
    icmp_header.set_sequence_number(295);
    // a random IP ID and ICMP request identifier
    icmp_header.set_identifier(idtf);

    let mut icmp_header = MutableIcmpPacket::new(&mut icmp_buff).unwrap();
    let checksum = icmp::checksum(&icmp_header.to_immutable());
    icmp_header.set_checksum(checksum);
    ip_header.set_payload(&icmp_header.packet());

    Ok(ip_buff.to_vec())
}

pub fn ie_packet_2_layer3(src_ipv4: Ipv4Addr, dst_ipv4: Ipv4Addr, idtf: u16) -> Result<Vec<u8>> {
    // 150 bytes of data is sent
    let mut rng = rand::thread_rng();

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PROBE_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PROBE_DATA_LEN) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    // the first one has the IP DF bit set
    ip_header.set_flags(Ipv4Flags::DontFragment);
    ip_header.set_ttl(IP_TTL);
    // a TOS of four (IP_TOS_RELIABILITY) is used
    // 000001|00
    ip_header.set_dscp(1);
    ip_header.set_ecn(0);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    let mut icmp_buff = [0u8; ICMP_HEADER_LEN + ICMP_PROBE_DATA_LEN];
    let mut icmp_header = MutableEchoRequestPacket::new(&mut icmp_buff[..]).unwrap();
    // the code is zero
    icmp_header.set_icmp_code(IcmpCode(9));
    icmp_header.set_icmp_type(IcmpType(8));
    icmp_header.set_sequence_number(295 + 1);
    // and the ICMP request ID and sequence numbers are incremented by one from the previous query values
    icmp_header.set_identifier(idtf);

    let mut icmp_header = MutableIcmpPacket::new(&mut icmp_buff).unwrap();
    let checksum = icmp::checksum(&icmp_header.to_immutable());
    icmp_header.set_checksum(checksum);
    ip_header.set_payload(&icmp_header.packet());

    Ok(ip_buff.to_vec())
}

pub fn ecn_packet_layer3(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16,
    );
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_ttl(IP_TTL);
    ip_header.set_ecn(1); // ECN
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_buff = [0u8; TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    // Sequence number is random.
    let sequence = rng.gen();
    tcp_header.set_sequence(sequence);
    // The acknowledgment number is zero.
    tcp_header.set_acknowledgement(0);
    // The reserved bit which immediately precedes the CWR bit is set.
    tcp_header.set_reserved(0xF);
    // Nmap tests this by sending a SYN packet which also has the ECN CWR and ECE congestion control flags set.
    tcp_header.set_flags(TcpFlags::SYN | TcpFlags::CWR | TcpFlags::ECE);
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
    ip_header.set_payload(tcp_header.packet());

    Ok(ip_buff.to_vec())
}

pub fn t2_packet_layer3(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16,
    );
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_buff = [0u8; TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.gen();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.gen();
    tcp_header.set_acknowledgement(acknowledgement);
    // T2 sends a TCP null (no flags set) packet with the IP DF bit set and a window field of 128 to an open port.
    tcp_header.set_flags(0);
    tcp_header.set_window(PRB_WINDOW_SZ[7]);
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
    assert_eq!(opt, PRB_OPT[7]);

    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    ip_header.set_payload(tcp_header.packet());

    Ok(ip_buff.to_vec())
}

pub fn t3_packet_layer3(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16,
    );
    let id = rng.gen();
    ip_header.set_identification(id);
    // ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF not set
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_buff = [0u8; TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.gen();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.gen();
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
    ip_header.set_payload(tcp_header.packet());

    Ok(ip_buff.to_vec())
}

pub fn t4_packet_layer3(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16,
    );
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_buff = [0u8; TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.gen();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.gen();
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
    ip_header.set_payload(tcp_header.packet());

    Ok(ip_buff.to_vec())
}

pub fn t5_packet_layer3(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16,
    );
    let id = rng.gen();
    ip_header.set_identification(id);
    // ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF not set
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_buff = [0u8; TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.gen();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.gen();
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
    ip_header.set_payload(tcp_header.packet());

    Ok(ip_buff.to_vec())
}

pub fn t6_packet_layer3(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16,
    );
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_buff = [0u8; TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.gen();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.gen();
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
    ip_header.set_payload(tcp_header.packet());

    Ok(ip_buff.to_vec())
}

pub fn t7_packet_layer3(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(
        (IPV4_HEADER_LEN + TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16,
    );
    let id = rng.gen();
    ip_header.set_identification(id);
    // ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF not set
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // tcp header
    let mut tcp_buff = [0u8; TCP_PROBE_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.gen();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.gen();
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
    ip_header.set_payload(tcp_header.packet());

    Ok(ip_buff.to_vec())
}

pub fn udp_packet_layer3(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
) -> Result<Vec<u8>> {
    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + UDP_HEADER_LEN + UDP_PROBE_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_LEN + UDP_HEADER_LEN + UDP_PROBE_DATA_LEN) as u16);
    // The IP ID value is set to 0x1042 for operating systems which allow us to set this.
    ip_header.set_identification(0x1042);
    // ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF not set
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip_header.set_source(src_ipv4);
    ip_header.set_ttl(64);
    ip_header.set_destination(dst_ipv4);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);

    // udp header
    let mut udp_buff = [0u8; UDP_HEADER_LEN + UDP_PROBE_DATA_LEN];
    let mut udp_header = MutableUdpPacket::new(&mut udp_buff[..]).unwrap();
    udp_header.set_source(src_port);
    udp_header.set_destination(dst_port);
    udp_header.set_length((UDP_HEADER_LEN + UDP_PROBE_DATA_LEN) as u16);
    // The character 'C' (0x43) is repeated 300 times for the data field.
    let udp_data: Vec<u8> = vec![0x43; 300];
    assert_eq!(udp_data.len(), 300);
    udp_header.set_payload(&udp_data);
    let checksum = udp::ipv4_checksum(&udp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    udp_header.set_checksum(checksum);
    ip_header.set_payload(udp_header.packet());

    Ok(ip_buff.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vec() {
        let udp_data: Vec<u8> = vec![0x43; 10];
        println!("{:?}", udp_data);
    }
    #[test]
    fn tcp_options_test() {
        let src_ipv4 = Ipv4Addr::new(192, 168, 1, 3);
        let src_port = 39876;
        let dst_ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let dst_port = 80;
        let _ = seq_packet_1_layer3(src_ipv4, src_port, dst_ipv4, dst_port);
        let _ = seq_packet_2_layer3(src_ipv4, src_port, dst_ipv4, dst_port);
        let _ = seq_packet_3_layer3(src_ipv4, src_port, dst_ipv4, dst_port);
        let _ = seq_packet_4_layer3(src_ipv4, src_port, dst_ipv4, dst_port);
        let _ = seq_packet_5_layer3(src_ipv4, src_port, dst_ipv4, dst_port);
        let _ = seq_packet_6_layer3(src_ipv4, src_port, dst_ipv4, dst_port);
        let _ = ecn_packet_layer3(src_ipv4, src_port, dst_ipv4, dst_port);
        let _ = t2_packet_layer3(src_ipv4, src_port, dst_ipv4, dst_port);
        let _ = t3_packet_layer3(src_ipv4, src_port, dst_ipv4, dst_port);
        let _ = t4_packet_layer3(src_ipv4, src_port, dst_ipv4, dst_port);
        let _ = t5_packet_layer3(src_ipv4, src_port, dst_ipv4, dst_port);
        let _ = t6_packet_layer3(src_ipv4, src_port, dst_ipv4, dst_port);
        let _ = t7_packet_layer3(src_ipv4, src_port, dst_ipv4, dst_port);
    }
}
