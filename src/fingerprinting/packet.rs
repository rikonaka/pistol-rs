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

const TCP_HEADER_WITH_OPTIONS_LEN: usize = 60; // 20 + 40 (options)

pub fn seq_packet_1_layer3(
    src_ipv4: Ipv4Addr,
    src_port: u16,
    dst_ipv4: Ipv4Addr,
    dst_port: u16,
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header
        .set_total_length((IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_ttl(IP_TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_buff = [0u8; TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
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
    tcp_header.set_window(1);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // Packet #1: window scale (10), NOP, MSS (1460), timestamp (TSval: 0xFFFFFFFF; TSecr: 0), SACK permitted.
    tcp_header.set_options(&vec![
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::mss(1460),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
        TcpOption::sack_perm(),
    ]);

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
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header
        .set_total_length((IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_ttl(IP_TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_buff = [0u8; TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
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
    tcp_header.set_window(63);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // Packet #2: MSS (1400), window scale (0), SACK permitted, timestamp (TSval: 0xFFFFFFFF; TSecr: 0), EOL.
    tcp_header.set_options(&vec![
        TcpOption::mss(1400),
        TcpOption::wscale(0),
        TcpOption::sack_perm(),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
    ]);

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
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header
        .set_total_length((IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_ttl(IP_TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_buff = [0u8; TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
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
    tcp_header.set_window(4);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // Packet #3: Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), NOP, NOP, window scale (5), NOP, MSS (640).
    tcp_header.set_options(&vec![
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
        TcpOption::nop(),
        TcpOption::nop(),
        TcpOption::wscale(5),
        TcpOption::nop(),
        TcpOption::mss(6400),
    ]);

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
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header
        .set_total_length((IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_ttl(IP_TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_buff = [0u8; TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
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
    tcp_header.set_window(4);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // Packet #4: SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), window scale (10), EOL.
    tcp_header.set_options(&vec![
        TcpOption::sack_perm(),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
        TcpOption::wscale(10),
    ]);

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
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header
        .set_total_length((IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_ttl(IP_TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_buff = [0u8; TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
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
    tcp_header.set_window(16);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // Packet #5: MSS (536), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), window scale (10), EOL.
    tcp_header.set_options(&vec![
        TcpOption::mss(536),
        TcpOption::sack_perm(),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
        TcpOption::wscale(10),
    ]);

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
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header
        .set_total_length((IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_ttl(IP_TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_buff = [0u8; TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
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
    tcp_header.set_window(512);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // Packet #6: MSS (265), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0).
    tcp_header.set_options(&vec![
        TcpOption::mss(265),
        TcpOption::sack_perm(),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
    ]);

    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    tcp_header.set_checksum(checksum);
    ip_header.set_payload(tcp_header.packet());

    Ok(ip_buff.to_vec())
}

pub fn icmp_echo_packet_1_layer3(src_ipv4: Ipv4Addr, dst_ipv4: Ipv4Addr) -> Result<(Vec<u8>, u16)> {
    // and 120 bytes of 0x00 for the data payload
    const ICMP_DATA_LEN: usize = 120;
    let mut rng = rand::thread_rng();

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_DATA_LEN) as u16);
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
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    let mut icmp_buff = [0u8; ICMP_HEADER_LEN + ICMP_DATA_LEN];
    let mut icmp_header = MutableEchoRequestPacket::new(&mut icmp_buff[..]).unwrap();
    // a code of nine (even though it should be zero)
    icmp_header.set_icmp_code(IcmpCode(9));
    icmp_header.set_icmp_type(IcmpType(8));
    // the sequence number 295
    icmp_header.set_sequence_number(295);
    // a random IP ID and ICMP request identifier
    let idtf = rng.gen();
    icmp_header.set_identifier(idtf);

    let mut icmp_header = MutableIcmpPacket::new(&mut icmp_buff).unwrap();
    let checksum = icmp::checksum(&icmp_header.to_immutable());
    icmp_header.set_checksum(checksum);
    ip_header.set_payload(&icmp_header.packet());

    Ok((ip_buff.to_vec(), idtf))
}

pub fn icmp_echo_packet_2_layer3(
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    packet_1_icmp_id: u16,
) -> Result<Vec<u8>> {
    // 150 bytes of data is sent
    const ICMP_DATA_LEN: usize = 150;
    let mut rng = rand::thread_rng();

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_DATA_LEN) as u16);
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
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    let mut icmp_buff = [0u8; ICMP_HEADER_LEN + ICMP_DATA_LEN];
    let mut icmp_header = MutableEchoRequestPacket::new(&mut icmp_buff[..]).unwrap();
    // the code is zero
    icmp_header.set_icmp_code(IcmpCode(9));
    icmp_header.set_icmp_type(IcmpType(8));
    // and the ICMP request ID and sequence numbers are incremented by one from the previous query values
    icmp_header.set_sequence_number(295 + 1);
    // and the ICMP request ID and sequence numbers are incremented by one from the previous query values
    icmp_header.set_identifier(packet_1_icmp_id + 1);

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
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header
        .set_total_length((IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_ttl(IP_TTL);
    ip_header.set_ecn(1); // ECN
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_buff = [0u8; TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
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
    tcp_header.set_window(3);
    // For an unrelated (to ECN) test, the urgent field value of 0xF7F5 is used even though the urgent flag is not set.
    tcp_header.set_urgent_ptr(0xF7F5);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // TCP options are WScale (10), NOP, MSS (1460), SACK permitted, NOP, NOP.
    tcp_header.set_options(&vec![
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::mss(1460),
        TcpOption::sack_perm(),
        TcpOption::nop(),
        TcpOption::nop(),
    ]);

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
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header
        .set_total_length((IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_buff = [0u8; TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.gen();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.gen();
    tcp_header.set_acknowledgement(acknowledgement);
    // T2 sends a TCP null (no flags set) packet with the IP DF bit set and a window field of 128 to an open port.
    tcp_header.set_flags(0);
    tcp_header.set_window(128);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // Those 20 bytes correspond to window scale (10), NOP, MSS (265), Timestamp (TSval: 0xFFFFFFFF; TSecr: 0),
    tcp_header.set_options(&vec![
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::mss(265),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
    ]);

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
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header
        .set_total_length((IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    // ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF not set
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_buff = [0u8; TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.gen();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.gen();
    tcp_header.set_acknowledgement(acknowledgement);
    // T3 sends a TCP packet with the SYN, FIN, URG, and PSH flags set and a window field of 256 to an open port. The IP DF bit is not set.
    tcp_header.set_flags(TcpFlags::SYN | TcpFlags::FIN | TcpFlags::URG | TcpFlags::PSH);
    tcp_header.set_window(256);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // Those 20 bytes correspond to window scale (10), NOP, MSS (265), Timestamp (TSval: 0xFFFFFFFF; TSecr: 0),
    tcp_header.set_options(&vec![
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::mss(265),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
    ]);

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
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header
        .set_total_length((IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_buff = [0u8; TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.gen();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.gen();
    tcp_header.set_acknowledgement(acknowledgement);
    // T4 sends a TCP ACK packet with IP DF and a window field of 1024 to an open port.
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // Those 20 bytes correspond to window scale (10), NOP, MSS (265), Timestamp (TSval: 0xFFFFFFFF; TSecr: 0),
    tcp_header.set_options(&vec![
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::mss(265),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
    ]);

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
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header
        .set_total_length((IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    // ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF not set
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_buff = [0u8; TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.gen();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.gen();
    tcp_header.set_acknowledgement(acknowledgement);
    // T5 sends a TCP SYN packet without IP DF and a window field of 31337 to a closed port.
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_window(31337);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // Those 20 bytes correspond to window scale (10), NOP, MSS (265), Timestamp (TSval: 0xFFFFFFFF; TSecr: 0),
    tcp_header.set_options(&vec![
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::mss(265),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
    ]);

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
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header
        .set_total_length((IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_buff = [0u8; TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    let sequence = rng.gen();
    tcp_header.set_sequence(sequence);
    let acknowledgement = rng.gen();
    tcp_header.set_acknowledgement(acknowledgement);
    // T6 sends a TCP ACK packet with IP DF and a window field of 32768 to a closed port.
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_window(32768);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // Those 20 bytes correspond to window scale (10), NOP, MSS (265), Timestamp (TSval: 0xFFFFFFFF; TSecr: 0),
    tcp_header.set_options(&vec![
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::mss(265),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
    ]);

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
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header
        .set_total_length((IPV4_HEADER_LEN + TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN) as u16);
    let id = rng.gen();
    ip_header.set_identification(id);
    // ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF not set
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // tcp header
    let mut tcp_buff = [0u8; TCP_HEADER_WITH_OPTIONS_LEN + TCP_DATA_LEN];
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
    tcp_header.set_window(65535);
    tcp_header.set_data_offset(15); // 4 * 15 = 60

    // Those 20 bytes correspond to window scale (10), NOP, MSS (265), Timestamp (TSval: 0xFFFFFFFF; TSecr: 0),
    tcp_header.set_options(&vec![
        TcpOption::wscale(10),
        TcpOption::nop(),
        TcpOption::mss(265),
        TcpOption::timestamp(0xFFFFFFFF, 0x0),
    ]);

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
    const UDP_DATA_LEN: usize = 300;

    // ip header
    let mut ip_buff = [0u8; IPV4_HEADER_LEN + UDP_DATA_LEN + UDP_DATA_LEN];
    let mut ip_header = MutableIpv4Packet::new(&mut ip_buff[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IPV4_HEADER_LEN + UDP_DATA_LEN + UDP_DATA_LEN) as u16);
    // The IP ID value is set to 0x1042 for operating systems which allow us to set this.
    ip_header.set_identification(0x1042);
    // ip_header.set_flags(Ipv4Flags::DontFragment); // IP DF not set
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let c = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(c);
    ip_header.set_source(src_ipv4);
    ip_header.set_destination(dst_ipv4);

    // udp header
    let mut udp_buff = [0u8; UDP_HEADER_LEN + UDP_DATA_LEN];
    let mut udp_header = MutableUdpPacket::new(&mut udp_buff[..]).unwrap();
    udp_header.set_source(src_port);
    udp_header.set_destination(dst_port);
    udp_header.set_length((UDP_HEADER_LEN + UDP_DATA_LEN) as u16);
    // The character 'C' (0x43) is repeated 300 times for the data field.
    let udp_data: Vec<u8> = vec![0x43; 300];
    udp_header.set_payload(&udp_data);
    let checksum = udp::ipv4_checksum(&udp_header.to_immutable(), &src_ipv4, &dst_ipv4);
    udp_header.set_checksum(checksum);
    ip_header.set_payload(udp_header.packet());

    Ok(ip_buff.to_vec())
}

#[cfg(test)]
mod tests {
    // use super::*;
    #[test]
    fn test_vec() {
        let udp_data: Vec<u8> = vec![0x43; 10];
        println!("{:?}", udp_data);
    }
}
