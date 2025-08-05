use pnet::datalink::MacAddr;
use pnet::packet::icmpv6;
use pnet::packet::icmpv6::Icmpv6Code;
use pnet::packet::icmpv6::Icmpv6Type;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmpv6::ndp::MutableNeighborSolicitPacket;
use pnet::packet::icmpv6::ndp::NdpOption;
use pnet::packet::icmpv6::ndp::NdpOptionTypes;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::MutableDestinationPacket;
use pnet::packet::ipv6::MutableHopByHopPacket;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::ipv6::MutableRoutingPacket;
use pnet::packet::tcp;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpOption;
use pnet::packet::udp;
use pnet::packet::udp::MutableUdpPacket;
use rand::Rng;
use std::net::Ipv6Addr;
use std::panic::Location;

use crate::error::PistolError;
use crate::layer::ICMPV6_ER_HEADER_SIZE;
use crate::layer::ICMPV6_NI_HEADER_SIZE;
use crate::layer::ICMPV6_NS_HEADER_SIZE;
use crate::layer::IPV6_HEADER_SIZE;
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

pub fn seq_packet_1_layer3(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
) -> Result<Vec<u8>, PistolError> {
    let mut rng = rand::rng();
    const TCP_OPTIONS_SIZE: usize =
        WSCALE_SIZE + NOP_SIZE + MSS_SIZE + TIMESTAMP_SIZE + SACK_PERM_SIZE;
    const TCP_DATA_SIZE: usize = 0;

    let mut ipv6_buff =
        [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    let hop_limit = rng.random_range(30..=50);
    // hop limits are set randomly
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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

    let checksum = tcp::ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);
    Ok(ipv6_buff.to_vec())
}

pub fn seq_packet_2_layer3(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
) -> Result<Vec<u8>, PistolError> {
    let mut rng = rand::rng();
    const TCP_OPTIONS_SIZE: usize = MSS_SIZE + WSCALE_SIZE + 1 + SACK_PERM_SIZE + TIMESTAMP_SIZE;
    const TCP_DATA_SIZE: usize = 0;

    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    let hop_limit = rng.random_range(30..=50);
    // hop limits are set randomly
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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

    let checksum = tcp::ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);
    Ok(ipv6_buff.to_vec())
}

pub fn seq_packet_3_layer3(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
) -> Result<Vec<u8>, PistolError> {
    let mut rng = rand::rng();
    const TCP_OPTIONS_SIZE: usize =
        TIMESTAMP_SIZE + NOP_SIZE + NOP_SIZE + WSCALE_SIZE + NOP_SIZE + MSS_SIZE;
    const TCP_DATA_SIZE: usize = 0;

    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    let hop_limit = rng.random_range(30..=50);
    // hop limits are set randomly
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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

    let checksum = tcp::ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);
    Ok(ipv6_buff.to_vec())
}

pub fn seq_packet_4_layer3(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
) -> Result<Vec<u8>, PistolError> {
    let mut rng = rand::rng();
    const TCP_OPTIONS_SIZE: usize = SACK_PERM_SIZE + 3 + TIMESTAMP_SIZE + WSCALE_SIZE + 3;
    const TCP_DATA_SIZE: usize = 0;

    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    let hop_limit = rng.random_range(30..=50);
    // hop limits are set randomly
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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

    let checksum = tcp::ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);
    Ok(ipv6_buff.to_vec())
}

pub fn seq_packet_5_layer3(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
) -> Result<Vec<u8>, PistolError> {
    let mut rng = rand::rng();
    const TCP_OPTIONS_SIZE: usize = MSS_SIZE + SACK_PERM_SIZE + TIMESTAMP_SIZE + WSCALE_SIZE + 1;
    const TCP_DATA_SIZE: usize = 0;

    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    let hop_limit = rng.random_range(30..=50);
    // hop limits are set randomly
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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

    let checksum = tcp::ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);
    Ok(ipv6_buff.to_vec())
}

pub fn seq_packet_6_layer3(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
) -> Result<Vec<u8>, PistolError> {
    let mut rng = rand::rng();
    const TCP_OPTIONS_SIZE: usize = MSS_SIZE + 1 + SACK_PERM_SIZE + 3 + TIMESTAMP_SIZE;
    const TCP_DATA_SIZE: usize = 0;

    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    let hop_limit = rng.random_range(30..=50);
    // hop limits are set randomly
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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

    let checksum = tcp::ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);
    Ok(ipv6_buff.to_vec())
}

pub fn ie_packet_1_layer3(dst_ipv6: Ipv6Addr, src_ipv6: Ipv6Addr) -> Result<Vec<u8>, PistolError> {
    let mut rng = rand::rng();
    const ICMPV6_PROBE_DATA_SIZE: usize = 120;
    const HOPBYHOP_OPTION_SIZE: usize = 8;

    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE
        + HOPBYHOP_OPTION_SIZE
        + ICMPV6_ER_HEADER_SIZE
        + ICMPV6_PROBE_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    // ipv6_header.set_flow_label(0x12345);
    ipv6_header.set_flow_label(0x12345);
    let payload_length = HOPBYHOP_OPTION_SIZE + ICMPV6_ER_HEADER_SIZE + ICMPV6_PROBE_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    // Hop-by-Hop Options
    ipv6_header.set_next_header(IpNextHeaderProtocol(0));
    let hop_limit = rng.random_range(30..=50);
    // hop limits are set randomly
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // there is one Hop-By-Hop extension header containing only padding
    let mut hop_option = match MutableHopByHopPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    hop_option.set_next_header(IpNextHeaderProtocols::Icmpv6);
    hop_option.set_hdr_ext_len(0);
    let options = [0x01, 0x04, 0x00, 0x00, 0x00, 0x00];
    hop_option.set_options(&options);

    // icmp header
    let mut icmpv6_header = match MutableEchoRequestPacket::new(
        &mut ipv6_buff[(IPV6_HEADER_SIZE + HOPBYHOP_OPTION_SIZE)..],
    ) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    // The type is 128 (Echo Request) and the code is 9, though it should be 0.
    icmpv6_header.set_icmpv6_type(Icmpv6Type(128));
    icmpv6_header.set_icmpv6_code(Icmpv6Code(9));
    // The ICMPv6 ID is 0xabcd and the sequence number is 0.
    icmpv6_header.set_identifier(0xabcd);
    icmpv6_header.set_sequence_number(0);
    // The data payload is 120 zero bytes.
    let icmp_data = [0x00; ICMPV6_PROBE_DATA_SIZE];
    icmpv6_header.set_payload(&icmp_data);

    let mut icmpv6_header =
        match MutableIcmpv6Packet::new(&mut ipv6_buff[(IPV6_HEADER_SIZE + HOPBYHOP_OPTION_SIZE)..])
        {
            Some(p) => p,
            None => {
                return Err(PistolError::BuildPacketError {
                    location: format!("{}", Location::caller()),
                });
            }
        };
    let checksum = icmpv6::checksum(&icmpv6_header.to_immutable(), &src_ipv6, &dst_ipv6);
    icmpv6_header.set_checksum(checksum);
    Ok(ipv6_buff.to_vec())
}

pub fn ie_packet_2_layer3(dst_ipv6: Ipv6Addr, src_ipv6: Ipv6Addr) -> Result<Vec<u8>, PistolError> {
    // 150 bytes of data is sent
    let mut rng = rand::rng();
    const ICMPV6_PROBE_DATA_SIZE: usize = 0;
    const HOPBYHOP_OPTION_SIZE: usize = 8;
    const DESTINATION_OPTION_SIZE: usize = 8;
    const ROUTING_OPTION_SIZE: usize = 8;

    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE
        + HOPBYHOP_OPTION_SIZE
        + DESTINATION_OPTION_SIZE
        + ROUTING_OPTION_SIZE
        + HOPBYHOP_OPTION_SIZE
        + ICMPV6_ER_HEADER_SIZE
        + ICMPV6_PROBE_DATA_SIZE];

    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    // ipv6_header.set_flow_label(0x12345);
    ipv6_header.set_flow_label(0x12345);
    let payload_length = HOPBYHOP_OPTION_SIZE
        + DESTINATION_OPTION_SIZE
        + ROUTING_OPTION_SIZE
        + HOPBYHOP_OPTION_SIZE
        + ICMPV6_ER_HEADER_SIZE
        + ICMPV6_PROBE_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    // Hop-by-Hop Options
    ipv6_header.set_next_header(IpNextHeaderProtocol(0));
    let hop_limit = rng.random_range(30..=50);
    // hop limits are set randomly
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // What makes this probe interesting are the erroneous extension headers it includes.
    // There are four of them in all, in this order:
    // 1) Hop-By-Hop
    // 2) Destination Options
    // 3) Routing
    // 4) Hop-By-Hop

    // Hop-By-Hop
    let mut hop_option = match MutableHopByHopPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    // Destination Options (before upper-layer header)
    hop_option.set_next_header(IpNextHeaderProtocol(60));
    hop_option.set_hdr_ext_len(0);
    let padn = [0x01, 0x04, 0x00, 0x00, 0x00, 0x00];
    hop_option.set_options(&padn);

    // Destination Options
    let mut dest_option = match MutableDestinationPacket::new(
        &mut ipv6_buff[(IPV6_HEADER_SIZE + HOPBYHOP_OPTION_SIZE)..],
    ) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    // Routing
    dest_option.set_next_header(IpNextHeaderProtocol(43));
    dest_option.set_hdr_ext_len(0);
    dest_option.set_options(&padn);

    // Routing
    let mut routing_option = match MutableRoutingPacket::new(
        &mut ipv6_buff[(IPV6_HEADER_SIZE + HOPBYHOP_OPTION_SIZE + DESTINATION_OPTION_SIZE)..],
    ) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    // Hop-by-Hop Options
    routing_option.set_next_header(IpNextHeaderProtocol(0));
    routing_option.set_hdr_ext_len(0);
    routing_option.set_routing_type(0x00);
    routing_option.set_segments_left(0x00);

    // Hop-By-Hop
    let mut hop_option = match MutableHopByHopPacket::new(
        &mut ipv6_buff[(IPV6_HEADER_SIZE
            + HOPBYHOP_OPTION_SIZE
            + DESTINATION_OPTION_SIZE
            + ROUTING_OPTION_SIZE)..],
    ) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    // Destination Options (before upper-layer header)
    hop_option.set_next_header(IpNextHeaderProtocols::Icmpv6);
    hop_option.set_hdr_ext_len(0);
    hop_option.set_options(&padn);

    // ICMPV6
    let mut icmpv6_header = match MutableEchoRequestPacket::new(
        &mut ipv6_buff[(IPV6_HEADER_SIZE
            + HOPBYHOP_OPTION_SIZE
            + DESTINATION_OPTION_SIZE
            + ROUTING_OPTION_SIZE
            + HOPBYHOP_OPTION_SIZE)..],
    ) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    // This is an echo request with a type of 128 (Echo Request) and a code of 0.
    icmpv6_header.set_icmpv6_type(Icmpv6Type(128));
    icmpv6_header.set_icmpv6_code(Icmpv6Code(0));
    // The ICMPv6 ID is 0xabcd and the sequence is 1.
    icmpv6_header.set_identifier(0xabcd);
    icmpv6_header.set_sequence_number(1);

    let mut icmpv6_header = match MutableIcmpv6Packet::new(
        &mut ipv6_buff[(IPV6_HEADER_SIZE
            + HOPBYHOP_OPTION_SIZE
            + DESTINATION_OPTION_SIZE
            + ROUTING_OPTION_SIZE
            + HOPBYHOP_OPTION_SIZE)..],
    ) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    let checksum = icmpv6::checksum(&icmpv6_header.to_immutable(), &src_ipv6, &dst_ipv6);
    icmpv6_header.set_checksum(checksum);
    Ok(ipv6_buff.to_vec())
}

pub fn ni_packet_layer3(dst_ipv6: Ipv6Addr, src_ipv6: Ipv6Addr) -> Result<Vec<u8>, PistolError> {
    let mut rng = rand::rng();
    const ICMPV6_DATA_SIZE: usize = 0;
    // ipv6 header
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + ICMPV6_NI_HEADER_SIZE + ICMPV6_DATA_SIZE];

    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    // ipv6_header.set_flow_label(0x12345);
    ipv6_header.set_flow_label(0x12345);
    let payload_length = ICMPV6_NI_HEADER_SIZE + ICMPV6_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Icmpv6);
    let hop_limit = rng.random_range(30..=50);
    // hop limits are set randomly
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);
    // Echo or Echo Reply Message
    /* https://datatracker.ietf.org/doc/html/rfc792

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Identifier          |        Sequence Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Data ...
    +-+-+-+-+-
     */

    // Node Information Messages
    /* https://datatracker.ietf.org/doc/rfc4620
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |           Checksum            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |             Qtype             |             Flags             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                             Nonce                             +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    /                             Data                              /
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    // icmp header
    let mut icmpv6_header = match MutableEchoRequestPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..])
    {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    // The NI probe has type 139 (ICMP Node Information Query) and code 0 (indicating that the subject is an IPv6 address).
    icmpv6_header.set_icmpv6_type(Icmpv6Type(139));
    icmpv6_header.set_icmpv6_code(Icmpv6Code(0));
    // The qtype is 4 (IPv4 Addresses).
    // identifier value in echo request packet is same place as in node information message
    icmpv6_header.set_identifier(4);

    /*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Qtype=3            |       unused      |G|S|L|C|A|T|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      */

    // The A flag (return all unicast addresses) flag is set, and no others.
    icmpv6_header.set_sequence_number(0b0010);
    // The nonce is set to the fixed string "\x01\x02\x03\x04\x05\x06\x07\x0a".
    icmpv6_header.set_payload(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0a]);

    let mut icmp_header = match MutableIcmpv6Packet::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    let checksum = icmpv6::checksum(&icmp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    icmp_header.set_checksum(checksum);
    Ok(ipv6_buff.to_vec())
}

pub fn ns_packet_layer3(
    dst_ipv6: Ipv6Addr,
    src_ipv6: Ipv6Addr,
    src_mac: MacAddr,
) -> Result<Vec<u8>, PistolError> {
    // This probe is only sent to hosts on the same subnet.
    const ICMPV6_DATA_SIZE: usize = 0;

    // ipv6
    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + ICMPV6_NS_HEADER_SIZE + ICMPV6_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    ipv6_header.set_traffic_class(0);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    // ipv6_header.set_flow_label(0x12345);
    ipv6_header.set_flow_label(0x12345);
    ipv6_header.set_payload_length((ICMPV6_NS_HEADER_SIZE + ICMPV6_DATA_SIZE) as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Icmpv6);
    // The hop limit is always set to 255.
    ipv6_header.set_hop_limit(255);
    ipv6_header.set_source(src_ipv6);
    // let dst_multicast = Ipv6::new(dst_ipv6).link_multicast();
    ipv6_header.set_destination(dst_ipv6);

    // icmpv6
    let mut icmpv6_header =
        match MutableNeighborSolicitPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
            Some(p) => p,
            None => {
                return Err(PistolError::BuildPacketError {
                    location: format!("{}", Location::caller()),
                });
            }
        };
    // Neighbor Solicitation
    icmpv6_header.set_icmpv6_type(Icmpv6Type(135));
    icmpv6_header.set_icmpv6_code(Icmpv6Code(0));
    icmpv6_header.set_reserved(0);
    icmpv6_header.set_target_addr(dst_ipv6);
    let ndp_option = NdpOption {
        option_type: NdpOptionTypes::SourceLLAddr,
        length: 1,
        data: src_mac.octets().to_vec(),
    };
    icmpv6_header.set_options(&vec![ndp_option]);

    let mut icmpv6_header = match MutableIcmpv6Packet::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    let checksum = icmpv6::checksum(&icmpv6_header.to_immutable(), &src_ipv6, &dst_ipv6);
    icmpv6_header.set_checksum(checksum);
    Ok(ipv6_buff.to_vec())
}

pub fn udp_packet_layer3(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
) -> Result<Vec<u8>, PistolError> {
    let mut rng = rand::rng();
    const UDP_DATA_SIZE: usize = 300;

    let mut ipv6_buff = [0u8; IPV6_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = UDP_HEADER_SIZE + UDP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Udp);
    let hop_limit = rng.random_range(30..=50);
    // hop limits are set randomly
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // udp header
    let mut udp_header = match MutableUdpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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
    let udp_data: Vec<u8> = vec![0x43; UDP_DATA_SIZE];
    assert_eq!(udp_data.len(), UDP_DATA_SIZE);
    udp_header.set_payload(&udp_data);
    let checksum = udp::ipv6_checksum(&udp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    udp_header.set_checksum(checksum);
    Ok(ipv6_buff.to_vec())
}

pub fn tecn_packet_layer3(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
) -> Result<Vec<u8>, PistolError> {
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

    let mut ipv6_buff =
        [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    let hop_limit = rng.random_range(30..=50);
    // hop limits are set randomly
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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
    tcp_header.set_data_offset(10); // 5 (header: 5 * 4 = 20) + 5 (options: 5 * 4 = 20)

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

    let checksum = tcp::ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);
    Ok(ipv6_buff.to_vec())
}

pub fn t2_packet_layer3(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
) -> Result<Vec<u8>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize =
        WSCALE_SIZE + NOP_SIZE + MSS_SIZE + TIMESTAMP_SIZE + SACK_PERM_SIZE;

    let mut ipv6_buff =
        [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    let hop_limit = rng.random_range(30..=50);
    // hop limits are set randomly
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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

    let checksum = tcp::ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);
    Ok(ipv6_buff.to_vec())
}

pub fn t3_packet_layer3(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
) -> Result<Vec<u8>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize =
        WSCALE_SIZE + NOP_SIZE + MSS_SIZE + TIMESTAMP_SIZE + SACK_PERM_SIZE;

    let mut ipv6_buff =
        [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    let hop_limit = rng.random_range(30..=50);
    // hop limits are set randomly
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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

    let checksum = tcp::ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);
    Ok(ipv6_buff.to_vec())
}

pub fn t4_packet_layer3(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
) -> Result<Vec<u8>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize =
        WSCALE_SIZE + NOP_SIZE + MSS_SIZE + TIMESTAMP_SIZE + SACK_PERM_SIZE;

    let mut ipv6_buff =
        [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    let hop_limit = rng.random_range(30..=50);
    // hop limits are set randomly
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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

    let checksum = tcp::ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);
    Ok(ipv6_buff.to_vec())
}

pub fn t5_packet_layer3(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
) -> Result<Vec<u8>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize =
        WSCALE_SIZE + NOP_SIZE + MSS_SIZE + TIMESTAMP_SIZE + SACK_PERM_SIZE;

    let mut ipv6_buff =
        [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    let hop_limit = rng.random_range(30..=50);
    // hop limits are set randomly
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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

    let checksum = tcp::ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);
    Ok(ipv6_buff.to_vec())
}

pub fn t6_packet_layer3(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
) -> Result<Vec<u8>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize =
        WSCALE_SIZE + NOP_SIZE + MSS_SIZE + TIMESTAMP_SIZE + SACK_PERM_SIZE;

    let mut ipv6_buff =
        [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    let hop_limit = rng.random_range(30..=50);
    // hop limits are set randomly
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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

    let checksum = tcp::ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);
    Ok(ipv6_buff.to_vec())
}

pub fn t7_packet_layer3(
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    src_ipv6: Ipv6Addr,
    src_port: u16,
) -> Result<Vec<u8>, PistolError> {
    let mut rng = rand::rng();
    const TCP_DATA_SIZE: usize = 0;
    const TCP_OPTIONS_SIZE: usize =
        WSCALE_SIZE + NOP_SIZE + MSS_SIZE + TIMESTAMP_SIZE + SACK_PERM_SIZE;

    let mut ipv6_buff =
        [0u8; IPV6_HEADER_SIZE + TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE];
    let mut ipv6_header = match MutableIpv6Packet::new(&mut ipv6_buff) {
        Some(p) => p,
        None => {
            return Err(PistolError::BuildPacketError {
                location: format!("{}", Location::caller()),
            });
        }
    };
    ipv6_header.set_version(6);
    // In all cases, the IPv6 flow label is 0x12345, on platforms that allow us to set it.
    // On platforms that do not (which includes non-Linux Unix platforms when not using Ethernet to send), the flow label will be 0.
    ipv6_header.set_flow_label(0x12345);
    let payload_length = TCP_HEADER_SIZE + TCP_OPTIONS_SIZE + TCP_DATA_SIZE;
    ipv6_header.set_payload_length(payload_length as u16);
    ipv6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    let hop_limit = rng.random_range(30..=50);
    // hop limits are set randomly
    ipv6_header.set_hop_limit(hop_limit);
    ipv6_header.set_source(src_ipv6);
    ipv6_header.set_destination(dst_ipv6);

    // tcp header
    let mut tcp_header = match MutableTcpPacket::new(&mut ipv6_buff[IPV6_HEADER_SIZE..]) {
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

    let checksum = tcp::ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);
    Ok(ipv6_buff.to_vec())
}
