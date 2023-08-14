use anyhow::Result;
use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Types};
use pnet::packet::tcp::{ipv6_checksum, MutableTcpPacket, TcpFlags};
use pnet::transport::{icmpv6_packet_iter, tcp_packet_iter};
use rand::Rng;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV6;
use std::net::TcpStream;
use std::time::Duration;

use crate::utils::return_layer4_icmp6_channel;
use crate::utils::return_layer4_tcp6_channel;
use crate::utils::ICMP_BUFF_SIZE;
use crate::utils::TCP_BUFF_SIZE;
use crate::utils::TCP_DATA_LEN;
use crate::utils::TCP_HEADER_LEN;
use crate::TcpScanStatus;

// const TCP_FLAGS_CWR_MASK: u8 = 0b10000000;
// const TCP_FLAGS_ECE_MASK: u8 = 0b01000000;
// const TCP_FLAGS_URG_MASK: u8 = 0b00100000;
// const TCP_FLAGS_ACK_MASK: u8 = 0b00010000;
// const TCP_FLAGS_PSH_MASK: u8 = 0b00001000;
const TCP_FLAGS_RST_MASK: u8 = 0b00000100;
// const TCP_FLAGS_SYN_MASK: u8 = 0b00000010;
// const TCP_FLAGS_FIN_MASK: u8 = 0b00000001;

pub fn send_syn_scan_packet(
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<TcpScanStatus> {
    let (mut tcp_tx, mut tcp_rx) = return_layer4_tcp6_channel(TCP_BUFF_SIZE)?;
    let (_, mut icmp_rx) = return_layer4_icmp6_channel(ICMP_BUFF_SIZE)?;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    match tcp_tx.send_to(tcp_header, dst_ipv6.into()) {
        Ok(n) => assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut tcp_iter = tcp_packet_iter(&mut tcp_rx);
    let mut icmp_iter = icmpv6_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((tcp_packet, addr)) => {
                    if addr == dst_ipv6 {
                        if tcp_packet.get_source() == dst_port
                            && tcp_packet.get_destination() == src_port
                        {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                                // tcp syn/ack response
                                return Ok(TcpScanStatus::Open);
                            } else if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok(TcpScanStatus::Closed);
                            }
                        }
                    }
                }
                _ => (), // do nothing
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((icmp_packet, addr)) => {
                    if addr == dst_ipv6 {
                        let icmp_type = icmp_packet.get_icmpv6_type();
                        let icmp_code = icmp_packet.get_icmpv6_code();
                        let codes = vec![
                            Icmpv6Code(1), // communication with destination administratively prohibited
                            Icmpv6Code(3), // address unreachable
                            Icmpv6Code(4), // port unreachable
                        ];
                        if icmp_type == Icmpv6Types::DestinationUnreachable
                            && codes.contains(&icmp_code)
                        {
                            // icmp unreachable error (type 3, code 1, 3, or 4)
                            return Ok(TcpScanStatus::Filtered);
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }
    // no response received (even after retransmissions)
    Ok(TcpScanStatus::Filtered)
}

pub fn send_fin_scan_packet(
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<TcpScanStatus> {
    let (mut tcp_tx, mut tcp_rx) = return_layer4_tcp6_channel(TCP_BUFF_SIZE)?;
    let (_, mut icmp_rx) = return_layer4_icmp6_channel(ICMP_BUFF_SIZE)?;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::FIN);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    match tcp_tx.send_to(tcp_header, dst_ipv6.into()) {
        Ok(n) => assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut tcp_iter = tcp_packet_iter(&mut tcp_rx);
    let mut icmp_iter = icmpv6_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((tcp_packet, addr)) => {
                    if addr == dst_ipv6 {
                        if tcp_packet.get_source() == dst_port
                            && tcp_packet.get_destination() == src_port
                        {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                                // tcp syn/ack response
                                return Ok(TcpScanStatus::Open);
                            } else if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst packet
                                return Ok(TcpScanStatus::Closed);
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((icmp_packet, addr)) => {
                    if addr == dst_ipv6 {
                        let icmp_type = icmp_packet.get_icmpv6_type();
                        let icmp_code = icmp_packet.get_icmpv6_code();
                        let codes = vec![
                            Icmpv6Code(1), // communication with destination administratively prohibited
                            Icmpv6Code(3), // address unreachable
                            Icmpv6Code(4), // port unreachable
                        ];
                        if icmp_type == Icmpv6Types::DestinationUnreachable
                            && codes.contains(&icmp_code)
                        {
                            // icmp unreachable error (type 3, code 1, 3, or 4)
                            return Ok(TcpScanStatus::Filtered);
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }
    // no response received (even after retransmissions)
    Ok(TcpScanStatus::OpenOrFiltered)
}

pub fn send_ack_scan_packet(
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<TcpScanStatus> {
    let (mut tcp_tx, mut tcp_rx) = return_layer4_tcp6_channel(TCP_BUFF_SIZE)?;
    let (_, mut icmp_rx) = return_layer4_icmp6_channel(ICMP_BUFF_SIZE)?;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    match tcp_tx.send_to(tcp_header, dst_ipv6.into()) {
        Ok(n) => assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut tcp_iter = tcp_packet_iter(&mut tcp_rx);
    let mut icmp_iter = icmpv6_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((tcp_packet, addr)) => {
                    if addr == dst_ipv6 {
                        if tcp_packet.get_destination() == src_port
                            && tcp_packet.get_source() == dst_port
                        {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                // tcp rst response
                                return Ok(TcpScanStatus::Unfiltered);
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((icmp_packet, addr)) => {
                    if addr == dst_ipv6 {
                        let icmp_type = icmp_packet.get_icmpv6_type();
                        let icmp_code = icmp_packet.get_icmpv6_code();
                        let codes = vec![
                            Icmpv6Code(1), // communication with destination administratively prohibited
                            Icmpv6Code(3), // address unreachable
                            Icmpv6Code(4), // port unreachable
                        ];
                        if icmp_type == Icmpv6Types::DestinationUnreachable
                            && codes.contains(&icmp_code)
                        {
                            // icmp unreachable error (type 3, code 1, 3, or 4)
                            return Ok(TcpScanStatus::Filtered);
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }
    // no response received (even after retransmissions)
    Ok(TcpScanStatus::Filtered)
}

pub fn send_null_scan_packet(
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<TcpScanStatus> {
    let (mut tcp_tx, mut tcp_rx) = return_layer4_tcp6_channel(TCP_BUFF_SIZE)?;
    let (_, mut icmp_rx) = return_layer4_icmp6_channel(ICMP_BUFF_SIZE)?;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(0);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    match tcp_tx.send_to(tcp_header, dst_ipv6.into()) {
        Ok(n) => assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut tcp_iter = tcp_packet_iter(&mut tcp_rx);
    let mut icmp_iter = icmpv6_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((tcp_packet, addr)) => {
                    if addr == dst_ipv6 {
                        if tcp_packet.get_destination() == src_port
                            && tcp_packet.get_source() == dst_port
                        {
                            if tcp_packet.get_source() == dst_port
                                && tcp_packet.get_destination() == src_port
                            {
                                let tcp_flags = tcp_packet.get_flags();
                                if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                    // tcp rst response
                                    return Ok(TcpScanStatus::Closed);
                                }
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((icmp_packet, addr)) => {
                    if addr == dst_ipv6 {
                        let icmp_type = icmp_packet.get_icmpv6_type();
                        let icmp_code = icmp_packet.get_icmpv6_code();
                        let codes = vec![
                            Icmpv6Code(1), // communication with destination administratively prohibited
                            Icmpv6Code(3), // address unreachable
                            Icmpv6Code(4), // port unreachable
                        ];
                        if icmp_type == Icmpv6Types::DestinationUnreachable
                            && codes.contains(&icmp_code)
                        {
                            // icmp unreachable error (type 3, code 1, 3, or 4)
                            return Ok(TcpScanStatus::Filtered);
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }
    // no response received (even after retransmissions)
    Ok(TcpScanStatus::OpenOrFiltered)
}

pub fn send_xmas_scan_packet(
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<TcpScanStatus> {
    let (mut tcp_tx, mut tcp_rx) = return_layer4_tcp6_channel(TCP_BUFF_SIZE)?;
    let (_, mut icmp_rx) = return_layer4_icmp6_channel(ICMP_BUFF_SIZE)?;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    match tcp_tx.send_to(tcp_header, dst_ipv6.into()) {
        Ok(n) => assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut tcp_iter = tcp_packet_iter(&mut tcp_rx);
    let mut icmp_iter = icmpv6_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((tcp_packet, addr)) => {
                    if addr == dst_ipv6 {
                        if tcp_packet.get_destination() == src_port
                            && tcp_packet.get_source() == dst_port
                        {
                            if tcp_packet.get_source() == dst_port
                                && tcp_packet.get_destination() == src_port
                            {
                                let tcp_flags = tcp_packet.get_flags();
                                if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                    // tcp rst response
                                    return Ok(TcpScanStatus::Closed);
                                }
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((icmp_packet, addr)) => {
                    if addr == dst_ipv6 {
                        let icmp_type = icmp_packet.get_icmpv6_type();
                        let icmp_code = icmp_packet.get_icmpv6_code();
                        let codes = vec![
                            Icmpv6Code(1), // communication with destination administratively prohibited
                            Icmpv6Code(3), // address unreachable
                            Icmpv6Code(4), // port unreachable
                        ];
                        if icmp_type == Icmpv6Types::DestinationUnreachable
                            && codes.contains(&icmp_code)
                        {
                            // icmp unreachable error (type 3, code 1, 3, or 4)
                            return Ok(TcpScanStatus::Filtered);
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }
    // no response received (even after retransmissions)
    Ok(TcpScanStatus::OpenOrFiltered)
}

pub fn send_window_scan_packet(
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<TcpScanStatus> {
    let (mut tcp_tx, mut tcp_rx) = return_layer4_tcp6_channel(TCP_BUFF_SIZE)?;
    let (_, mut icmp_rx) = return_layer4_icmp6_channel(ICMP_BUFF_SIZE)?;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    match tcp_tx.send_to(tcp_header, dst_ipv6.into()) {
        Ok(n) => assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut tcp_iter = tcp_packet_iter(&mut tcp_rx);
    let mut icmp_iter = icmpv6_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((tcp_packet, addr)) => {
                    if addr == dst_ipv6 {
                        if tcp_packet.get_destination() == src_port
                            && tcp_packet.get_source() == dst_port
                        {
                            let tcp_flags = tcp_packet.get_flags();
                            if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                if tcp_packet.get_window() > 0 {
                                    // tcp rst response with non-zero window field
                                    return Ok(TcpScanStatus::Open);
                                } else {
                                    // tcp rst response with zero window field
                                    return Ok(TcpScanStatus::Closed);
                                }
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((icmp_packet, addr)) => {
                    if addr == dst_ipv6 {
                        let icmp_type = icmp_packet.get_icmpv6_type();
                        let icmp_code = icmp_packet.get_icmpv6_code();
                        let codes = vec![
                            Icmpv6Code(1), // communication with destination administratively prohibited
                            Icmpv6Code(3), // address unreachable
                            Icmpv6Code(4), // port unreachable
                        ];
                        if icmp_type == Icmpv6Types::DestinationUnreachable
                            && codes.contains(&icmp_code)
                        {
                            // icmp unreachable error (type 3, code 1, 3, or 4)
                            return Ok(TcpScanStatus::Filtered);
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }
    // no response received (even after retransmissions)
    Ok(TcpScanStatus::Filtered)
}

pub fn send_maimon_scan_packet(
    src_ipv6: Ipv6Addr,
    src_port: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    timeout: Duration,
    max_loop: usize,
) -> Result<TcpScanStatus> {
    let (mut tcp_tx, mut tcp_rx) = return_layer4_tcp6_channel(TCP_BUFF_SIZE)?;
    let (_, mut icmp_rx) = return_layer4_icmp6_channel(ICMP_BUFF_SIZE)?;

    // tcp header
    let mut rng = rand::thread_rng();
    let mut tcp_buff = [0u8; TCP_HEADER_LEN + TCP_DATA_LEN];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buff[..]).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rng.gen());
    tcp_header.set_acknowledgement(rng.gen());
    tcp_header.set_reserved(0);
    tcp_header.set_flags(TcpFlags::FIN | TcpFlags::ACK);
    tcp_header.set_urgent_ptr(0);
    tcp_header.set_window(1024);
    tcp_header.set_data_offset(5);
    let checksum = ipv6_checksum(&tcp_header.to_immutable(), &src_ipv6, &dst_ipv6);
    tcp_header.set_checksum(checksum);

    match tcp_tx.send_to(tcp_header, dst_ipv6.into()) {
        Ok(n) => assert_eq!(n, TCP_HEADER_LEN + TCP_DATA_LEN),
        Err(e) => return Err(e.into()),
    }

    let mut tcp_iter = tcp_packet_iter(&mut tcp_rx);
    let mut icmp_iter = icmpv6_packet_iter(&mut icmp_rx);
    for _ in 0..max_loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((tcp_packet, addr)) => {
                    if addr == dst_ipv6 {
                        if tcp_packet.get_destination() == src_port
                            && tcp_packet.get_source() == dst_port
                        {
                            if tcp_packet.get_source() == dst_port
                                && tcp_packet.get_destination() == src_port
                            {
                                let tcp_flags = tcp_packet.get_flags();
                                if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                                    // tcp rst response
                                    return Ok(TcpScanStatus::Closed);
                                }
                            }
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
        match icmp_iter.next_with_timeout(timeout) {
            Ok(r) => match r {
                Some((icmp_packet, addr)) => {
                    if addr == dst_ipv6 {
                        let icmp_type = icmp_packet.get_icmpv6_type();
                        let icmp_code = icmp_packet.get_icmpv6_code();
                        let codes = vec![
                            Icmpv6Code(1), // communication with destination administratively prohibited
                            Icmpv6Code(3), // address unreachable
                            Icmpv6Code(4), // port unreachable
                        ];
                        if icmp_type == Icmpv6Types::DestinationUnreachable
                            && codes.contains(&icmp_code)
                        {
                            // icmp unreachable error (type 3, code 1, 3, or 4)
                            return Ok(TcpScanStatus::Filtered);
                        }
                    }
                }
                _ => (),
            },
            Err(e) => return Err(e.into()),
        }
    }
    // no response received (even after retransmissions)
    Ok(TcpScanStatus::OpenOrFiltered)
}

pub fn send_connect_scan_packet(
    _: Ipv6Addr,
    _: u16,
    dst_ipv6: Ipv6Addr,
    dst_port: u16,
    timeout: Duration,
    _: usize,
) -> Result<TcpScanStatus> {
    let addr = SocketAddr::V6(SocketAddrV6::new(dst_ipv6, dst_port, 0, 0));
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => Ok(TcpScanStatus::Open),
        Err(_) => Ok(TcpScanStatus::Closed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_send_syn_scan_packet_new() {
        // 240e:34c:8b:25b0:17c1:ac6c:9baa:ade
        let src_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x17c1, 0xac6c, 0x9baa, 0xade);
        // 240e:34c:8b:25b0:20c:29ff:fe0c:237e
        let dst_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x20c, 0x29ff, 0xfe0c, 0x237e);
        let src_port = 32109;
        let dst_port = 80;
        let timeout = Duration::from_secs(1);
        let max_loop = 4;
        let ret = send_syn_scan_packet(src_ipv6, src_port, dst_ipv6, dst_port, timeout, max_loop)
            .unwrap();
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_fin_scan_packet() {
        // 240e:34c:8b:25b0:17c1:ac6c:9baa:ade
        let src_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x17c1, 0xac6c, 0x9baa, 0xade);
        // 240e:34c:8b:25b0:20c:29ff:fe0c:237e
        let dst_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x20c, 0x29ff, 0xfe0c, 0x237e);
        let timeout = Duration::from_secs(1);
        let max_loop = 8;
        let ret = send_fin_scan_packet(src_ipv6, 53511, dst_ipv6, 80, timeout, max_loop);
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_ack_scan_packet() {
        // 240e:34c:8b:25b0:17c1:ac6c:9baa:ade
        let src_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x17c1, 0xac6c, 0x9baa, 0xade);
        // 240e:34c:8b:25b0:20c:29ff:fe0c:237e
        let dst_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x20c, 0x29ff, 0xfe0c, 0x237e);
        let timeout = Duration::from_secs(1);
        let max_loop = 8;
        let ret = send_ack_scan_packet(src_ipv6, 53511, dst_ipv6, 80, timeout, max_loop);
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_null_scan_packet() {
        // 240e:34c:8b:25b0:17c1:ac6c:9baa:ade
        let src_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x17c1, 0xac6c, 0x9baa, 0xade);
        // 240e:34c:8b:25b0:20c:29ff:fe0c:237e
        let dst_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x20c, 0x29ff, 0xfe0c, 0x237e);
        let timeout = Duration::from_secs(1);
        let max_loop = 8;
        let ret = send_null_scan_packet(src_ipv6, 53511, dst_ipv6, 80, timeout, max_loop);
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_window_scan_packet() {
        // 240e:34c:8b:25b0:17c1:ac6c:9baa:ade
        let src_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x17c1, 0xac6c, 0x9baa, 0xade);
        // 240e:34c:8b:25b0:20c:29ff:fe0c:237e
        let dst_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x20c, 0x29ff, 0xfe0c, 0x237e);
        let timeout = Duration::from_secs(1);
        let max_loop = 8;
        let ret = send_window_scan_packet(src_ipv6, 53511, dst_ipv6, 80, timeout, max_loop);
        println!("{:?}", ret);
    }
    #[test]
    fn test_send_tcp_handshark() {
        // 240e:34c:8b:25b0:17c1:ac6c:9baa:ade
        let src_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x17c1, 0xac6c, 0x9baa, 0xade);
        // 240e:34c:8b:25b0:20c:29ff:fe0c:237e
        let dst_ipv6 = Ipv6Addr::new(0x240e, 0x34c, 0x8b, 0x25b0, 0x20c, 0x29ff, 0xfe0c, 0x237e);
        let timeout = Duration::from_secs(10);
        let max_loop = 64;
        let src_port = 56781;
        let ret =
            send_connect_scan_packet(src_ipv6, src_port, dst_ipv6, 81, timeout, max_loop).unwrap();
        println!("{:?}", ret);
    }
}
