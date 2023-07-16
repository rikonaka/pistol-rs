use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{tcp_packet_iter, transport_channel};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use subnetwork::Ipv4Pool;

fn send_tcp_syn_scan_packet() {
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));

    // Create a new transport channel, dealing with layer 4 packets on a test protocol
    // It has a receive buffer of 4096 bytes.
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    // We treat received packets as if they were UDP packets
    let mut iter = tcp_packet_iter(&mut rx);
    let mut buff: Vec<u8> = vec![0; 20];
    let mut tcp_syn_packet = MutableTcpPacket::new(&mut buff).unwrap();
    tcp_syn_packet.set_flags(TcpFlags::SYN);

    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                // Allocate enough space for a new packet
                let mut vec: Vec<u8> = vec![0; packet.packet().len()];
                let mut new_packet = MutableTcpPacket::new(&mut vec[..]).unwrap();

                // Create a clone of the original packet
                new_packet.clone_from(&packet);

                // Switch the source and destination ports
                new_packet.set_source(packet.get_destination());
                new_packet.set_destination(packet.get_source());

                // Send the packet
                match tx.send_to(new_packet, addr) {
                    Ok(n) => assert_eq!(n, packet.packet().len()),
                    Err(e) => panic!("failed to send packet: {}", e),
                }
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
