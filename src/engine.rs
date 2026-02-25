use pcapture::Capture;
use pnet::datalink::Channel;
use pnet::datalink::ChannelType;
use pnet::datalink::Config;
use pnet::datalink::MacAddr;
use pnet::datalink::channel;
use pnet::packet::ethernet::EtherType;
use pnet::packet::ethernet::MutableEthernetPacket;
use std::collections::HashMap;
use std::net::IpAddr;
use std::panic::Location;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use tracing::debug;
use tracing::error;

use crate::ETHERNET_BUFF_SIZE;
use crate::ETHERNET_HEADER_SIZE;
use crate::error::PistolError;
use crate::find_interface_by_name;
use crate::layer::PacketFilter;

const MAX_HISTORY_PACKETS: usize = 10_000;

#[derive(Debug, Clone)]
pub(crate) struct EngineMsg {
    /* PART 1 */
    pub(crate) iface: String,  // the interface to send and receive
    pub(crate) target: IpAddr, // the target ip address
    pub(crate) port: u16,      // the target port
    /* PART 2 */
    pub(crate) dst_mac: MacAddr,            // destination mac address
    pub(crate) src_mac: MacAddr,            // source mac address
    pub(crate) ethernet_payload: Arc<[u8]>, // the layer3 packet to send
    pub(crate) ethernet_type: EtherType,    // the layer3 protocol type, e.g., IPv4, IPv6, ARP
    pub(crate) retransmit: usize,           // retransmit the packet (only used in flooding attack)
    pub(crate) filters: Vec<PacketFilter>,  // runner receive filters to match
    /* PART 3 */
    pub(crate) response: Arc<[u8]>, // the expected response packet
}

impl EngineMsg {
    fn check_packet(&self, received_packet: &[u8]) -> (bool, Option<PacketFilter>) {
        for filter in &self.filters {
            if filter.check(received_packet) {
                debug!("layer2 recv matched filter: {}", filter.name());
                return (true, Some(filter.clone()));
            }
        }
        (false, None)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum EngineStatus {
    None,
    Sended(EngineMsg),
    WaitingResponse,
    Received(EngineMsg),
    Timeout,
    Retransmission,
    Finished,
}

pub(crate) struct PistolEngine {
    pub(crate) status: HashMap<IpAddr, HashMap<u16, EngineStatus>>,
}

impl PistolEngine {
    pub(crate) fn get_status(&mut self, addr: IpAddr, port: u16) -> EngineStatus {
        match self.status.get_mut(&addr) {
            Some(port_map) => match port_map.get_mut(&port) {
                Some(status) => status.clone(),
                None => {
                    port_map.insert(port, EngineStatus::None);
                    EngineStatus::None
                }
            },
            None => {
                let mut port_map = HashMap::new();
                port_map.insert(port, EngineStatus::None);
                self.status.insert(addr, port_map);
                EngineStatus::None
            }
        }
    }
    fn send_loop(&mut self, iface: String, timeout: Duration) -> Result<(), PistolError> {
        debug!("start sender for iface: {}", iface);
        let config = Config {
            write_buffer_size: ETHERNET_BUFF_SIZE,
            read_buffer_size: ETHERNET_BUFF_SIZE,
            read_timeout: Some(timeout),
            write_timeout: Some(timeout),
            channel_type: ChannelType::Layer2,
            bpf_fd_attempts: 1000,
            linux_fanout: None,
            promiscuous: false,
            socket_fd: None,
        };

        let interface = match find_interface_by_name(&iface) {
            Some(i) => i,
            None => return Err(PistolError::CanNotFoundInterface { i: iface }),
        };

        let (mut sender, _) = match channel(&interface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(PistolError::CreateDatalinkChannelFailed),
            Err(e) => return Err(e.into()),
        };
        loop {
            let status = self.status.clone();
            for (addr, hm) in &status {
                for (port, engine_status) in hm {
                    match engine_status {
                        EngineStatus::Sended(msg) => {
                            let payload = &msg.ethernet_payload;
                            let dst_mac = msg.dst_mac;
                            let src_mac = msg.src_mac;
                            let ether_type = msg.ethernet_type;
                            let retransmit = msg.retransmit;

                            let payload_len = payload.len();
                            let ethernet_buff_len = ETHERNET_HEADER_SIZE + payload_len;
                            let mut buff = vec![0u8; ethernet_buff_len];
                            let mut ethernet_packet = match MutableEthernetPacket::new(&mut buff) {
                                Some(p) => p,
                                None => {
                                    return Err(PistolError::BuildPacketError {
                                        location: format!("{}", Location::caller()),
                                    });
                                }
                            };
                            ethernet_packet.set_destination(dst_mac);
                            ethernet_packet.set_source(src_mac);
                            ethernet_packet.set_ethertype(ether_type);
                            ethernet_packet.set_payload(&payload);

                            let m = format!(
                                "dm: {}, sm: {}, et: {}, l: {}",
                                dst_mac,
                                src_mac,
                                ether_type.to_string().to_lowercase(),
                                payload.len()
                            );
                            if retransmit == 0 {
                                // send packet once
                                if let Some(r) = sender.send_to(&buff, None) {
                                    match r {
                                        Ok(_) => debug!("send packet success, {}", m),
                                        Err(e) => error!("send packet error, {} - {}", m, e),
                                    }
                                }
                                self.set_waiting_response(*addr, *port);
                            } else {
                                // send packet multiple times to flood the network,
                                // which can increase the chance of receiving packets back,
                                // but also can cause network congestion, so we need to control the retransmit times.
                                for i in 0..retransmit {
                                    if let Some(r) = sender.send_to(&buff, None) {
                                        match r {
                                            Ok(_) => {
                                                debug!("send flood {} packet success, {}", i, m)
                                            }
                                            Err(e) => {
                                                error!(
                                                    "send flood {} packet error, {} - {}",
                                                    i, m, e
                                                )
                                            }
                                        }
                                    }
                                }
                                self.set_finished(*addr, *port);
                            }
                        }
                        _ => continue,
                    }
                }
            }
        }
    }
    fn recv_all(
        &self,
        iface: String,
        msgs: &[EngineMsg],
        timeout: Duration,
    ) -> Result<Vec<EngineMsg>, PistolError> {
        let mut cap = Capture::new(&iface)?;
        cap.set_timeout(50);
        cap.set_promiscuous_mode(true);
        // cap.set_immediate_mode(true);

        // The history_packets is used to store recently received packets,
        // which will be matched with new filters when they arrive.
        // This is to avoid missing packets that arrive before filters,
        // since libpcap will not loss any packets,
        // we can store all received packets in memory and match them with new filters when they arrive.
        let mut history_packets = Vec::new();
        let mut ret_msgs = Vec::new();
        let start = Instant::now();
        loop {
            #[cfg(feature = "debug")]
            let loop_start = Instant::now();

            // Fetch packets first, then check if there are new filters to match,
            // this can avoid missing packets that arrive before filters.
            let packets = cap.fetch_as_vec()?;
            debug!("layer2 recv {} packets", packets.len());

            for packet in packets {
                // #[cfg(feature = "debug")]
                // debug_show_packet(packet, None);
                // #[cfg(feature = "debug")]
                // debug_show_packet(packet, Some(EtherTypes::Arp));
                history_packets.push(Arc::from(packet));
            }

            if history_packets.len() > MAX_HISTORY_PACKETS {
                // remove old packets to avoid memory overflow, keep the latest MAX_HISTORY_PACKETS packets
                history_packets =
                    history_packets.split_off(history_packets.len() - MAX_HISTORY_PACKETS);
            }

            for packet in &history_packets {
                #[cfg(feature = "debug")]
                debug_show_packet(packet, Some(EtherTypes::Arp));
                for m in msgs {
                    let (check_ret, filter) = m.check_packet(packet);
                    if check_ret {
                        debug!("matched packet [{}]", packet.len());
                        if let Some(filter) = filter {
                            if let Some(hp) = filter.get_handle_param() {
                                let mut m = m.clone();
                                m.response = hp.payload.clone();
                                ret_msgs.push(m);
                            }
                        };
                        break;
                    }
                }
            }

            #[cfg(feature = "debug")]
            println!(
                "runner loop cost: {:.2}ms",
                loop_start.elapsed().as_secs_f64() * 1000.0
            );

            if start.elapsed() > timeout {
                debug!("layer2 runner {} timeout, exit loop", iface);
                break;
            }
        }
        Ok(ret_msgs)
    }
    pub(crate) fn add(&mut self, addr: IpAddr, port: u16) {}
    pub(crate) fn run(
        &mut self,
        iface: String,
        payloads: Vec<EngineMsg>,
        timeout: Duration,
    ) -> Result<(), PistolError> {
        for payload in &payloads {
            let addr = payload.target;
            let port = payload.port;
            let payload = payload.ethernet_payload.clone();
            self.set_sended(addr, port);
        }
        let iface_clone = iface.clone();
        let payloads_clone = payloads.clone();
        // Make receiver run first to avoid missing packets that arrive before filters,
        // since libpcap will not loss any packets,
        // we can store all received packets in memory and match them with new filters when they arrive.
        let recv_handle =
            thread::spawn(
                move || match self.recv_all(iface_clone, &payloads_clone, timeout) {
                    Ok(hps) => hps,
                    Err(e) => {
                        error!("recv thread error: {:?}", e);
                        Vec::new()
                    }
                },
            );
        let _send_handle = thread::spawn(move || send_all(iface, &payloads, timeout));
        // if let Err(e) = _send_handle.join() {
        //     error!("send thread error: {:?}", e);
        // }
        match recv_handle.join() {
            Ok(hps) => {
                for hp in hps {
                    self.set_received(hp);
                }
            }
            Err(e) => error!("recv thread error: {:?}", e),
        }
        Ok(())
    }
    fn set_sended(&mut self, addr: IpAddr, port: u16, payload: Arc<[u8]>) {
        match self.status.get_mut(&addr) {
            Some(port_map) => {
                let status = EngineStatus::Sended(payload);
                port_map.insert(port, status);
            }
            None => {
                let mut port_map = HashMap::new();
                let status = EngineStatus::Sended;
                port_map.insert(port, status);
                self.status.insert(addr, port_map);
            }
        }
    }
    fn set_waiting_response(&mut self, addr: IpAddr, port: u16) {
        match self.status.get_mut(&addr) {
            Some(port_map) => {
                port_map.insert(port, EngineStatus::WaitingResponse);
            }
            None => {
                let port_map = HashMap::new();
                self.status.insert(addr, port_map);
            }
        }
    }
    fn set_received(&mut self, addr: IpAddr, port: u16, msg: EngineMsg) {
        match self.status.get_mut(&addr) {
            Some(port_map) => {
                let status = EngineStatus::Received(msg);
                port_map.insert(port, status);
            }
            None => {
                let mut port_map = HashMap::new();
                let status = EngineStatus::Received(msg);
                port_map.insert(port, status);
                self.status.insert(addr, port_map);
            }
        }
    }
    fn set_finished(&mut self, addr: IpAddr, port: u16) {
        match self.status.get_mut(&addr) {
            Some(port_map) => {
                port_map.insert(port, EngineStatus::Finished);
            }
            None => {
                let port_map = HashMap::new();
                self.status.insert(addr, port_map);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_host_engine() {
        let mut engine = HostEngine::new();
        // gen all send buff
        let iface = String::from("ens33");
        let payloads = Vec::new();
        let timeout = Duration::from_secs(5);
        engine.run(iface, payloads, timeout).unwrap();
    }
}
