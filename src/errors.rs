use std::error::Error;
use std::fmt;
use serde::Deserialize;
use serde::Serialize;

use crate::TargetType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotSupportIpTypeForArpScan {
    target_type: TargetType,
}
impl fmt::Display for NotSupportIpTypeForArpScan {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "arp scan not support {:?}", self.target_type)
    }
}
impl NotSupportIpTypeForArpScan {
    pub fn new(target_type: TargetType) -> NotSupportIpTypeForArpScan {
        NotSupportIpTypeForArpScan { target_type }
    }
}
impl Error for NotSupportIpTypeForArpScan {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanNotFoundRouterAddress;
impl fmt::Display for CanNotFoundRouterAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "can not found router address")
    }
}
impl CanNotFoundRouterAddress {
    pub fn new() -> CanNotFoundRouterAddress {
        CanNotFoundRouterAddress {}
    }
}
impl Error for CanNotFoundRouterAddress {}

/* OS DETECT ERRORS */

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalcDiffFailed;
impl fmt::Display for CalcDiffFailed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "calculation of diff vec failed, the input vec length is not enough"
        )
    }
}
impl CalcDiffFailed {
    pub fn new() -> CalcDiffFailed {
        CalcDiffFailed {}
    }
}
impl Error for CalcDiffFailed {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetIpv4PacketFailed;
impl fmt::Display for GetIpv4PacketFailed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "get ipv4 packet failed")
    }
}
impl GetIpv4PacketFailed {
    pub fn new() -> GetIpv4PacketFailed {
        GetIpv4PacketFailed {}
    }
}
impl Error for GetIpv4PacketFailed {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetIpv6PacketFailed;
impl fmt::Display for GetIpv6PacketFailed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "get ipv6 packet failed")
    }
}
impl GetIpv6PacketFailed {
    pub fn new() -> GetIpv6PacketFailed {
        GetIpv6PacketFailed {}
    }
}
impl Error for GetIpv6PacketFailed {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetIcmpv6PacketFailed;
impl fmt::Display for GetIcmpv6PacketFailed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "get icmpv6 packet failed")
    }
}
impl GetIcmpv6PacketFailed {
    pub fn new() -> GetIcmpv6PacketFailed {
        GetIcmpv6PacketFailed {}
    }
}
impl Error for GetIcmpv6PacketFailed {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTcpPacketFailed;
impl fmt::Display for GetTcpPacketFailed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "get tcp packet failed")
    }
}
impl GetTcpPacketFailed {
    pub fn new() -> GetTcpPacketFailed {
        GetTcpPacketFailed {}
    }
}
impl Error for GetTcpPacketFailed {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetIcmpPacketFailed;
impl fmt::Display for GetIcmpPacketFailed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "get icmp packet failed")
    }
}
impl GetIcmpPacketFailed {
    pub fn new() -> GetIcmpPacketFailed {
        GetIcmpPacketFailed {}
    }
}
impl Error for GetIcmpPacketFailed {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetUdpPacketFailed;
impl fmt::Display for GetUdpPacketFailed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "get udp packet failed")
    }
}
impl GetUdpPacketFailed {
    pub fn new() -> GetUdpPacketFailed {
        GetUdpPacketFailed {}
    }
}
impl Error for GetUdpPacketFailed {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalcISRFailed;
impl fmt::Display for CalcISRFailed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "calculation of ISR failed")
    }
}
impl CalcISRFailed {
    pub fn new() -> CalcISRFailed {
        CalcISRFailed {}
    }
}
impl Error for CalcISRFailed {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalcSSFailed;
impl fmt::Display for CalcSSFailed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "calculation of SS failed")
    }
}
impl CalcSSFailed {
    pub fn new() -> CalcSSFailed {
        CalcSSFailed {}
    }
}
impl Error for CalcSSFailed {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsDetectPortError;
impl fmt::Display for OsDetectPortError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "not enough port value for os detect")
    }
}
impl OsDetectPortError {
    pub fn new() -> OsDetectPortError {
        OsDetectPortError {}
    }
}
impl Error for OsDetectPortError {}

/* layer */

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDatalinkChannelFailed;
impl fmt::Display for CreateDatalinkChannelFailed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "create datalink channel failed")
    }
}
impl CreateDatalinkChannelFailed {
    pub fn new() -> CreateDatalinkChannelFailed {
        CreateDatalinkChannelFailed {}
    }
}
impl Error for CreateDatalinkChannelFailed {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanNotFoundMacAddress;
impl fmt::Display for CanNotFoundMacAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "can not found the mac address, please check the target is alive"
        )
    }
}
impl CanNotFoundMacAddress {
    pub fn new() -> CanNotFoundMacAddress {
        CanNotFoundMacAddress {}
    }
}
impl Error for CanNotFoundMacAddress {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanNotFoundInterface;
impl fmt::Display for CanNotFoundInterface {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "can not found the interface")
    }
}
impl CanNotFoundInterface {
    pub fn new() -> CanNotFoundInterface {
        CanNotFoundInterface {}
    }
}
impl Error for CanNotFoundInterface {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanNotFoundSourceAddress;
impl fmt::Display for CanNotFoundSourceAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "can not found the source address, please set it maunal")
    }
}
impl CanNotFoundSourceAddress {
    pub fn new() -> CanNotFoundSourceAddress {
        CanNotFoundSourceAddress {}
    }
}
impl Error for CanNotFoundSourceAddress {}