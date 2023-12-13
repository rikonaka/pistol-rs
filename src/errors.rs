use std::error::Error;
use std::fmt;

use crate::TargetType;

#[derive(Debug, Clone)]
pub struct FindInterfaceError {
    interface: String,
}
impl fmt::Display for FindInterfaceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "can not found interface {}", self.interface)
    }
}
impl FindInterfaceError {
    pub fn new(interface: &str) -> FindInterfaceError {
        let interface = interface.to_string();
        FindInterfaceError { interface }
    }
}
impl Error for FindInterfaceError {}

#[derive(Debug, Clone)]
pub struct GetInterfaceIPError {
    interface: String,
}
impl fmt::Display for GetInterfaceIPError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "can not get ip from interface {}", self.interface)
    }
}
impl GetInterfaceIPError {
    pub fn new(interface: &str) -> GetInterfaceIPError {
        let interface = interface.to_string();
        GetInterfaceIPError { interface }
    }
}
impl Error for GetInterfaceIPError {}

#[derive(Debug, Clone)]
pub struct GetInterfaceMACError {
    interface: String,
}
impl fmt::Display for GetInterfaceMACError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "can not get mac from interface {}", self.interface)
    }
}
impl GetInterfaceMACError {
    pub fn new(interface: &str) -> GetInterfaceMACError {
        let interface = interface.to_string();
        GetInterfaceMACError { interface }
    }
}
impl Error for GetInterfaceMACError {}

#[derive(Debug, Clone)]
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

/* OS DETECT ERRORS */

#[derive(Debug, Clone)]
pub struct CalcDiffFailed {}
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

#[derive(Debug, Clone)]
pub struct GetIpv4PacketFailed {}
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

#[derive(Debug, Clone)]
pub struct GetTcpPacketFailed {}
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

#[derive(Debug, Clone)]
pub struct GetIcmpPacketFailed {}
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

#[derive(Debug, Clone)]
pub struct GetUdpPacketFailed {}
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

#[derive(Debug, Clone)]
pub struct CalcISRFailed {}
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

#[derive(Debug, Clone)]
pub struct CalcSSFailed {}
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

#[derive(Debug, Clone)]
pub struct OsDetectPortError {}
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
