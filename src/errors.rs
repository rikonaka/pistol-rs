use std::error::Error;
use std::fmt;

use crate::TargetType;

/* FindInterfaceError */
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

/* GetInterfaceIPError */
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

/* GetInterfaceIPError */
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

/* NotSupportIpTypeForArpScan */
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

/* WrongIpType */
#[derive(Debug, Clone)]
pub struct WrongTargetType {
    target_type: TargetType,
}

impl fmt::Display for WrongTargetType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "wrong target type {:?}", self.target_type)
    }
}

impl WrongTargetType {
    pub fn new(target_type: TargetType) -> WrongTargetType {
        WrongTargetType { target_type }
    }
}

impl Error for WrongTargetType {}
