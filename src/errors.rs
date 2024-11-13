use std::net::Ipv4Addr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PistolErrors {
    /* OS DETECT ERRORS */
    #[error("calculation of diff vec failed, the input vec length is not enough")]
    CalcDiffFailed,
    #[error("get ipv4 packet failed")]
    GetIpv4PacketFailed,
    #[error("get ipv6 packet failed")]
    GetIpv6PacketFailed,
    #[error("get icmp packet failed")]
    GetIcmpPacketFailed,
    #[error("get icmpv6 packet failed")]
    GetIcmpv6PacketFailed,
    #[error("get tcp packet failed")]
    GetTcpPacketFailed,
    #[error("get udp packet failed")]
    GetUdpPacketFailed,
    #[error("calculation of isr failed")]
    CalcISRFailed,
    #[error("calculation of ss failed")]
    CalcSSFailed,
    #[error("not enough port value for os detect")]
    OSDetectPortsNotEnough,
    #[error("os detect results is null")]
    OSDetectResultsNullError,
    #[error("tsval value length is not enough")]
    TsValIsNull,
    #[error("system time error")]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error("os db parser error: {name}-{line}")]
    OSDBParseError { name: String, line: String },
    #[error("zip error")]
    ZipError(#[from] zip::result::ZipError),
    #[error("zip file empty")]
    ZipEmptyError,

    /* SCAN ERRORS */
    #[error("idle scan zombie {zombie_ipv4} port {zombie_port} cannot be used because IP ID sequence class is: all zeros, try another proxy")]
    IdleScanAllZeroError {
        zombie_ipv4: Ipv4Addr,
        zombie_port: u16,
    },
    #[error("serde json error")]
    SerdeJsonError(#[from] serde_json::Error),

    /* SERVICE DETECT ERRORS */
    #[error("parse int error")]
    ParseIntError(#[from] std::num::ParseIntError),

    /* LAYERS ERRORS */
    #[error("create datalink channel failed")]
    CreateDatalinkChannelFailed,
    #[error("can not found the target mac address, please make sure the target is alive")]
    CanNotFoundMacAddress,
    #[error("can not found the route's mac address")]
    CanNotFoundRouteMacAddress,
    #[error("can not found the interface")]
    CanNotFoundInterface,
    #[error("can not found the source address, please set it maunal")]
    CanNotFoundSourceAddress,
    #[error("can not found router address")]
    CanNotFoundRouterAddress,

    /* ROUTE ERRORS */
    #[error("subnetwork error")]
    RegexError(#[from] regex::Error),

    /* OTHER ERRORS */
    #[error("std error")]
    IOError(#[from] std::io::Error),
    #[error("subnetwork error")]
    SubnetworkErrors(#[from] subnetwork::SubnetworkErrors),
    #[error("log error")]
    SetLoggerError(#[from] log::SetLoggerError),
    #[error("hex error")]
    FromHexError(#[from] hex::FromHexError),
}
