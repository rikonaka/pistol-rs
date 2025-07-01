use std::net::Ipv4Addr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PistolError {
    /* OS DETECT ERROR */
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
    #[error("service probes parser error: {name}-{line}")]
    ServiceProbesParseError { name: String, line: String },
    #[error("service probes protocol unknown: {protocol}")]
    ServiceProbesProtocolUnknown { protocol: String },
    #[error("zip error")]
    ZipError(#[from] zip::result::ZipError),
    #[error("zip file empty")]
    ZipEmptyError,

    /* SCAN ERROR */
    #[error(
        "idle scan zombie {zombie_ipv4} port {zombie_port} cannot be used because IP ID sequence class is: all zeros, try another proxy"
    )]
    IdleScanAllZeroError {
        zombie_ipv4: Ipv4Addr,
        zombie_port: u16,
    },
    #[error("serde json error")]
    SerdeJsonError(#[from] serde_json::Error),

    /* SERVICE DETECT ERROR */
    #[error("parse int error")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("fancy_regex error")]
    FancyRegexError(#[from] fancy_regex::Error),
    #[error("no match found")]
    NoMatchFound,
    #[error("can not unescape string [{s}]: {e}")]
    CanNotUnescapeString { s: String, e: String },

    /* LAYERS ERROR */
    #[error("create datalink channel failed")]
    CreateDatalinkChannelFailed,
    #[error("can not found the target mac address, please make sure the target is alive")]
    CanNotFoundMacAddress,
    #[error("can not found the route's mac address")]
    CanNotFoundRouteMacAddress,
    #[error("can not found the interface")]
    CanNotFoundInterface,
    #[error("can not found the source address, please make sure target is alive or set it maunal")]
    CanNotFoundSourceAddress,
    #[error("can not found router address")]
    CanNotFoundRouterAddress,
    #[error("build packet error occurret at [{path}]")]
    BuildPacketError { path: String },
    #[error("the `PistolRunner` monitoring threads is not running, please run it first")]
    PistolRunnerIsNotRunning,

    /* ROUTE ERROR */
    #[error("subnetwork error")]
    RegexError(#[from] regex::Error),

    /* OTHER ERROR */
    #[error("std error")]
    IOError(#[from] std::io::Error),
    #[error("subnetwork error")]
    SubnetworkError(#[from] subnetwork::SubnetworkError),
    #[error("log error")]
    SetLoggerError(#[from] log::SetLoggerError),
    #[error("hex error")]
    FromHexError(#[from] hex::FromHexError),
    #[error("init the capture function error: {e}")]
    InitCaptureError { e: String },
    #[error("save the traffic error: {e}")]
    SaveCaptureError { e: String },
    #[error("pcapture error")]
    PcaptureError(#[from] pcapture::PcaptureError),
    #[error("try lock {var_name} failed: {e}")]
    TryLockGlobalVarFailed { var_name: String, e: String },
}
