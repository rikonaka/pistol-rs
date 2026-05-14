use std::net::IpAddr;
use std::net::Ipv4Addr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PistolError {
    /* OS DETECT ERROR */
    #[error("not enough port value for os detect")]
    OsDetectPortsNotEnough,
    #[error("os detect results is null")]
    OsDetectResultsNullError,
    #[error("system time error")]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error("os db parser error: {name}-{line}")]
    OsDbParseError { name: String, line: String },
    #[error("service probes parser error: {name}-{line}")]
    ServiceProbesParseError { name: String, line: String },
    #[error("service probes protocol unknown: {protocol}")]
    ServiceProbesProtocolUnknown { protocol: String },
    #[error("zip error")]
    ZipError(#[from] zip::result::ZipError),
    #[error("zip file empty")]
    ZipEmptyError,

    /* PING ERROR */
    #[error("The target {target} does not support this detection method {method}")]
    PingDetectionMethodError { target: IpAddr, method: String },
    #[error("can not parse ping response")]
    PingParseResponseError,

    /* SCAN ERROR */
    #[error("can not found the stream for the destination address {addr}")]
    CanNotFoundStream { addr: IpAddr },
    #[error("parse int error")]
    BitcodeError(#[from] bitcode::Error),
    #[error("can not found the loopback interface, please check your network connection")]
    CanNotFoundLoopbackInterface,
    #[error(
        "idle scan zombie {zombie_ipv4} port {zombie_port} cannot be used because IP ID sequence class is all zeros, try another proxy"
    )]
    IdleScanAllZeroError {
        zombie_ipv4: Ipv4Addr,
        zombie_port: u16,
    },
    #[error("idle scan need params: {params}")]
    IdleScanNeedParamsError { params: String },
    #[error("idle scan not support ipv6")]
    IdleScanNotSupportIpVersion,
    #[error("serde json error")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("no destination port specified")]
    NoDstPortSpecified,
    #[error("arp scan address {addr} not match")]
    AttackAddressNotMatch { addr: IpAddr },
    #[error("can not parse ethernet packet")]
    CanNotParseEthernetPacket,

    /* SERVICE DETECT ERROR */
    #[error("parse int error")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("pcre2 regex error")]
    Pcre2RegexError(#[from] pcre2::Error),
    #[error("no match found")]
    NoMatchFound,
    #[error("can not unescape string [{s}]: {e}")]
    CanNotUnescapeString { s: String, e: String },

    /* LAYERS ERROR */
    #[error("create datalink channel failed")]
    CreateDatalinkChannelFailed,
    #[error("can not found the src mac address, please check your network connection")]
    CanNotFoundSrcMacAddress,
    #[error("can not found the route's mac address")]
    CanNotFoundRouteMacAddress,
    #[error("can not found the interface {i}")]
    CanNotFoundInterface { i: String },
    #[error("can not found the source address, please set the source address manually")]
    CanNotFoundSrcAddress,
    #[error("can not found router address")]
    CanNotFoundRouterAddress,
    #[error("build packet error occurret at [{location}]")]
    BuildPacketError { location: String },

    /* LIB */
    #[error("the destination address and source address Ip versions do not match")]
    IpVersionNotMatch,
    #[error("can not found the interface filter channel {i}")]
    CanNotFoundInterfaceFilterChannel { i: String },
    #[error("no loopback protocol")]
    NoLoopbackProtocol,
    #[error("can not found the target net info")]
    CanNotFoundNetInfo,

    /* ROUTE ERROR */
    #[error("subnetwork error")]
    RegexError(#[from] regex::Error),
    #[error("invalid route via address: {addr}")]
    InvalidRouteViaAddress { addr: IpAddr },

    /* OTHER ERROR */
    #[error("std error")]
    IOError(#[from] std::io::Error),
    #[error("subnetwork error")]
    SubnetworkError(#[from] subnetwork::SubnetworkError),
    #[error("hex error")]
    FromHexError(#[from] hex::FromHexError),
    #[error("pcapture error")]
    PcaptureError(#[from] pcapture::error::PcaptureError),
    #[error("try to lock some var failed: {e}")]
    LockVarFailed { e: String },
    #[error("tracing error")]
    SetGlobalDefaultError(#[from] tracing::subscriber::SetGlobalDefaultError),
}
