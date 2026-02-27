use std::net::IpAddr;
use std::net::Ipv4Addr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PistolError {
    /* OS DETECT ERROR */
    #[error("calculation of diff vec failed, the input vec length is not enough")]
    CalcDiffFailed,
    #[error("build {probe_name} ipv4 packet failed")]
    BuildIpv4PacketFailed { probe_name: String },
    #[error("build {probe_name} ipv6 packet failed")]
    BuildIpv6PacketFailed { probe_name: String },
    #[error("build {probe_name} icmp packet failed")]
    BuildIcmpPacketFailed { probe_name: String },
    #[error("build {probe_name} icmpv6 packet failed")]
    BuildIcmpv6PacketFailed { probe_name: String },
    #[error("build {probe_name} tcp packet failed")]
    BuildTcpPacketFailed { probe_name: String },
    #[error("build udp packet failed")]
    BuildUdpPacketFailed { probe_name: String },
    #[error("calculation of isr failed")]
    CalcISRFailed,
    #[error("calculation of ss failed")]
    CalcSSFailed,
    #[error("icmp length is not enough")]
    CalcUNFailed,
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

    /* PING ERROR */
    #[error("The target {target} does not support this detection method {method}")]
    PingDetectionMethodError { target: IpAddr, method: String },

    /* SCAN ERROR */
    #[error(
        "idle scan zombie {zombie_ipv4} port {zombie_port} cannot be used because IP ID sequence class is all zeros, try another proxy"
    )]
    IdleScanAllZeroError {
        zombie_ipv4: Ipv4Addr,
        zombie_port: u16,
    },
    #[error("idle scan has no params: {params}")]
    IdleScanNoParamsError { params: String },
    #[error("idle scan not support ipv6")]
    IdleScanNotSupportIpVersion,
    #[error("serde json error")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("no destination port specified")]
    NoDstPortSpecified,
    #[error("arp scan address {addr} not match")]
    AttackAddressNotMatch { addr: IpAddr },

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
    #[error("can not found the dst mac address, please make sure the target is alive")]
    CanNotFoundDstMacAddress,
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

    /* ROUTE ERROR */
    #[error("subnetwork error")]
    RegexError(#[from] regex::Error),

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
    LockGlobalVarFailed { e: String },
    #[error("tracing error")]
    SetGlobalDefaultError(#[from] tracing::subscriber::SetGlobalDefaultError),
    #[error("input {v} is too loog to convert to u32")]
    InputTooLoog { v: String },
}
