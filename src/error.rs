use std::net::IpAddr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PistolError {
    /* OS DETECT ERROR */
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
    #[error("serde json error")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("arp scan address {addr} not match")]
    AttackAddressNotMatch { addr: IpAddr },
    #[error("can not parse ethernet packet")]
    CanNotParseEthernetPacket,
    #[error("try to lock some var failed: {e}")]
    LockVarFailed { e: String },

    /* SERVICE DETECT ERROR */
    #[error("parse int error")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("pcre2 regex error")]
    Pcre2RegexError(#[from] pcre2::Error),
    #[error("regex error")]
    RegexError(#[from] regex::Error),
    #[error("no match found")]
    NoMatchFound,
    #[error("can not unescape string [{s}]: {e}")]
    CanNotUnescapeString { s: String, e: String },

    /* LAYERS ERROR */
    #[error("create datalink channel failed")]
    CreateDatalinkChannelFailed,
    #[error("can not found the src mac address, please check your network connection")]
    CanNotFoundSrcMacAddress,
    #[error("can not found the source address, please set the source address manually")]
    CanNotFoundSrcAddress,
    #[error("build packet error occurret at [{location}]")]
    BuildPacketError { location: String },

    /* LIB */
    #[error("can not found the target net info")]
    CanNotFoundNetInfo,

    /* ROUTE ERROR */
    #[error("mac address parse error: {mac}")]
    ParseMacAddrErr { mac: String },
    #[error("crossnet error")]
    CrossNetError(#[from] crossnet::error::CrossNetError),
    #[error("route addr type error")]
    RouteAddrTypeError,
    #[error("can not found route for the destination address {dst}")]
    CanNotFoundRoute { dst: IpAddr },
    #[error("can not found mac address for the destination address {dst}")]
    CanNotFoundMac { dst: IpAddr },

    /* OTHER ERROR */
    #[error("std error")]
    IOError(#[from] std::io::Error),
    #[error("subnetwork error")]
    SubnetworkError(#[from] subnetwork::SubnetworkError),
    #[error("hex error")]
    FromHexError(#[from] hex::FromHexError),
    #[error("pcapture error")]
    PcaptureError(#[from] pcapture::error::PcaptureError),
    #[error("tracing error")]
    SetGlobalDefaultError(#[from] tracing::subscriber::SetGlobalDefaultError),
}
