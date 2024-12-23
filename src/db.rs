use std::collections::HashMap;

pub mod xraypocs;

pub enum PocProtocols {
    Tcp,
    Udp,
}

pub enum PocHttpMethods {
    Post,
    Get,
}

pub enum How2GetValue {
    Random(usize),
    All,
}

pub struct PocHttpRequest {
    pub method: PocHttpMethods,
    pub header: HashMap<String, String>,
    pub body: Option<String>,
}

pub struct PocInfo {
    pub origin_author: String,
    pub remix_author: String,
    pub link: String,
}

pub struct Pocs<T> {
    pub name: String,
    pub protocol: PocProtocols,
    pub values: Vec<T>,
    pub how2getvalue: How2GetValue,
    pub request: PocHttpRequest,
    pub info: PocInfo,
}

impl<T> Pocs<T> {
    pub fn build(
        name: &str,
        protocol: &str,
        values: &str,
        how2getvalue: &str,
        request: HashMap<&str, &str>,
        origin_author: &str,
        remix_author: &str,
        link: &str,
    ) {
        let name = name.to_string();
        let protocol = match protocol.to_lowercase().as_str() {
            "tcp" => PocProtocols::Tcp,
            "udp" => PocProtocols::Udp,
        };
    }
}
