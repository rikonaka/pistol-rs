use fancy_regex::Regex as FancyRegex;
use log::error;
use regex::Regex;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;

use crate::errors::PistolErrors;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ProbeProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    // match or softmatch
    pub class: String,
    // This is simply the service name that the pattern matches.
    pub service: String,
    // This pattern is used to determine whether the response received matches the service given in the previous parameter.
    pub pattern: String,
    // The <versioninfo> section actually contains several optional fields.
    pub versioninfo: String,
}

impl fmt::Display for Match {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.service)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    /// This must be either TCP or UDP. Nmap only uses probes that match the protocol of the service it is trying to scan.
    pub probeprotocol: ProbeProtocol,
    /// This is a plain English name for the probe. It is used in service fingerprints to describe which probes elicited responses.
    pub probename: String,
    /// Tells Nmap what to send.
    pub probestring: String,
    /// This keyword is used to instruct Nmap not to use the given probe as a protocol-specific payload during UDP port scanning.
    pub no_payload: bool,
}

impl Probe {
    pub fn empty() -> Probe {
        Probe {
            probeprotocol: ProbeProtocol::Tcp,
            probename: String::new(),
            probestring: String::new(),
            no_payload: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceProbe {
    pub probe: Probe,
    pub matchs: Vec<Match>,
    pub softmatchs: Vec<Match>,
    /// This line tells Nmap what ports the services identified by this probe are commonly found on.
    pub ports: Vec<u16>,
    /// This is the same as 'ports' directive described above, except that these ports are often used to wrap a service in SSL.
    pub sslports: Vec<u16>,
    /// This rarely necessary directive specifies the amount of time Nmap should wait before giving up on the most recently defined Probe against a particular service.
    pub totalwaitms: usize,
    /// This directive is only used for the Null probe.
    pub tcpwrappedms: usize,
    /// The rarity directive roughly corresponds to how infrequently this probe can be expected to return useful results.
    pub rarity: usize,
    /// This optional directive specifies which probes should be used as fallbacks for if there are no matches in the current Probe section.
    pub fallback: Vec<String>,
}

impl ServiceProbe {
    pub fn check(&self, recv_str: &str) -> Vec<Match> {
        let match_function = |m: &Match, re: &FancyRegex, recv_str: &str| -> Option<Match> {
            match re.is_match(&recv_str) {
                Ok(b) => {
                    if b {
                        let captures_group = match re.captures(&recv_str) {
                            Ok(v) => v,
                            Err(_) => None,
                        };
                        match captures_group {
                            Some(v) => {
                                let mut versioninfo = m.versioninfo.to_string();
                                for i in 0..v.len() {
                                    let value = v.get(i).unwrap();
                                    versioninfo =
                                        versioninfo.replace(&format!("${}", i), value.as_str());
                                }
                                let new_match = Match {
                                    class: m.class.clone(),
                                    service: m.service.clone(),
                                    pattern: m.pattern.clone(),
                                    versioninfo,
                                };
                                return Some(new_match);
                            }
                            None => {
                                let new_match = Match {
                                    class: m.class.clone(),
                                    service: m.service.clone(),
                                    pattern: m.pattern.clone(),
                                    versioninfo: String::from(""),
                                };
                                return Some(new_match);
                            }
                        }
                    }
                }
                Err(_) => (),
            }
            None
        };

        let mut ret = Vec::new();
        // match
        for m in &self.matchs {
            // println!("{}", m.pattern);
            let recv_str = recv_str.to_string();
            let re = match FancyRegex::new(&m.pattern) {
                Ok(r) => r,
                Err(_) => continue, // rust regex is not support some format, and it will return error here
            };
            let r = match_function(m, &re, &recv_str);
            match r {
                Some(r) => ret.push(r),
                None => (),
            }
        }

        // softmatch
        for m in &self.softmatchs {
            let re = match FancyRegex::new(&m.pattern) {
                Ok(r) => r,
                Err(_) => continue, // rust regex is not support some format, and it will return error here
            };
            let r = match_function(m, &re, &recv_str);
            match r {
                Some(r) => ret.push(r),
                None => (),
            }
        }
        ret
    }
}

fn ports_parser(ports: &str) -> Result<Vec<u16>, PistolErrors> {
    let mut ret = Vec::new();
    let ports_split: Vec<&str> = ports.split(",").map(|s| s.trim()).collect();
    for ps in ports_split {
        if ps.contains("-") {
            let ps_split: Vec<&str> = ps.split("-").collect();
            let ps_start: u16 = ps_split[0].parse()?;
            let ps_end: u16 = ps_split[1].parse()?;
            for p in ps_start..=ps_end {
                ret.push(p);
            }
        } else {
            let p: u16 = ps.parse()?;
            ret.push(p);
        }
    }
    Ok(ret)
}

/// Instead of getting the `Exclude` port based on the `nmap-service-probes` file,
/// we expect the user to provide a parameter to specify this value themselves.
pub fn nmap_service_probes_parser(lines: Vec<String>) -> Result<Vec<ServiceProbe>, PistolErrors> {
    let probe_name_reg = Regex::new(
        r"Probe (?P<probeprotocol>[^\s]+) (?P<probename>[^\s]+) q\|(?P<probestring>[\w]+|)\|.+",
    )?;
    let ports_reg = Regex::new(r"ports (?P<ports>[\d,-]+)")?;
    let sslports_reg = Regex::new(r"sslports (?P<sslports>[\d,-]+)")?;
    let totalwaitms_reg = Regex::new(r"totalwaitms (?P<totalwaitms>[\d]+)")?;
    let tcpwrappedms_reg = Regex::new(r"tcpwrappedms (?P<tcpwrappedms>[\d]+)")?;
    let rarity_reg = Regex::new(r"rarity (?P<rarity>[\d]+)")?;
    let match_reg = Regex::new(
        r"match (?P<service>.+) m(\||/)(?P<pattern>[^/\|]+)(\||/)(\w)?( p/(?P<p>[^/]+)/)?( v/(?P<v>[^/]+)/)?( h/(?P<h>[^/]+)/)?( i/(?P<i>[^/]+)/)?( o/(?P<o>[^/]+)/)?( (?P<cpe>cpe:/[^/]+)/(\w)?)?",
    )?;
    let softmatch_reg = Regex::new(r"softmatch (?P<service>[^\s]+) m(\||/)(?P<pattern>.+)(\||/)")?;
    let fallback_reg = Regex::new(r"fallback (?P<fallback>[\w\d,]+)")?;

    let mut ret_v: Vec<ServiceProbe> = Vec::new();
    let mut probe_v: Probe = Probe::empty();
    let mut ports_v: Vec<u16> = Vec::new();
    let mut sslports_v: Vec<u16> = Vec::new();
    let mut totalwaitms_v: usize = 0;
    let mut tcpwrappedms_v: usize = 0;
    let mut rarity_v: usize = 0;
    let mut match_v: Vec<Match> = Vec::new();
    let mut softmatch_v: Vec<Match> = Vec::new();
    let mut fallback_v: Vec<String> = Vec::new();

    let mut first_probe = true;

    for line in lines {
        if line.starts_with("#") {
            continue;
        }
        if line.starts_with("Probe") {
            if !first_probe {
                let probe = probe_v;
                let totalwaitms = totalwaitms_v;
                let tcpwrappedms = tcpwrappedms_v;
                let rarity = rarity_v;
                let ports = ports_v.clone();
                let sslports = sslports_v.clone();
                let matchs = match_v.clone();
                let softmatchs = softmatch_v.clone();
                let fallback = fallback_v.clone();

                let sp = ServiceProbe {
                    probe,
                    matchs,
                    softmatchs,
                    ports,
                    sslports,
                    totalwaitms,
                    tcpwrappedms,
                    rarity,
                    fallback,
                };
                ret_v.push(sp);

                // probe_v = Probe::empty();
                ports_v.clear();
                sslports_v.clear();
                totalwaitms_v = 0;
                tcpwrappedms_v = 0;
                rarity_v = 0;
                match_v.clear();
                softmatch_v.clear();
                fallback_v.clear();
                first_probe = false;
            }

            /* probe name part */
            let (probeprotocol, probename, probestring) = match probe_name_reg.captures(&line) {
                Some(caps) => {
                    let probeprotocol = caps.name("probeprotocol").map_or("", |m| m.as_str());
                    let probename = caps.name("probename").map_or("", |m| m.as_str());
                    let probestring = caps.name("probestring").map_or("", |m| m.as_str());
                    (
                        probeprotocol.to_string(),
                        probename.to_string(),
                        probestring.to_string(),
                    )
                }
                None => {
                    return Err(PistolErrors::ServiceProbesParseError {
                        name: String::from("Probe"),
                        line: line.to_string(),
                    })
                }
            };
            let probeprotocol = match probeprotocol.as_str() {
                "TCP" => ProbeProtocol::Tcp,
                "UDP" => ProbeProtocol::Udp,
                _ => {
                    return Err(PistolErrors::ServiceProbesProtocolUnknown {
                        protocol: probeprotocol,
                    })
                }
            };
            let no_payload = if line.contains("no-payload") {
                true
            } else {
                false
            };

            let probe = Probe {
                probeprotocol,
                probename,
                probestring,
                no_payload,
            };
            probe_v = probe;
        } else if line.starts_with("ports") {
            let ports_str = match ports_reg.captures(&line) {
                Some(caps) => {
                    let ports_str = caps.name("ports").map_or("", |m| m.as_str());
                    ports_str
                }
                None => {
                    return Err(PistolErrors::ServiceProbesParseError {
                        name: String::from("ports"),
                        line: line.to_string(),
                    })
                }
            };
            ports_v = ports_parser(ports_str)?;
        } else if line.starts_with("sslports") {
            let ports_str = match sslports_reg.captures(&line) {
                Some(caps) => {
                    let ports_str = caps.name("sslports").map_or("", |m| m.as_str());
                    ports_str
                }
                None => {
                    return Err(PistolErrors::ServiceProbesParseError {
                        name: String::from("ports"),
                        line: line.to_string(),
                    })
                }
            };
            sslports_v = ports_parser(ports_str)?;
        } else if line.starts_with("totalwaitms") {
            let totalwaitms = match totalwaitms_reg.captures(&line) {
                Some(caps) => {
                    let totalwaitms_str = caps.name("totalwaitms").map_or("", |m| m.as_str());
                    totalwaitms_str
                }
                None => {
                    return Err(PistolErrors::ServiceProbesParseError {
                        name: String::from("totalwaitms"),
                        line: line.to_string(),
                    })
                }
            };
            let totalwaitms: usize = totalwaitms.parse()?;
            totalwaitms_v = totalwaitms;
        } else if line.starts_with("tcpwrappedms") {
            let tcpwrappedms = match tcpwrappedms_reg.captures(&line) {
                Some(caps) => {
                    let tcpwrappedms_str = caps.name("tcpwrappedms").map_or("", |m| m.as_str());
                    tcpwrappedms_str
                }
                None => {
                    return Err(PistolErrors::ServiceProbesParseError {
                        name: String::from("tcpwrappedms"),
                        line: line.to_string(),
                    })
                }
            };
            let tcpwrappedms: usize = tcpwrappedms.parse()?;
            tcpwrappedms_v = tcpwrappedms;
        } else if line.starts_with("rarity") {
            let rarity = match rarity_reg.captures(&line) {
                Some(caps) => {
                    let rarity_str = caps.name("rarity").map_or("", |m| m.as_str());
                    rarity_str
                }
                None => {
                    return Err(PistolErrors::ServiceProbesParseError {
                        name: String::from("rarity"),
                        line: line.to_string(),
                    })
                }
            };
            let rarity: usize = rarity.parse()?;
            rarity_v = rarity;
        } else if line.starts_with("match") {
            let matchx = match match_reg.captures(&line) {
                Some(caps) => {
                    let service_str = caps.name("service").map_or("", |m| m.as_str());
                    let pattern_str = caps.name("pattern").map_or("", |m| m.as_str());
                    let p_str = caps.name("p").map_or("", |m| m.as_str());
                    let v_str = caps.name("v").map_or("", |m| m.as_str());
                    let h_str = caps.name("h").map_or("", |m| m.as_str());
                    let i_str = caps.name("i").map_or("", |m| m.as_str());
                    let o_str = caps.name("o").map_or("", |m| m.as_str());
                    let cpe_str = caps.name("cpe").map_or("", |m| m.as_str());
                    let x = r"match (?P<service>.+) m(\||/)(?P<pattern>[^/\|]+)(\||/)(\w)?( p/(?P<p>[^/]+)/)?( v/(?P<v>[^/]+)/)?( h/(?P<h>[^/]+)/)?( i/(?P<i>[^/]+)/)?( o/(?P<o>[^/]+)/)?( (?P<cpe>cpe:/[^/]+)/(\w)?)?";
                    service_str
                }
                None => {
                    return Err(PistolErrors::ServiceProbesParseError {
                        name: String::from("rarity"),
                        line: line.to_string(),
                    })
                }
            };
        }
    }

    // last value
    let probe = probe_v;
    let totalwaitms = totalwaitms_v;
    let tcpwrappedms = tcpwrappedms_v;
    let rarity = rarity_v;
    let ports = ports_v.clone();
    let sslports = sslports_v.clone();
    let matchs = match_v.clone();
    let softmatchs = softmatch_v.clone();
    let fallback = fallback_v.clone();

    let sp = ServiceProbe {
        probe,
        matchs,
        softmatchs,
        ports,
        sslports,
        totalwaitms,
        tcpwrappedms,
        rarity,
        fallback,
    };
    ret_v.push(sp);

    Ok(ret_v)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExcludePorts {
    pub ports: Vec<u16>,
    pub tcp_ports: Vec<u16>,
    pub udp_ports: Vec<u16>,
}

impl ExcludePorts {
    pub fn new(ports: Vec<u16>) -> ExcludePorts {
        ExcludePorts {
            ports,
            tcp_ports: vec![],
            udp_ports: vec![],
        }
    }
}
