use anyhow::Result;
use fancy_regex::Regex;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ProbesProtocol {
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
    pub protocol: ProbesProtocol,
    /// This is a plain English name for the probe. It is used in service fingerprints to describe which probes elicited responses.
    pub probename: String,
    /// Tells Nmap what to send.
    pub probestring: String,
    /// This keyword is used to instruct Nmap not to use the given probe as a protocol-specific payload during UDP port scanning.
    pub no_payload: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceProbe {
    pub probe: Probe,
    pub matchs: Vec<Match>,
    pub softmatchs: Vec<Match>,
    /// This line tells Nmap what ports the services identified by this probe are commonly found on.
    pub ports: Option<Vec<u16>>,
    /// This is the same as 'ports' directive described above, except that these ports are often used to wrap a service in SSL.
    pub sslports: Option<Vec<u16>>,
    /// This rarely necessary directive specifies the amount of time Nmap should wait before giving up on the most recently defined Probe against a particular service.
    pub totalwaitms: Option<u64>,
    /// This directive is only used for the Null probe.
    pub tcpwrappedms: Option<u64>,
    /// The rarity directive roughly corresponds to how infrequently this probe can be expected to return useful results.
    pub rarity: Option<u64>,
    /// This optional directive specifies which probes should be used as fallbacks for if there are no matches in the current Probe section.
    pub fallback: Option<Vec<String>>,
}

impl ServiceProbe {
    pub fn check(&self, recv_str: &str) -> Vec<Match> {
        let match_function = |m: &Match, re: &Regex, recv_str: &str| -> Option<Match> {
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
            let re = match Regex::new(&m.pattern) {
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
            let re = match Regex::new(&m.pattern) {
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

fn ports_parser(ports: &str) -> Result<Vec<u16>> {
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
pub fn nsp_parser(lines: &[String]) -> Result<Vec<ServiceProbe>> {
    let mut ret: Vec<ServiceProbe> = Vec::new();
    let mut probe_global: Option<Probe> = None;
    let mut matchs_global: Vec<Match> = Vec::new();
    let mut softmatchs_global: Vec<Match> = Vec::new();
    let mut ports_global: Option<Vec<u16>> = None;
    let mut sslports_global: Option<Vec<u16>> = None;
    let mut totalwaitms_global: Option<u64> = None;
    let mut tcpwrappedms_global: Option<u64> = None;
    let mut rarity_global: Option<u64> = None;
    let mut fallback_gloabl: Option<Vec<String>> = None;
    for line in lines {
        if line.contains("#") {
            continue;
        } else if line.contains("Exclude") {
            continue;
        }

        if line.starts_with("Probe") {
            match probe_global {
                Some(p) => {
                    let sp = ServiceProbe {
                        probe: p,
                        matchs: matchs_global,
                        softmatchs: softmatchs_global,
                        ports: ports_global.clone(),
                        sslports: sslports_global.clone(),
                        totalwaitms: totalwaitms_global,
                        tcpwrappedms: tcpwrappedms_global,
                        rarity: rarity_global,
                        fallback: fallback_gloabl.clone(),
                    };
                    ret.push(sp);
                    matchs_global = Vec::new();
                    softmatchs_global = Vec::new();
                    ports_global = None;
                    sslports_global = None;
                    totalwaitms_global = None;
                    tcpwrappedms_global = None;
                    rarity_global = None;
                    fallback_gloabl = None;
                }
                None => (),
            }

            // println!("{}", line);
            let line_split: Vec<&str> = line.split(" ").collect();
            let protocol = match line_split[1] {
                "TCP" => ProbesProtocol::Tcp,
                "UDP" => ProbesProtocol::Udp,
                _ => panic!("new protocol: {}", line_split[1]),
            };
            let probename = line_split[2].to_string();
            let probelast = line_split[3..].to_vec().join(" ");
            let probelast_split: Vec<&str> = probelast.split("|").map(|s| s.trim()).collect();
            let probestring = probelast_split[1].to_string();
            let no_payload = if probelast.contains("no-payload") {
                true
            } else {
                false
            };
            let sp = Probe {
                protocol,
                probename,
                probestring,
                no_payload,
            };
            probe_global = Some(sp);
        } else if line.starts_with("match") {
            let line_split: Vec<&str> = line.split(" ").collect();
            let class = line_split[0].to_string();
            let service = line_split[1].to_string();
            let line_other = line_split[2..].to_vec().join(" ");

            let line_other_replace = line_other.replace("|s", "|");
            let line_other_split: Vec<&str> = line_other_replace.split("|").collect();
            let mut pattern = line_other_split[1].to_string();
            if line_other.contains("|s") {
                pattern += r"\s"
            } else if line_other.contains("|i") {
                pattern += r"\i";
            }

            let versioninfo = line_other_split[line_other_split.len() - 1]
                .trim()
                .to_string();

            let m = Match {
                class,
                service,
                pattern,
                versioninfo,
            };
            matchs_global.push(m);
        } else if line.starts_with("softmatch") {
            let line_split: Vec<&str> = line.split(" ").collect();
            let class = line_split[0].to_string();
            let service = line_split[1].to_string();
            let line_other = line_split[2..].to_vec().join(" ");

            let line_other_replace = line_other.replace("|s", "|");
            let line_other_split: Vec<&str> = line_other_replace.split("|").collect();
            let mut pattern = line_other_split[1].to_string();
            if line_other.contains("|s") {
                pattern += r"\s"
            } else if line_other.contains("|i") {
                pattern += r"\i";
            }

            let versioninfo = line_other_split[line_other_split.len() - 1]
                .trim()
                .to_string();

            let m = Match {
                class,
                service,
                pattern,
                versioninfo,
            };
            softmatchs_global.push(m);
        } else if line.starts_with("ports") {
            let line_split: Vec<&str> = line.split(" ").collect();
            let ports_line = line_split[1..].to_vec().join(" ");
            let ports = ports_parser(&ports_line)?;
            ports_global = Some(ports);
        } else if line.starts_with("sslports") {
            let line_split: Vec<&str> = line.split(" ").collect();
            let sslports_line = line_split[1..].to_vec().join(" ");
            let sslports = ports_parser(&sslports_line)?;
            sslports_global = Some(sslports);
        } else if line.starts_with("totalwaitms") {
            let line_split: Vec<&str> = line.split(" ").collect();
            let totalwaitms: u64 = line_split[1].parse()?;
            totalwaitms_global = Some(totalwaitms);
        } else if line.starts_with("tcpwrappedms") {
            let line_split: Vec<&str> = line.split(" ").collect();
            let tcpwrappedms: u64 = line_split[1].parse()?;
            tcpwrappedms_global = Some(tcpwrappedms);
        } else if line.starts_with("rarity") {
            let line_split: Vec<&str> = line.split(" ").collect();
            let rarity: u64 = line_split[1].parse()?;
            rarity_global = Some(rarity);
        } else if line.starts_with("fallback") {
            let line_split: Vec<String> = line.split(" ").map(|s| s.to_string()).collect();
            let fallback = line_split[1..].to_vec();
            fallback_gloabl = Some(fallback);
        }
    }
    match probe_global {
        Some(p) => {
            let sp = ServiceProbe {
                probe: p,
                matchs: matchs_global,
                softmatchs: softmatchs_global,
                ports: ports_global,
                sslports: sslports_global,
                totalwaitms: totalwaitms_global,
                tcpwrappedms: tcpwrappedms_global,
                rarity: rarity_global,
                fallback: fallback_gloabl,
            };
            ret.push(sp);
        }
        None => (),
    }
    Ok(ret)
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

pub fn nsp_exclued_parser(lines: &[String]) -> Result<ExcludePorts> {
    let mut ports: Vec<u16> = Vec::new();
    let mut tcp_ports: Vec<u16> = Vec::new();
    let mut udp_ports: Vec<u16> = Vec::new();
    for line in lines {
        if line.starts_with("Exclude") {
            // println!("{}", line);
            let line_split: Vec<&str> = line.split(" ").collect();
            let exclued = line_split[1..].to_vec().join(" ");
            let exclued_split: Vec<&str> = exclued.split(",").map(|s| s.trim()).collect();
            for ex in &exclued_split {
                if ex.contains(":") {
                    let ex_split: Vec<&str> = ex.split(":").collect();
                    match ex_split[0] {
                        "T" => {
                            if ex_split[1].contains("-") {
                                let ex_split_split: Vec<&str> = ex_split[1].split("-").collect();
                                let start: u16 = ex_split_split[0].parse()?;
                                let end: u16 = ex_split_split[1].parse()?;
                                for p in start..=end {
                                    tcp_ports.push(p);
                                }
                            } else {
                                let p: u16 = ex_split[1].parse()?;
                                tcp_ports.push(p);
                            }
                        }
                        "U" => {
                            if ex_split[1].contains("-") {
                                let ex_split_split: Vec<&str> =
                                    exclued_split[1].split("-").collect();
                                let start: u16 = ex_split_split[0].parse()?;
                                let end: u16 = ex_split_split[1].parse()?;
                                for p in start..=end {
                                    udp_ports.push(p);
                                }
                            } else {
                                let p: u16 = ex_split[1].parse()?;
                                udp_ports.push(p);
                            }
                        }
                        _ => (),
                    }
                } else {
                    let p: u16 = ex.parse()?;
                    ports.push(p);
                }
            }
            break;
        }
    }
    let ep = ExcludePorts {
        ports,
        tcp_ports,
        udp_ports,
    };
    Ok(ep)
}
