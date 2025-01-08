use escape_bytes;
use fancy_regex::Regex as FancyRegex;
use kdam::tqdm;
use log::debug;
use log::error;
use regex::Captures;
use regex::Regex;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;

use crate::errors::PistolErrors;

use super::vscan::MatchX;

fn unescape_string(input: &str) -> Result<Vec<u8>, PistolErrors> {
    let output = match escape_bytes::unescape(input.as_bytes()) {
        Ok(o) => o,
        Err(e) => {
            return Err(PistolErrors::CanNotUnescapeString {
                s: input.to_string(),
                e: format!("{:?}", e),
            })
        }
    };
    Ok(output)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ProbeProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub p: String,
    pub v: String,
    pub h: String,
    pub i: String,
    pub o: String,
    pub cpe: String,
    pub fix: String,
}

impl fmt::Display for VersionInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut versioninfo_vec = Vec::new();
        if self.fix.len() == 0 {
            if self.p.len() > 0 {
                versioninfo_vec.push(format!("p:{}", self.p));
            }
            if self.v.len() > 0 {
                versioninfo_vec.push(format!("v:{}", self.v));
            }
            if self.h.len() > 0 {
                versioninfo_vec.push(format!("h:{}", self.h));
            }
            if self.i.len() > 0 {
                versioninfo_vec.push(format!("i:{}", self.i));
            }
            if self.o.len() > 0 {
                versioninfo_vec.push(format!("o:{}", self.o));
            }
            if self.cpe.len() > 0 {
                versioninfo_vec.push(format!("{}", self.cpe));
            }
            let versioninfo = versioninfo_vec.join("\n");
            write!(f, "{}", versioninfo)
        } else {
            write!(f, "{}", self.fix)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    // This is simply the service name that the pattern matches.
    pub service: String,
    // This pattern is used to determine whether the response received matches the service given in the previous parameter.
    pub pattern: String,
    // The versioninfo section actually contains several optional fields.
    pub versioninfo: VersionInfo,
}

impl fmt::Display for Match {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.service)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftMatch {
    // This is simply the service name that the pattern matches.
    pub service: String,
    // This pattern is used to determine whether the response received matches the service given in the previous parameter.
    pub pattern: String,
}

impl fmt::Display for SoftMatch {
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
    pub probestring: Vec<u8>,
    /// This keyword is used to instruct Nmap not to use the given probe as a protocol-specific payload during UDP port scanning.
    pub no_payload: bool,
}

impl Probe {
    pub fn empty() -> Probe {
        Probe {
            probeprotocol: ProbeProtocol::Tcp,
            probename: String::new(),
            probestring: Vec::new(),
            no_payload: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceProbe {
    pub probe: Probe,
    pub matchs: Vec<Match>,
    pub softmatchs: Vec<SoftMatch>,
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
    fn pattern_fix(&self, pattern: &str) -> String {
        // This code convert C style regex format to Rust style regex format.
        let pattern = pattern.replace(r"[\xfb-\xfe]", r"(\xfb|\xfc|\xfd|\xfe)");
        let pattern = pattern.replace(r"[\x0a-\x0b]", r"(\x0a|\x0b)");
        let pattern = pattern.replace(r"[\x5e-\x60]", r"(\x5e|\x5f|\x60)");
        let pattern = pattern.replace(r"[\x60-\x62]", r"(\x60|\x61|\x62)");
        let pattern = pattern.replace(r"[\x03-\x05]", r"(\x03|\x04|\x05)");
        let pattern = pattern.replace(r"[\x8b-\x8f]", r"(\x8b|\x8c|\x8d|\x8e|\x8f)");
        let pattern = pattern.replace(r"[\x17-\x1a]", r"(\x17|\x18|\x19|\x1a)");
        let pattern = pattern.replace(r"[\x6d-\x6f]", r"(\x6d|\x6f)");
        let pattern = pattern.replace(r"[\x6b-\x6d]", r"(\x6b|\x6c|\x6d)");
        let pattern = pattern.replace(r"[\x69-\x6b]", r"(\x69|\x6a|\x6b)");
        let pattern = pattern.replace(r"[\x4a-\x4c]", r"(\x4a|\x4b|\x4c)");
        let pattern = pattern.replace(r"[\x48-\x4a]", r"(\x48|\x49|\x4a)");
        let pattern = pattern.replace(r"[\x46-\x48]", r"(\x46|\x47|\x48)");
        // destructive match, too much values if I replace it to below format
        let pattern = pattern.replace(r"[\x40-\x90]", r"\x[a-f0-9]{2}");
        let pattern = pattern.replace(r"[\x3e-\x8e]", r"\x[a-f0-9]{2}");
        let pattern = pattern.replace(r"[\x3c-\x8c]", r"\x[a-f0-9]{2}");
        let pattern = pattern.replace(r"[\x50-\x90]", r"\x[a-f0-9]{2}");
        let pattern = pattern.replace(r"[\x4e-\x8e]", r"\x[a-f0-9]{2}");
        let pattern = pattern.replace(r"[\x4c-\x8c]", r"\x[a-f0-9]{2}");
        let pattern = pattern.replace(r"[\x90-\xdb]", r"\x[a-f0-9]{2}");
        let pattern = pattern.replace(r"[\x90-\xdb]", r"\x[a-f0-9]{2}");
        let pattern = pattern.replace(r"[\x90-\xd8]", r"\x[a-f0-9]{2}");
        let pattern = pattern.replace(r"[\xad-\xd8]", r"\x[a-f0-9]{2}");
        // The stupid developer wrote a bunch of ambiguous regular expressions,
        // and now I have to fix them one by one.
        let pattern = pattern.replace(r"[][\w._ ]+", r"[\]\[\w._\s]+");
        let pattern = pattern.replace(r"[][\w:.]+", r"[\]\[\w:.]+");
        let pattern = pattern.replace(
            r"([^[]+) \[[^]]+ ([\d.]+)\]",
            r"([^\[]+) \[[^\]]+ ([\d.]+)\]",
        );
        let pattern = pattern.replace(r"[][\w._:-]+", r"[\]\[\w._:-]+");
        let pattern = pattern.replace(r"[][\w.:]+", r"[\]\[\w.:]+");
        let pattern = pattern.replace(r"[^[]", r"[^\[]");

        let pattern = match FancyRegex::new(r"(?<!\\)\\x") {
            Ok(regex) => regex.replace_all(&pattern, r"\\x").to_string(),
            Err(e) => {
                error!("special regex failed: {}", e);
                pattern
            }
        };
        let pattern = match FancyRegex::new(r"(?<!\\)\\0") {
            Ok(regex) => regex.replace_all(&pattern, r"\\0").to_string(),
            Err(e) => {
                error!("special regex failed: {}", e);
                pattern
            }
        };
        // leave this codes here
        // let pattern = match FancyRegex::new(r"(?<!\\)\\r") {
        //     Ok(regex) => regex.replace_all(&pattern, r"\\r").to_string(),
        //     Err(e) => {
        //         error!("special regex failed: {}", e);
        //         pattern
        //     }
        // };
        // let pattern = match FancyRegex::new(r"(?<!\\)\\n") {
        //     Ok(regex) => regex.replace_all(&pattern, r"\\n").to_string(),
        //     Err(e) => {
        //         error!("special regex failed: {}", e);
        //         pattern
        //     }
        // };
        // let pattern = match FancyRegex::new(r"(?<!\\)\\t") {
        //     Ok(regex) => regex.replace_all(&pattern, r"\\t").to_string(),
        //     Err(e) => {
        //         error!("special regex failed: {}", e);
        //         pattern
        //     }
        // };

        pattern
    }
    fn match_pattern(&self, m: &Match, recv_str: &str) -> Result<Match, PistolErrors> {
        let new_pattern = self.pattern_fix(&m.pattern);

        let re = FancyRegex::new(&new_pattern)?;
        let captures_group = re.captures(recv_str)?;
        match captures_group {
            Some(v) => {
                let mut versioninfo_fix = m.versioninfo.to_string();
                for i in 0..v.len() {
                    let value = match v.get(i) {
                        Some(v) => v,
                        None => continue,
                    };
                    versioninfo_fix = versioninfo_fix.replace(&format!("${}", i), value.as_str());
                }
                let mut new_m = m.clone();
                new_m.versioninfo.fix = versioninfo_fix;
                Ok(new_m)
            }
            None => {
                // if m.pattern.contains(r"^HTTP/1\.[01] \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: Apache[/ ](\d[-.\w]+) ([^\r\n]+)") {
                //     debug!("match {}", new_pattern);
                //     debug!("source: {}", recv_str);
                // }
                Err(PistolErrors::NoMatchFound) // avoid to using Option<'_> here make less code
            }
        }
    }
    fn softmatch_function(
        &self,
        sm: &SoftMatch,
        recv_str: &str,
    ) -> Result<SoftMatch, PistolErrors> {
        let new_pattern = self.pattern_fix(&sm.pattern);
        let re = FancyRegex::new(&new_pattern)?;
        if re.is_match(recv_str)? {
            Ok(sm.clone())
        } else {
            Err(PistolErrors::NoMatchFound)
        }
    }
    pub fn check(&self, recv_str: &str) -> Option<MatchX> {
        let mut match_ret = Vec::new();
        let mut softmatch_ret = Vec::new();

        // match
        for m in &self.matchs {
            match self.match_pattern(&m, recv_str) {
                Ok(m) => {
                    match_ret.push(m);
                    break;
                }
                Err(e) => match e {
                    PistolErrors::NoMatchFound => (),
                    _ => {
                        error!("match pattern error: {}", e);
                        continue;
                    }
                },
            }
        }

        if match_ret.len() == 0 {
            // softmatch
            for sm in &self.softmatchs {
                match self.softmatch_function(&sm, recv_str) {
                    Ok(sm) => {
                        softmatch_ret.push(sm);
                        break;
                    }
                    Err(e) => match e {
                        PistolErrors::NoMatchFound => (), // do noting for no match found
                        _ => {
                            error!("softmatch pattern error: {}", e);
                            continue;
                        }
                    },
                }
            }
        }
        debug!(
            "match: {}, softmatch: {}",
            match_ret.len(),
            softmatch_ret.len()
        );
        if match_ret.len() > 0 {
            Some(MatchX::Match(match_ret[0].clone()))
        } else if softmatch_ret.len() > 0 {
            Some(MatchX::SoftMatch(softmatch_ret[0].clone()))
        } else {
            None
        }
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
        r"Probe (?P<probeprotocol>[^\s]+) (?P<probename>[^\s]+) q\|(?P<probestring>[^\|]+|)\|(.+)?",
    )?;
    let ports_reg = Regex::new(r"ports (?P<ports>[\d,-]+)")?;
    let sslports_reg = Regex::new(r"sslports (?P<sslports>[\d,-]+)")?;
    let totalwaitms_reg = Regex::new(r"totalwaitms (?P<totalwaitms>[\d]+)")?;
    let tcpwrappedms_reg = Regex::new(r"tcpwrappedms (?P<tcpwrappedms>[\d]+)")?;
    let rarity_reg = Regex::new(r"rarity (?P<rarity>[\d]+)")?;

    let match_split_symbol = vec![r"\|", "/", "=", "%", "@"];
    let mut match_regs = Vec::new();
    for s in &match_split_symbol {
        let p = format!(
            r"match (?P<service>.+) m{s}(?P<pattern>[^{s}]+){s}(?P<modifiers>\w+)?( p/(?P<p>[^/]+)/)?( v/(?P<v>[^/]+)/)?( h/(?P<h>[^/]+)/)?( i/(?P<i>[^/]+)/)?( o/(?P<o>[^/]+)/)?( (?P<cpe>cpe:/[^/]+)/(\w)?)?"
        );
        let reg = Regex::new(&p)?;
        match_regs.push(reg);
    }
    let mut softmatch_regs = Vec::new();
    for s in &match_split_symbol {
        let p = format!(
            r"softmatch (?P<service>[^\s]+) m{s}(?P<pattern>[^{s}]+){s}(?P<modifiers>\w+)?"
        );
        let reg = Regex::new(&p)?;
        softmatch_regs.push(reg);
    }
    // lazy code
    fn do_regex_match<'a>(regs: &'a [Regex], line: &'a str) -> Option<Captures<'a>> {
        for reg in regs {
            match reg.captures(line) {
                Some(caps) => {
                    return Some(caps);
                }
                None => (),
            }
        }
        None
    }

    let fallback_reg = Regex::new(r"fallback (?P<fallback>[\w\d,]+)")?;

    let mut ret_v: Vec<ServiceProbe> = Vec::new();
    let mut probe_v: Probe = Probe::empty();
    let mut ports_v: Vec<u16> = Vec::new();
    let mut sslports_v: Vec<u16> = Vec::new();
    let mut totalwaitms_v: usize = 0;
    let mut tcpwrappedms_v: usize = 0;
    let mut rarity_v: usize = 0;
    let mut match_v: Vec<Match> = Vec::new();
    let mut softmatch_v: Vec<SoftMatch> = Vec::new();
    let mut fallback_v: Vec<String> = Vec::new();

    let mut first_probe = true;

    for line in tqdm!(lines.iter()) {
        if line.starts_with("#") || line.trim().len() == 0 {
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
            }

            first_probe = false;
            /* probe name part */
            let (probeprotocol, probename, probestring) = match probe_name_reg.captures(&line) {
                Some(caps) => {
                    let probeprotocol = caps.name("probeprotocol").map_or("", |m| m.as_str());
                    let probename = caps.name("probename").map_or("", |m| m.as_str());
                    let probestring = caps.name("probestring").map_or("", |m| m.as_str());
                    let probestring = unescape_string(&probestring)?;
                    (
                        probeprotocol.trim().to_string(),
                        probename.trim().to_string(),
                        probestring,
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
            let caps = match do_regex_match(&match_regs, &line) {
                Some(caps) => caps,
                None => {
                    return Err(PistolErrors::ServiceProbesParseError {
                        name: String::from("match"),
                        line: line.to_string(),
                    })
                }
            };

            let service_str = caps.name("service").map_or("", |m| m.as_str());
            let pattern_str = caps.name("pattern").map_or("", |m| m.as_str());
            let modifiers_str = caps.name("modifiers").map_or("", |m| m.as_str());
            let p_str = caps.name("p").map_or("", |m| m.as_str());
            let v_str = caps.name("v").map_or("", |m| m.as_str());
            let h_str = caps.name("h").map_or("", |m| m.as_str());
            let i_str = caps.name("i").map_or("", |m| m.as_str());
            let o_str = caps.name("o").map_or("", |m| m.as_str());
            let cpe_str = caps.name("cpe").map_or("", |m| m.as_str());

            let pattern_str = if modifiers_str.trim().len() > 0 {
                format!("(?{}){}", modifiers_str.trim(), pattern_str)
            } else {
                pattern_str.to_string()
            };
            // let pattern_str = pattern_fix(&pattern_str);

            let versioninfo = VersionInfo {
                p: p_str.trim().to_string(),
                v: v_str.trim().to_string(),
                h: h_str.trim().to_string(),
                i: i_str.trim().to_string(),
                o: o_str.trim().to_string(),
                cpe: cpe_str.trim().to_string(),
                fix: String::new(),
            };
            let m = Match {
                service: service_str.to_string(),
                pattern: pattern_str.to_string(),
                versioninfo,
            };
            match_v.push(m);
        } else if line.starts_with("softmatch") {
            let caps = match do_regex_match(&softmatch_regs, &line) {
                Some(caps) => caps,
                None => {
                    return Err(PistolErrors::ServiceProbesParseError {
                        name: String::from("match"),
                        line: line.to_string(),
                    })
                }
            };

            let service_str = caps.name("service").map_or("", |m| m.as_str());
            let pattern_str = caps.name("pattern").map_or("", |m| m.as_str());
            let modifiers_str = caps.name("modifiers").map_or("", |m| m.as_str());

            let pattern_str = if modifiers_str.trim().len() > 0 {
                format!("(?{}){}", modifiers_str.trim(), pattern_str)
            } else {
                pattern_str.to_string()
            };
            // let pattern_str = pattern_fix(&pattern_str);

            let sm = SoftMatch {
                service: service_str.trim().to_string(),
                pattern: pattern_str.trim().to_string(),
            };
            softmatch_v.push(sm);
        } else if line.starts_with("fallback") {
            let fallback = match fallback_reg.captures(&line) {
                Some(caps) => {
                    let fallback_str = caps.name("fallback").map_or("", |m| m.as_str());
                    fallback_str
                }
                None => {
                    return Err(PistolErrors::ServiceProbesParseError {
                        name: String::from("fallback"),
                        line: line.to_string(),
                    })
                }
            };
            fallback_v.push(fallback.trim().to_string());
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

#[cfg(test)]
mod tests {
    use super::*;
    use fancy_regex::Regex as FancyRegex;
    use std::fs::File;
    use std::io::Write;
    #[test]
    #[ignore]
    fn test_parser() {
        // use crate::Logger;
        // let _ = Logger::init_debug_logging();
        let nsp_str = include_str!("../db/nmap-service-probes");
        let mut nsp_lines = Vec::new();
        for l in nsp_str.lines() {
            nsp_lines.push(l.to_string());
        }
        let ret = nmap_service_probes_parser(nsp_lines).unwrap();
        println!("ret len: {}", ret.len());

        let serialized = serde_json::to_string(&ret).unwrap();
        let mut file_write = File::create("nmap-service-probes.pistol").unwrap();
        file_write.write_all(serialized.as_bytes()).unwrap();
    }
    #[test]
    fn test_gen() {
        let test_str = r"[\x40-\x90]";
        let test_str = test_str.replace("]", "").replace("[", "");
        let test_split: Vec<&str> = test_str.split("-").collect();
        let start = test_split[0];
        let end = test_split[1];

        let start_ues = unescape_string(&start).unwrap();
        let end_ues = unescape_string(&end).unwrap();

        let start = start_ues[0];
        let end = end_ues[0];

        let mut ret_string = String::from("(");
        for i in start..=end {
            let tmp = format!("\\x{:02x}", i);
            ret_string += &tmp;
            ret_string += "|"
        }
        ret_string.pop();
        ret_string += ")";
        println!("{}", ret_string);
    }
    #[test]
    fn test_new_method() {
        let text = r"abc\xdef\\xghi\xjkl";
        let re = FancyRegex::new(r"(?<!\\)\\x").unwrap();
        let result = re.replace_all(text, r"\\x");
        println!("{}", result);
    }
    #[test]
    fn test_unescape() {
        let test_str = r"\x80\0\0\x28\x72\xFE\x1D\x13\0\0\0\0\0\0\0\x02\0\x01\x86\xA0\0\x01\x97\x7C\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let output = unescape_string(&test_str).unwrap();
        println!("{:?}", output);
    }
}
