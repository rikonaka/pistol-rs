use fancy_regex::Regex as FancyRegex;
use kdam::tqdm;
use log::error;
use regex::Captures;
use regex::Regex;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;

use crate::errors::PistolErrors;
use crate::utils::unescape_string;

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
        if self.fix.len() == 0 {
            let mut versioninfo = String::new();
            if self.p.len() > 0 {
                versioninfo += &format!("p: {}", self.p);
            }
            if self.v.len() > 0 {
                versioninfo += &format!("v: {}", self.v);
            }
            if self.h.len() > 0 {
                versioninfo += &format!("h: {}", self.h);
            }
            if self.i.len() > 0 {
                versioninfo += &format!("i: {}", self.i);
            }
            if self.o.len() > 0 {
                versioninfo += &format!("o: {}", self.o);
            }
            if self.cpe.len() > 0 {
                versioninfo += &format!("cpe: {}", self.cpe);
            }
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
    pub fn check(&self, recv_str: &str) -> (Vec<Match>, Vec<SoftMatch>) {
        fn match_pattern(m: &Match, recv_str: &str) -> Result<Match, PistolErrors> {
            let re = FancyRegex::new(&m.pattern)?;
            let captures_group = re.captures(&recv_str)?;
            match captures_group {
                Some(v) => {
                    let mut versioninfo_fix = m.versioninfo.to_string();
                    for i in 0..v.len() {
                        let value = match v.get(i) {
                            Some(v) => v,
                            None => continue,
                        };
                        versioninfo_fix =
                            versioninfo_fix.replace(&format!("${}", i), value.as_str());
                    }
                    let mut new_m = m.clone();
                    new_m.versioninfo.fix = versioninfo_fix;
                    Ok(new_m)
                }
                None => Err(PistolErrors::NoMatchFound),
            }
        }

        fn softmatch_function(sm: &SoftMatch, recv_str: &str) -> Result<SoftMatch, PistolErrors> {
            let re = FancyRegex::new(&sm.pattern)?;
            if re.is_match(&recv_str)? {
                Ok(sm.clone())
            } else {
                Err(PistolErrors::NoMatchFound)
            }
        }

        let mut match_ret = Vec::new();
        let mut softmatch_ret = Vec::new();

        // match
        for m in &self.matchs {
            // println!("{}", m.pattern);
            match match_pattern(&m, recv_str) {
                Ok(m) => match_ret.push(m),
                Err(e) => match e {
                    PistolErrors::NoMatchFound => (),
                    _ => {
                        error!("match pattern error: {}", e);
                        continue;
                    }
                },
            }
        }

        // softmatch
        for sm in &self.softmatchs {
            match softmatch_function(&sm, recv_str) {
                Ok(sm) => softmatch_ret.push(sm),
                Err(e) => match e {
                    PistolErrors::NoMatchFound => (), // do noting for no match found
                    _ => {
                        error!("softmatch pattern error: {}", e);
                        continue;
                    }
                },
            }
        }
        (match_ret, softmatch_ret)
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
    fn pattern_fix(pattern: &str) -> String {
        let pattern = pattern.replace(r"\0", "\0");
        // The stupid developer wrote a bunch of ambiguous regular expressions,
        // and now I have to fix them one by one.
        let pattern = pattern.replace(r"[][\w._ ]+", r"[\]\[\w._\s]+");
        let pattern = pattern.replace(r"[][\w:.]+", r"[\]\[\w:.]+");
        let pattern = pattern.replace(
            r"([^[]+) \[[^]]+ ([\d.]+)\]",
            r"([^\[]+) \[[^\]]+ ([\d.]+)\]",
        );
        let pattern = pattern.replace(r"[][\w._:-]+", r"[\[\]\w._:-]+");
        let pattern = pattern.replace(r"[][\w.:]+", r"[\]\[\w.:]+");
        let pattern = pattern.replace(r"[^[]", r"[^\[]");
        pattern
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
            let pattern_str = pattern_fix(&pattern_str);

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
            let pattern_str = pattern_fix(&pattern_str);

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
    fn test_parser() {
        let nsp_str = include_str!("../db/nmap-service-probes");
        let mut nsp_lines = Vec::new();
        for l in nsp_str.lines() {
            nsp_lines.push(l.to_string());
        }
        let ret = nmap_service_probes_parser(nsp_lines).unwrap();
        println!("ret len: {}", ret.len());

        let mut total_reg = 0;
        let mut failed_reg = 0;

        for r in &ret {
            for m in &r.matchs {
                total_reg += 1;
                let pattern = &m.pattern;
                match FancyRegex::new(&pattern) {
                    Ok(_) => (),
                    Err(e) => {
                        failed_reg += 1;
                        println!(
                            "match service: {}, pattern: {}, error: {}",
                            &m.service, &pattern, e
                        );
                        // return ();
                    }
                }
            }
            for sm in &r.softmatchs {
                total_reg += 1;
                let pattern = &sm.pattern;
                match FancyRegex::new(&pattern) {
                    Ok(_) => (),
                    Err(e) => {
                        failed_reg += 1;
                        println!(
                            "softmatch service: {}, pattern: {}, error: {}",
                            &sm.service, &pattern, e
                        );
                        // return ();
                    }
                }
            }
        }

        println!("{}/{}", failed_reg, total_reg);

        let serialized = serde_json::to_string(&ret).unwrap();
        let mut file_write = File::create("nmap-service-probes.pistol").unwrap();
        file_write.write_all(serialized.as_bytes()).unwrap();
    }
}
