use anyhow::Result;
use regex::Regex;

#[derive(Debug, Clone, Copy)]
pub enum ProbesProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct Match {
    // This is simply the service name that the pattern matches.
    pub service: String,
    // This pattern is used to determine whether the response received matches the service given in the previous parameter.
    pub pattern: String,
    // The <versioninfo> section actually contains several optional fields.
    pub versioninfo: String,
}

#[derive(Debug, Clone)]
pub struct Probe {
    // This must be either TCP or UDP. Nmap only uses probes that match the protocol of the service it is trying to scan.
    pub protocol: ProbesProtocol,
    // This is a plain English name for the probe. It is used in service fingerprints to describe which probes elicited responses.
    pub probename: String,
    // Tells Nmap what to send.
    pub probestring: String,
    // This keyword is used to instruct Nmap not to use the given probe as a protocol-specific payload during UDP port scanning.
    pub no_payload: bool,
}

#[derive(Debug, Clone)]
pub struct ServiceProbes {
    pub probe: Probe,
    pub matchs: Vec<Match>,
}

/// Instead of getting the `Exclude` port based on the `nmap-service-probes` file,
/// we expect the user to provide a parameter to specify this value themselves.
pub fn nmap_service_probes_parser(lines: Vec<String>) -> Result<()> {
    let mut ret: Vec<ServiceProbes> = Vec::new();
    let mut sp_global: Option<Probe> = None;
    for line in lines {
        if line.contains("#") {
            continue;
        } else if line.contains("Exclude") {
            continue;
        }

        if line.starts_with("Probe") {
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
            sp_global = Some(sp);
        } else if line.starts_with("match") {
            let line_split: Vec<&str> = line.split(" ").collect();
            let service = line_split[1].to_string();
            let matchlast = line_split[2..].to_vec().join(" ");
            let matchlast_split: Vec<&str> = matchlast.split("|").collect();
            let mut pattern = matchlast_split[1].to_string();
            if matchlast.contains("|i") {
                pattern += "/i"
            } else if matchlast.contains("|s") {
                pattern += "/s";
            }
            println!("{}", line);
            println!("{}", pattern);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_spp() {
        let nmap_service_probes_str = include_str!("../db/nmap-service-probes");
        let nmap_service_probes_lines: Vec<String> = nmap_service_probes_str
            .split("\n")
            .map(|s| s.to_string())
            .collect();

        nmap_service_probes_parser(nmap_service_probes_lines).unwrap();
    }
}
