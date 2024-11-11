use regex::Regex;
use serde::Deserialize;
use serde::Serialize;

use crate::errors::PistolErrors;
use crate::os::NmapOsDb;

/// Process standard `nmap-os-db files` and return a structure that can be processed by the program.
/// Each item in the input vec `lines` represents a line of nmap-os-db file content.
/// So just read the nmap file line by line and store it in vec for input.
pub fn nmap_os_db_parser(lines: Vec<String>) -> Result<Vec<NmapOsDb>, PistolErrors> {
    let name_reg = Regex::new(r"Fingerprint\s+(?P<name>.+)")?;
    let class_reg = Regex::new(
        r"Class\s+(?P<class1>[^|]+)\s+\|\s+(?P<class2>[^|]+)\s+\|(\|)?\s+(?P<class3>[^|]+)(\s+\|(\|)?\s+(?P<class4>[^|]+))?",
    )?;
    let cpe_reg = Regex::new(r"CPE\s+(?P<cpe>.+)")?;
    let seq_reg = Regex::new(
        r"SEQ\((SP=(?P<sp>[^%^(^)^=]+))?(R=(?P<r>[^%^(^)^=]+))?(%GCD=(?P<gcd>[^%^(^)^=]+))?(%?ISR=(?P<isr>[^%^(^)^=]+))?(%?TI=(?P<ti>[^%^(^)^=]+))?(%?CI=(?P<ci>[^%^(^)^=]+))?(%?II=(?P<ii>[^%^(^)^=]+))?(%SS=(?P<ss>[^%^(^)^=]+))?(%TS=(?P<ts>[^%^(^)^=]+))?\)",
    )?;
    let ops_reg = Regex::new(
        r"OPS\((R=(?P<r>[^%^(^)^=]+|))?(O1=(?P<o1>[^%^(^)^=]+|))?(%O2=(?P<o2>[^%^(^)^=]+|))?(%O3=(?P<o3>[^%^(^)^=]+|))?(%O4=(?P<o4>[^%^(^)^=]+|))?(%O5=(?P<o5>[^%^(^)^=]+|))?(%O6=(?P<o6>[^%^(^)^=]+|))?\)",
    )?;
    let win_reg = Regex::new(
        r"WIN\((R=(?P<r>[^%^(^)^=]+))?(W1=(?P<w1>[^%^(^)^=]+))?(%W2=(?P<w2>[^%^(^)^=]+))?(%W3=(?P<w3>[^%^(^)^=]+))?(%W4=(?P<w4>[^%^(^)^=]+))?(%W5=(?P<w5>[^%^(^)^=]+))?(%W6=(?P<w6>[^%^(^)^=]+))?\)",
    )?;
    let ecn_reg = Regex::new(
        r"ECN\(R=(?P<r>[^%^(^)^=]+|)(%DF=(?P<df>[^%^(^)^=]+|))?(%T=(?P<t>[^%^(^)^=]+|))?(%TG=(?P<tg>[^%^(^)^=]+|))?(%W=(?P<w>[^%^(^)^=]+|))?(%O=(?P<o>[^%^(^)^=]+|))?(%CC=(?P<cc>[^%^(^)^=]+|))?(%Q=(?P<q>[^%^(^)^=]+|))?\)",
    )?;
    let t1_reg = Regex::new(
        r"T1\((R=(?P<r>[^%^(^)^=]+))?(%?DF=(?P<df>[^%^(^)^=]+))?(%T=(?P<t>[^%^(^)^=]+))?(%TG=(?P<tg>[^%^(^)^=]+))?(%W=(?P<w>[^%^(^)^=]+))?(%S=(?P<s>[^%^(^)^=]+))?(%A=(?P<a>[^%^(^)^=]+))?(%F=(?P<f>[^%^(^)^=]+))?(%O=(?P<o>[^%^(^)^=]+|))?(%RD=(?P<rd>[^%^(^)^=]+))?(%Q=(?P<q>[^%^(^)^=]+|))?\)",
    )?;
    let t2_reg = Regex::new(
        r"T2\((R=(?P<r>[^%^(^)^=]+))?(%?DF=(?P<df>[^%^(^)^=]+))?(%T=(?P<t>[^%^(^)^=]+))?(%TG=(?P<tg>[^%^(^)^=]+))?(%W=(?P<w>[^%^(^)^=]+))?(%S=(?P<s>[^%^(^)^=]+))?(%A=(?P<a>[^%^(^)^=]+))?(%F=(?P<f>[^%^(^)^=]+))?(%O=(?P<o>[^%^(^)^=]+|))?(%RD=(?P<rd>[^%^(^)^=]+))?(%Q=(?P<q>[^%^(^)^=]+|))?\)",
    )?;
    let t3_reg = Regex::new(
        r"T3\((R=(?P<r>[^%^(^)^=]+))?(%?DF=(?P<df>[^%^(^)^=]+))?(%T=(?P<t>[^%^(^)^=]+))?(%TG=(?P<tg>[^%^(^)^=]+))?(%W=(?P<w>[^%^(^)^=]+))?(%S=(?P<s>[^%^(^)^=]+))?(%A=(?P<a>[^%^(^)^=]+))?(%F=(?P<f>[^%^(^)^=]+))?(%O=(?P<o>[^%^(^)^=]+|))?(%RD=(?P<rd>[^%^(^)^=]+))?(%Q=(?P<q>[^%^(^)^=]+|))?\)",
    )?;
    let t4_reg = Regex::new(
        r"T4\((R=(?P<r>[^%^(^)^=]+))?(%?DF=(?P<df>[^%^(^)^=]+))?(%T=(?P<t>[^%^(^)^=]+))?(%TG=(?P<tg>[^%^(^)^=]+))?(%W=(?P<w>[^%^(^)^=]+))?(%S=(?P<s>[^%^(^)^=]+))?(%A=(?P<a>[^%^(^)^=]+))?(%F=(?P<f>[^%^(^)^=]+))?(%O=(?P<o>[^%^(^)^=]+|))?(%RD=(?P<rd>[^%^(^)^=]+))?(%Q=(?P<q>[^%^(^)^=]+|))?\)",
    )?;
    let t5_reg = Regex::new(
        r"T5\((R=(?P<r>[^%^(^)^=]+))?(%?DF=(?P<df>[^%^(^)^=]+))?(%T=(?P<t>[^%^(^)^=]+))?(%TG=(?P<tg>[^%^(^)^=]+))?(%W=(?P<w>[^%^(^)^=]+))?(%S=(?P<s>[^%^(^)^=]+))?(%A=(?P<a>[^%^(^)^=]+))?(%F=(?P<f>[^%^(^)^=]+))?(%O=(?P<o>[^%^(^)^=]+|))?(%RD=(?P<rd>[^%^(^)^=]+))?(%Q=(?P<q>[^%^(^)^=]+|))?\)",
    )?;
    let t6_reg = Regex::new(
        r"T6\((R=(?P<r>[^%^(^)^=]+))?(%?DF=(?P<df>[^%^(^)^=]+))?(%T=(?P<t>[^%^(^)^=]+))?(%TG=(?P<tg>[^%^(^)^=]+))?(%W=(?P<w>[^%^(^)^=]+))?(%S=(?P<s>[^%^(^)^=]+))?(%A=(?P<a>[^%^(^)^=]+))?(%F=(?P<f>[^%^(^)^=]+))?(%O=(?P<o>[^%^(^)^=]+|))?(%RD=(?P<rd>[^%^(^)^=]+))?(%Q=(?P<q>[^%^(^)^=]+|))?\)",
    )?;
    let t7_reg = Regex::new(
        r"T7\((R=(?P<r>[^%^(^)^=]+))?(%?DF=(?P<df>[^%^(^)^=]+))?(%T=(?P<t>[^%^(^)^=]+))?(%TG=(?P<tg>[^%^(^)^=]+))?(%W=(?P<w>[^%^(^)^=]+))?(%S=(?P<s>[^%^(^)^=]+))?(%A=(?P<a>[^%^(^)^=]+))?(%F=(?P<f>[^%^(^)^=]+))?(%O=(?P<o>[^%^(^)^=]+|))?(%RD=(?P<rd>[^%^(^)^=]+))?(%Q=(?P<q>[^%^(^)^=]+|))?\)",
    )?;
    let u1_reg = Regex::new(
        r"U1\((R=(?P<r>[^%^(^)^=]+))?(%?DF=(?P<df>[^%^(^)^=]+))?(%T=(?P<t>[^%^(^)^=]+))?(%TG=(?P<tg>[^%^(^)^=]+))?(%IPL=(?P<ipl>[^%^(^)^=]+))?(%UN=(?P<un>[^%^(^)^=]+))?(%RIPL=(?P<ripl>[^%^(^)^=]+))?(%RID=(?P<rid>[^%^(^)^=]+))?(%RIPCK=(?P<ripck>[^%^(^)^=]+))?(%RUCK=(?P<ruck>[^%^(^)^=]+))?(%RUD=(?P<rud>[^%^(^)^=]+))?\)",
    )?;
    let ie_reg = Regex::new(
        r"IE\((R=(?P<r>[^%^)^)^=]+))?(%?DFI=(?P<dfi>[^%^)^)^=]+))?(%T=(?P<t>[^%^)^)^=]+))?(%TG=(?P<tg>[^%^)^)^=]+))?(%CD=(?P<cd>[^%^)^)^=]+))?\)",
    )?;

    let mut nmap_os_db_vec = Vec::new();

    let mut iter = lines.into_iter();

    loop {
        match iter.next() {
            Some(line) => {

                if line.starts_with("Fingerprint") {
                    let name = match name_reg.captures(&line) {
                        Some(caps) => {
                            let name = &caps["name"];
                            name.to_string()
                        }
                        None => {
                            return Err(PistolErrors::OsDbParseError {
                                name: String::from("Fingerprint"),
                                line,
                            })
                        }
                    };
                }
                match iter.next() {
                    Some(line) => (),
                    None => (),
                }
            }
            None => (),
        }

    }

    for line in iter {
        if line.starts_with("Fingerprint") {
            let name = match name_reg.captures(&line) {
                Some(caps) => {
                    let name = &caps["name"];
                    name.to_string()
                }
                None => {
                    return Err(PistolErrors::OsDbParseError {
                        name: String::from("Fingerprint"),
                        line,
                    })
                }
            };
            let class_info = match iter.next() {
                Some(line) => {
                    match name_reg.captures(&line) {
                        Some(caps) => {
                            let name = &caps["name"];
                            name.to_string()
                        }
                        None => {
                            return Err(PistolErrors::OsDbParseError {
                                name: String::from("Fingerprint"),
                                line,
                            })
                        }
                    }
                }
                None => {
                    return Err(PistolErrors::OsDbParseError {
                        name: String::from("Next"),
                        line: String::new(),
                    })
                }
            }
        }
    }

    Ok(nmap_os_db_vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_regex() {
        let nmap_os_file = include_str!("../db/nmap-os-db");
        let mut nmap_os_file_lines = Vec::new();
        for l in nmap_os_file.lines() {
            nmap_os_file_lines.push(l.to_string());
        }

        let name_reg = Regex::new(r"Fingerprint\s+(?P<name>.+)").unwrap();
        let class_reg = Regex::new(
            r"Class\s+(?P<class1>[^|]+)\s+\|\s+(?P<class2>[^|]+)\s+\|(\|)?\s+(?P<class3>[^|]+)(\s+\|(\|)?\s+(?P<class4>[^|]+))?",
        )
        .unwrap();
        let cpe_reg = Regex::new(r"CPE\s+(?P<cpe>.+)").unwrap();
        let seq_reg = Regex::new(
            r"SEQ\((SP=(?P<sp>[^%^(^)^=]+))?(R=(?P<r>[^%^(^)^=]+))?(%GCD=(?P<gcd>[^%^(^)^=]+))?(%?ISR=(?P<isr>[^%^(^)^=]+))?(%?TI=(?P<ti>[^%^(^)^=]+))?(%?CI=(?P<ci>[^%^(^)^=]+))?(%?II=(?P<ii>[^%^(^)^=]+))?(%SS=(?P<ss>[^%^(^)^=]+))?(%TS=(?P<ts>[^%^(^)^=]+))?\)",
        ).unwrap();
        let ops_reg = Regex::new(
            r"OPS\((R=(?P<r>[^%^(^)^=]+|))?(O1=(?P<o1>[^%^(^)^=]+|))?(%O2=(?P<o2>[^%^(^)^=]+|))?(%O3=(?P<o3>[^%^(^)^=]+|))?(%O4=(?P<o4>[^%^(^)^=]+|))?(%O5=(?P<o5>[^%^(^)^=]+|))?(%O6=(?P<o6>[^%^(^)^=]+|))?\)",
        ).unwrap();
        let win_reg = Regex::new(
            r"WIN\((R=(?P<r>[^%^(^)^=]+))?(W1=(?P<w1>[^%^(^)^=]+))?(%W2=(?P<w2>[^%^(^)^=]+))?(%W3=(?P<w3>[^%^(^)^=]+))?(%W4=(?P<w4>[^%^(^)^=]+))?(%W5=(?P<w5>[^%^(^)^=]+))?(%W6=(?P<w6>[^%^(^)^=]+))?\)",
        ).unwrap();
        let ecn_reg = Regex::new(
            r"ECN\(R=(?P<r>[^%^(^)^=]+|)(%DF=(?P<df>[^%^(^)^=]+|))?(%T=(?P<t>[^%^(^)^=]+|))?(%TG=(?P<tg>[^%^(^)^=]+|))?(%W=(?P<w>[^%^(^)^=]+|))?(%O=(?P<o>[^%^(^)^=]+|))?(%CC=(?P<cc>[^%^(^)^=]+|))?(%Q=(?P<q>[^%^(^)^=]+|))?\)",
        ).unwrap();
        let t1_reg = Regex::new(
            r"T1\((R=(?P<r>[^%^(^)^=]+))?(%?DF=(?P<df>[^%^(^)^=]+))?(%T=(?P<t>[^%^(^)^=]+))?(%TG=(?P<tg>[^%^(^)^=]+))?(%W=(?P<w>[^%^(^)^=]+))?(%S=(?P<s>[^%^(^)^=]+))?(%A=(?P<a>[^%^(^)^=]+))?(%F=(?P<f>[^%^(^)^=]+))?(%O=(?P<o>[^%^(^)^=]+|))?(%RD=(?P<rd>[^%^(^)^=]+))?(%Q=(?P<q>[^%^(^)^=]+|))?\)",
        ).unwrap();
        let t2_reg = Regex::new(
            r"T2\((R=(?P<r>[^%^(^)^=]+))?(%?DF=(?P<df>[^%^(^)^=]+))?(%T=(?P<t>[^%^(^)^=]+))?(%TG=(?P<tg>[^%^(^)^=]+))?(%W=(?P<w>[^%^(^)^=]+))?(%S=(?P<s>[^%^(^)^=]+))?(%A=(?P<a>[^%^(^)^=]+))?(%F=(?P<f>[^%^(^)^=]+))?(%O=(?P<o>[^%^(^)^=]+|))?(%RD=(?P<rd>[^%^(^)^=]+))?(%Q=(?P<q>[^%^(^)^=]+|))?\)",
        ).unwrap();
        let t3_reg = Regex::new(
            r"T3\((R=(?P<r>[^%^(^)^=]+))?(%?DF=(?P<df>[^%^(^)^=]+))?(%T=(?P<t>[^%^(^)^=]+))?(%TG=(?P<tg>[^%^(^)^=]+))?(%W=(?P<w>[^%^(^)^=]+))?(%S=(?P<s>[^%^(^)^=]+))?(%A=(?P<a>[^%^(^)^=]+))?(%F=(?P<f>[^%^(^)^=]+))?(%O=(?P<o>[^%^(^)^=]+|))?(%RD=(?P<rd>[^%^(^)^=]+))?(%Q=(?P<q>[^%^(^)^=]+|))?\)",
        ).unwrap();
        let t4_reg = Regex::new(
            r"T4\((R=(?P<r>[^%^(^)^=]+))?(%?DF=(?P<df>[^%^(^)^=]+))?(%T=(?P<t>[^%^(^)^=]+))?(%TG=(?P<tg>[^%^(^)^=]+))?(%W=(?P<w>[^%^(^)^=]+))?(%S=(?P<s>[^%^(^)^=]+))?(%A=(?P<a>[^%^(^)^=]+))?(%F=(?P<f>[^%^(^)^=]+))?(%O=(?P<o>[^%^(^)^=]+|))?(%RD=(?P<rd>[^%^(^)^=]+))?(%Q=(?P<q>[^%^(^)^=]+|))?\)",
        ).unwrap();
        let t5_reg = Regex::new(
            r"T5\((R=(?P<r>[^%^(^)^=]+))?(%?DF=(?P<df>[^%^(^)^=]+))?(%T=(?P<t>[^%^(^)^=]+))?(%TG=(?P<tg>[^%^(^)^=]+))?(%W=(?P<w>[^%^(^)^=]+))?(%S=(?P<s>[^%^(^)^=]+))?(%A=(?P<a>[^%^(^)^=]+))?(%F=(?P<f>[^%^(^)^=]+))?(%O=(?P<o>[^%^(^)^=]+|))?(%RD=(?P<rd>[^%^(^)^=]+))?(%Q=(?P<q>[^%^(^)^=]+|))?\)",
        ).unwrap();
        let t6_reg = Regex::new(
            r"T6\((R=(?P<r>[^%^(^)^=]+))?(%?DF=(?P<df>[^%^(^)^=]+))?(%T=(?P<t>[^%^(^)^=]+))?(%TG=(?P<tg>[^%^(^)^=]+))?(%W=(?P<w>[^%^(^)^=]+))?(%S=(?P<s>[^%^(^)^=]+))?(%A=(?P<a>[^%^(^)^=]+))?(%F=(?P<f>[^%^(^)^=]+))?(%O=(?P<o>[^%^(^)^=]+|))?(%RD=(?P<rd>[^%^(^)^=]+))?(%Q=(?P<q>[^%^(^)^=]+|))?\)",
        ).unwrap();
        let t7_reg = Regex::new(
            r"T7\((R=(?P<r>[^%^(^)^=]+))?(%?DF=(?P<df>[^%^(^)^=]+))?(%T=(?P<t>[^%^(^)^=]+))?(%TG=(?P<tg>[^%^(^)^=]+))?(%W=(?P<w>[^%^(^)^=]+))?(%S=(?P<s>[^%^(^)^=]+))?(%A=(?P<a>[^%^(^)^=]+))?(%F=(?P<f>[^%^(^)^=]+))?(%O=(?P<o>[^%^(^)^=]+|))?(%RD=(?P<rd>[^%^(^)^=]+))?(%Q=(?P<q>[^%^(^)^=]+|))?\)",
        ).unwrap();
        let u1_reg = Regex::new(
            r"U1\((R=(?P<r>[^%^(^)^=]+))?(%?DF=(?P<df>[^%^(^)^=]+))?(%T=(?P<t>[^%^(^)^=]+))?(%TG=(?P<tg>[^%^(^)^=]+))?(%IPL=(?P<ipl>[^%^(^)^=]+))?(%UN=(?P<un>[^%^(^)^=]+))?(%RIPL=(?P<ripl>[^%^(^)^=]+))?(%RID=(?P<rid>[^%^(^)^=]+))?(%RIPCK=(?P<ripck>[^%^(^)^=]+))?(%RUCK=(?P<ruck>[^%^(^)^=]+))?(%RUD=(?P<rud>[^%^(^)^=]+))?\)",
        ).unwrap();
        let ie_reg = Regex::new(
            r"IE\((R=(?P<r>[^%^)^)^=]+))?(%?DFI=(?P<dfi>[^%^)^)^=]+))?(%T=(?P<t>[^%^)^)^=]+))?(%TG=(?P<tg>[^%^)^)^=]+))?(%CD=(?P<cd>[^%^)^)^=]+))?\)",
        ).unwrap();

        for line in nmap_os_file_lines {
            if line.starts_with("Fingerprint") && !name_reg.is_match(&line) {
                println!("{}", line);
            }
            if line.starts_with("Class") && !class_reg.is_match(&line) {
                println!("{}", line);
            }
            if line.starts_with("CPE") && !cpe_reg.is_match(&line) {
                println!("{}", line);
            }
            if line.starts_with("SEQ") && !seq_reg.is_match(&line) {
                println!("{}", line);
            }
            if line.starts_with("OPS") && !ops_reg.is_match(&line) {
                println!("{}", line);
            }
            if line.starts_with("WIN") && !win_reg.is_match(&line) {
                println!("{}", line);
            }
            if line.starts_with("ECN") && !ecn_reg.is_match(&line) {
                println!("{}", line);
            }
            if line.starts_with("T1") && !t1_reg.is_match(&line) {
                println!("{}", line);
            }
            if line.starts_with("T2") && !t2_reg.is_match(&line) {
                println!("{}", line);
            }
            if line.starts_with("T3") && !t3_reg.is_match(&line) {
                println!("{}", line);
            }
            if line.starts_with("T4") && !t4_reg.is_match(&line) {
                println!("{}", line);
            }
            if line.starts_with("T5") && !t5_reg.is_match(&line) {
                println!("{}", line);
            }
            if line.starts_with("T6") && !t6_reg.is_match(&line) {
                println!("{}", line);
            }
            if line.starts_with("T7") && !t7_reg.is_match(&line) {
                println!("{}", line);
            }
            if line.starts_with("U1") && !u1_reg.is_match(&line) {
                println!("{}", line);
            }
            if line.starts_with("IE") && !ie_reg.is_match(&line) {
                println!("{}", line);
            }
        }
    }
}
