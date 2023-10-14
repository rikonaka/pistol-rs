use data_encoding::HEXUPPER;
use std::{collections::HashMap, fs::read_to_string};

#[derive(Debug, Clone)]
pub struct RangeValue {
    pub start: u32,
    pub end: u32,
}

impl RangeValue {
    pub fn new(start: u32, end: u32) -> RangeValue {
        RangeValue { start, end }
    }
}

#[derive(Debug, Clone)]
pub struct SingleValue {
    pub value: u32,
}

impl SingleValue {
    pub fn new(value: u32) -> SingleValue {
        SingleValue { value }
    }
}

#[derive(Debug, Clone)]
pub struct EnumValue {
    pub values: Vec<u32>,
}

impl EnumValue {
    pub fn new(values: Vec<u32>) -> EnumValue {
        EnumValue { values }
    }
}

#[derive(Debug, Clone)]
pub struct StringValue {
    pub value: String,
}

impl StringValue {
    pub fn new(value: &str) -> StringValue {
        StringValue {
            value: value.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EmptyValue {}

impl EmptyValue {
    pub fn new() -> EmptyValue {
        EmptyValue {}
    }
}

#[derive(Debug, Clone)]
pub enum NmapValueTypes {
    RangeValue(RangeValue),
    EnumValue(EnumValue),
    SingleValue(SingleValue),
    StringValue(StringValue),
    EmptyValue(EmptyValue),
}

impl NmapValueTypes {
    pub fn empty() -> NmapValueTypes {
        NmapValueTypes::EmptyValue(EmptyValue::new())
    }
    pub fn check_u32(&self, input: Option<u32>) -> bool {
        match self {
            NmapValueTypes::EnumValue(e) => match input {
                Some(input) => {
                    if e.values.contains(&input) {
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            },
            NmapValueTypes::RangeValue(r) => match input {
                Some(input) => {
                    if input >= r.start && input <= r.end {
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            },
            NmapValueTypes::SingleValue(s) => match input {
                Some(input) => {
                    if input == s.value {
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            },
            NmapValueTypes::EmptyValue(_) => match input {
                None => true,
                _ => false,
            },
            _ => panic!("Wrong type: {:?}!", self),
        }
    }
    pub fn check_string(&self, input: Option<&str>) -> bool {
        match self {
            NmapValueTypes::StringValue(s) => match input {
                Some(input) => {
                    if input == s.value {
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            },
            NmapValueTypes::EmptyValue(_) => match input {
                None => true,
                _ => false,
            },
            _ => panic!("Wrong type: {:?}!", self),
        }
    }
}

pub struct SEQ {
    pub sp: NmapValueTypes,
    pub gcd: NmapValueTypes,
    pub isr: NmapValueTypes,
    pub ti: NmapValueTypes,
    pub ci: NmapValueTypes,
    pub ii: NmapValueTypes,
    pub ss: NmapValueTypes,
    pub ts: NmapValueTypes,
}

impl SEQ {
    fn new(map: HashMap<&str, NmapValueTypes>) -> SEQ {
        let sp = match map.get("sp") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let gcd = match map.get("gcd") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let isr = match map.get("isr") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let ti = match map.get("ti") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let ci = match map.get("ci") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let ii = match map.get("ii") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let ss = match map.get("ss") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let ts = match map.get("ts") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };

        SEQ {
            sp,
            gcd,
            isr,
            ti,
            ci,
            ii,
            ss,
            ts,
        }
    }
}

pub struct OPS {
    pub o1: NmapValueTypes,
    pub o2: NmapValueTypes,
    pub o3: NmapValueTypes,
    pub o4: NmapValueTypes,
    pub o5: NmapValueTypes,
    pub o6: NmapValueTypes,
}

impl OPS {
    fn new(map: HashMap<&str, NmapValueTypes>) -> OPS {
        let o1 = match map.get("o1") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let o2 = match map.get("o2") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let o3 = match map.get("o3") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let o4 = match map.get("o4") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let o5 = match map.get("o5") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let o6 = match map.get("o6") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };

        OPS {
            o1,
            o2,
            o3,
            o4,
            o5,
            o6,
        }
    }
}

pub struct WIN {
    pub w1: NmapValueTypes,
    pub w2: NmapValueTypes,
    pub w3: NmapValueTypes,
    pub w4: NmapValueTypes,
    pub w5: NmapValueTypes,
    pub w6: NmapValueTypes,
}

impl WIN {
    fn new(map: HashMap<&str, NmapValueTypes>) -> WIN {
        let w1 = match map.get("w1") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let w2 = match map.get("w2") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let w3 = match map.get("w3") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let w4 = match map.get("w4") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let w5 = match map.get("w5") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let w6 = match map.get("w6") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };

        WIN {
            w1,
            w2,
            w3,
            w4,
            w5,
            w6,
        }
    }
}

pub struct ECN {
    pub r: NmapValueTypes,
    pub df: NmapValueTypes,
    pub t: NmapValueTypes,
    pub tg: NmapValueTypes,
    pub w: NmapValueTypes,
    pub o: NmapValueTypes,
    pub cc: NmapValueTypes,
    pub q: NmapValueTypes,
}

impl ECN {
    fn new(map: HashMap<&str, NmapValueTypes>) -> ECN {
        let r = match map.get("r") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let df = match map.get("df") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let t = match map.get("t") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let tg = match map.get("tg") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let w = match map.get("w") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let o = match map.get("o") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let cc = match map.get("cc") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let q = match map.get("q") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };

        ECN {
            r,
            df,
            t,
            tg,
            w,
            o,
            cc,
            q,
        }
    }
}

pub struct T {
    pub r: NmapValueTypes,
    pub df: NmapValueTypes,
    pub t: NmapValueTypes,
    pub tg: NmapValueTypes,
    pub s: NmapValueTypes,
    pub a: NmapValueTypes,
    pub f: NmapValueTypes,
    pub rd: NmapValueTypes,
    pub q: NmapValueTypes,
}

pub struct U1 {
    pub df: NmapValueTypes,
    pub t: NmapValueTypes,
    pub tg: NmapValueTypes,
    pub ipl: NmapValueTypes,
    pub un: NmapValueTypes,
    pub ripl: NmapValueTypes,
    pub rid: NmapValueTypes,
    pub ripck: NmapValueTypes,
    pub ruck: NmapValueTypes,
    pub rud: NmapValueTypes,
}

pub struct IE {
    pub dfi: NmapValueTypes,
    pub t: NmapValueTypes,
    pub tg: NmapValueTypes,
    pub cd: NmapValueTypes,
}

pub struct NmapDB {
    pub fingerprint: String,
    pub class: Vec<String>,
    pub cpe: String,
    pub seq: SEQ,
    pub ops: OPS,
    pub win: WIN,
    pub ecn: ECN,
    pub t1: T,
    pub t2: T,
    pub t3: T,
    pub t4: T,
    pub t5: T,
    pub t6: T,
    pub t7: T,
    pub u1: U1,
    pub ie: IE,
}

fn vec2u32(input: Vec<u8>) -> u32 {
    let mut ret: u32 = 0;
    let mut i = input.len();
    for v in input {
        let mut new_v: u32 = v as u32;
        i -= 1;
        new_v <<= i * 8;
        ret += new_v;
    }
    return ret;
}

fn value_parser_u32(info: &str) -> NmapValueTypes {
    let value_split: Vec<&str> = info.split("=").collect();
    let value = value_split[1];
    let ret = if value.contains("-") {
        // range value
        let range_value_split: Vec<&str> = value.split("-").collect();
        let start_vec = HEXUPPER.decode(&range_value_split[0].as_bytes()).unwrap();
        let end_vec = HEXUPPER.decode(&range_value_split[1].as_bytes()).unwrap();
        let start = vec2u32(start_vec);
        let end = vec2u32(end_vec);
        NmapValueTypes::RangeValue(RangeValue::new(start, end))
    } else if value.contains("|") {
        // enum value
        let enum_value_split: Vec<&str> = value.split("|").collect();
        let mut values = Vec::new();
        for e in enum_value_split {
            let e_vec = HEXUPPER.decode(e.as_bytes()).unwrap();
            let e_u32 = vec2u32(e_vec);
            values.push(e_u32);
        }
        NmapValueTypes::EnumValue(EnumValue::new(values))
    } else {
        if value.len() > 0 {
            // single value
            let single = value.parse().unwrap();
            NmapValueTypes::SingleValue(SingleValue::new(single))
        } else {
            NmapValueTypes::empty()
        }
    };
    ret
}

fn value_parser_str(info: &str) -> NmapValueTypes {
    let value_split: Vec<&str> = info.split("=").collect();
    let value = value_split[1];
    if value.len() > 0 {
        NmapValueTypes::StringValue(StringValue::new(value))
    } else {
        NmapValueTypes::empty()
    }
}

fn seq_parser(line: String) -> SEQ {
    let split_1: Vec<&str> = line.split("(").collect();
    let split_2: Vec<&str> = split_1[1].split(")").collect();
    let many_info = split_2[0];
    let info_split: Vec<&str> = many_info.split("%").collect();

    let mut map = HashMap::new();
    for info in info_split {
        if info.contains("SP") {
            let value = value_parser_u32(info);
            map.insert("sp", value);
        } else if info.contains("GCD") {
            let value = value_parser_u32(info);
            map.insert("gcd", value);
        } else if info.contains("ISR") {
            let value = value_parser_u32(info);
            map.insert("isr", value);
        } else if info.contains("TI") {
            let value = value_parser_str(info);
            map.insert("ti", value);
        } else if info.contains("CI") {
            let value = value_parser_str(info);
            map.insert("ci", value);
        } else if info.contains("II") {
            let value = value_parser_str(info);
            map.insert("ii", value);
        } else if info.contains("SS") {
            let value = value_parser_str(info);
            map.insert("ss", value);
        } else if info.contains("TS") {
            let value = value_parser_str(info);
            map.insert("ts", value);
        } else {
            panic!("New type: {}", info);
        }
    }

    SEQ::new(map)
}

fn ops_parser(line: String) -> OPS {
    let split_1: Vec<&str> = line.split("(").collect();
    let split_2: Vec<&str> = split_1[1].split(")").collect();
    let many_info = split_2[0];
    let info_split: Vec<&str> = many_info.split("%").collect();

    let mut map = HashMap::new();
    for info in info_split {
        if info.contains("O1") {
            let value = value_parser_str(info);
            map.insert("o1", value);
        } else if info.contains("O2") {
            let value = value_parser_str(info);
            map.insert("o2", value);
        } else if info.contains("O3") {
            let value = value_parser_str(info);
            map.insert("o3", value);
        } else if info.contains("O4") {
            let value = value_parser_str(info);
            map.insert("o4", value);
        } else if info.contains("O5") {
            let value = value_parser_str(info);
            map.insert("o5", value);
        } else if info.contains("O6") {
            let value = value_parser_str(info);
            map.insert("o6", value);
        } else {
            panic!("New type: {}", info);
        }
    }

    OPS::new(map)
}

fn win_parser(line: String) -> WIN {
    let split_1: Vec<&str> = line.split("(").collect();
    let split_2: Vec<&str> = split_1[1].split(")").collect();
    let many_info = split_2[0];
    let info_split: Vec<&str> = many_info.split("%").collect();

    let mut map = HashMap::new();
    for info in info_split {
        if info.contains("W1") {
            let value = value_parser_u32(info);
            map.insert("w1", value);
        } else if info.contains("W2") {
            let value = value_parser_u32(info);
            map.insert("w2", value);
        } else if info.contains("W3") {
            let value = value_parser_u32(info);
            map.insert("w3", value);
        } else if info.contains("W4") {
            let value = value_parser_u32(info);
            map.insert("w4", value);
        } else if info.contains("W5") {
            let value = value_parser_u32(info);
            map.insert("w5", value);
        } else if info.contains("W6") {
            let value = value_parser_u32(info);
            map.insert("w6", value);
        } else {
            panic!("New type: {}", info);
        }
    }
    WIN::new(map)
}

fn ecn_parser(line: String) -> ECN {
    let split_1: Vec<&str> = line.split("(").collect();
    let split_2: Vec<&str> = split_1[1].split(")").collect();
    let many_info = split_2[0];
    let info_split: Vec<&str> = many_info.split("%").collect();

    let mut map = HashMap::new();
    for info in info_split {
        if info.contains("R") {
            let value = value_parser_str(info);
            map.insert("r", value);
        } else if info.contains("DF") {
            let value = value_parser_str(info);
            map.insert("df", value);
        } else if info.contains("T") {
            let value = value_parser_u32(info);
            map.insert("t", value);
        } else if info.contains("TG") {
            let value = value_parser_u32(info);
            map.insert("tg", value);
        } else if info.contains("W") {
            let value = value_parser_u32(info);
            map.insert("w", value);
        } else if info.contains("O") {
            let value = value_parser_str(info);
            map.insert("o", value);
        } else if info.contains("CC") {
            let value = value_parser_str(info);
            map.insert("cc", value);
        } else if info.contains("Q") {
            let value = value_parser_u32(info);
            map.insert("q", value);
        } else {
            panic!("New type: {}", info);
        }
    }

    ECN::new(map)
}

fn parser() {
    let filename = "nmap-os-db";
    let lines: Vec<String> = read_to_string(filename)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();

    let mut ret = HashMap::new();
    let mut seq = None;
    let mut ops = None;
    let mut win = None;
    let mut ecn = None;
    for l in lines {
        if l.contains("#") {
            ret.insert("l1", l);
        } else if l.contains("Class") {
            ret.insert("l2", l);
        } else if l.contains("CPE") {
            ret.insert("l3", l);
        } else {
            // not comments
            // println!("{}", l);
            if l.contains("SEQ") {
                seq = Some(seq_parser(l));
            } else if l.contains("OPS") {
                ops = Some(ops_parser(l));
            } else if l.contains("WIN") {
                win = Some(ops_parser(l));
            } else if l.contains("ECN") {
                ecn = Some(ecn_parser(l))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parser() {
        parser();
    }
    #[test]
    fn test_convert() {
        let v: Vec<u8> = vec![0, 0, 1, 1];
        let r = vec2u32(v);
        println!("{}", r);

        let s = "51E80C";
        let sv = HEXUPPER.decode(&s.as_bytes()).unwrap();
        let r = vec2u32(sv);
        println!("{}", r);
    }
}
