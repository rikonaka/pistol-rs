use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::utils::Hex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RangeValueTypes {
    Left,  // 10 <= x
    Right, // x <= 20
    Both,  // 10 <= x <= 20
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeValue {
    pub start: u32,
    pub end: u32,
    pub range_value_type: RangeValueTypes,
}

impl RangeValue {
    pub fn new(start: u32, end: u32, range_value_type: RangeValueTypes) -> RangeValue {
        RangeValue {
            start,
            end,
            range_value_type,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleValue {
    pub value: u32,
}

impl SingleValue {
    pub fn new(value: u32) -> SingleValue {
        SingleValue { value }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmptyValue {}

impl EmptyValue {
    pub fn new() -> EmptyValue {
        EmptyValue {}
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixValue {
    pub range_values: Vec<RangeValue>,
    pub single_values: Vec<SingleValue>,
}

impl MixValue {
    pub fn new(range_value: Vec<RangeValue>, single_value: Vec<SingleValue>) -> MixValue {
        MixValue {
            range_values: range_value,
            single_values: single_value,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NmapOsDbValueTypes {
    StringValue(StringValue),
    EmptyValue(EmptyValue),
    MixValue(MixValue), // u32, example: GCD=1-6|>5000
}

impl NmapOsDbValueTypes {
    pub fn empty() -> NmapOsDbValueTypes {
        NmapOsDbValueTypes::EmptyValue(EmptyValue::new())
    }
    pub fn within_u32(&self, input: Option<u32>) -> bool {
        match self {
            NmapOsDbValueTypes::EmptyValue(_) => match input {
                None => true,
                _ => false,
            },
            NmapOsDbValueTypes::MixValue(m) => match input {
                Some(input) => {
                    let m = m.clone();
                    for r in m.range_values {
                        match r.range_value_type {
                            RangeValueTypes::Both => {
                                if input >= r.start && input <= r.end {
                                    return true;
                                }
                            }
                            RangeValueTypes::Left => {
                                if input >= r.start {
                                    return true;
                                }
                            }
                            RangeValueTypes::Right => {
                                if input <= r.end {
                                    return true;
                                }
                            }
                        }
                    }
                    for s in m.single_values {
                        if input == s.value {
                            return true;
                        }
                    }
                    false
                }
                _ => false,
            },
            _ => panic!("Wrong type: {:?}!", self),
        }
    }
    pub fn check_string(&self, input: Option<&str>) -> bool {
        match self {
            NmapOsDbValueTypes::StringValue(s) => match input {
                Some(input) => {
                    if input == s.value {
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            },
            NmapOsDbValueTypes::EmptyValue(_) => match input {
                None => true,
                _ => false,
            },
            _ => panic!("Wrong type: {:?}!", self),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SEQ {
    pub sp: NmapOsDbValueTypes,
    pub gcd: NmapOsDbValueTypes,
    pub isr: NmapOsDbValueTypes,
    pub ti: NmapOsDbValueTypes,
    pub ci: NmapOsDbValueTypes,
    pub ii: NmapOsDbValueTypes,
    pub ss: NmapOsDbValueTypes,
    pub ts: NmapOsDbValueTypes,
    pub r: NmapOsDbValueTypes,
}

impl SEQ {
    fn new(map: HashMap<&str, NmapOsDbValueTypes>) -> SEQ {
        let sp = match map.get("sp") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let gcd = match map.get("gcd") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let isr = match map.get("isr") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let ti = match map.get("ti") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let ci = match map.get("ci") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let ii = match map.get("ii") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let ss = match map.get("ss") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let ts = match map.get("ts") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let r = match map.get("r") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
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
            r,
        }
    }
    fn parser(line: String) -> SEQ {
        let split_1: Vec<&str> = line.split("(").collect();
        let split_2: Vec<&str> = split_1[1].split(")").collect();
        let many_info = split_2[0];
        let info_split: Vec<&str> = many_info.split("%").collect();

        let mut map = HashMap::new();
        for info in info_split {
            if info.contains("SP=") {
                let value = value_parser_u32(info).unwrap();
                map.insert("sp", value);
            } else if info.contains("GCD=") {
                let value = value_parser_u32(info).unwrap();
                map.insert("gcd", value);
            } else if info.contains("ISR=") {
                let value = value_parser_u32(info).unwrap();
                map.insert("isr", value);
            } else if info.contains("TI=") {
                let value = value_parser_str(info);
                map.insert("ti", value);
            } else if info.contains("CI=") {
                let value = value_parser_str(info);
                map.insert("ci", value);
            } else if info.contains("II=") {
                let value = value_parser_str(info);
                map.insert("ii", value);
            } else if info.contains("SS=") {
                let value = value_parser_str(info);
                map.insert("ss", value);
            } else if info.contains("TS=") {
                let value = value_parser_str(info);
                map.insert("ts", value);
            } else if info.contains("R=") {
                let value = value_parser_str(info);
                map.insert("r", value);
            } else {
                panic!("New type: {}", info);
            }
        }

        SEQ::new(map)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OPS {
    pub o1: NmapOsDbValueTypes,
    pub o2: NmapOsDbValueTypes,
    pub o3: NmapOsDbValueTypes,
    pub o4: NmapOsDbValueTypes,
    pub o5: NmapOsDbValueTypes,
    pub o6: NmapOsDbValueTypes,
    pub r: NmapOsDbValueTypes,
}

impl OPS {
    fn new(map: HashMap<&str, NmapOsDbValueTypes>) -> OPS {
        let o1 = match map.get("o1") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let o2 = match map.get("o2") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let o3 = match map.get("o3") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let o4 = match map.get("o4") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let o5 = match map.get("o5") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let o6 = match map.get("o6") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let r = match map.get("r") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };

        OPS {
            o1,
            o2,
            o3,
            o4,
            o5,
            o6,
            r,
        }
    }
    fn parser(line: String) -> OPS {
        let split_1: Vec<&str> = line.split("(").collect();
        let split_2: Vec<&str> = split_1[1].split(")").collect();
        let many_info = split_2[0];
        let info_split: Vec<&str> = many_info.split("%").collect();

        let mut map = HashMap::new();
        for info in info_split {
            if info.contains("O1=") {
                let value = value_parser_str(info);
                map.insert("o1", value);
            } else if info.contains("O2=") {
                let value = value_parser_str(info);
                map.insert("o2", value);
            } else if info.contains("O3=") {
                let value = value_parser_str(info);
                map.insert("o3", value);
            } else if info.contains("O4=") {
                let value = value_parser_str(info);
                map.insert("o4", value);
            } else if info.contains("O5=") {
                let value = value_parser_str(info);
                map.insert("o5", value);
            } else if info.contains("O6=") {
                let value = value_parser_str(info);
                map.insert("o6", value);
            } else if info.contains("R=") {
                let value = value_parser_str(info);
                map.insert("r", value);
            } else {
                panic!("New type: {}", info);
            }
        }

        OPS::new(map)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WIN {
    pub w1: NmapOsDbValueTypes,
    pub w2: NmapOsDbValueTypes,
    pub w3: NmapOsDbValueTypes,
    pub w4: NmapOsDbValueTypes,
    pub w5: NmapOsDbValueTypes,
    pub w6: NmapOsDbValueTypes,
    pub r: NmapOsDbValueTypes,
}

impl WIN {
    fn new(map: HashMap<&str, NmapOsDbValueTypes>) -> WIN {
        let w1 = match map.get("w1") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let w2 = match map.get("w2") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let w3 = match map.get("w3") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let w4 = match map.get("w4") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let w5 = match map.get("w5") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let w6 = match map.get("w6") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let r = match map.get("r") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };

        WIN {
            w1,
            w2,
            w3,
            w4,
            w5,
            w6,
            r,
        }
    }
    fn parser(line: String) -> WIN {
        let split_1: Vec<&str> = line.split("(").collect();
        let split_2: Vec<&str> = split_1[1].split(")").collect();
        let many_info = split_2[0];
        let info_split: Vec<&str> = many_info.split("%").collect();

        let mut map = HashMap::new();
        for info in info_split {
            if info.contains("W1=") {
                let value = value_parser_u32(info).unwrap();
                map.insert("w1", value);
            } else if info.contains("W2=") {
                let value = value_parser_u32(info).unwrap();
                map.insert("w2", value);
            } else if info.contains("W3=") {
                let value = value_parser_u32(info).unwrap();
                map.insert("w3", value);
            } else if info.contains("W4=") {
                let value = value_parser_u32(info).unwrap();
                map.insert("w4", value);
            } else if info.contains("W5=") {
                let value = value_parser_u32(info).unwrap();
                map.insert("w5", value);
            } else if info.contains("W6=") {
                let value = value_parser_u32(info).unwrap();
                map.insert("w6", value);
            } else if info.contains("R=") {
                let value = value_parser_str(info);
                map.insert("r", value);
            } else {
                panic!("New type: {}", info);
            }
        }
        WIN::new(map)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECN {
    pub r: NmapOsDbValueTypes,
    pub df: NmapOsDbValueTypes,
    pub t: NmapOsDbValueTypes,
    pub tg: NmapOsDbValueTypes,
    pub w: NmapOsDbValueTypes,
    pub o: NmapOsDbValueTypes,
    pub cc: NmapOsDbValueTypes,
    pub q: NmapOsDbValueTypes,
    pub s: NmapOsDbValueTypes,
    pub a: NmapOsDbValueTypes,
    pub f: NmapOsDbValueTypes,
    pub rd: NmapOsDbValueTypes,
}

impl ECN {
    fn new(map: HashMap<&str, NmapOsDbValueTypes>) -> ECN {
        let r = match map.get("r") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let df = match map.get("df") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let t = match map.get("t") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let tg = match map.get("tg") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let w = match map.get("w") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let o = match map.get("o") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let cc = match map.get("cc") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let q = match map.get("q") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let s = match map.get("s") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let a = match map.get("a") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let f = match map.get("f") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let rd = match map.get("rd") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
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
            s,
            a,
            f,
            rd,
        }
    }
    fn parser(line: String) -> ECN {
        let split_1: Vec<&str> = line.split("(").collect();
        let split_2: Vec<&str> = split_1[1].split(")").collect();
        let many_info = split_2[0];
        let info_split: Vec<&str> = many_info.split("%").collect();

        let mut map = HashMap::new();
        for info in info_split {
            if info.contains("R=") {
                let value = value_parser_str(info);
                map.insert("r", value);
            } else if info.contains("DF=") {
                let value = value_parser_str(info);
                map.insert("df", value);
            } else if info.contains("T=") {
                let value = value_parser_u32(info).unwrap();
                map.insert("t", value);
            } else if info.contains("TG=") {
                let value = value_parser_u32(info).unwrap();
                map.insert("tg", value);
            } else if info.contains("W=") {
                let value = value_parser_u32(info).unwrap();
                map.insert("w", value);
            } else if info.contains("O=") {
                let value = value_parser_str(info);
                map.insert("o", value);
            } else if info.contains("CC=") {
                let value = value_parser_str(info);
                map.insert("cc", value);
            } else if info.contains("Q=") {
                let value = value_parser_str(info);
                map.insert("q", value);
            } else if info.contains("S=") {
                let value = value_parser_str(info);
                map.insert("s", value);
            } else if info.contains("A=") {
                let value = value_parser_str(info);
                map.insert("a", value);
            } else if info.contains("F=") {
                let value = value_parser_str(info);
                map.insert("f", value);
            } else if info.contains("RD=") {
                let value = value_parser_u32(info).unwrap();
                map.insert("rd", value);
            } else {
                panic!("New type: {}", info);
            }
        }

        ECN::new(map)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TX {
    pub r: NmapOsDbValueTypes,
    pub df: NmapOsDbValueTypes,
    pub t: NmapOsDbValueTypes,
    pub tg: NmapOsDbValueTypes,
    pub w: NmapOsDbValueTypes,
    pub s: NmapOsDbValueTypes,
    pub a: NmapOsDbValueTypes,
    pub f: NmapOsDbValueTypes,
    pub o: NmapOsDbValueTypes,
    pub rd: NmapOsDbValueTypes,
    pub q: NmapOsDbValueTypes,
}

impl TX {
    fn new(map: HashMap<&str, NmapOsDbValueTypes>) -> TX {
        let r = match map.get("r") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let df = match map.get("df") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let t = match map.get("t") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let tg = match map.get("tg") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let w = match map.get("tg") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let s = match map.get("s") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let a = match map.get("a") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let f = match map.get("f") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let o = match map.get("o") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let rd = match map.get("RD") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let q = match map.get("q") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };

        TX {
            r,
            df,
            t,
            tg,
            w,
            s,
            a,
            f,
            o,
            rd,
            q,
        }
    }
    fn parser(line: String) -> TX {
        let split_1: Vec<&str> = line.split("(").collect();
        let split_2: Vec<&str> = split_1[1].split(")").collect();
        let many_info = split_2[0];
        let info_split: Vec<&str> = many_info.split("%").collect();

        let mut map = HashMap::new();
        for info in info_split {
            if info.contains("R=") {
                let value = value_parser_str(info);
                map.insert("r", value);
            } else if info.contains("DF=") {
                let value = value_parser_str(info);
                map.insert("df", value);
            } else if info.contains("T=") {
                let value = value_parser_u32(info).unwrap();
                map.insert("t", value);
            } else if info.contains("TG=") {
                let value = value_parser_u32(info).unwrap();
                map.insert("tg", value);
            } else if info.contains("W=") {
                let value = value_parser_u32(info).unwrap();
                map.insert("w", value);
            } else if info.contains("S=") {
                let value = value_parser_str(info);
                map.insert("s", value);
            } else if info.contains("A=") {
                let value = value_parser_str(info);
                map.insert("a", value);
            } else if info.contains("F=") {
                let value = value_parser_str(info);
                map.insert("f", value);
            } else if info.contains("O=") {
                let value = value_parser_str(info);
                map.insert("o", value);
            } else if info.contains("RD=") {
                let value = value_parser_str(info);
                map.insert("rd", value);
            } else if info.contains("Q=") {
                let value = value_parser_str(info);
                map.insert("q", value);
            } else {
                panic!("New type: {}", info);
            }
        }

        TX::new(map)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct U1 {
    pub r: NmapOsDbValueTypes,
    pub df: NmapOsDbValueTypes,
    pub t: NmapOsDbValueTypes,
    pub tg: NmapOsDbValueTypes,
    pub ipl: NmapOsDbValueTypes,
    pub un: NmapOsDbValueTypes,
    pub ripl: NmapOsDbValueTypes,
    pub rid: NmapOsDbValueTypes,
    pub ripck: NmapOsDbValueTypes,
    pub ruck: NmapOsDbValueTypes,
    pub rud: NmapOsDbValueTypes,
}

impl U1 {
    fn new(map: HashMap<&str, NmapOsDbValueTypes>) -> U1 {
        let r = match map.get("r") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let df = match map.get("df") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let t = match map.get("t") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let tg = match map.get("tg") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let ipl = match map.get("ipl") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let un = match map.get("un") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let ripl = match map.get("ripl") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let rid = match map.get("rid") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let ripck = match map.get("ripck") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let ruck = match map.get("ruck") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let rud = match map.get("rud") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };

        U1 {
            r,
            df,
            t,
            tg,
            ipl,
            un,
            ripl,
            rid,
            ripck,
            ruck,
            rud,
        }
    }
    fn parser(line: String) -> U1 {
        let split_1: Vec<&str> = line.split("(").collect();
        let split_2: Vec<&str> = split_1[1].split(")").collect();
        let many_info = split_2[0];
        let info_split: Vec<&str> = many_info.split("%").collect();

        let mut map = HashMap::new();
        for info in info_split {
            if info.contains("R=") {
                let value = value_parser_str(info);
                map.insert("r", value);
            } else if info.contains("DF=") {
                let value = value_parser_str(info);
                map.insert("df", value);
            } else if info.contains("T=") {
                let value = value_parser_str(info);
                map.insert("t", value);
            } else if info.contains("TG=") {
                let value = value_parser_str(info);
                map.insert("tg", value);
            } else if info.contains("IPL=") {
                let value = value_parser_str(info);
                map.insert("ipl", value);
            } else if info.contains("UN=") {
                let value = value_parser_str(info);
                map.insert("un", value);
            } else if info.contains("RIPL=") {
                let value = value_parser_str(info);
                map.insert("ripl", value);
            } else if info.contains("RID=") {
                let value = value_parser_str(info);
                map.insert("rid", value);
            } else if info.contains("RIPCK=") {
                let value = value_parser_str(info);
                map.insert("ripck", value);
            } else if info.contains("RUCK=") {
                let value = value_parser_str(info);
                map.insert("ruck", value);
            } else if info.contains("RUD=") {
                let value = value_parser_str(info);
                map.insert("rud", value);
            } else {
                panic!("New type: {}", info);
            }
        }

        U1::new(map)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IE {
    pub dfi: NmapOsDbValueTypes,
    pub t: NmapOsDbValueTypes,
    pub tg: NmapOsDbValueTypes,
    pub cd: NmapOsDbValueTypes,
}

impl IE {
    fn new(map: HashMap<&str, NmapOsDbValueTypes>) -> IE {
        let dfi = match map.get("dfi") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let t = match map.get("t") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let tg = match map.get("tg") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
        let cd = match map.get("cd") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };

        IE { dfi, t, tg, cd }
    }
    fn parser(line: String) -> IE {
        let split_1: Vec<&str> = line.split("(").collect();
        let split_2: Vec<&str> = split_1[1].split(")").collect();
        let many_info = split_2[0];
        let info_split: Vec<&str> = many_info.split("%").collect();

        let mut map = HashMap::new();
        for info in info_split {
            if info.contains("R=") {
                let value = value_parser_str(info);
                map.insert("r", value);
            } else if info.contains("DFI=") {
                let value = value_parser_str(info);
                map.insert("dfi", value);
            } else if info.contains("T=") {
                let value = value_parser_str(info);
                map.insert("t", value);
            } else if info.contains("TG=") {
                let value = value_parser_str(info);
                map.insert("tg", value);
            } else if info.contains("CD=") {
                let value = value_parser_str(info);
                map.insert("cd", value);
            } else {
                panic!("New type: {}", info);
            }
        }

        IE::new(map)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapOsDb {
    pub info: String,
    pub fingerprint: String,
    pub class: String,
    pub cpe: String,
    pub seq: SEQ,
    pub ops: OPS,
    pub win: WIN,
    pub ecn: ECN,
    pub t1: TX,
    pub t2: TX,
    pub t3: TX,
    pub t4: TX,
    pub t5: TX,
    pub t6: TX,
    pub t7: TX,
    pub u1: U1,
    pub ie: IE,
}

fn value_parser_u32(info: &str) -> Result<NmapOsDbValueTypes> {
    let value_split: Vec<&str> = info.split("=").collect();
    let value = value_split[1];
    let items: Vec<&str> = value.split("|").collect();
    let mut range_values: Vec<RangeValue> = Vec::new();
    let mut single_values: Vec<SingleValue> = Vec::new();
    for i in items {
        if i.contains("-") {
            // 1-6
            let range_value_split: Vec<&str> = i.split("-").collect();
            let hs = Hex::new_hex(range_value_split[0]);
            let start = hs.decode()?;
            let he = Hex::new_hex(range_value_split[1]);
            let end = he.decode()?;
            let range_value = RangeValue::new(start, end, RangeValueTypes::Both);
            range_values.push(range_value);
        } else if i.contains(">") {
            // still have some problem
            let special_value_split: Vec<&str> = i.split(">").collect();
            let h = Hex::new_hex(special_value_split[1]);
            let value = h.decode()?;
            let range_value = RangeValue::new(value, 0, RangeValueTypes::Left);
            range_values.push(range_value);
        } else if i.contains("<") {
            // still have some problem
            let special_value_split: Vec<&str> = i.split(">").collect();
            let h = Hex::new_hex(special_value_split[1]);
            let value = h.decode()?;
            let range_value = RangeValue::new(value, 0, RangeValueTypes::Right);
            range_values.push(range_value);
        } else {
            let he = Hex::new_hex(i);
            let e_u32 = he.decode()?;
            let single_value = SingleValue::new(e_u32);
            single_values.push(single_value);
        }
    }
    let ret = NmapOsDbValueTypes::MixValue(MixValue::new(range_values, single_values));

    Ok(ret)
}

fn value_parser_str(info: &str) -> NmapOsDbValueTypes {
    let value_split: Vec<&str> = info.split("=").collect();
    let value = value_split[1];
    if value.len() > 0 {
        NmapOsDbValueTypes::StringValue(StringValue::new(value))
    } else {
        NmapOsDbValueTypes::empty()
    }
}

/// Each item in the input vec `lines` represents a line of nmap-os-db file content.
/// So just read the nmap file line by line and store it in vec for input.
pub fn nmap_os_db_parser(lines: Vec<String>) -> Vec<NmapOsDb> {
    let mut result = Vec::new();

    let mut l1 = None;
    let mut l2 = None;
    let mut l3 = None;
    let mut l4 = None;
    let mut seq = None;
    let mut ops = None;
    let mut win = None;
    let mut ecn = None;
    let mut t1 = None;
    let mut t2 = None;
    let mut t3 = None;
    let mut t4 = None;
    let mut t5 = None;
    let mut t6 = None;
    let mut t7 = None;
    let mut u1 = None;
    let mut ie = None;
    for l in lines {
        let l = l.trim().to_string();
        if l.len() > 0 {
            if l.contains("#") {
                // pack before result
                if l1.is_some() && l2.is_some() && l3.is_some() && l4.is_some() {
                    let v = NmapOsDb {
                        info: l1.clone().unwrap(),
                        fingerprint: l2.clone().unwrap(),
                        class: l3.clone().unwrap(),
                        cpe: l4.clone().unwrap(),
                        seq: seq.clone().unwrap(),
                        ops: ops.clone().unwrap(),
                        win: win.clone().unwrap(),
                        ecn: ecn.clone().unwrap(),
                        t1: t1.clone().unwrap(),
                        t2: t2.clone().unwrap(),
                        t3: t3.clone().unwrap(),
                        t4: t4.clone().unwrap(),
                        t5: t5.clone().unwrap(),
                        t6: t6.clone().unwrap(),
                        t7: t7.clone().unwrap(),
                        u1: u1.clone().unwrap(),
                        ie: ie.clone().unwrap(),
                    };
                    result.push(v);
                }

                l1 = Some(l);
            } else if l.contains("Fingerprint") {
                l2 = Some(l);
            } else if l.contains("Class") {
                l3 = Some(l);
            } else if l.contains("CPE") {
                l4 = Some(l);
            } else {
                if l.contains("SEQ") {
                    seq = Some(SEQ::parser(l));
                } else if l.contains("OPS") {
                    ops = Some(OPS::parser(l));
                } else if l.contains("WIN") {
                    win = Some(WIN::parser(l));
                } else if l.contains("ECN") {
                    ecn = Some(ECN::parser(l))
                } else if l.contains("T1") {
                    t1 = Some(TX::parser(l))
                } else if l.contains("T2") {
                    t2 = Some(TX::parser(l))
                } else if l.contains("T3") {
                    t3 = Some(TX::parser(l))
                } else if l.contains("T4") {
                    t4 = Some(TX::parser(l))
                } else if l.contains("T5") {
                    t5 = Some(TX::parser(l))
                } else if l.contains("T6") {
                    t6 = Some(TX::parser(l))
                } else if l.contains("T7") {
                    t7 = Some(TX::parser(l))
                } else if l.contains("U1") {
                    u1 = Some(U1::parser(l))
                } else if l.contains("IE") {
                    ie = Some(IE::parser(l))
                }
            }
        }
    }
    result
}

pub fn nmap_os_db_pistol_load(serialized: String) -> Result<Vec<NmapOsDb>> {
    let deserialized: Vec<NmapOsDb> = serde_json::from_str(&serialized)?;
    Ok(deserialized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{read_to_string, File};
    use std::io::prelude::*;
    use std::time::SystemTime;
    #[test]
    fn test_parser() {
        let start = SystemTime::now();
        let filename = "nmap-os-db";
        let lines: Vec<String> = read_to_string(filename)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();

        let ret = nmap_os_db_parser(lines);
        // for i in 0..5 {
        //     let r = &ret[i];
        //     println!("{:?}", r.seq.gcd);
        // }

        // in my homelab server: parse time: 1.285817538s
        println!("parse time: {:?}", start.elapsed().unwrap());
        let serialized = serde_json::to_string(&ret).unwrap();
        let mut file = File::create("nmap-os-db.pistol").unwrap();
        file.write_all(serialized.as_bytes()).unwrap();
    }
    #[test]
    fn test_load() {
        let mut file = File::open("nmap-os-db.pistol").unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let n = nmap_os_db_pistol_load(contents).unwrap();
        println!("{:?}", n[0]);
    }
}
