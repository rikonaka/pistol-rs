use anyhow::Result;
use std::{collections::HashMap, fs::read_to_string};

#[derive(Debug, Clone)]
pub enum RangeValueTypes {
    Left,  // x >= 10
    Right, // x <= 20
    Both,  // 10 <= x <= 20
}

#[derive(Debug, Clone)]
pub struct RangeValue {
    pub start: u32,
    pub end: u32,
    pub value_type: RangeValueTypes,
}

impl RangeValue {
    pub fn new(start: u32, end: u32, value_type: RangeValueTypes) -> RangeValue {
        RangeValue {
            start,
            end,
            value_type,
        }
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
pub struct MixValue {
    pub range_value: Option<RangeValue>,
    pub single_value: Option<SingleValue>,
    pub enum_value: Option<EnumValue>,
}

impl MixValue {
    pub fn new(
        range_value: Option<RangeValue>,
        single_value: Option<SingleValue>,
        enum_value: Option<EnumValue>,
    ) -> MixValue {
        MixValue {
            range_value,
            single_value,
            enum_value,
        }
    }
}

#[derive(Debug, Clone)]
pub enum NmapValueTypes {
    RangeValue(RangeValue),
    EnumValue(EnumValue),
    SingleValue(SingleValue),
    StringValue(StringValue),
    EmptyValue(EmptyValue),
    MixValue(MixValue),
}

impl NmapValueTypes {
    pub fn empty() -> NmapValueTypes {
        NmapValueTypes::EmptyValue(EmptyValue::new())
    }
    pub fn within_u32(&self, input: Option<u32>) -> bool {
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
                Some(input) => match r.value_type {
                    RangeValueTypes::Both => {
                        if input >= r.start && input <= r.end {
                            true
                        } else {
                            false
                        }
                    }
                    RangeValueTypes::Left => {
                        if input >= r.start {
                            true
                        } else {
                            false
                        }
                    }
                    RangeValueTypes::Right => {
                        if input <= r.end {
                            true
                        } else {
                            false
                        }
                    }
                },
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
            NmapValueTypes::MixValue(m) => match input {
                Some(input) => {
                    if m.range_value.is_some() {
                        let r = m.range_value.as_ref().unwrap();
                        match r.value_type {
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
                    if m.single_value.is_some() {
                        if input == m.single_value.as_ref().unwrap().value {
                            return true;
                        }
                    }
                    if m.enum_value.is_some() {
                        if m.enum_value.as_ref().unwrap().values.contains(&input) {
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

#[derive(Debug, Clone)]
pub struct SEQ {
    pub sp: NmapValueTypes,
    pub gcd: NmapValueTypes,
    pub isr: NmapValueTypes,
    pub ti: NmapValueTypes,
    pub ci: NmapValueTypes,
    pub ii: NmapValueTypes,
    pub ss: NmapValueTypes,
    pub ts: NmapValueTypes,
    pub r: NmapValueTypes,
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
        let r = match map.get("r") {
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
                println!("{}", info);
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

#[derive(Debug, Clone)]
pub struct OPS {
    pub o1: NmapValueTypes,
    pub o2: NmapValueTypes,
    pub o3: NmapValueTypes,
    pub o4: NmapValueTypes,
    pub o5: NmapValueTypes,
    pub o6: NmapValueTypes,
    pub r: NmapValueTypes,
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
        let r = match map.get("r") {
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

#[derive(Debug, Clone)]
pub struct WIN {
    pub w1: NmapValueTypes,
    pub w2: NmapValueTypes,
    pub w3: NmapValueTypes,
    pub w4: NmapValueTypes,
    pub w5: NmapValueTypes,
    pub w6: NmapValueTypes,
    pub r: NmapValueTypes,
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
        let r = match map.get("r") {
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

#[derive(Debug, Clone)]
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
                let value = value_parser_u32(info).unwrap();
                map.insert("q", value);
            } else {
                panic!("New type: {}", info);
            }
        }

        ECN::new(map)
    }
}

#[derive(Debug, Clone)]
pub struct TX {
    pub r: NmapValueTypes,
    pub df: NmapValueTypes,
    pub t: NmapValueTypes,
    pub tg: NmapValueTypes,
    pub w: NmapValueTypes,
    pub s: NmapValueTypes,
    pub a: NmapValueTypes,
    pub f: NmapValueTypes,
    pub o: NmapValueTypes,
    pub rd: NmapValueTypes,
    pub q: NmapValueTypes,
}

impl TX {
    fn new(map: HashMap<&str, NmapValueTypes>) -> TX {
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
        let w = match map.get("tg") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let s = match map.get("s") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let a = match map.get("a") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let f = match map.get("f") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let o = match map.get("o") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let rd = match map.get("RD") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let q = match map.get("q") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
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

#[derive(Debug, Clone)]
pub struct U1 {
    pub r: NmapValueTypes,
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

impl U1 {
    fn new(map: HashMap<&str, NmapValueTypes>) -> U1 {
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
        let ipl = match map.get("ipl") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let un = match map.get("un") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let ripl = match map.get("ripl") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let rid = match map.get("rid") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let ripck = match map.get("ripck") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let ruck = match map.get("ruck") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
        };
        let rud = match map.get("rud") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
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

#[derive(Debug, Clone)]
pub struct IE {
    pub dfi: NmapValueTypes,
    pub t: NmapValueTypes,
    pub tg: NmapValueTypes,
    pub cd: NmapValueTypes,
}

impl IE {
    fn new(map: HashMap<&str, NmapValueTypes>) -> IE {
        let dfi = match map.get("dfi") {
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
        let cd = match map.get("cd") {
            Some(v) => v.clone(),
            _ => NmapValueTypes::empty(),
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

pub struct NmapDB {
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

struct Hex {
    _dec: Option<Vec<u8>>,
    hex: Option<String>,
}
impl Hex {
    fn new_dec_u32(dec_u32: u32) -> Hex {
        Hex {
            _dec: Some(Hex::u32_to_vec(dec_u32)),
            hex: None,
        }
    }
    fn new_hex(hex_str: &str) -> Hex {
        Hex {
            _dec: None,
            hex: Some(Hex::length_completion(hex_str).to_string()),
        }
    }
    fn length_completion(hex_str: &str) -> String {
        let hex_str_len = hex_str.len();
        if hex_str_len % 2 == 1 {
            format!("0{}", hex_str)
        } else {
            hex_str.to_string()
        }
    }
    fn vec_to_u32(input: Vec<u8>) -> u32 {
        let mut ret: u32 = 0;
        let mut i = input.len();
        for v in input {
            let mut new_v: u32 = v as u32;
            i -= 1;
            new_v <<= i * 8;
            ret += new_v;
        }
        ret
    }
    fn u32_to_vec(input: u32) -> Vec<u8> {
        let mut ret = Vec::new();
        for i in 0..4 {
            let value = (input >> i * 8) as u8;
            ret.push(value)
        }
        ret.reverse();
        ret
    }
    fn decode(&self) -> Result<u32> {
        match &self.hex {
            Some(hex_str) => match hex::decode(hex_str) {
                Ok(d) => Ok(Hex::vec_to_u32(d)),
                Err(e) => Err(e.into()),
            },
            None => panic!("set value before decode!"),
        }
    }
    fn encode(&self) -> Result<String> {
        match &self._dec {
            Some(dec_vec) => Ok(hex::encode(dec_vec)),
            None => panic!("set value before decode!"),
        }
    }
}

fn value_parser_u32(info: &str) -> Result<NmapValueTypes> {
    let value_split: Vec<&str> = info.split("=").collect();
    let value = value_split[1];
    let ret = if value.contains("-") & value.contains("|") {
        // enum value
        let enum_value_split: Vec<&str> = value.split("|").collect();
        let mut values = Vec::new();
        let mut range_value = None;
        let mut enum_value = None;
        for e in enum_value_split {
            if e.contains("-") {
                let range_value_split: Vec<&str> = e.split("-").collect();
                let hs = Hex::new_hex(range_value_split[0]);
                let start = hs.decode()?;
                let he = Hex::new_hex(range_value_split[1]);
                let end = he.decode()?;
                for v in start..end {
                    values.push(v);
                }
            } else if e.contains(">") {
                // still have some problem
                let special_value_split: Vec<&str> = e.split(">").collect();
                let h = Hex::new_hex(special_value_split[1]);
                let value = h.decode()?;
                range_value = Some(RangeValue::new(value, 0, RangeValueTypes::Left));
            } else {
                let he = Hex::new_hex(e);
                let e_u32 = he.decode()?;
                values.push(e_u32);
            }
        }
        enum_value = Some(EnumValue::new(values));
        NmapValueTypes::MixValue(MixValue::new(range_value, None, enum_value))
    } else if value.contains("-") {
        // range value
        let range_value_split: Vec<&str> = value.split("-").collect();
        let hs = Hex::new_hex(range_value_split[0]);
        let start = hs.decode()?;
        let he = Hex::new_hex(range_value_split[1]);
        let end = he.decode()?;
        NmapValueTypes::RangeValue(RangeValue::new(start, end, RangeValueTypes::Both))
    } else if value.contains("|") {
        // enum value
        let enum_value_split: Vec<&str> = value.split("|").collect();
        let mut values = Vec::new();
        for e in enum_value_split {
            let he = Hex::new_hex(e);
            let e_u32 = he.decode()?;
            values.push(e_u32);
        }
        NmapValueTypes::EnumValue(EnumValue::new(values))
    } else {
        if value.len() > 0 {
            // single value
            let h = Hex::new_hex(value);
            let single = h.decode()?;
            NmapValueTypes::SingleValue(SingleValue::new(single))
        } else {
            NmapValueTypes::empty()
        }
    };
    Ok(ret)
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

fn parser() {
    let filename = "nmap-os-db";
    let lines: Vec<String> = read_to_string(filename)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();

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
                    let v = NmapDB {
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
        let r = Hex::vec_to_u32(v);
        assert_eq!(r, 257);

        let s = "51E80C";
        let h = Hex::new_hex(s);
        let r = h.decode().unwrap();
        assert_eq!(r, 5367820);

        let s = "1C";
        let h = Hex::new_hex(s);
        let r = h.decode().unwrap();
        assert_eq!(r, 28);

        let v = 257;
        let v2 = Hex::u32_to_vec(v);
        assert_eq!(v2, vec![0, 0, 1, 1]);
    }
}
