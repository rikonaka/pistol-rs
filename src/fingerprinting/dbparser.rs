use data_encoding::HEXUPPER;
use std::{collections::HashMap, fs::read_to_string};

#[derive(Debug)]
enum NmapValueTypes {
    Range,
    Enum,
    Single,
}

#[derive(Debug)]
pub struct NmapValue {
    value_type: NmapValueTypes,
    // for range value
    value_start: u32,
    value_end: u32,
    // for enum value
    value_vec: Vec<u32>,
    // single value:
    value_single: u32,
}

impl NmapValue {
    fn new_range(value_start: u32, value_end: u32) -> NmapValue {
        NmapValue {
            value_type: NmapValueTypes::Single,
            value_start,
            value_end,
            value_vec: vec![],
            value_single: 0,
        }
    }
    fn new_enum(value_vec: Vec<u32>) -> NmapValue {
        NmapValue {
            value_type: NmapValueTypes::Single,
            value_start: 0,
            value_end: 0,
            value_vec,
            value_single: 0,
        }
    }
    fn new_single(value_single: u32) -> NmapValue {
        NmapValue {
            value_type: NmapValueTypes::Single,
            value_start: 0,
            value_end: 0,
            value_vec: vec![],
            value_single,
        }
    }
    fn within(&self, v: u32) -> bool {
        match self.value_type {
            NmapValueTypes::Range => {
                if v >= self.value_start || v <= self.value_end {
                    true
                } else {
                    false
                }
            }
            NmapValueTypes::Enum => {
                if self.value_vec.contains(&v) {
                    true
                } else {
                    false
                }
            }
            NmapValueTypes::Single => {
                if self.value_single == v {
                    true
                } else {
                    false
                }
            }
        }
    }
}

pub struct SEQ {
    sp: NmapValue,
    gcd: NmapValue,
    isr: NmapValue,
    ti: NmapValue,
    ci: NmapValue,
    ii: NmapValue,
    ss: NmapValue,
    ts: NmapValue,
}

pub struct NmapDB {
    fingerprint: String,
    class: Vec<String>,
    cpe: String,
    seq: SEQ,
}

fn u8vec_2_u32(input: Vec<u8>) -> u32 {
    if input.len() != 4 {
        panic!("Convert u32 from u8 vec failed")
    } else {
        let mut ret: u32 = 0;
        for (i, v) in input.iter().enumerate() {
            let mut new_v: u32 = *v as u32;
            new_v <<= (3 - i) * 8;
            ret += new_v;
        }
        println!("{}", ret);
        return ret;
    }
}

fn _value_parser(info: &str) -> NmapValue {
    let value_split: Vec<&str> = info.split("=").collect();
    let value = value_split[1];
    let ret = if value.contains("-") {
        // range value
        let range_value_split: Vec<&str> = value.split("-").collect();
        let start_value_vec = HEXUPPER.decode(&range_value_split[0].as_bytes()).unwrap();
        let end_value_vec = HEXUPPER.decode(&range_value_split[1].as_bytes()).unwrap();
        let value_start = u8vec_2_u32(start_value_vec);
        let value_end = u8vec_2_u32(end_value_vec);
        NmapValue::new_range(value_start, value_end)
    } else if value.contains("|") {
        // enum value
        let enum_value_split: Vec<&str> = value.split("|").collect();
        let mut value_vec = Vec::new();
        for e in enum_value_split {
            let e_vec = HEXUPPER.decode(e.as_bytes()).unwrap();
            let e_u32 = u8vec_2_u32(e_vec);
            value_vec.push(e_u32);
        }
        NmapValue::new_enum(value_vec)
    } else {
        // single value
        let value_single = value.parse().unwrap();
        NmapValue::new_single(value_single)
    };
    ret
}

fn seq_parser(line: String) {
    let split_1: Vec<&str> = line.split("(").collect();
    let split_2: Vec<&str> = split_1[1].split(")").collect();
    let seq_info = split_2[0];
    let info_split: Vec<&str> = seq_info.split("%").collect();

    let mut seq_map = HashMap::new();
    for info in info_split {
        if info.contains("SP") {
            let value = _value_parser(info);
            seq_map.insert("sp", value);
        } else if info.contains("GCD") {
            let value = _value_parser(info);
            seq_map.insert("gcd", value);
        }
        } else if info.contains("GCD") {
            let value = _value_parser(info);
            seq_map.insert("gcd", value);
        }
    }
}

fn parser() {
    let filename = "nmap-os-db";
    let lines: Vec<String> = read_to_string(filename)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();

    for l in lines {
        let first_char = l.chars().next();
        if first_char != Some('#') {
            // not comments
            // println!("{}", l);
            if l.contains("SEQ") {
                let seq_ret = seq_parser(l);
                break;
            }
        }
    }
}

#[test]
fn test_parser() {
    parser();
}
