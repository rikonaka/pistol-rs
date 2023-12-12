use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{read_to_string, File};
use std::io::prelude::*;

use crate::utils::Hex;

use super::osscan::{NmapFingerprint, ECNX, IEX, OPSX, SEQX, TXX, U1X, WINX};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DbRangeValueTypes {
    Left,  // 10 <= x
    Right, // x <= 20
    Both,  // 10 <= x <= 20
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbRangeValue {
    pub start: usize,
    pub end: usize,
    pub range_value_type: DbRangeValueTypes,
}

impl DbRangeValue {
    pub fn new(start: usize, end: usize, range_value_type: DbRangeValueTypes) -> DbRangeValue {
        DbRangeValue {
            start,
            end,
            range_value_type,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbSingleValue {
    pub value: usize,
}

impl DbSingleValue {
    pub fn new(value: usize) -> DbSingleValue {
        DbSingleValue { value }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbStringValue {
    pub value: Vec<String>,
}

impl DbStringValue {
    pub fn new(value: Vec<String>) -> DbStringValue {
        DbStringValue { value }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbEmptyValue {}

impl DbEmptyValue {
    pub fn new() -> DbEmptyValue {
        DbEmptyValue {}
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbMixValue {
    pub range_values: Vec<DbRangeValue>,
    pub single_values: Vec<DbSingleValue>,
}

impl DbMixValue {
    pub fn new(range_value: Vec<DbRangeValue>, single_value: Vec<DbSingleValue>) -> DbMixValue {
        DbMixValue {
            range_values: range_value,
            single_values: single_value,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NmapOsDbValueTypes {
    DbMixStringValue(DbStringValue),
    DbEmptyValue(DbEmptyValue),
    DbMixValue(DbMixValue), // u32, example: GCD=1-6|>5000
}

impl NmapOsDbValueTypes {
    pub fn empty() -> NmapOsDbValueTypes {
        NmapOsDbValueTypes::DbEmptyValue(DbEmptyValue::new())
    }
    pub fn check_usize(&self, input: usize) -> bool {
        match self {
            NmapOsDbValueTypes::DbEmptyValue(_) => match input {
                0 => true,
                _ => false,
            },
            NmapOsDbValueTypes::DbMixValue(m) => {
                let m = m.clone();
                for r in m.range_values {
                    match r.range_value_type {
                        DbRangeValueTypes::Both => {
                            if input >= r.start && input <= r.end {
                                return true;
                            }
                        }
                        DbRangeValueTypes::Left => {
                            if input >= r.start {
                                return true;
                            }
                        }
                        DbRangeValueTypes::Right => {
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
            _ => panic!("wrong type: {:?} - {}", self, input),
        }
    }
    pub fn check_string(&self, input: &str) -> bool {
        match self {
            NmapOsDbValueTypes::DbMixStringValue(v) => match input.len() {
                0 => false,
                _ => {
                    let mut ret = false;
                    for s in &v.value {
                        if input == s {
                            ret = true;
                        }
                    }
                    ret
                }
            },
            NmapOsDbValueTypes::DbEmptyValue(_) => match input.len() {
                0 => true,
                _ => false,
            },
            _ => panic!("wrong type: {:?} - {}", self, input),
        }
    }
    pub fn check_r(&self, input: &str) -> bool {
        match self {
            NmapOsDbValueTypes::DbMixStringValue(v) => match input.len() {
                0 => false,
                _ => {
                    let mut ret = false;
                    for s in &v.value {
                        if input == s {
                            ret = true;
                        }
                    }
                    ret
                }
            },
            NmapOsDbValueTypes::DbEmptyValue(_) => match input {
                "Y" => true,
                _ => false,
            },
            _ => panic!("wrong type: {:?} - {}", self, input),
        }
    }
}

fn bool_score(bool_vec: Vec<bool>) -> usize {
    let mut score = 0;
    for i in bool_vec {
        match i {
            true => score += 1,
            _ => (),
        }
    }
    score
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SEQDB {
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

impl SEQDB {
    pub fn check(&self, seqx: &SEQX) -> (usize, usize) {
        let r_check = self.r.check_r(&seqx.r);
        if r_check {
            match seqx.r.as_str() {
                "N" => (),
                _ => {
                    let sp_check = self.sp.check_usize(seqx.sp as usize);
                    let gcd_check = self.gcd.check_usize(seqx.gcd as usize);
                    let isr_check = self.isr.check_usize(seqx.isr as usize);
                    let ti_check = self.ti.check_string(&seqx.ti);
                    let ci_check = self.ci.check_string(&seqx.ci);
                    let ii_check = self.ii.check_string(&seqx.ii);
                    let ss_check = self.ss.check_string(&seqx.ss);
                    let ts_check = self.ts.check_string(&seqx.ts);

                    // println!(">>> {}", sp_check);
                    // println!(">>> {}", gcd_check);
                    // println!(">>> {}", isr_check);
                    // println!(">>> {}", ti_check);
                    // println!(">>> {}", ci_check);
                    // println!(">>> {}", ii_check);
                    // println!(">>> {}", ss_check);
                    // println!(">>> {}", ts_check);

                    let bool_vec = vec![
                        sp_check, gcd_check, isr_check, ti_check, ci_check, ii_check, ss_check,
                        ts_check,
                    ];

                    return (bool_score(bool_vec), 8);
                }
            }
        }
        (0, 8)
    }
    pub fn new(map: HashMap<&str, NmapOsDbValueTypes>) -> SEQDB {
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

        SEQDB {
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
    pub fn parser(line: String) -> Result<SEQDB> {
        let split_1: Vec<&str> = line.split("(").collect();
        let split_2: Vec<&str> = split_1[1].split(")").collect();
        let many_info = split_2[0];
        let info_split: Vec<&str> = many_info.split("%").collect();

        let mut map = HashMap::new();
        for info in info_split {
            if info.contains("SP=") {
                let value = value_parser_usize(info)?;
                map.insert("sp", value);
            } else if info.contains("GCD=") {
                let value = value_parser_usize(info)?;
                map.insert("gcd", value);
            } else if info.contains("ISR=") {
                let value = value_parser_usize(info)?;
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
                panic!("new type: {}", info);
            }
        }
        Ok(SEQDB::new(map))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OPSDB {
    pub o1: NmapOsDbValueTypes,
    pub o2: NmapOsDbValueTypes,
    pub o3: NmapOsDbValueTypes,
    pub o4: NmapOsDbValueTypes,
    pub o5: NmapOsDbValueTypes,
    pub o6: NmapOsDbValueTypes,
    pub r: NmapOsDbValueTypes,
}

impl OPSDB {
    pub fn check(&self, opsx: &OPSX) -> (usize, usize) {
        let r_check = self.r.check_r(&opsx.r);
        if r_check {
            match opsx.r.as_str() {
                "N" => (),
                _ => {
                    let o1_check = self.o1.check_string(&opsx.o1);
                    let o2_check = self.o2.check_string(&opsx.o2);
                    let o3_check = self.o3.check_string(&opsx.o3);
                    let o4_check = self.o4.check_string(&opsx.o4);
                    let o5_check = self.o5.check_string(&opsx.o5);
                    let o6_check = self.o6.check_string(&opsx.o6);
                    let bool_vec = vec![o1_check, o2_check, o3_check, o4_check, o5_check, o6_check];
                    return (bool_score(bool_vec), 6);
                }
            }
        }
        (0, 6)
    }
    pub fn new(map: HashMap<&str, NmapOsDbValueTypes>) -> OPSDB {
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

        OPSDB {
            o1,
            o2,
            o3,
            o4,
            o5,
            o6,
            r,
        }
    }
    pub fn parser(line: String) -> Result<OPSDB> {
        let mut map = HashMap::new();
        if line.contains("%") {
            let split_1: Vec<&str> = line.split("(").collect();
            let split_2: Vec<&str> = split_1[1].split(")").collect();
            let many_info = split_2[0];
            let info_split: Vec<&str> = many_info.split("%").collect();

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
                    panic!("new type: {}", info);
                }
            }
        }
        Ok(OPSDB::new(map))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WINDB {
    pub w1: NmapOsDbValueTypes,
    pub w2: NmapOsDbValueTypes,
    pub w3: NmapOsDbValueTypes,
    pub w4: NmapOsDbValueTypes,
    pub w5: NmapOsDbValueTypes,
    pub w6: NmapOsDbValueTypes,
    pub r: NmapOsDbValueTypes,
}

impl WINDB {
    pub fn check(&self, winx: &WINX) -> (usize, usize) {
        let r_check = self.r.check_r(&winx.r);
        if r_check {
            match winx.r.as_str() {
                "N" => (),
                _ => {
                    let w1_check = self.w1.check_usize(winx.w1 as usize);
                    let w2_check = self.w2.check_usize(winx.w2 as usize);
                    let w3_check = self.w3.check_usize(winx.w3 as usize);
                    let w4_check = self.w4.check_usize(winx.w4 as usize);
                    let w5_check = self.w5.check_usize(winx.w5 as usize);
                    let w6_check = self.w6.check_usize(winx.w6 as usize);
                    let bool_vec = vec![w1_check, w2_check, w3_check, w4_check, w5_check, w6_check];
                    return (bool_score(bool_vec), 6);
                }
            }
        }
        (0, 6)
    }
    pub fn new(map: HashMap<&str, NmapOsDbValueTypes>) -> WINDB {
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

        WINDB {
            w1,
            w2,
            w3,
            w4,
            w5,
            w6,
            r,
        }
    }
    pub fn parser(line: String) -> Result<WINDB> {
        let split_1: Vec<&str> = line.split("(").collect();
        let split_2: Vec<&str> = split_1[1].split(")").collect();
        let many_info = split_2[0];
        let info_split: Vec<&str> = many_info.split("%").collect();

        let mut map = HashMap::new();
        for info in info_split {
            if info.contains("W1=") {
                let value = value_parser_usize(info)?;
                map.insert("w1", value);
            } else if info.contains("W2=") {
                let value = value_parser_usize(info)?;
                map.insert("w2", value);
            } else if info.contains("W3=") {
                let value = value_parser_usize(info)?;
                map.insert("w3", value);
            } else if info.contains("W4=") {
                let value = value_parser_usize(info)?;
                map.insert("w4", value);
            } else if info.contains("W5=") {
                let value = value_parser_usize(info)?;
                map.insert("w5", value);
            } else if info.contains("W6=") {
                let value = value_parser_usize(info)?;
                map.insert("w6", value);
            } else if info.contains("R=") {
                let value = value_parser_str(info);
                map.insert("r", value);
            } else {
                panic!("new type: {}", info);
            }
        }
        Ok(WINDB::new(map))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECNDB {
    pub r: NmapOsDbValueTypes,
    pub df: NmapOsDbValueTypes,
    pub t: NmapOsDbValueTypes,
    pub tg: NmapOsDbValueTypes,
    pub w: NmapOsDbValueTypes,
    pub o: NmapOsDbValueTypes,
    pub cc: NmapOsDbValueTypes,
    pub q: NmapOsDbValueTypes,
}

impl ECNDB {
    pub fn check(&self, ecnx: &ECNX) -> (usize, usize) {
        let r_check = self.r.check_r(&ecnx.r);
        if r_check {
            match ecnx.r.as_str() {
                "N" => (),
                _ => {
                    let df_check = self.df.check_string(&ecnx.df);
                    let t_check = if ecnx.t > 0 {
                        self.t.check_usize(ecnx.t as usize)
                    } else {
                        self.tg.check_usize(ecnx.tg as usize)
                    };
                    let w_check = self.w.check_usize(ecnx.w as usize);
                    let o_check = self.o.check_string(&ecnx.o);
                    let cc_check = self.cc.check_string(&ecnx.cc);
                    let q_check = self.q.check_string(&ecnx.q);
                    let bool_vec = vec![df_check, t_check, w_check, o_check, cc_check, q_check];
                    return (bool_score(bool_vec), 6);
                }
            }
        }
        (0, 6)
    }
    pub fn new(map: HashMap<&str, NmapOsDbValueTypes>) -> ECNDB {
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

        ECNDB {
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
    pub fn parser(line: String) -> Result<ECNDB> {
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
                let value = value_parser_usize(info)?;
                map.insert("t", value);
            } else if info.contains("TG=") {
                let value = value_parser_usize(info)?;
                map.insert("tg", value);
            } else if info.contains("W=") {
                let value = value_parser_usize(info)?;
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
            } else {
                panic!("new type: {}", info);
            }
        }
        Ok(ECNDB::new(map))
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
    pub fn check(&self, txx: &TXX, name: &str) -> (usize, usize) {
        let r_check = self.r.check_r(&txx.r);
        if r_check {
            match txx.r.as_str() {
                "N" => (),
                _ => {
                    let df_check = self.df.check_string(&txx.df);
                    let t_check = if txx.t > 0 {
                        self.t.check_usize(txx.t as usize)
                    } else {
                        self.tg.check_usize(txx.tg as usize)
                    };
                    let w_check = if name != "T1" {
                        self.w.check_usize(txx.w as usize)
                    } else {
                        true
                    };
                    let s_check = self.s.check_string(&txx.s);
                    let a_check = self.a.check_string(&txx.a);
                    let f_check = self.f.check_string(&txx.f);
                    let o_check = if name != "T1" {
                        self.o.check_string(&txx.o)
                    } else {
                        true
                    };
                    let rd_check = self.rd.check_usize(txx.rd as usize);
                    let q_check = self.q.check_string(&txx.q);

                    // println!("{}", df_check);
                    // println!("{}", t_check);
                    // println!("{}", w_check);
                    // println!("{}", s_check);
                    // println!("{}", a_check);
                    // println!("{}", f_check);
                    // println!("{}", o_check);
                    // println!("{}", rd_check);
                    // println!("{}", q_check);

                    let bool_vec = vec![
                        df_check, t_check, w_check, s_check, a_check, f_check, o_check, rd_check,
                        q_check,
                    ];
                    return (bool_score(bool_vec), 9);
                }
            }
        }
        (0, 9)
    }
    pub fn new(map: HashMap<&str, NmapOsDbValueTypes>) -> TX {
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
        let rd = match map.get("rd") {
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
    pub fn parser(line: String) -> Result<TX> {
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
                let value = value_parser_usize(info)?;
                map.insert("t", value);
            } else if info.contains("TG=") {
                let value = value_parser_usize(info)?;
                map.insert("tg", value);
            } else if info.contains("W=") {
                let value = value_parser_usize(info)?;
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
                let value = value_parser_usize(info)?;
                map.insert("rd", value);
            } else if info.contains("Q=") {
                let value = value_parser_str(info);
                map.insert("q", value);
            } else {
                panic!("new type: {}", info);
            }
        }

        Ok(TX::new(map))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct U1DB {
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

impl U1DB {
    pub fn check(&self, u1x: &U1X) -> (usize, usize) {
        let r_check = self.r.check_r(&u1x.r);
        if r_check {
            match u1x.r.as_str() {
                "N" => (),
                _ => {
                    let df_check = self.df.check_string(&u1x.df);
                    let t_check = if u1x.t > 0 {
                        self.t.check_usize(u1x.t as usize)
                    } else {
                        self.tg.check_usize(u1x.tg as usize)
                    };
                    let ipl_check = self.ipl.check_usize(u1x.ipl as usize);
                    let un_check = self.un.check_usize(u1x.un as usize);
                    let ripl_check = self.ripl.check_string(&u1x.ripl);
                    let rid_check = self.rid.check_string(&u1x.rid);
                    let ripck_check = self.ripck.check_string(&u1x.ripck);
                    let ruck_check = self.ruck.check_string(&u1x.ruck);
                    let rud_check = self.rud.check_string(&u1x.rud);

                    // println!("{}", df_check);
                    // println!("{}", t_check);
                    // println!("{}", ipl_check);
                    // println!("{}", un_check);
                    // println!("{}", ripl_check);
                    // println!("{}", rid_check);
                    // println!("{}", ripck_check);
                    // println!("{}", ruck_check);
                    // println!("{}", rud_check);

                    let bool_vec = vec![
                        df_check,
                        t_check,
                        ipl_check,
                        un_check,
                        ripl_check,
                        rid_check,
                        ripck_check,
                        ruck_check,
                        rud_check,
                    ];
                    return (bool_score(bool_vec), 9);
                }
            }
        }
        (0, 9)
    }
    pub fn new(map: HashMap<&str, NmapOsDbValueTypes>) -> U1DB {
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

        U1DB {
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
    pub fn parser(line: String) -> Result<U1DB> {
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
                let value = value_parser_usize(info)?;
                map.insert("t", value);
            } else if info.contains("TG=") {
                let value = value_parser_usize(info)?;
                map.insert("tg", value);
            } else if info.contains("RIPL=") {
                let value = value_parser_str(info);
                map.insert("ripl", value);
            } else if info.contains("IPL=") {
                let value = value_parser_usize(info)?;
                map.insert("ipl", value);
            } else if info.contains("UN=") {
                let value = value_parser_usize(info)?;
                map.insert("un", value);
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
                panic!("new type: {}", info);
            }
        }
        Ok(U1DB::new(map))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IEDB {
    pub r: NmapOsDbValueTypes,
    pub dfi: NmapOsDbValueTypes,
    pub t: NmapOsDbValueTypes,
    pub tg: NmapOsDbValueTypes,
    pub cd: NmapOsDbValueTypes,
}

impl IEDB {
    pub fn check(&self, iex: &IEX) -> (usize, usize) {
        let r_check = self.r.check_r(&iex.r);
        if r_check {
            match iex.r.as_str() {
                "N" => (),
                _ => {
                    let dfi_check = self.dfi.check_string(&iex.dfi);
                    let t_check = if iex.t > 0 {
                        self.t.check_usize(iex.t as usize)
                    } else {
                        self.tg.check_usize(iex.tg as usize)
                    };
                    let cd_check = self.cd.check_string(&iex.cd);
                    let bool_vec = vec![dfi_check, t_check, cd_check];
                    return (bool_score(bool_vec), 3);
                }
            }
        }
        (0, 3)
    }
    pub fn new(map: HashMap<&str, NmapOsDbValueTypes>) -> IEDB {
        let r = match map.get("r") {
            Some(v) => v.clone(),
            _ => NmapOsDbValueTypes::empty(),
        };
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

        IEDB { r, dfi, t, tg, cd }
    }
    fn parser(line: String) -> Result<IEDB> {
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
                let value = value_parser_usize(info)?;
                map.insert("t", value);
            } else if info.contains("TG=") {
                let value = value_parser_usize(info)?;
                map.insert("tg", value);
            } else if info.contains("CD=") {
                let value = value_parser_str(info);
                map.insert("cd", value);
            } else {
                panic!("new type: {}", info);
            }
        }
        Ok(IEDB::new(map))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapOsDb {
    pub info: String,
    pub fingerprint: String,
    pub class: String,
    pub cpe: String,
    pub seq: SEQDB,
    pub ops: OPSDB,
    pub win: WINDB,
    pub ecn: ECNDB,
    pub t1: TX,
    pub t2: TX,
    pub t3: TX,
    pub t4: TX,
    pub t5: TX,
    pub t6: TX,
    pub t7: TX,
    pub u1: U1DB,
    pub ie: IEDB,
}

impl NmapOsDb {
    pub fn check(&self, probe_ret: &NmapFingerprint) -> (usize, usize) {
        let (seq_score, seq_total) = self.seq.check(&probe_ret.seqx);
        // println!("SEQ: {}", seq_check);
        let (ops_score, ops_total) = self.ops.check(&probe_ret.opsx);
        // println!("OPS: {}", ops_check);
        let (win_score, win_total) = self.win.check(&probe_ret.winx);
        // println!("WIN: {}", win_check);
        let (ecn_score, ecn_total) = self.ecn.check(&probe_ret.ecnx);
        // println!("ECN: {}", ecn_check);
        let (t1_score, t1_total) = self.t1.check(&probe_ret.t1x, "T1");
        // println!("T1: {}", t1_check);
        let (t2_score, t2_total) = self.t2.check(&probe_ret.t2x, "T2");
        // println!("T2: {}", t2_check);
        let (t3_score, t3_total) = self.t3.check(&probe_ret.t3x, "T3");
        // println!("T3: {}", t3_check);
        let (t4_score, t4_total) = self.t4.check(&probe_ret.t4x, "T4");
        // println!("T4: {}", t4_check);
        let (t5_score, t5_total) = self.t5.check(&probe_ret.t5x, "T5");
        // println!("T5: {}", t5_check);
        let (t6_score, t6_total) = self.t6.check(&probe_ret.t6x, "T6");
        // println!("T6: {}", t6_check);
        let (t7_score, t7_total) = self.t7.check(&probe_ret.t7x, "T7");
        // println!("T7: {}", t7_check);
        let (u1_score, u1_total) = self.u1.check(&probe_ret.u1x);
        // println!("U1: {}", u1_check);
        let (ie_score, ie_total) = self.ie.check(&probe_ret.iex);
        // println!("IE: {}", ie_check);

        let score = seq_score
            + ops_score
            + win_score
            + ecn_score
            + t1_score
            + t2_score
            + t3_score
            + t4_score
            + t5_score
            + t6_score
            + t7_score
            + u1_score
            + ie_score;

        let total = seq_total
            + ops_total
            + win_total
            + ecn_total
            + t1_total
            + t2_total
            + t3_total
            + t4_total
            + t5_total
            + t6_total
            + t7_total
            + u1_total
            + ie_total;

        (score, total)
    }
}

fn value_parser_usize(info: &str) -> Result<NmapOsDbValueTypes> {
    let value_split: Vec<&str> = info.split("=").collect();
    let value = value_split[1];
    let items: Vec<&str> = value.split("|").collect();
    let mut range_values: Vec<DbRangeValue> = Vec::new();
    let mut single_values: Vec<DbSingleValue> = Vec::new();
    for i in items {
        if i.contains("-") {
            // 1-6
            let range_value_split: Vec<&str> = i.split("-").collect();
            let hs = Hex::new_hex(range_value_split[0]);
            let start = hs.decode()? as usize;
            let he = Hex::new_hex(range_value_split[1]);
            let end = he.decode()? as usize;
            let range_value = DbRangeValue::new(start, end, DbRangeValueTypes::Both);
            range_values.push(range_value);
        } else if i.contains(">") {
            // still have some problem
            let special_value_split: Vec<&str> = i.split(">").collect();
            let h = Hex::new_hex(special_value_split[1]);
            let value = h.decode()? as usize;
            let range_value = DbRangeValue::new(value, 0, DbRangeValueTypes::Left);
            range_values.push(range_value);
        } else if i.contains("<") {
            // still have some problem
            let special_value_split: Vec<&str> = i.split(">").collect();
            let h = Hex::new_hex(special_value_split[1]);
            let value = h.decode()? as usize;
            let range_value = DbRangeValue::new(value, 0, DbRangeValueTypes::Right);
            range_values.push(range_value);
        } else {
            let he = Hex::new_hex(i);
            let e_u32 = he.decode()?;
            let single_value = DbSingleValue::new(e_u32 as usize);
            single_values.push(single_value);
        }
    }
    let ret = NmapOsDbValueTypes::DbMixValue(DbMixValue::new(range_values, single_values));

    Ok(ret)
}

fn value_parser_str(info: &str) -> NmapOsDbValueTypes {
    let value_split: Vec<&str> = info.split("=").collect();
    let value = value_split[1].to_string();
    if value.contains("|") {
        let mut ret = Vec::new();
        let s_split: Vec<&str> = value.split("|").collect();
        for s in s_split {
            ret.push(s.to_string());
        }
        NmapOsDbValueTypes::DbMixStringValue(DbStringValue::new(ret))
    } else {
        if value.len() > 0 {
            NmapOsDbValueTypes::DbMixStringValue(DbStringValue::new(vec![value]))
        } else {
            NmapOsDbValueTypes::empty()
        }
    }
}

/// Each item in the input vec `lines` represents a line of nmap-os-db file content.
/// So just read the nmap file line by line and store it in vec for input.
pub fn nmap_os_db_parser(filename: &str) -> Result<Vec<NmapOsDb>> {
    let lines: Vec<String> = read_to_string(filename)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();

    let option_string = |x: Option<String>| -> String {
        match x {
            Some(x) => x,
            _ => String::new(),
        }
    };

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
    for l in lines {
        // println!("{}", l);
        let l = l.trim().to_string();
        if l.len() > 0 {
            if l.starts_with("#") {
                let l = match l1 {
                    Some(x) => {
                        let l = format!("{}\n{}", x, l);
                        l
                    }
                    None => l,
                };
                l1 = Some(l);
            } else if l.starts_with("Fingerprint") {
                let l = match l2 {
                    Some(x) => {
                        let l = format!("{}\n{}", x, l);
                        l
                    }
                    None => l,
                };
                l2 = Some(l);
            } else if l.starts_with("Class") {
                let l = match l3 {
                    Some(x) => {
                        let l = format!("{}\n{}", x, l);
                        l
                    }
                    None => l,
                };
                l3 = Some(l);
            } else if l.starts_with("CPE") {
                let l = match l4 {
                    Some(x) => {
                        let l = format!("{}\n{}", x, l);
                        l
                    }
                    None => l,
                };
                l4 = Some(l);
            } else if l.starts_with("SEQ") {
                seq = Some(SEQDB::parser(l)?);
            } else if l.starts_with("OPS") {
                ops = Some(OPSDB::parser(l)?);
            } else if l.starts_with("WIN") {
                win = Some(WINDB::parser(l)?);
            } else if l.starts_with("ECN") {
                ecn = Some(ECNDB::parser(l)?);
            } else if l.starts_with("T1") {
                t1 = Some(TX::parser(l)?);
            } else if l.starts_with("T2") {
                t2 = Some(TX::parser(l)?);
            } else if l.starts_with("T3") {
                t3 = Some(TX::parser(l)?);
            } else if l.starts_with("T4") {
                t4 = Some(TX::parser(l)?);
            } else if l.starts_with("T5") {
                t5 = Some(TX::parser(l)?);
            } else if l.starts_with("T6") {
                t6 = Some(TX::parser(l)?);
            } else if l.starts_with("T7") {
                t7 = Some(TX::parser(l)?);
            } else if l.starts_with("U1") {
                u1 = Some(U1DB::parser(l)?);
            } else if l.starts_with("IE") {
                // last line
                let ie = Some(IEDB::parser(l)?);
                let v = NmapOsDb {
                    info: option_string(l1),
                    fingerprint: option_string(l2),
                    class: option_string(l3),
                    cpe: option_string(l4),
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
                l1 = None;
                l2 = None;
                l3 = None;
                l4 = None;
            }
        }
    }
    Ok(result)
}

pub fn nmape_os_db_pistol_dump(filename: &str, output: Option<&str>) -> Result<()> {
    let output = match output {
        Some(o) => o.to_string(),
        _ => "nmap-os-db.pistol".to_string(), // default name
    };

    let ret = nmap_os_db_parser(filename)?;
    let serialized = serde_json::to_string(&ret)?;
    let mut file_write = File::create(output)?;
    file_write.write_all(serialized.as_bytes())?;
    Ok(())
}

pub fn nmap_os_db_pistol_load(serialized: String) -> Result<Vec<NmapOsDb>> {
    let deserialized: Vec<NmapOsDb> = serde_json::from_str(&serialized)?;
    Ok(deserialized)
}

#[cfg(test)]
mod tests {
    use super::*;
    // use std::fs::{read_to_string, File};
    // use std::io::prelude::*;
    use std::time::SystemTime;
    #[test]
    fn test_parser() {
        let start = SystemTime::now();
        let filename = "nmap-os-db";

        let _ret = nmap_os_db_parser(filename).unwrap();
        // for i in 0..5 {
        //     let r = &ret[i];
        //     println!("{:?}", r.seq.gcd);
        // }

        // in my homelab server: parse time: 1.285817538s
        println!("parse time: {:?}", start.elapsed().unwrap());
        // let serialized = serde_json::to_string(&ret).unwrap();
        // let mut file_write = File::create("nmap-os-db.pistol").unwrap();
        // file_write.write_all(serialized.as_bytes()).unwrap();
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
