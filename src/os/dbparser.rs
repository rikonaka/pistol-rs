use regex::Regex;
use serde::Deserialize;
use serde::Serialize;

use crate::error::PistolError;
use crate::os::osscan::ECNX;
use crate::os::osscan::Fingerprint;
use crate::os::osscan::IEX;
use crate::os::osscan::OPSX;
use crate::os::osscan::SEQX;
use crate::os::osscan::TXX;
use crate::os::osscan::U1X;
use crate::os::osscan::WINX;
use crate::utils::SpHex;

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NmapRangeTypes {
    Left,  // 10 <= x
    Right, // x <= 20
    Both,  // 10 <= x <= 20
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NmapRangeValue {
    pub start: usize,
    pub end: usize,
    pub range_value_type: NmapRangeTypes,
}

impl NmapRangeValue {
    pub fn new(start: usize, end: usize, range_value_type: NmapRangeTypes) -> NmapRangeValue {
        NmapRangeValue {
            start,
            end,
            range_value_type,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NmapSingleValue {
    pub value: usize,
}

impl NmapSingleValue {
    pub fn new(value: usize) -> NmapSingleValue {
        NmapSingleValue { value }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NmapString {
    pub value: Vec<String>,
}

impl NmapString {
    pub fn new(value: Vec<String>) -> NmapString {
        NmapString { value }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NmapEmpty {}

impl NmapEmpty {
    pub fn new() -> NmapEmpty {
        NmapEmpty {}
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NmapMix {
    pub range_values: Vec<NmapRangeValue>,
    pub single_values: Vec<NmapSingleValue>,
}

impl NmapMix {
    pub fn new(range_value: Vec<NmapRangeValue>, single_value: Vec<NmapSingleValue>) -> NmapMix {
        NmapMix {
            range_values: range_value,
            single_values: single_value,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NmapData {
    NmapString(NmapString),
    NmapEmpty(NmapEmpty),
    NmapMix(NmapMix), // u32, example: GCD=1-6|>5000
}

impl NmapData {
    pub fn parser_usize(input: &str) -> Result<NmapData, PistolError> {
        let input = input.trim();
        if input.len() == 0 {
            Ok(NmapData::empty())
        } else {
            let mut range_values = Vec::new();
            let mut single_values = Vec::new();
            let items: Vec<&str> = input.split("|").collect();

            // println!(">>> usize input: {}", input);
            let range_reg = Regex::new(r"(?P<start>[^%]+)-(?P<end>[^%]+)")?;
            let great_reg = Regex::new(r">(?P<start>[^%]+)")?;
            let less_reg = Regex::new(r"<(?P<end>[^%]+)")?;

            for it in items {
                if range_reg.is_match(it) {
                    match range_reg.captures(it) {
                        Some(caps) => {
                            let start = caps.name("start").map_or("", |m| m.as_str());
                            let end = caps.name("end").map_or("", |m| m.as_str());
                            let start: usize = match start.parse() {
                                Ok(s) => s,
                                Err(_) => {
                                    let he = SpHex::new_hex(start);
                                    let e_u32 = he.decode()?;
                                    e_u32 as usize
                                }
                            };
                            let end: usize = match end.parse() {
                                Ok(e) => e,
                                Err(_) => {
                                    let he = SpHex::new_hex(end);
                                    let e_u32 = he.decode()?;
                                    e_u32 as usize
                                }
                            };
                            let range = NmapRangeValue::new(start, end, NmapRangeTypes::Both);
                            range_values.push(range);
                        }
                        None => (),
                    }
                } else if great_reg.is_match(it) {
                    match great_reg.captures(it) {
                        Some(caps) => {
                            let start = caps.name("start").map_or("", |m| m.as_str());
                            let start: usize = match start.parse() {
                                Ok(s) => s,
                                Err(_) => {
                                    let he = SpHex::new_hex(start);
                                    let e_u32 = he.decode()?;
                                    e_u32 as usize
                                }
                            };
                            let range = NmapRangeValue::new(start, 0, NmapRangeTypes::Left);
                            range_values.push(range);
                        }
                        None => (),
                    }
                } else if less_reg.is_match(it) {
                    match less_reg.captures(it) {
                        Some(caps) => {
                            let end = caps.name("end").map_or("", |m| m.as_str());
                            let end: usize = match end.parse() {
                                Ok(e) => e,
                                Err(_) => {
                                    let he = SpHex::new_hex(end);
                                    let e_u32 = he.decode()?;
                                    e_u32 as usize
                                }
                            };
                            let range = NmapRangeValue::new(end, 0, NmapRangeTypes::Right);
                            range_values.push(range);
                        }
                        None => (),
                    }
                } else {
                    let he = SpHex::new_hex(it);
                    let e_u32 = he.decode()?;
                    let single = NmapSingleValue::new(e_u32 as usize);
                    single_values.push(single);
                }
            }
            let ret = NmapData::NmapMix(NmapMix::new(range_values, single_values));
            Ok(ret)
        }
    }
    pub fn parser_str(input: &str) -> NmapData {
        let input = input.trim();
        if input.len() == 0 {
            NmapData::empty()
        } else {
            let value = input.to_string();
            if value.contains("|") {
                let mut ret = Vec::new();
                let s_split: Vec<&str> = value.split("|").collect();
                for s in s_split {
                    ret.push(s.to_string());
                }
                NmapData::NmapString(NmapString::new(ret))
            } else {
                if value.len() > 0 {
                    NmapData::NmapString(NmapString::new(vec![value]))
                } else {
                    NmapData::empty()
                }
            }
        }
    }
    pub fn empty() -> NmapData {
        NmapData::NmapEmpty(NmapEmpty::new())
    }
    pub fn check_usize(&self, input: usize) -> bool {
        match self {
            NmapData::NmapEmpty(_) => match input {
                0 => true,
                _ => false,
            },
            NmapData::NmapMix(m) => {
                let m = m.clone();
                for r in m.range_values {
                    match r.range_value_type {
                        NmapRangeTypes::Both => {
                            if input >= r.start && input <= r.end {
                                return true;
                            }
                        }
                        NmapRangeTypes::Left => {
                            if input >= r.start {
                                return true;
                            }
                        }
                        NmapRangeTypes::Right => {
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
            NmapData::NmapString(v) => match input.len() {
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
            NmapData::NmapEmpty(_) => match input.len() {
                0 => true,
                _ => false,
            },
            _ => panic!("wrong type: {:?} - {}", self, input),
        }
    }
    pub fn check_r(&self, input: &str) -> bool {
        match self {
            NmapData::NmapString(v) => match input.len() {
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
            NmapData::NmapEmpty(_) => match input {
                "Y" => true,
                _ => false,
            },
            _ => panic!("wrong type: {:?} - {}", self, input),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SEQDB {
    pub sp: NmapData,
    pub r: NmapData,
    pub gcd: NmapData,
    pub isr: NmapData,
    pub ti: NmapData,
    pub ci: NmapData,
    pub ii: NmapData,
    pub ss: NmapData,
    pub ts: NmapData,
}

impl SEQDB {
    pub fn check(&self, seqx: &SEQX) -> (usize, usize) {
        let r_check = self.r.check_r(&seqx.r);
        if r_check {
            match seqx.r.as_str() {
                "N" => (),
                _ => {
                    // let sp_check = self.sp.check_usize(seqx.sp as usize);
                    let sp_check = true;
                    let gcd_check = self.gcd.check_usize(seqx.gcd as usize);
                    // let isr_check = self.isr.check_usize(seqx.isr as usize);
                    let isr_check = true;
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OPSDB {
    pub o1: NmapData,
    pub o2: NmapData,
    pub o3: NmapData,
    pub o4: NmapData,
    pub o5: NmapData,
    pub o6: NmapData,
    pub r: NmapData,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WINDB {
    pub w1: NmapData,
    pub w2: NmapData,
    pub w3: NmapData,
    pub w4: NmapData,
    pub w5: NmapData,
    pub w6: NmapData,
    pub r: NmapData,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECNDB {
    pub r: NmapData,
    pub df: NmapData,
    pub t: NmapData,
    pub tg: NmapData,
    pub w: NmapData,
    pub o: NmapData,
    pub cc: NmapData,
    pub q: NmapData,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TXDB {
    pub r: NmapData,
    pub df: NmapData,
    pub t: NmapData,
    pub tg: NmapData,
    pub w: NmapData,
    pub s: NmapData,
    pub a: NmapData,
    pub f: NmapData,
    pub o: NmapData,
    pub rd: NmapData,
    pub q: NmapData,
}

impl TXDB {
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct U1DB {
    pub r: NmapData,
    pub df: NmapData,
    pub t: NmapData,
    pub tg: NmapData,
    pub ipl: NmapData,
    pub un: NmapData,
    pub ripl: NmapData,
    pub rid: NmapData,
    pub ripck: NmapData,
    pub ruck: NmapData,
    pub rud: NmapData,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IEDB {
    pub r: NmapData,
    pub dfi: NmapData,
    pub t: NmapData,
    pub tg: NmapData,
    pub cd: NmapData,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapOSDB {
    pub name: String,
    pub class: Vec<String>,
    pub cpe: Vec<String>,
    pub seq: SEQDB,
    pub ops: OPSDB,
    pub win: WINDB,
    pub ecn: ECNDB,
    pub t1: TXDB,
    pub t2: TXDB,
    pub t3: TXDB,
    pub t4: TXDB,
    pub t5: TXDB,
    pub t6: TXDB,
    pub t7: TXDB,
    pub u1: U1DB,
    pub ie: Option<IEDB>,
}

impl NmapOSDB {
    pub fn check(&self, probe_ret: &Fingerprint) -> (usize, usize) {
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
        let (ie_score, ie_total) = match &self.ie {
            Some(ie) => ie.check(&probe_ret.iex),
            None => (0, 3), // all scores
        };
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

/// Process standard `nmap-os-db files` and return a structure that can be processed by the program.
/// Each item in the input vec `lines` represents a line of nmap-os-db file content.
/// So just read the nmap file line by line and store it in vec for input.
pub fn nmap_os_db_parser(lines: Vec<String>) -> Result<Vec<NmapOSDB>, PistolError> {
    let name_reg = Regex::new(r"Fingerprint (?P<name>.+)")?;
    let class_reg = Regex::new(
        r"Class (?P<class1>[^|]+) \|(?P<class2>[^|]+)\|(\|)? (?P<class3>[^|]+)( \|(\|)? (?P<class4>[^|]+))?",
    )?;
    let cpe_reg = Regex::new(r"CPE (?P<cpe>.+)")?;
    let seq_reg = Regex::new(
        r"SEQ\((SP=(?P<sp>[^%]+))?(R=(?P<r>[^%]+))?(%GCD=(?P<gcd>[^%]+))?(%?ISR=(?P<isr>[^%]+))?(%?TI=(?P<ti>[^%]+))?(%?CI=(?P<ci>[^%]+))?(%?II=(?P<ii>[^%]+))?(%SS=(?P<ss>[^%]+))?(%TS=(?P<ts>[^%]+))?\)",
    )?;
    let ops_reg = Regex::new(
        r"OPS\((R=(?P<r>[^%]+|))?(O1=(?P<o1>[^%]+|))?(%O2=(?P<o2>[^%]+|))?(%O3=(?P<o3>[^%]+|))?(%O4=(?P<o4>[^%]+|))?(%O5=(?P<o5>[^%]+|))?(%O6=(?P<o6>[^%]+|))?\)",
    )?;
    let win_reg = Regex::new(
        r"WIN\((R=(?P<r>[^%]+))?(W1=(?P<w1>[^%]+)%W2=(?P<w2>[^%]+)%W3=(?P<w3>[^%]+)%W4=(?P<w4>[^%]+)%W5=(?P<w5>[^%]+)%W6=(?P<w6>[^%]+))?\)",
    )?;
    let ecn_reg = Regex::new(
        r"ECN\(R=(?P<r>[^%]+|)(%DF=(?P<df>[^%]+|))?(%T=(?P<t>[^%]+|))?(%TG=(?P<tg>[^%]+|))?(%W=(?P<w>[^%]+|))?(%O=(?P<o>[^%]+|))?(%CC=(?P<cc>[^%]+|))?(%Q=(?P<q>[^%]+|))?\)",
    )?;
    let tx_reg = Regex::new(
        r"T\d\((R=(?P<r>[^%]+))?(%?DF=(?P<df>[^%]+))?(%T=(?P<t>[^%]+))?(%TG=(?P<tg>[^%]+))?(%W=(?P<w>[^%]+))?(%S=(?P<s>[^%]+))?(%A=(?P<a>[^%]+))?(%F=(?P<f>[^%]+))?(%O=(?P<o>[^%]+|))?(%RD=(?P<rd>[^%]+))?(%Q=(?P<q>[^%]+|))?\)",
    )?;
    let u1_reg = Regex::new(
        r"U1\((R=(?P<r>[^%]+))?(%?DF=(?P<df>[^%]+))?(%T=(?P<t>[^%]+))?(%TG=(?P<tg>[^%]+))?(%IPL=(?P<ipl>[^%]+))?(%UN=(?P<un>[^%]+))?(%RIPL=(?P<ripl>[^%]+))?(%RID=(?P<rid>[^%]+))?(%RIPCK=(?P<ripck>[^%]+))?(%RUCK=(?P<ruck>[^%]+))?(%RUD=(?P<rud>[^%]+))?\)",
    )?;
    let ie_reg = Regex::new(
        r"IE\((R=(?P<r>[^%]+))?(%?DFI=(?P<dfi>[^%]+))?(%T=(?P<t>[^%]+))?(%TG=(?P<tg>[^%]+))?(%CD=(?P<cd>[^%]+))?\)",
    )?;

    let mut ret = Vec::new();
    let lines_len = lines.len();
    let mut iter = lines.into_iter();
    for _ in 0..lines_len {
        match iter.next() {
            Some(line) => {
                if line.starts_with("#") || line.trim().len() == 0 {
                    continue;
                }
                if line.starts_with("Fingerprint") {
                    /* name part */
                    let name = match name_reg.captures(&line) {
                        Some(caps) => {
                            let name = caps.name("name").map_or("", |m| m.as_str());
                            name.to_string()
                        }
                        None => {
                            return Err(PistolError::OSDBParseError {
                                name: String::from("Fingerprint"),
                                line,
                            });
                        }
                    };
                    // println!("{}", name);
                    /* class part */
                    let class_parser = |line: String| -> Result<Vec<String>, PistolError> {
                        match class_reg.captures(&line) {
                            Some(caps) => {
                                let class1 = caps.name("class1").map_or("", |m| m.as_str());
                                let class2 = caps.name("class2").map_or("", |m| m.as_str());
                                let class3 = caps.name("class3").map_or("", |m| m.as_str());
                                let class4 = caps.name("class4").map_or("", |m| m.as_str());

                                let class1 = class1.trim().to_string();
                                let class2 = class2.trim().to_string();
                                let class3 = class3.trim().to_string();
                                let class4 = class4.trim().to_string();
                                let mut class = Vec::new();
                                let mut class_push = |input: String| {
                                    if input.len() > 0 {
                                        class.push(input);
                                    }
                                };
                                class_push(class1);
                                class_push(class2);
                                class_push(class3);
                                class_push(class4);
                                Ok(class)
                            }
                            None => Err(PistolError::OSDBParseError {
                                name: String::from("Class"),
                                line,
                            }),
                        }
                    };
                    /* cpe part */
                    let cpe_parser = |line: String| -> Result<String, PistolError> {
                        match cpe_reg.captures(&line) {
                            Some(caps) => {
                                let cpe = caps.name("cpe").map_or("", |m| m.as_str());
                                Ok(cpe.to_string())
                            }
                            None => {
                                return Err(PistolError::OSDBParseError {
                                    name: String::from("CPE"),
                                    line,
                                });
                            }
                        }
                    };
                    /* seq part */
                    let seq_parser = |line: String| -> Result<SEQDB, PistolError> {
                        match seq_reg.captures(&line) {
                            Some(caps) => {
                                let sp = caps.name("sp").map_or("", |m| m.as_str());
                                let r = caps.name("r").map_or("", |m| m.as_str());
                                let gcd = caps.name("gcd").map_or("", |m| m.as_str());
                                let isr = caps.name("isr").map_or("", |m| m.as_str());
                                let ti = caps.name("ti").map_or("", |m| m.as_str());
                                let ci = caps.name("ci").map_or("", |m| m.as_str());
                                let ii = caps.name("ii").map_or("", |m| m.as_str());
                                let ss = caps.name("ss").map_or("", |m| m.as_str());
                                let ts = caps.name("ts").map_or("", |m| m.as_str());

                                let sp = NmapData::parser_usize(sp)?;
                                let r = NmapData::parser_str(r);
                                let gcd = NmapData::parser_usize(gcd)?;
                                let isr = NmapData::parser_usize(isr)?;
                                let ti = NmapData::parser_str(ti);
                                let ci = NmapData::parser_str(ci);
                                let ii = NmapData::parser_str(ii);
                                let ss = NmapData::parser_str(ss);
                                let ts = NmapData::parser_str(ts);

                                let seq = SEQDB {
                                    sp,
                                    r,
                                    gcd,
                                    isr,
                                    ti,
                                    ci,
                                    ii,
                                    ss,
                                    ts,
                                };
                                Ok(seq)
                            }
                            None => {
                                return Err(PistolError::OSDBParseError {
                                    name: String::from("SEQ"),
                                    line,
                                });
                            }
                        }
                    };
                    /* ops part */
                    let ops_parser = |line: String| -> Result<OPSDB, PistolError> {
                        match ops_reg.captures(&line) {
                            Some(caps) => {
                                let r = caps.name("r").map_or("", |m| m.as_str());
                                let o1 = caps.name("o1").map_or("", |m| m.as_str());
                                let o2 = caps.name("o2").map_or("", |m| m.as_str());
                                let o3 = caps.name("o3").map_or("", |m| m.as_str());
                                let o4 = caps.name("o4").map_or("", |m| m.as_str());
                                let o5 = caps.name("o5").map_or("", |m| m.as_str());
                                let o6 = caps.name("o6").map_or("", |m| m.as_str());

                                let r = NmapData::parser_str(r);
                                let o1 = NmapData::parser_str(o1);
                                let o2 = NmapData::parser_str(o2);
                                let o3 = NmapData::parser_str(o3);
                                let o4 = NmapData::parser_str(o4);
                                let o5 = NmapData::parser_str(o5);
                                let o6 = NmapData::parser_str(o6);

                                let ops = OPSDB {
                                    r,
                                    o1,
                                    o2,
                                    o3,
                                    o4,
                                    o5,
                                    o6,
                                };
                                Ok(ops)
                            }
                            None => {
                                return Err(PistolError::OSDBParseError {
                                    name: String::from("OPS"),
                                    line,
                                });
                            }
                        }
                    };
                    /* win part */
                    let win_parser = |line: String| -> Result<WINDB, PistolError> {
                        match win_reg.captures(&line) {
                            Some(caps) => {
                                let r = caps.name("r").map_or("", |m| m.as_str());
                                let w1 = caps.name("w1").map_or("", |m| m.as_str());
                                let w2 = caps.name("w2").map_or("", |m| m.as_str());
                                let w3 = caps.name("w3").map_or("", |m| m.as_str());
                                let w4 = caps.name("w4").map_or("", |m| m.as_str());
                                let w5 = caps.name("w5").map_or("", |m| m.as_str());
                                let w6 = caps.name("w6").map_or("", |m| m.as_str());

                                let r = NmapData::parser_str(r);
                                let w1 = NmapData::parser_usize(w1)?;
                                let w2 = NmapData::parser_usize(w2)?;
                                let w3 = NmapData::parser_usize(w3)?;
                                let w4 = NmapData::parser_usize(w4)?;
                                let w5 = NmapData::parser_usize(w5)?;
                                let w6 = NmapData::parser_usize(w6)?;

                                let win = WINDB {
                                    r,
                                    w1,
                                    w2,
                                    w3,
                                    w4,
                                    w5,
                                    w6,
                                };
                                Ok(win)
                            }
                            None => {
                                return Err(PistolError::OSDBParseError {
                                    name: String::from("WIN"),
                                    line,
                                });
                            }
                        }
                    };
                    /* ecn part */
                    let ecn_parser = |line: String| -> Result<ECNDB, PistolError> {
                        match ecn_reg.captures(&line) {
                            Some(caps) => {
                                let r = caps.name("r").map_or("", |m| m.as_str());
                                let df = caps.name("df").map_or("", |m| m.as_str());
                                let t = caps.name("t").map_or("", |m| m.as_str());
                                let tg = caps.name("tg").map_or("", |m| m.as_str());
                                let w = caps.name("w").map_or("", |m| m.as_str());
                                let o = caps.name("o").map_or("", |m| m.as_str());
                                let cc = caps.name("cc").map_or("", |m| m.as_str());
                                let q = caps.name("q").map_or("", |m| m.as_str());

                                let r = NmapData::parser_str(r);
                                let df = NmapData::parser_str(df);
                                let t = NmapData::parser_usize(t)?;
                                let tg = NmapData::parser_usize(tg)?;
                                let w = NmapData::parser_usize(w)?;
                                let o = NmapData::parser_str(o);
                                let cc = NmapData::parser_str(cc);
                                let q = NmapData::parser_str(q);

                                let ecn = ECNDB {
                                    r,
                                    df,
                                    t,
                                    tg,
                                    w,
                                    o,
                                    cc,
                                    q,
                                };
                                Ok(ecn)
                            }
                            None => {
                                return Err(PistolError::OSDBParseError {
                                    name: String::from("ECN"),
                                    line,
                                });
                            }
                        }
                    };
                    /* tx part */
                    let tx_parser = |line: String| -> Result<TXDB, PistolError> {
                        match tx_reg.captures(&line) {
                            Some(caps) => {
                                let r = caps.name("r").map_or("", |m| m.as_str());
                                let df = caps.name("df").map_or("", |m| m.as_str());
                                let t = caps.name("t").map_or("", |m| m.as_str());
                                let tg = caps.name("tg").map_or("", |m| m.as_str());
                                let w = caps.name("w").map_or("", |m| m.as_str());
                                let s = caps.name("s").map_or("", |m| m.as_str());
                                let a = caps.name("a").map_or("", |m| m.as_str());
                                let f = caps.name("f").map_or("", |m| m.as_str());
                                let o = caps.name("o").map_or("", |m| m.as_str());
                                let rd = caps.name("rd").map_or("", |m| m.as_str());
                                let q = caps.name("q").map_or("", |m| m.as_str());

                                let r = NmapData::parser_str(r);
                                let df = NmapData::parser_str(df);
                                let t = NmapData::parser_usize(t)?;
                                let tg = NmapData::parser_usize(tg)?;
                                let w = NmapData::parser_usize(w)?;
                                let s = NmapData::parser_str(s);
                                let a = NmapData::parser_str(a);
                                let f = NmapData::parser_str(f);
                                let o = NmapData::parser_str(o);
                                let rd = NmapData::parser_usize(rd)?;
                                let q = NmapData::parser_str(q);

                                let txdb = TXDB {
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
                                };
                                Ok(txdb)
                            }
                            None => {
                                return Err(PistolError::OSDBParseError {
                                    name: format!("TX"),
                                    line,
                                });
                            }
                        }
                    };
                    /* u1 part */
                    let u1_parser = |line: String| -> Result<U1DB, PistolError> {
                        match u1_reg.captures(&line) {
                            Some(caps) => {
                                let r = caps.name("r").map_or("", |m| m.as_str());
                                let df = caps.name("df").map_or("", |m| m.as_str());
                                let t = caps.name("t").map_or("", |m| m.as_str());
                                let tg = caps.name("tg").map_or("", |m| m.as_str());
                                let ripl = caps.name("ripl").map_or("", |m| m.as_str());
                                let ipl = caps.name("ipl").map_or("", |m| m.as_str());
                                let un = caps.name("un").map_or("", |m| m.as_str());
                                let rid = caps.name("rid").map_or("", |m| m.as_str());
                                let ripck = caps.name("ripck").map_or("", |m| m.as_str());
                                let ruck = caps.name("ruck").map_or("", |m| m.as_str());
                                let rud = caps.name("rud").map_or("", |m| m.as_str());

                                let r = NmapData::parser_str(r);
                                let df = NmapData::parser_str(df);
                                let t = NmapData::parser_usize(t)?;
                                let tg = NmapData::parser_usize(tg)?;
                                let ripl = NmapData::parser_str(ripl);
                                let ipl = NmapData::parser_usize(ipl)?;
                                let un = NmapData::parser_usize(un)?;
                                let rid = NmapData::parser_str(rid);
                                let ripck = NmapData::parser_str(ripck);
                                let ruck = NmapData::parser_str(ruck);
                                let rud = NmapData::parser_str(rud);

                                let u1 = U1DB {
                                    r,
                                    df,
                                    t,
                                    tg,
                                    ripl,
                                    ipl,
                                    un,
                                    rid,
                                    ripck,
                                    ruck,
                                    rud,
                                };
                                Ok(u1)
                            }
                            None => {
                                return Err(PistolError::OSDBParseError {
                                    name: format!("U1"),
                                    line,
                                });
                            }
                        }
                    };
                    /* ie part */
                    let ie_parser = |line: String| -> Result<Option<IEDB>, PistolError> {
                        match ie_reg.captures(&line) {
                            Some(caps) => {
                                let r = caps.name("r").map_or("", |m| m.as_str());
                                let dfi = caps.name("dfi").map_or("", |m| m.as_str());
                                let t = caps.name("t").map_or("", |m| m.as_str());
                                let tg = caps.name("tg").map_or("", |m| m.as_str());
                                let cd = caps.name("cd").map_or("", |m| m.as_str());

                                let r = NmapData::parser_str(r);
                                let dfi = NmapData::parser_str(dfi);
                                let t = NmapData::parser_usize(t)?;
                                let tg = NmapData::parser_usize(tg)?;
                                let cd = NmapData::parser_str(cd);

                                let ie = IEDB { r, dfi, t, tg, cd };
                                Ok(Some(ie))
                            }
                            None => {
                                // return Err(PistolError::OSDBParseError {
                                //     name: format!("IE"),
                                //     line,
                                // })
                                Ok(None)
                            }
                        }
                    };

                    let mut class = Vec::new();
                    let mut cpe = Vec::new();
                    loop {
                        match iter.next() {
                            Some(line) => {
                                if line.starts_with("Class") {
                                    class.extend(class_parser(line)?);
                                } else if line.starts_with("CPE") {
                                    let c = cpe_parser(line)?;
                                    cpe.push(c);
                                } else if line.starts_with("SEQ") {
                                    // only one line
                                    let seq = seq_parser(line)?;
                                    let line = match iter.next() {
                                        Some(line) => line,
                                        None => break,
                                    };
                                    let ops = ops_parser(line)?;
                                    let line = match iter.next() {
                                        Some(line) => line,
                                        None => break,
                                    };
                                    let win = win_parser(line)?;
                                    let line = match iter.next() {
                                        Some(line) => line,
                                        None => break,
                                    };
                                    let ecn = ecn_parser(line)?;
                                    let line = match iter.next() {
                                        Some(line) => line,
                                        None => break,
                                    };
                                    let t1 = tx_parser(line)?;
                                    let line = match iter.next() {
                                        Some(line) => line,
                                        None => break,
                                    };
                                    let t2 = tx_parser(line)?;
                                    let line = match iter.next() {
                                        Some(line) => line,
                                        None => break,
                                    };
                                    let t3 = tx_parser(line)?;
                                    let line = match iter.next() {
                                        Some(line) => line,
                                        None => break,
                                    };
                                    let t4 = tx_parser(line)?;
                                    let line = match iter.next() {
                                        Some(line) => line,
                                        None => break,
                                    };
                                    let t5 = tx_parser(line)?;
                                    let line = match iter.next() {
                                        Some(line) => line,
                                        None => break,
                                    };
                                    let t6 = tx_parser(line)?;
                                    let line = match iter.next() {
                                        Some(line) => line,
                                        None => break,
                                    };
                                    let t7 = tx_parser(line)?;
                                    let line = match iter.next() {
                                        Some(line) => line,
                                        None => break,
                                    };
                                    let u1 = u1_parser(line)?;
                                    let line = match iter.next() {
                                        Some(line) => line,
                                        None => break,
                                    };
                                    let ie = ie_parser(line)?;

                                    let nmap_os_db = NmapOSDB {
                                        name: name.clone(),
                                        class: class.clone(),
                                        cpe: cpe.clone(),
                                        seq,
                                        ops,
                                        win,
                                        ecn,
                                        t1,
                                        t2,
                                        t3,
                                        t4,
                                        t5,
                                        t6,
                                        t7,
                                        u1,
                                        ie,
                                    };
                                    ret.push(nmap_os_db);
                                } else {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
            None => break,
        }
    }

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::time::Instant;
    #[test]
    #[ignore]
    fn test_parser() {
        /* THIS CODES PERFORMENCE IS SO POORLY THAN MY IMAGEINATION */
        /* SO JUST LEAVE ITS HERE AND NOT USE IT IN OTHER FUNCTIONS */

        let start = Instant::now();
        let nmap_os_file = include_str!("../db/nmap-os-db");
        let mut nmap_os_file_lines = Vec::new();
        for l in nmap_os_file.lines() {
            nmap_os_file_lines.push(l.to_string());
        }
        println!("read os db file finish");
        let ret = nmap_os_db_parser(nmap_os_file_lines).unwrap();
        println!("len: {}", ret.len());

        println!("parse time: {:.3}", start.elapsed().as_secs_f64());

        let serialized = serde_json::to_string(&ret).unwrap();
        let mut file_write = File::create("nmap-os-db.pistol").unwrap();
        file_write.write_all(serialized.as_bytes()).unwrap();
    }
}
