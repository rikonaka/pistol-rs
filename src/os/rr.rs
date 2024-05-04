use std::time::Duration;

// Each request corresponds to a response, all layer3 packet
#[derive(Debug, Clone)]
pub struct RequestAndResponse {
    // pub name: String,
    pub request: Vec<u8>,  // layer3
    pub response: Vec<u8>, // layer3, if no response: response.len() == 0
}

#[derive(Debug, Clone)]
pub struct SEQRR {
    pub seq1: RequestAndResponse,
    pub seq2: RequestAndResponse,
    pub seq3: RequestAndResponse,
    pub seq4: RequestAndResponse,
    pub seq5: RequestAndResponse,
    pub seq6: RequestAndResponse,
    pub elapsed: f64,
}

#[derive(Debug, Clone)]
pub struct IERR {
    pub ie1: RequestAndResponse,
    pub ie2: RequestAndResponse,
}

#[derive(Debug, Clone)]
pub struct ECNRR {
    pub ecn: RequestAndResponse,
}

#[derive(Debug, Clone)]
pub struct TXRR {
    pub t2: RequestAndResponse,
    pub t3: RequestAndResponse,
    pub t4: RequestAndResponse,
    pub t5: RequestAndResponse,
    pub t6: RequestAndResponse,
    pub t7: RequestAndResponse,
}

#[derive(Debug, Clone)]
pub struct U1RR {
    pub u1: RequestAndResponse,
}

#[derive(Debug, Clone)]
pub struct AllPacketRR {
    pub seq: SEQRR,
    pub ie: IERR,
    pub ecn: ECNRR,
    pub tx: TXRR,
    pub u1: U1RR,
}

#[derive(Debug, Clone)]
pub struct NXRR6 {
    pub ni: RequestAndResponse,
    pub ns: RequestAndResponse,
    pub sti: Duration,
    pub rti: Duration,
    pub sts: Duration,
    pub rts: Duration,
}

#[derive(Debug, Clone)]
pub struct TECNRR6 {
    pub tecn: RequestAndResponse,
    pub st: Duration,
    pub rt: Duration,
}

#[derive(Debug, Clone)]
pub struct SEQRR6 {
    pub seq1: RequestAndResponse,
    pub seq2: RequestAndResponse,
    pub seq3: RequestAndResponse,
    pub seq4: RequestAndResponse,
    pub seq5: RequestAndResponse,
    pub seq6: RequestAndResponse,
    pub elapsed: f64,
    pub st1: Duration,
    pub rt1: Duration,
    pub st2: Duration,
    pub rt2: Duration,
    pub st3: Duration,
    pub rt3: Duration,
    pub st4: Duration,
    pub rt4: Duration,
    pub st5: Duration,
    pub rt5: Duration,
    pub st6: Duration,
    pub rt6: Duration,
}

#[derive(Debug, Clone)]
pub struct IERR6 {
    pub ie1: RequestAndResponse,
    pub ie2: RequestAndResponse,
    pub st1: Duration,
    pub rt1: Duration,
    pub st2: Duration,
    pub rt2: Duration,
}

#[derive(Debug, Clone)]
pub struct U1RR6 {
    pub u1: RequestAndResponse,
    pub st: Duration,
    pub rt: Duration,
}

#[derive(Debug, Clone)]
pub struct TXRR6 {
    pub t2: RequestAndResponse,
    pub t3: RequestAndResponse,
    pub t4: RequestAndResponse,
    pub t5: RequestAndResponse,
    pub t6: RequestAndResponse,
    pub t7: RequestAndResponse,
    pub st2: Duration,
    pub rt2: Duration,
    pub st3: Duration,
    pub rt3: Duration,
    pub st4: Duration,
    pub rt4: Duration,
    pub st5: Duration,
    pub rt5: Duration,
    pub st6: Duration,
    pub rt6: Duration,
    pub st7: Duration,
    pub rt7: Duration,
}

#[derive(Debug, Clone)]
pub struct AllPacketRR6 {
    pub seq: SEQRR6,
    pub ie: IERR6,
    pub nx: NXRR6,
    pub u1: U1RR6,
    pub tecn: TECNRR6,
    pub tx: TXRR6,
}
