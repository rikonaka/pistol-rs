// Each request corresponds to a response, all layer3 packet
#[derive(Debug, Clone)]
pub struct RequestAndResponse {
    pub name: String,
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
pub struct NXRR {
    pub ni: RequestAndResponse,
    pub ns: RequestAndResponse,
}

#[derive(Debug, Clone)]
pub struct TECNRR {
    pub tecn: RequestAndResponse,
}

#[derive(Debug, Clone)]
pub struct AllPacketRR6 {
    pub seq: SEQRR,
    pub ie: IERR,
    pub nx: NXRR,
    pub u1: U1RR,
    pub tecn: TECNRR,
    pub tx: TXRR,
}
