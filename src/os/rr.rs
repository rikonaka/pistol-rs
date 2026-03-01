use std::sync::Arc;
use std::time::Duration;

// Each request corresponds to a response, all layer3 packet
#[derive(Debug, Clone)]
pub(crate) struct RequestResponse {
    // pub(crate) name: String,
    pub(crate) request: Arc<[u8]>,  // layer3
    pub(crate) response: Arc<[u8]>, // layer3, if no response: response.len() == 0
    pub(crate) rtt: Duration,
}

impl Default for RequestResponse {
    fn default() -> Self {
        Self {
            request: Arc::new([]),
            response: Arc::new([]),
            rtt: Duration::ZERO,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SEQRR {
    pub(crate) seq1: RequestResponse,
    pub(crate) seq2: RequestResponse,
    pub(crate) seq3: RequestResponse,
    pub(crate) seq4: RequestResponse,
    pub(crate) seq5: RequestResponse,
    pub(crate) seq6: RequestResponse,
    pub(crate) elapsed: f64,
}

#[derive(Debug, Clone)]
pub(crate) struct IERR {
    pub(crate) ie1: RequestResponse,
    pub(crate) ie2: RequestResponse,
}

#[derive(Debug, Clone)]
pub(crate) struct ECNRR {
    pub(crate) ecn: RequestResponse,
}

#[derive(Debug, Clone)]
pub(crate) struct TXRR {
    pub(crate) t2: RequestResponse,
    pub(crate) t3: RequestResponse,
    pub(crate) t4: RequestResponse,
    pub(crate) t5: RequestResponse,
    pub(crate) t6: RequestResponse,
    pub(crate) t7: RequestResponse,
}

#[derive(Debug, Clone)]
pub(crate) struct U1RR {
    pub(crate) u1: RequestResponse,
}

#[derive(Debug, Clone)]
pub(crate) struct AllPacketRR {
    pub(crate) seq: SEQRR,
    pub(crate) ie: IERR,
    pub(crate) ecn: ECNRR,
    pub(crate) tx: TXRR,
    pub(crate) u1: U1RR,
}

#[derive(Debug, Clone)]
pub(crate) struct NXRR6 {
    pub(crate) ni: RequestResponse,
    pub(crate) ns: RequestResponse,
    pub(crate) sti: Duration,
    pub(crate) rti: Duration,
    pub(crate) sts: Duration,
    pub(crate) rts: Duration,
}

#[derive(Debug, Clone)]
pub(crate) struct TECNRR6 {
    pub(crate) tecn: RequestResponse,
    pub(crate) st: Duration,
    pub(crate) rt: Duration,
}

#[derive(Debug, Clone)]
pub(crate) struct SEQRR6 {
    pub(crate) seq1: RequestResponse,
    pub(crate) seq2: RequestResponse,
    pub(crate) seq3: RequestResponse,
    pub(crate) seq4: RequestResponse,
    pub(crate) seq5: RequestResponse,
    pub(crate) seq6: RequestResponse,
    pub(crate) elapsed: f64,
    pub(crate) st1: Duration,
    pub(crate) rt1: Duration,
    pub(crate) st2: Duration,
    pub(crate) rt2: Duration,
    pub(crate) st3: Duration,
    pub(crate) rt3: Duration,
    pub(crate) st4: Duration,
    pub(crate) rt4: Duration,
    pub(crate) st5: Duration,
    pub(crate) rt5: Duration,
    pub(crate) st6: Duration,
    pub(crate) rt6: Duration,
}

#[derive(Debug, Clone)]
pub(crate) struct IERR6 {
    pub(crate) ie1: RequestResponse,
    pub(crate) ie2: RequestResponse,
    pub(crate) st1: Duration,
    pub(crate) rt1: Duration,
    pub(crate) st2: Duration,
    pub(crate) rt2: Duration,
}

#[derive(Debug, Clone)]
pub(crate) struct U1RR6 {
    pub(crate) u1: RequestResponse,
    pub(crate) st: Duration,
    pub(crate) rt: Duration,
}

#[derive(Debug, Clone)]
pub(crate) struct TXRR6 {
    pub(crate) t2: RequestResponse,
    pub(crate) t3: RequestResponse,
    pub(crate) t4: RequestResponse,
    pub(crate) t5: RequestResponse,
    pub(crate) t6: RequestResponse,
    pub(crate) t7: RequestResponse,
    pub(crate) st2: Duration,
    pub(crate) rt2: Duration,
    pub(crate) st3: Duration,
    pub(crate) rt3: Duration,
    pub(crate) st4: Duration,
    pub(crate) rt4: Duration,
    pub(crate) st5: Duration,
    pub(crate) rt5: Duration,
    pub(crate) st6: Duration,
    pub(crate) rt6: Duration,
    pub(crate) st7: Duration,
    pub(crate) rt7: Duration,
}

#[derive(Debug, Clone)]
pub(crate) struct AllPacketRR6 {
    pub(crate) seq: SEQRR6,
    pub(crate) ie: IERR6,
    pub(crate) nx: NXRR6,
    pub(crate) u1: U1RR6,
    pub(crate) tecn: TECNRR6,
    pub(crate) tx: TXRR6,
}
