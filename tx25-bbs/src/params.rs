//! Public parameters: the pairing group, the bases `H_1 .. H_{ell+1}`, and the CL framework.

use std::sync::Arc;

use tcl::cl::ClParameters;

use threshold_bbs::bls381::{hash_to_g1, G1};

pub const DST_BASE: &[u8] = b"tx25-bbs/v01/setup/H";

pub struct PublicParameters {
    pub cl: Arc<ClParameters>,
    pub message_len: usize,
    /// `H_1 .. H_{ell+1}`: `H_1` is the base of `s`, `H_2..` are the message bases.
    pub bases: Vec<G1>,
}

impl PublicParameters {
    pub fn new(cl: Arc<ClParameters>, message_len: usize) -> Arc<Self> {
        let bases = (0..=message_len)
            .map(|index| hash_to_g1(DST_BASE, &(index as u64).to_be_bytes()))
            .collect();
        Arc::new(Self {
            cl,
            message_len,
            bases,
        })
    }
}
