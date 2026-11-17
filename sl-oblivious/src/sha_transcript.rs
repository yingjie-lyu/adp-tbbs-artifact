// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.
//
// SHA-256 transcript (added locally; see MODIFICATIONS.md).
//
// Drop-in replacement for the subset of `merlin::Transcript` this crate uses
// (`new` / `append_message` / `append_u64` / `challenge_bytes`), so that the OT layer hashes
// with SHA-256, which x86 SHA-NI accelerates, instead of STROBE/Keccak-f1600.
//
// It is *not* a STROBE implementation: every `challenge_bytes` call is a fresh SHA-256 over
// (domain, absorbed buffer, call counter, label, block index). Both parties run the same code,
// so the transcripts agree; the construction is an ordinary Fiat–Shamir hash chain and carries
// no claim of STROBE's security arguments.

use sha2::{Digest, Sha256};

pub struct Transcript {
    domain: Vec<u8>,
    buffer: Vec<u8>,
    challenges: u64,
}

fn push_item(buffer: &mut Vec<u8>, item: &[u8]) {
    buffer.extend_from_slice(&(item.len() as u32).to_le_bytes());
    buffer.extend_from_slice(item);
}

impl Transcript {
    pub fn new(label: &'static [u8]) -> Self {
        let mut domain = Vec::new();
        push_item(&mut domain, label);
        Self {
            domain,
            buffer: Vec::new(),
            challenges: 0,
        }
    }

    pub fn append_message(&mut self, label: &'static [u8], message: &[u8]) -> &mut Self {
        push_item(&mut self.buffer, label);
        push_item(&mut self.buffer, message);
        self
    }

    pub fn append_u64(&mut self, label: &'static [u8], value: u64) -> &mut Self {
        self.append_message(label, &value.to_le_bytes())
    }

    pub fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        let mut labelised = Vec::new();
        push_item(&mut labelised, label);
        let mut written = 0usize;
        let mut block = 0u64;
        while written < dest.len() {
            let mut hasher = Sha256::new();
            hasher.update(&self.domain);
            hasher.update(&self.buffer);
            hasher.update(self.challenges.to_le_bytes());
            hasher.update(&labelised);
            hasher.update(block.to_le_bytes());
            let digest = hasher.finalize();
            let take = core::cmp::min(32, dest.len() - written);
            dest[written..written + take].copy_from_slice(&digest[..take]);
            written += take;
            block += 1;
        }
        self.challenges += 1;
    }
}
