//! A minimal in-memory bulletin board.
//!
//! The point of this module is to make the wire boundary real: parties exchange `Vec<u8>`
//! and nothing else, so the encoders in [`crate::wire`] are exercised on every session. A
//! deployment replaces [`Bus`] with a network client; the session driver in
//! [`crate::session`] only needs `publish` and `drain`.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Round {
    One,
    Two,
}

#[derive(Clone, Debug)]
pub struct Envelope {
    pub session: Vec<u8>,
    pub round: Round,
    pub from: usize,
    pub payload: Vec<u8>,
}

impl Envelope {
    pub fn size(&self) -> usize {
        self.payload.len()
    }
}

/// A broadcast medium with one inbox per party.
///
/// Publishing appends to every inbox, including the sender's: in this protocol a party needs
/// its own round-1 message to key the pairwise masks and to recompute the transcript.
#[derive(Default, Debug)]
pub struct Bus {
    inboxes: BTreeMap<usize, Vec<Envelope>>,
    sent: usize,
    delivered: usize,
    bytes: usize,
}

impl Bus {
    pub fn new(parties: &[usize]) -> Self {
        let mut inboxes = BTreeMap::new();
        for id in parties {
            inboxes.insert(*id, Vec::new());
        }
        Self {
            inboxes,
            sent: 0,
            delivered: 0,
            bytes: 0,
        }
    }

    pub fn is_party(&self, id: usize) -> bool {
        self.inboxes.contains_key(&id)
    }

    /// Broadcast a payload to every party.
    pub fn publish(
        &mut self,
        session: &[u8],
        round: Round,
        from: usize,
        payload: Vec<u8>,
    ) -> Result<()> {
        if !self.inboxes.contains_key(&from) {
            return Err(Error::UnexpectedMessage("publisher is not a party"));
        }
        let envelope = Envelope {
            session: session.to_vec(),
            round,
            from,
            payload,
        };
        self.sent += 1;
        self.bytes += envelope.size();
        for inbox in self.inboxes.values_mut() {
            inbox.push(envelope.clone());
            self.delivered += 1;
        }
        Ok(())
    }

    /// Take every message for `id` in `(session, round)`. Later queued messages stay put.
    pub fn drain(&mut self, id: usize, session: &[u8], round: Round) -> Result<Vec<Envelope>> {
        let inbox = self
            .inboxes
            .get_mut(&id)
            .ok_or(Error::UnexpectedMessage("unknown recipient"))?;
        let mut taken = Vec::new();
        let mut kept = Vec::with_capacity(inbox.len());
        for envelope in inbox.drain(..) {
            if envelope.session == session && envelope.round == round {
                taken.push(envelope);
            } else {
                kept.push(envelope);
            }
        }
        *inbox = kept;
        Ok(taken)
    }

    /// `(messages published, deliveries, payload bytes published)`.
    pub fn stats(&self) -> (usize, usize, usize) {
        (self.sent, self.delivered, self.bytes)
    }

    pub fn pending(&self) -> usize {
        self.inboxes.values().map(|inbox| inbox.len()).sum()
    }
}
