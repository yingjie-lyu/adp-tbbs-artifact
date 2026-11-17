//! An in-memory bulletin board with a private channel.
//!
//! The point of this module is to keep the wire boundary real: parties exchange `Vec<u8>` and
//! nothing else, so every encoder is exercised on every session. A deployment replaces
//! [`Bus`] with a network client; the session drivers in [`crate::session`] only need
//! `publish`, `send_to`, `broadcast` and `direct`.
//!
//! Traffic is metered per `(party, round)`, which is what the paper's Table 3 reports:
//! outgoing communication per signer.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Round {
    SeedCommit,
    SeedOpen,
    Pvss,
    KeygenCommit,
    KeygenOpen,
    SignCommit,
    SignOpen,
    SignShare,
}

impl Round {
    pub const ALL: [Round; 8] = [
        Round::SeedCommit,
        Round::SeedOpen,
        Round::Pvss,
        Round::KeygenCommit,
        Round::KeygenOpen,
        Round::SignCommit,
        Round::SignOpen,
        Round::SignShare,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Round::SeedCommit => "seed commit",
            Round::SeedOpen => "seed open",
            Round::Pvss => "PVSS",
            Round::KeygenCommit => "keygen commit",
            Round::KeygenOpen => "keygen open",
            Round::SignCommit => "sign r1",
            Round::SignOpen => "sign r2",
            Round::SignShare => "sign r3",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Envelope {
    pub round: Round,
    pub from: usize,
    /// `None` for a broadcast, `Some(id)` for a point-to-point message.
    pub to: Option<usize>,
    pub payload: Vec<u8>,
}

impl Envelope {
    pub fn size(&self) -> usize {
        self.payload.len()
    }
}

/// A broadcast medium plus a private channel, with one inbox per party.
#[derive(Debug, Default)]
pub struct Bus {
    inboxes: BTreeMap<usize, Vec<Envelope>>,
    /// `(party, round) -> (messages sent, bytes sent)`.
    sent: BTreeMap<(usize, Round), (usize, usize)>,
}

impl Bus {
    pub fn new(parties: &[usize]) -> Self {
        let mut inboxes = BTreeMap::new();
        for id in parties {
            inboxes.insert(*id, Vec::new());
        }
        Self {
            inboxes,
            sent: BTreeMap::new(),
        }
    }

    fn meter(&mut self, from: usize, round: Round, payload: &[u8]) {
        let entry = self.sent.entry((from, round)).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += payload.len();
    }

    /// Broadcast: every party, including the sender, receives a copy.
    pub fn publish(&mut self, round: Round, from: usize, payload: Vec<u8>) -> Result<()> {
        if !self.inboxes.contains_key(&from) {
            return Err(Error::Protocol("publisher is not a party"));
        }
        self.meter(from, round, &payload);
        let envelope = Envelope {
            round,
            from,
            to: None,
            payload,
        };
        for inbox in self.inboxes.values_mut() {
            inbox.push(envelope.clone());
        }
        Ok(())
    }

    /// Point-to-point: only the recipient's inbox gets a copy.
    pub fn send_to(&mut self, round: Round, from: usize, to: usize, payload: Vec<u8>) -> Result<()> {
        if !self.inboxes.contains_key(&from) || !self.inboxes.contains_key(&to) {
            return Err(Error::Protocol("unknown party on the private channel"));
        }
        self.meter(from, round, &payload);
        let envelope = Envelope {
            round,
            from,
            to: Some(to),
            payload,
        };
        self.inboxes
            .get_mut(&to)
            .ok_or(Error::Protocol("unknown recipient"))?
            .push(envelope);
        Ok(())
    }

    fn drain(&mut self, id: usize, round: Round, broadcast: bool) -> Result<Vec<Envelope>> {
        let inbox = self
            .inboxes
            .get_mut(&id)
            .ok_or(Error::Protocol("unknown recipient"))?;
        let mut taken = Vec::new();
        let mut kept = Vec::with_capacity(inbox.len());
        for envelope in inbox.drain(..) {
            let matches = envelope.round == round && envelope.to.is_none() == broadcast;
            if matches {
                taken.push(envelope);
            } else {
                kept.push(envelope);
            }
        }
        *inbox = kept;
        Ok(taken)
    }

    /// Take this party's broadcast messages for `round`.
    pub fn broadcast(&mut self, id: usize, round: Round) -> Result<Vec<Envelope>> {
        self.drain(id, round, true)
    }

    /// Take this party's point-to-point messages for `round`.
    pub fn direct(&mut self, id: usize, round: Round) -> Result<Vec<Envelope>> {
        self.drain(id, round, false)
    }

    /// `(messages, bytes)` published by `id` so far.
    pub fn outgoing(&self, id: usize) -> (usize, usize) {
        self.sent
            .iter()
            .filter(|((party, _), _)| *party == id)
            .fold((0, 0), |total, (_, entry)| (total.0 + entry.0, total.1 + entry.1))
    }

    /// `(messages, bytes)` published by `id` in `round`.
    pub fn outgoing_in(&self, id: usize, round: Round) -> (usize, usize) {
        *self.sent.get(&(id, round)).unwrap_or(&(0, 0))
    }

    /// `(messages, bytes)` published by everyone.
    pub fn total_outgoing(&self) -> (usize, usize) {
        self.sent
            .values()
            .fold((0, 0), |total, entry| (total.0 + entry.0, total.1 + entry.1))
    }

    pub fn pending(&self) -> usize {
        self.inboxes.values().map(|inbox| inbox.len()).sum()
    }
}
