//! DKLST baseline: threshold BBS+ over the DKLs18 OT-based multiplier.
//!
//! Standalone crate (own workspace) because the OT layer `sl-oblivious` is under a
//! non-commercial licence and must not leak into the main `threshold-bbs` tree.
//!
//! With the `libote` feature the same protocol runs over <https://github.com/osu-crypto/libOTe>'s
//! SoftSpokenOT instead; see [`ot::Backend`] and [`libote`].

#[cfg(feature = "libote")]
pub mod libote;
pub mod mul;
pub mod ot;
pub mod params;
pub mod sign;
