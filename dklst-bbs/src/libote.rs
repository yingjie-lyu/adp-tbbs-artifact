//! FFI to the libOTe SoftSpokenOT shim (`cpp/libote_shim.cc`).
//!
//! The shim keeps the C++ side as thin as possible: it owns the base OTs and runs one extension,
//! nothing else. Every DKLST-specific operation stays in Rust, so switching backends changes only
//! the OT library and not the protocol.
//!
//! The two parties are driven with `macoro::when_all_ready` over an in-process
//! `coproto::LocalAsyncSocket` pair, on the calling thread. This matters for the numbers: the
//! measured wall time is the joint cost of both parties, exactly like the sequential
//! single-threaded measurements of the `sl-oblivious` backend.

use std::ffi::c_void;
use std::os::raw::{c_char, c_int};

/// Timing and wire statistics reported by the shim. Mirrors `libote_stats`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub wall_ns: u64,
    pub bytes_sender: u64,
    pub bytes_receiver: u64,
    pub ok: i32,
}

extern "C" {
    fn libote_pair_new(field_bits: u32, stats: *mut Stats) -> *mut c_void;
    fn libote_pair_free(handle: *mut c_void);
    fn libote_extend(
        handle: *mut c_void,
        choices: *const u8,
        n: u64,
        v0: *mut u8,
        v1: *mut u8,
        vx: *mut u8,
        stats: *mut Stats,
    ) -> c_int;
    fn libote_shim_version() -> *const c_char;
    fn libote_base_ot_count() -> u64;
}

/// One ordered pair's base OTs, owned by libOTe.
pub struct Pair {
    handle: *mut c_void,
    /// Base-OT cost, measured once at setup.
    pub setup: Stats,
}

// The handle is only ever touched from the thread that created it: the benchmark is
// single-threaded and the shim itself does not spawn threads.
unsafe impl Send for Pair {}
unsafe impl Sync for Pair {}

impl Pair {
    /// Run the base OTs. `field_bits` is SoftSpokenOT's computation/communication knob; 2 is
    /// libOTe's default and the setting its own benchmarks use.
    pub fn new() -> Option<Self> {
        Self::with_field_bits(2)
    }

    pub fn with_field_bits(field_bits: u32) -> Option<Self> {
        let mut stats = Stats::default();
        let handle = unsafe { libote_pair_new(field_bits, &mut stats) };
        if handle.is_null() {
            return None;
        }
        Some(Self { handle, setup: stats })
    }

    /// One extension of `n` 128-bit OTs; returns the three pad streams as raw 16-byte blocks.
    #[allow(clippy::type_complexity)]
    pub fn extend(&self, choices: &[u8], n: usize) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>, Stats)> {
        if n == 0 || choices.len() * 8 < n {
            return None;
        }
        let mut v0 = vec![0u8; 16 * n];
        let mut v1 = vec![0u8; 16 * n];
        let mut vx = vec![0u8; 16 * n];
        let mut stats = Stats::default();
        let ok = unsafe {
            libote_extend(
                self.handle,
                choices.as_ptr(),
                n as u64,
                v0.as_mut_ptr(),
                v1.as_mut_ptr(),
                vx.as_mut_ptr(),
                &mut stats,
            )
        };
        if ok == 0 {
            None
        } else {
            Some((v0, v1, vx, stats))
        }
    }

    /// Cost of the base OTs paid by this pair, measured at construction.
    pub fn base_ot_stats(&self) -> Stats {
        self.setup
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        unsafe { libote_pair_free(self.handle) };
    }
}

/// Description of the linked libOTe build, for the benchmark report.
pub fn version() -> String {
    let raw = unsafe { libote_shim_version() };
    if raw.is_null() {
        return "libOTe".to_string();
    }
    unsafe { std::ffi::CStr::from_ptr(raw) }
        .to_string_lossy()
        .into_owned()
}

/// Number of base OTs one pair consumes (SoftSpokenOT seeds, 128).
pub fn base_ot_count() -> u64 {
    unsafe { libote_base_ot_count() }
}
