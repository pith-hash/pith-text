//! The C ABI surface of `pith-text`: the entry points the Python
//! (ctypes), Node (koffi) and Go (cgo) SDKs bind through.
//!
//! The suite's FFI convention, defined by this module and mirrored by
//! every `pith-*` cdylib:
//!
//! * one flat set of `#[unsafe(no_mangle)] pub unsafe extern "C"`
//!   functions — raw pointers plus lengths, no structs across the
//!   boundary;
//! * every function returns a status code (see the constants below),
//!   never a `Result`, never a panic: a `panic = "abort"` cdylib must
//!   not be reachable from a foreign caller;
//! * an operation either hands ownership to the caller (and ships a
//!   matching `_free` — [`pith_text_free`] here) or writes into
//!   caller-provided out-parameters — [`pith_text_jaccard`] allocates
//!   nothing, so it ships no free;
//! * the `unsafe` allowance is confined to this module; every core
//!   module stays unsafe-free behind the crate-root `#![deny]`.
//!
//! # Wire formats (the cross-SDK contract)
//!
//! `pith_text_fingerprint` hands out the canonical fingerprint stream
//! of [`crate::reference::canonical_stream`]:
//!
//! ```text
//! [0..4)    word_count     u32 big-endian
//! [4..8)    shingle_count  u32 big-endian
//! [8..8+C)  canonical      the canonical UTF-8 bytes (C bytes)
//! [8+C..)   signature      128 u64 little-endian words (1024 bytes)
//! ```
//!
//! so `canonical_sha256 == sha256(stream[8..8+C])` and the
//! `signature_fnv1a64` / `signature_sha256` folds of `reference.json`
//! are the standard folds over the 1024-byte little-endian tail. The
//! input is UTF-8: `len` is a **byte** length, and bytes that are not
//! valid UTF-8 are rejected ([`PITH_E_REJECTED`]), never lossily
//! coerced. The empty input is valid and pins the sentinel stream
//! (zero counts, 128 `u64::MAX` words) — it is *not* a refusal.
//!
//! `pith_text_jaccard` compares two `u64` word slices: the words are
//! read one element at a time with [`core::ptr::read_unaligned`] (the
//! SDK-side blob is a byte buffer, alignment is not guaranteed), and
//! the estimate crosses the ABI as its **f64 bit pattern** through a
//! `u64` out-parameter — no float crosses the boundary, so the SDKs
//! compare `value_bits` hex-exactly. A null pointer with `len == 0`
//! is the legal empty slice — the sentinel operand
//! (`reference.json`'s `empty-signature` arm passes `Vec::new()`,
//! *not* `signature("")`, whose all-`u64::MAX` words would score
//! ≈ 0) — while a null pointer with `len > 0` is [`PITH_E_INVALID`].

#![allow(unsafe_code)]

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::jaccard_estimate;
use crate::reference::canonical_stream;

/// Status: success.
pub const PITH_OK: i32 = 0;
/// Status: a caller argument is invalid — a null pointer (or a null
/// buffer carrying a nonzero length where a slice is read).
pub const PITH_E_INVALID: i32 = -1;
/// Status: the core pipeline refused the input (the bytes are not
/// valid UTF-8).
pub const PITH_E_REJECTED: i32 = -2;

/// Computes the full text fingerprint of a UTF-8 string into the
/// canonical byte stream the `reference.json` vectors are defined
/// over.
///
/// `data` points at `len` **bytes** of UTF-8 input (a byte length, so
/// multi-ordinal inputs are passed whole, never truncated to a
/// character count); `len == 0` — with or without a null `data` — is
/// the valid empty input. On success the function allocates a buffer,
/// writes its address through `out`, its length through `out_len`,
/// and returns [`PITH_OK`]; the caller owns the buffer and must
/// release it with [`pith_text_free`], passing back the same pointer
/// *and* length. The buffer layout is documented in the [module
/// docs](self): big-endian counts header, canonical UTF-8 bytes,
/// 128 little-endian signature words.
///
/// # Safety
///
/// `data` must point to `len` readable bytes; `out` to one writable
/// pointer; `out_len` to one writable `usize`. All must stay valid
/// for the duration of the call; the function retains nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pith_text_fingerprint(
    data: *const u8,
    len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if out.is_null() || out_len.is_null() {
        return PITH_E_INVALID;
    }
    let bytes: &[u8] = if len == 0 {
        // The empty input is legal (the canon-empty / sentinel case);
        // a null pointer carries no bytes to read.
        &[]
    } else {
        if data.is_null() {
            return PITH_E_INVALID;
        }
        unsafe { core::slice::from_raw_parts(data, len) }
    };
    match fingerprint_stream(bytes) {
        Ok(stream) => {
            let len = stream.len();
            // Hand the exact-length buffer to the caller; `pith_text_free`
            // reconstructs the boxed slice from the same length.
            let ptr = Box::into_raw(stream.into_boxed_slice());
            unsafe {
                *out = ptr.cast::<u8>();
                *out_len = len;
            }
            PITH_OK
        }
        Err(status) => status,
    }
}

/// Estimates the Jaccard index of the two shingle sets that produced
/// the `a_words` and `b_words` signature words.
///
/// `a` and `b` point at the callers' `u64` signature words (the
/// little-endian tail of a [`pith_text_fingerprint`] stream); the
/// words are read unaligned-safe, so the SDK-side buffers carry no
/// alignment promise. Callers comparing signatures pass full
/// 128-word signatures; the empty slice (`len == 0`, null allowed)
/// is the sentinel operand of `reference.json`'s `empty-signature`
/// vectors. On success the estimate is written through `out_bits` as
/// its `f64` bit pattern and [`PITH_OK`] is returned.
///
/// # Safety
///
/// `a` must point to `a_words` readable `u64` values and `b` to
/// `b_words` readable `u64` values (null is only legal with a zero
/// length); `out_bits` must point to one writable `u64`. All must
/// stay valid for the duration of the call; the function retains
/// nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pith_text_jaccard(
    a: *const u64,
    a_words: usize,
    b: *const u64,
    b_words: usize,
    out_bits: *mut u64,
) -> i32 {
    if out_bits.is_null() {
        return PITH_E_INVALID;
    }
    let a = match unsafe { read_words(a, a_words) } {
        Ok(words) => words,
        Err(status) => return status,
    };
    let b = match unsafe { read_words(b, b_words) } {
        Ok(words) => words,
        Err(status) => return status,
    };
    unsafe { *out_bits = jaccard_bits(&a, &b) };
    PITH_OK
}

/// Releases a buffer handed out by [`pith_text_fingerprint`].
///
/// # Safety
///
/// `ptr` must be a pointer returned by [`pith_text_fingerprint`]
/// with the `out_len` value that came back with it, and must not
/// have been released (or otherwise freed) before. Null is accepted
/// and ignored, so callers can free unconditionally on the error
/// path.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pith_text_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(ptr, len) };
    drop(unsafe { Box::from_raw(slice) });
}

/// The safe core of [`pith_text_fingerprint`]: validate UTF-8, then
/// serialize the canonical stream. Non-UTF-8 bytes map to
/// [`PITH_E_REJECTED`].
fn fingerprint_stream(bytes: &[u8]) -> Result<Vec<u8>, i32> {
    let text = core::str::from_utf8(bytes).map_err(|_| PITH_E_REJECTED)?;
    Ok(canonical_stream(text))
}

/// The safe core of [`pith_text_jaccard`]: the estimate as its `f64`
/// bit pattern.
fn jaccard_bits(a: &[u64], b: &[u64]) -> u64 {
    jaccard_estimate(a, b).to_bits()
}

/// Copies `words` `u64` values out of `ptr`, one
/// [`core::ptr::read_unaligned`] per element — the SDK-side blob is a
/// byte buffer, alignment is not guaranteed. A null pointer with a
/// zero length is the legal empty slice; a null pointer with a
/// nonzero length is [`PITH_E_INVALID`].
///
/// # Safety
///
/// `ptr` must point to `words` readable `u64` values (or be null
/// with `words == 0`).
unsafe fn read_words(ptr: *const u64, words: usize) -> Result<Vec<u64>, i32> {
    if ptr.is_null() {
        if words == 0 {
            return Ok(Vec::new());
        }
        return Err(PITH_E_INVALID);
    }
    let mut out = Vec::new();
    for i in 0..words {
        out.push(unsafe { core::ptr::read_unaligned(ptr.add(i)) });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{
        PITH_E_INVALID, PITH_E_REJECTED, PITH_OK, fingerprint_stream, jaccard_bits,
        pith_text_fingerprint, pith_text_free, pith_text_jaccard, read_words,
    };

    /// The canonical stream through the public module path, from raw
    /// input bytes — exactly the wire the FFI serves.
    fn canonical_stream_core(input: &[u8]) -> Vec<u8> {
        crate::reference::canonical_stream(core::str::from_utf8(input).expect("utf-8"))
    }

    /// Loads a committed fixture's bytes (UTF-8 by conformance).
    fn fixture(name: &str) -> Vec<u8> {
        let path = format!("{}/tests/fixtures/{name}.txt", env!("CARGO_MANIFEST_DIR"));
        std::fs::read(&path).expect("fixture")
    }

    /// The signature words of a fixture (the little-endian tail of its
    /// fingerprint stream), for jaccard pointer round-trips.
    fn fixture_words(name: &str) -> Vec<u64> {
        let stream = fingerprint_stream(&fixture(name)).expect("utf-8");
        let tail = &stream[stream.len() - 1024..];
        tail.chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect()
    }

    /// The FFI reproduces the safe core byte-for-byte and hands the
    /// buffer back through `pith_text_free`.
    #[test]
    fn ffi_fingerprint_roundtrips_the_canonical_stream() {
        let input = b"alpha beta gamma";
        let expected = canonical_stream_core(input);
        assert_eq!(expected.len(), 8 + 17 + 1024);

        let mut out: *mut u8 = core::ptr::null_mut();
        let mut out_len: usize = 0;
        let status =
            unsafe { pith_text_fingerprint(input.as_ptr(), input.len(), &mut out, &mut out_len) };
        assert_eq!(status, PITH_OK);
        assert_eq!(out_len, expected.len());
        let handed_back = unsafe { core::slice::from_raw_parts(out, out_len) };
        assert_eq!(handed_back, expected.as_slice());
        // The header is the documented one: 3 words, 1 shingle.
        assert_eq!(&handed_back[..8], &[0, 0, 0, 3, 0, 0, 0, 1]);
        unsafe { pith_text_free(out, out_len) };
    }

    /// The empty input is valid and carries the sentinel stream (this
    /// is the canon-empty / signature-empty-sentinel case, not a
    /// refusal).
    #[test]
    fn ffi_fingerprint_accepts_the_empty_input() {
        let expected = canonical_stream_core(b"");
        assert_eq!(expected.len(), 8 + 1 + 1024);

        let empty: Vec<u8> = Vec::new();
        let mut out: *mut u8 = core::ptr::null_mut();
        let mut out_len: usize = 0;
        let status =
            unsafe { pith_text_fingerprint(empty.as_ptr(), empty.len(), &mut out, &mut out_len) };
        assert_eq!(status, PITH_OK);
        let handed_back = unsafe { core::slice::from_raw_parts(out, out_len) };
        assert_eq!(handed_back, expected.as_slice());
        assert_eq!(handed_back[8], b'\n');
        assert!(handed_back[9..].iter().all(|&b| b == 0xff));
        unsafe { pith_text_free(out, out_len) };

        // A null pointer with len == 0 is the same legal empty input
        // (how the Go binding passes zero-length operands).
        let status = unsafe { pith_text_fingerprint(core::ptr::null(), 0, &mut out, &mut out_len) };
        assert_eq!(status, PITH_OK);
        unsafe { pith_text_free(out, out_len) };
    }

    /// Null out-parameters and a null buffer with a nonzero length are
    /// [`PITH_E_INVALID`]; non-UTF-8 bytes are [`PITH_E_REJECTED`]; a
    /// null buffer is a legal free.
    #[test]
    fn ffi_fingerprint_refusals() {
        let mut out: *mut u8 = core::ptr::null_mut();
        let mut out_len: usize = 0;
        let input = b"text";

        let null_out = unsafe {
            pith_text_fingerprint(
                input.as_ptr(),
                input.len(),
                core::ptr::null_mut(),
                &mut out_len,
            )
        };
        assert_eq!(null_out, PITH_E_INVALID);

        let null_out_len = unsafe {
            pith_text_fingerprint(input.as_ptr(), input.len(), &mut out, core::ptr::null_mut())
        };
        assert_eq!(null_out_len, PITH_E_INVALID);

        let null_data = unsafe {
            pith_text_fingerprint(core::ptr::null(), input.len(), &mut out, &mut out_len)
        };
        assert_eq!(null_data, PITH_E_INVALID);

        let bad_utf8: &[u8] = &[b'o', b'n', b'e', 0xFF];
        let status = unsafe {
            pith_text_fingerprint(bad_utf8.as_ptr(), bad_utf8.len(), &mut out, &mut out_len)
        };
        assert_eq!(status, PITH_E_REJECTED);

        unsafe { pith_text_free(core::ptr::null_mut(), 0) };
    }

    /// The safe core rejects non-UTF-8 bytes with the documented
    /// status instead of panicking.
    #[test]
    fn safe_core_rejects_non_utf8() {
        assert_eq!(fingerprint_stream(&[0xFF]), Err(PITH_E_REJECTED));
        assert_eq!(fingerprint_stream(b"ok"), Ok(canonical_stream_core(b"ok")));
    }

    /// The jaccard FFI reproduces the `reference.json` pins through
    /// raw, deliberately misaligned-style pointers: near-duplicate,
    /// unrelated, identical, and the empty-slice sentinel operand.
    #[test]
    fn ffi_jaccard_matches_reference_pins() {
        let doc_a = fixture_words("doc_a");
        let doc_a_edit = fixture_words("doc_a_edit");
        let doc_b = fixture_words("doc_b");
        let prose = fixture_words("prose");

        let mut bits: u64 = 0;
        // jaccard-near-duplicate: doc_a vs doc_a_edit == 0x3fef800000000000.
        let status = unsafe {
            pith_text_jaccard(
                doc_a.as_ptr(),
                doc_a.len(),
                doc_a_edit.as_ptr(),
                doc_a_edit.len(),
                &mut bits,
            )
        };
        assert_eq!(status, PITH_OK);
        assert_eq!(bits, 0x3fef_8000_0000_0000);

        // jaccard-unrelated: doc_a vs doc_b == 0.
        let status = unsafe {
            pith_text_jaccard(
                doc_a.as_ptr(),
                doc_a.len(),
                doc_b.as_ptr(),
                doc_b.len(),
                &mut bits,
            )
        };
        assert_eq!(status, PITH_OK);
        assert_eq!(bits, 0x0000_0000_0000_0000);

        // jaccard-identical: prose vs prose == 1.0.
        let status = unsafe {
            pith_text_jaccard(
                prose.as_ptr(),
                prose.len(),
                prose.as_ptr(),
                prose.len(),
                &mut bits,
            )
        };
        assert_eq!(status, PITH_OK);
        assert_eq!(bits, 0x3ff0_0000_0000_0000);

        // jaccard-against-empty: doc_a vs the EMPTY slice (null, 0
        // words) == 1.0 — `Vec::new()`, not signature("").
        let status = unsafe {
            pith_text_jaccard(doc_a.as_ptr(), doc_a.len(), core::ptr::null(), 0, &mut bits)
        };
        assert_eq!(status, PITH_OK);
        assert_eq!(bits, 0x3ff0_0000_0000_0000);

        // empty vs empty is the degenerate 1.0.
        let status =
            unsafe { pith_text_jaccard(core::ptr::null(), 0, core::ptr::null(), 0, &mut bits) };
        assert_eq!(status, PITH_OK);
        assert_eq!(bits, 0x3ff0_0000_0000_0000);
    }

    /// A null word pointer with a nonzero length and a null
    /// out-parameter are [`PITH_E_INVALID`].
    #[test]
    fn ffi_jaccard_refusals() {
        let words = [1u64, 2, 3];
        let mut bits: u64 = 0;

        let null_bits = unsafe {
            pith_text_jaccard(
                words.as_ptr(),
                words.len(),
                words.as_ptr(),
                words.len(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(null_bits, PITH_E_INVALID);

        let null_a = unsafe {
            pith_text_jaccard(core::ptr::null(), 1, words.as_ptr(), words.len(), &mut bits)
        };
        assert_eq!(null_a, PITH_E_INVALID);

        let null_b = unsafe {
            pith_text_jaccard(words.as_ptr(), words.len(), core::ptr::null(), 2, &mut bits)
        };
        assert_eq!(null_b, PITH_E_INVALID);
    }

    /// [`read_words`] and [`jaccard_bits`] mirror the FFI contract in
    /// the safe world: null+0 is empty, null+len is invalid, and the
    /// bits are `f64::to_bits` of the estimate.
    #[test]
    fn safe_cores_match_the_abi_contract() {
        assert_eq!(unsafe { read_words(core::ptr::null(), 0) }, Ok(Vec::new()));
        assert_eq!(
            unsafe { read_words(core::ptr::null(), 1) },
            Err(PITH_E_INVALID)
        );
        let words = [7u64, 9];
        assert_eq!(
            unsafe { read_words(words.as_ptr(), words.len()) },
            Ok(words.to_vec())
        );
        assert_eq!(jaccard_bits(&[], &[]), 1.0f64.to_bits());
        // Equal words → 1.0; differing words at the common prefix → 0.0.
        assert_eq!(jaccard_bits(&[1], &[1]), 1.0f64.to_bits());
        assert_eq!(jaccard_bits(&[1], &[2]), 0.0f64.to_bits());
    }
}
