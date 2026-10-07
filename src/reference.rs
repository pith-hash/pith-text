//! The canonical serialization the `reference.json` vectors are
//! defined over — the single source of truth shared by the vector
//! generator ([`crate::reference`] consumers, `tools/gen-reference`)
//! and the FFI surface ([`crate::ffi`]).
//!
//! [`pipeline`] runs the documented pipeline stages over an input and
//! reports the canonical UTF-8 bytes plus the tokenization/shingling
//! counts; [`measure_signature`] folds a 128-word MinHash signature
//! for compact transport (first two words verbatim, then FNV-1a 64
//! and SHA-256 over all 128 little-endian words). Both were moved
//! verbatim out of `tools/gen-reference/main.rs` so the generator and
//! the SDKs cannot drift; `gen-reference verify` compares against the
//! committed `reference.json` byte-for-byte on every run.
//!
//! [`canonical_stream`] packs both into the one byte stream the
//! `pith_text_fingerprint` FFI hands out:
//!
//! ```text
//! [0..4)    word_count     u32 big-endian
//! [4..8)    shingle_count  u32 big-endian
//! [8..8+C)  canonical      the canonical UTF-8 bytes (C bytes)
//! [8+C..)   signature      128 u64 little-endian words (1024 bytes)
//! ```
//!
//! so `canonical_sha256 == sha256(stream[8..8+C])` and the signature
//! folds of `reference.json` are folds over the 1024-byte tail.
//! `canonical_stream("")` is the empty-input sentinel: zero counts,
//! the one-byte canonical form `"\n"`, and a tail of 128 `u64::MAX`
//! words.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use pith_digest::{fnv1a64, sha256};

use crate::{SIGNATURE_WORDS, canonicalize, signature};

/// Shingle width of the pipeline (spec §4: three consecutive words). The
/// signature vectors pin it implicitly: a width change drifts them and
/// `verify` fails loudly.
pub const SHINGLE_WORDS: usize = 3;

/// One canonicalisation measurement: the canonical UTF-8 bytes plus the
/// tokenization/shingling counts the pipeline derives from them.
pub struct Canonicalized {
    /// The canonical UTF-8 form ([`canonicalize`] output).
    pub canonical: String,
    /// Whitespace-separated word count of the canonical form.
    pub word_count: usize,
    /// Consecutive `k`-word window count, `k = min(3, n)` (spec §4).
    pub shingle_count: usize,
}

/// Runs the documented pipeline stages over `input` and counts the
/// tokens and `k`-word windows.
pub fn pipeline(input: &str) -> Canonicalized {
    let canonical = canonicalize(input);
    let word_count = canonical.split_whitespace().count();
    let shingle_count = if word_count == 0 {
        0
    } else {
        word_count - word_count.min(SHINGLE_WORDS) + 1
    };
    Canonicalized {
        canonical,
        word_count,
        shingle_count,
    }
}

/// The 128-word MinHash signature folded for compact transport: first
/// two words verbatim, then FNV-1a 64 and SHA-256 over all 128
/// little-endian words.
pub struct SigFold {
    /// Signature word 0, verbatim.
    pub first: u64,
    /// Signature word 1, verbatim.
    pub second: u64,
    /// FNV-1a 64 over all 128 words as little-endian bytes.
    pub fnv1a64: u64,
    /// SHA-256 over all 128 words as little-endian bytes, hex.
    pub sha256: String,
    /// The full 128-word signature.
    pub words: Vec<u64>,
}

/// Folds the 128-word MinHash signature of `input` for compact
/// transport (see [`SigFold`]).
pub fn measure_signature(input: &str) -> SigFold {
    let words = signature(input);
    assert_eq!(words.len(), 128, "signature length is part of the contract");
    let mut le = Vec::with_capacity(words.len() * 8);
    for w in &words {
        le.extend_from_slice(&w.to_le_bytes());
    }
    SigFold {
        first: words[0],
        second: words[1],
        fnv1a64: fnv1a64(&le),
        sha256: hex(sha256(&le).expect("sha256 of signature words").as_bytes()),
        words,
    }
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Serializes the full fingerprint of `input` into the canonical byte
/// stream the `reference.json` vectors and the `pith_text_fingerprint`
/// FFI are defined over (layout in the [module docs](self)):
/// big-endian counts header, the canonical UTF-8 bytes, then the
/// 128 signature words little-endian. `canonical_stream("")` carries
/// the empty-input sentinel: zero counts, no canonical bytes, and a
/// tail of 128 `u64::MAX` words.
#[must_use]
pub fn canonical_stream(input: &str) -> Vec<u8> {
    let d = pipeline(input);
    let sig = measure_signature(&d.canonical);
    let mut stream = Vec::with_capacity(8 + d.canonical.len() + SIGNATURE_WORDS * 8);
    stream.extend_from_slice(&(d.word_count as u32).to_be_bytes());
    stream.extend_from_slice(&(d.shingle_count as u32).to_be_bytes());
    stream.extend_from_slice(d.canonical.as_bytes());
    for w in &sig.words {
        stream.extend_from_slice(&w.to_le_bytes());
    }
    stream
}

#[cfg(test)]
mod tests {
    use super::{SHINGLE_WORDS, canonical_stream, hex, measure_signature, pipeline};

    /// Lowercase hex of `bytes` — the test-side re-derivation of the
    /// private helper (the public folds are pinned instead).
    #[test]
    fn hex_encodes_lowercase() {
        assert_eq!(hex(&[0x0f, 0xa0, 0x00]), "0fa000");
    }

    /// The stream over the golden-pin input carries the pinned counts,
    /// the canonical bytes and the pinned signature words/folds.
    #[test]
    fn canonical_stream_alpha_beta_gamma() {
        let stream = canonical_stream("alpha beta gamma");
        assert_eq!(u32::from_be_bytes(stream[0..4].try_into().unwrap()), 3);
        assert_eq!(u32::from_be_bytes(stream[4..8].try_into().unwrap()), 1);
        assert_eq!(&stream[8..8 + 17], b"alpha beta gamma\n");
        // 8-byte header + 17 canonical bytes + 1024-byte signature tail.
        assert_eq!(stream.len(), 8 + 17 + 1024);
        let word = |i: usize| {
            u64::from_le_bytes(
                stream[8 + 17 + i * 8..8 + 17 + (i + 1) * 8]
                    .try_into()
                    .unwrap(),
            )
        };
        // Golden pins, byte-for-byte from the monorepo conformance suite
        // (the same values `signature-alpha-beta-gamma` records).
        assert_eq!(word(0), 0x5409_aadb_22bb_8479);
        assert_eq!(word(1), 0xb2e6_ff4e_debf_53c6);
        let tail = &stream[8 + 17..];
        assert_eq!(tail.len(), 1024);
        assert_eq!(pith_digest::fnv1a64(tail), 0x46f8_ab1a_50c6_1813);
    }

    /// The empty input pins the sentinel stream: zero counts, the
    /// one-byte canonical form (`canonicalize("") == "\n"`), 128
    /// `u64::MAX` words — the exact folds `signature-empty-sentinel`
    /// records.
    #[test]
    fn canonical_stream_empty_input_is_the_sentinel() {
        let stream = canonical_stream("");
        assert_eq!(stream.len(), 8 + 1 + 1024);
        assert_eq!(&stream[..8], &[0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(stream[8], b'\n');
        assert!(stream[9..].iter().all(|&b| b == 0xff));
        assert_eq!(measure_signature("").fnv1a64, 0x89bf_a3a9_2853_9725);
        assert_eq!(
            measure_signature("").sha256,
            "5f4ecdb7b71c3e403983fe405cddcdc2f2576b655fdb3e80d94a6f7c32e58bc2"
        );
    }

    /// The stream header and [`pipeline`] always agree on both counts.
    #[test]
    fn stream_counts_agree_with_pipeline() {
        for input in [
            "",
            "   \n \t ",
            "text\r\n",
            "one two three",
            "one two three four five",
            "Ti\u{00EA}\u{0301}ng Vi\u{00EA}\u{0323}t",
        ] {
            let d = pipeline(input);
            let stream = canonical_stream(input);
            assert_eq!(
                u32::from_be_bytes(stream[0..4].try_into().unwrap()) as usize,
                d.word_count
            );
            assert_eq!(
                u32::from_be_bytes(stream[4..8].try_into().unwrap()) as usize,
                d.shingle_count
            );
            assert_eq!(&stream[8..8 + d.canonical.len()], d.canonical.as_bytes());
        }
    }

    /// The shingle-count rule moved with `pipeline` unchanged
    /// (`k = min(3, n)` windows, zero for the empty document).
    #[test]
    fn shingle_counts_follow_the_min_rule() {
        assert_eq!(pipeline("").shingle_count, 0);
        assert_eq!(pipeline("one").shingle_count, 1);
        assert_eq!(pipeline("one two").shingle_count, 1);
        assert_eq!(pipeline("one two three").shingle_count, 1);
        assert_eq!(pipeline("one two three four").shingle_count, 2);
        assert_eq!(pipeline("one two three four five").shingle_count, 3);
        assert_eq!(pipeline("one two three four five").word_count, 5);
        assert_eq!(SHINGLE_WORDS, 3);
    }
}
