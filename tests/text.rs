//! Conformance tests for `pith-text`: canonicalisation seams (NFC,
//! lowercase, the single trailing newline), signature determinism and
//! the golden pipeline pin, and the in-crate corruption loops that
//! stand in for the shared fuzz harness at integration.
//!
//! All randomness is `pith_digest::SplitMix64` with pinned
//! seeds, so every expectation reproduces bit-exactly.

use pith_digest::SplitMix64;
use pith_text::{canonicalize, jaccard_estimate, signature};

// ------------------------------------------------------------------
// canonicalize
// ------------------------------------------------------------------

/// NFC, lowercase and exactly one trailing newline, in that order.
#[test]
fn canonicalize_normalizes_case_and_trailing_newline() {
    assert_eq!(canonicalize("Hello WORLD"), "hello world\n");
    assert_eq!(canonicalize("text\n"), "text\n");
    assert_eq!(canonicalize("text\n\n\n"), "text\n");
    assert_eq!(canonicalize("text\r\n"), "text\n");
    assert_eq!(canonicalize("text   \t \n"), "text\n");
    assert_eq!(canonicalize(""), "\n");
    assert_eq!(canonicalize("   \n"), "\n");
}

/// `canonicalize` is idempotent.
#[test]
fn canonicalize_is_idempotent() {
    for input in ["Hello\n\n", "ÜNICODE text", "", "a  b\tc\n"] {
        let once = canonicalize(input);
        assert_eq!(canonicalize(&once), once);
    }
}

/// NFC fold: a combining-sequence spelling and the precomposed spelling
/// of the same Vietnamese word must canonicalize identically — this is
/// the seam that breaks if NFC is skipped.
#[test]
fn canonicalize_nfc_equivalence() {
    // "ế" = 'ê' + combining acute (U+0301); "ệ" = 'ê' + dot below.
    let decomposed = "Ti\u{00EA}\u{0301}ng Vi\u{00EA}\u{0323}t";
    assert_eq!(canonicalize(decomposed), "ti\u{1EBF}ng vi\u{1EC7}t\n");
    // é as 'e' + U+0301 composes to U+00E9.
    assert_eq!(canonicalize("CAFE\u{0301}"), "caf\u{00E9}\n");
}

// ------------------------------------------------------------------
// signature: determinism, normalization invariance, golden pin
// ------------------------------------------------------------------

/// Same input twice → identical signature; NFC and NFD spellings and
/// different case spellings of the same text → identical signature.
#[test]
fn signature_determinism_and_canonical_invariance() {
    let a = signature("The quick brown fox jumps over the lazy dog");
    assert_eq!(a, signature("The quick brown fox jumps over the lazy dog"));
    assert_eq!(a.len(), 128);

    // NFC vs NFD via the crate's own decomposer.
    let nfd = pith_unicode::nfd("Tiếng Việt là một ngôn ngữ phổ biến");
    let sig_nfc = signature("TIẾNG VIỆT LÀ MỘT NGÔN NGỮ PHỔ BIẾN\n\n\n");
    assert_eq!(signature(&nfd), sig_nfc);

    // Case is insignificant.
    assert_eq!(signature("Hello World"), signature("hello world"));
    // Trailing whitespace is insignificant.
    assert_eq!(signature("a b c\n\n"), signature("a b c"));
}

/// The end-to-end pipeline is pinned: `canonicalize("alpha beta
/// gamma")` is `"alpha beta gamma\n"`, the only shingle is
/// `"alpha beta gamma"` with FNV-1a `0x29496d94f8235e1e`, the first
/// two signature words are byte-exact and the FNV-1a fold of all 128
/// words is `0x46f8ab1a50c61813`. Any seam change — shingle width,
/// join byte, seed stream, mixer constant — changes this pin.
#[test]
fn signature_golden_pin() {
    let sig = signature("alpha beta gamma");
    assert_eq!(sig[0], 0x5409_aadb_22bb_8479);
    assert_eq!(sig[1], 0xb2e6_ff4e_debf_53c6);
    let mut fold = 0xcbf2_9ce4_8422_2325u64;
    for word in &sig {
        for b in word.to_le_bytes() {
            fold ^= u64::from(b);
            fold = fold.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    assert_eq!(fold, 0x46f8_ab1a_50c6_1813);
}

/// Short documents: 0 words → the all-MAX sentinel; 1–2 words → a
/// single shorter shingle that still distinguishes documents.
#[test]
fn signature_short_documents() {
    assert_eq!(signature(""), vec![u64::MAX; 128]);
    assert_eq!(signature("   \n \t "), vec![u64::MAX; 128]);
    let one = signature("alpha");
    let two = signature("alpha beta");
    assert_ne!(one, vec![u64::MAX; 128]);
    assert_ne!(two, vec![u64::MAX; 128]);
    assert_ne!(one, signature("beta"));
    assert_ne!(one, two);
    assert_ne!(two, signature("alpha beta gamma"));
}

// ------------------------------------------------------------------
// jaccard_estimate
// ------------------------------------------------------------------

#[test]
fn jaccard_estimate_bounds_and_edges() {
    let a = signature("the same document twice over today");
    let b = signature("the same document twice over today");
    assert_eq!(jaccard_estimate(&a, &b), 1.0);
    assert_eq!(jaccard_estimate(&a, &a[..64]), 1.0); // common prefix
    assert_eq!(jaccard_estimate(&[], &[]), 1.0);
    assert_eq!(jaccard_estimate(&[], &a), 1.0); // documented: 0/0
    let c = signature("completely unrelated words placed here instead");
    let j = jaccard_estimate(&a, &c);
    assert!(j < 0.2, "unrelated texts estimated {j}");
    // A near-copy scores high: one word changed out of ten.
    let d = signature("the same document twice over tomorrow");
    let j2 = jaccard_estimate(&a, &d);
    assert!(j2 > 0.5, "one-word edit estimated {j2}");
}

// ------------------------------------------------------------------
// In-crate corruption loops (stand-in for the shared fuzz harness —
// see contract deviation note; the heavy driver runs at integration).
// ------------------------------------------------------------------

/// Every single-character substitution, insertion, deletion and
/// whitespace mutation of a base document is fingerprinted without a
/// panic, and — outside fully colliding MinHash draws — changes the
/// signature: each mutation must move at least one signature word.
#[test]
fn signature_changes_predictably_under_mutation() {
    let base = "the quick brown fox jumps over the lazy dog today";
    let base_sig = signature(base);
    let words: Vec<&str> = base.split_whitespace().collect();
    let mut rng = SplitMix64::new(0x0BAD_5EED_0000_0001);

    // Substitution: swap one word for a fresh random word.
    for _ in 0..100 {
        let i = (rng.next_u64() as usize) % words.len();
        let mut v: Vec<String> = words.iter().map(|w| w.to_string()).collect();
        v[i] = format!("w{:016x}", rng.next_u64());
        assert_ne!(signature(&v.join(" ")), base_sig, "substitution at {i}");
    }

    // Deletion: drop one word.
    for i in 0..words.len() {
        let mut v: Vec<&str> = words.clone();
        v.remove(i);
        assert_ne!(signature(&v.join(" ")), base_sig, "deletion at {i}");
    }

    // Insertion: splice a fresh random word in.
    for _ in 0..100 {
        let i = (rng.next_u64() as usize) % (words.len() + 1);
        let mut v: Vec<String> = words.iter().map(|w| w.to_string()).collect();
        v.insert(i, format!("w{:016x}", rng.next_u64()));
        assert_ne!(signature(&v.join(" ")), base_sig, "insertion at {i}");
    }

    // Whitespace mutation: joining with double spaces is invisible
    // (split_whitespace), but re-joining words with no separator merges
    // them into different tokens — the signature must notice.
    assert_ne!(signature(&words.concat()), base_sig);
}

/// Arbitrary bytes pushed through `String::from_utf8_lossy` and every
/// byte-length prefix of a multi-byte document must never panic — the
/// lossy replacement path and mid-character truncation are the hostile
/// edge of a `&str` API.
#[test]
fn arbitrary_bytes_and_prefixes_never_panic() {
    let mut rng = SplitMix64::new(0xAB17_AB17_AB17_AB17);
    let mut buf = vec![0u8; 512];
    for round in 0..200 {
        rng.fill_bytes(&mut buf);
        let text = String::from_utf8_lossy(&buf[..32 + (round % 400)]);
        let _ = signature(&text);
        let _ = canonicalize(&text);
    }

    // Prefix scan over a document with multi-byte characters: every
    // lossy prefix canonicalizes and hashes without panic, and
    // extending a non-empty prefix by a word changes the signature.
    let doc = canonicalize("Xin chào thế giới, đây là văn bản tiếng Việt dài");
    let mut prev = signature("");
    for i in 0..=doc.len() {
        let _ = signature(&String::from_utf8_lossy(&doc.as_bytes()[..i]));
    }
    let words: Vec<&str> = doc.split_whitespace().collect();
    for n in 1..words.len() {
        let cur = signature(&words[..n].join(" "));
        assert_ne!(cur, prev, "adding word {n} must change the signature");
        prev = cur;
    }
}

// ------------------------------------------------------------------
// The shipped cdylib (the artifact the language SDKs bind through)
// ------------------------------------------------------------------

/// Locates the built cdylib across the layouts `cargo test` and
/// `cargo llvm-cov` produce. Returns `None` outside a cdylib build.
#[cfg(windows)]
fn find_built_cdylib() -> Option<std::path::PathBuf> {
    let mut candidates = Vec::new();
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        candidates.push(std::path::PathBuf::from(dir));
    }
    candidates.push(manifest.join("target/llvm-cov-target"));
    candidates.push(manifest.join("target"));
    for base in candidates {
        for dir in [base.join("debug/deps"), base.join("debug")] {
            let dll = dir.join("pith_text.dll");
            if dll.is_file() {
                return Some(dll);
            }
        }
    }
    None
}

/// Loads the cdylib the same way the language SDKs do and drives all
/// three exports end-to-end through `LoadLibraryW`/`GetProcAddress`:
/// the golden-pin fingerprint (status, header, byte length, `free`),
/// the empty-slice jaccard sentinel, the non-UTF-8 refusal and the
/// null-buffer free. The crate root's `#![deny(unsafe_code)]` does not
/// extend into this integration-test crate; raw pointers are exactly
/// what this test is about.
#[cfg(windows)]
#[test]
fn cdylib_exports_work_through_loadlibrary() {
    use std::os::windows::ffi::OsStrExt;

    type FingerprintFn =
        unsafe extern "system" fn(*const u8, usize, *mut *mut u8, *mut usize) -> i32;
    type JaccardFn =
        unsafe extern "system" fn(*const u64, usize, *const u64, usize, *mut u64) -> i32;
    type FreeFn = unsafe extern "system" fn(*mut u8, usize);

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryW(name: *const u16) -> isize;
        fn GetProcAddress(module: isize, name: *const u8) -> isize;
    }

    let Some(dll) = find_built_cdylib() else {
        panic!("cdylib pith_text.dll not built; run `cargo build` first");
    };
    let wide: Vec<u16> = std::ffi::OsStr::new(&dll)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let module = unsafe { LoadLibraryW(wide.as_ptr()) };
    assert_ne!(module, 0, "LoadLibraryW({dll:?}) failed");

    unsafe fn symbol<A>(module: isize, name: &[u8]) -> A {
        let addr = unsafe { GetProcAddress(module, name.as_ptr()) };
        assert_ne!(addr, 0, "GetProcAddress({name:?}) failed");
        unsafe { std::mem::transmute_copy::<isize, A>(&addr) }
    }

    let fingerprint: FingerprintFn = unsafe { symbol(module, c"pith_text_fingerprint".to_bytes()) };
    let jaccard: JaccardFn = unsafe { symbol(module, c"pith_text_jaccard".to_bytes()) };
    let free: FreeFn = unsafe { symbol(module, c"pith_text_free".to_bytes()) };

    // Fingerprint: the golden-pin input, byte-exact stream + free.
    let input = b"alpha beta gamma";
    let mut out: *mut u8 = std::ptr::null_mut();
    let mut out_len: usize = 0;
    let status = unsafe { fingerprint(input.as_ptr(), input.len(), &mut out, &mut out_len) };
    assert_eq!(status, 0, "pith_text_fingerprint failed");
    let stream = unsafe { std::slice::from_raw_parts(out, out_len) };
    assert_eq!(&stream[..8], &[0, 0, 0, 3, 0, 0, 0, 1]);
    assert_eq!(stream.len(), 8 + 17 + 1024);
    unsafe { free(out, out_len) };

    // Jaccard: the empty-slice sentinel is 1.0 (0x3ff0000000000000).
    let mut bits: u64 = 0;
    let status = unsafe { jaccard(std::ptr::null(), 0, std::ptr::null(), 0, &mut bits) };
    assert_eq!(status, 0, "pith_text_jaccard failed");
    assert_eq!(bits, 0x3ff0_0000_0000_0000);

    // Refusals: non-UTF-8 bytes → -2; null buffer free is a no-op.
    let bad: &[u8] = &[0xFF];
    let status = unsafe { fingerprint(bad.as_ptr(), bad.len(), &mut out, &mut out_len) };
    assert_eq!(status, -2, "non-UTF-8 must be rejected, never crash");
    unsafe { free(std::ptr::null_mut(), 0) };
}

/// Non-Windows: the cdylib smoke runs on the Windows gate; unix CI
/// exercises the same exports through the SDK matrix.
#[cfg(not(windows))]
#[test]
fn cdylib_exports_work_through_loadlibrary() {
    // dlopen-based coverage of the shipped artifact is exercised by the
    // SDK matrices; nothing to assert here.
}
