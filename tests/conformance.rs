//! Fixture-driven conformance: the `tests/fixtures/*.txt` corpus (embedded
//! with `include_str!`, LF bytes by `.gitattributes` contract) pushed
//! through the public pipeline. The absolute per-fixture values live in
//! `reference.json` (`gen-reference verify` is the byte gate); the pins
//! here are the structural seams the generator itself relies on —
//! NFC-folding across spellings, near-duplicate sensitivity and
//! determinism on real multi-KB documents.

use pith_digest::sha256;
use pith_text::{canonicalize, jaccard_estimate, signature};

/// Byte-identity pins for every embedded fixture, matching
/// `tests/fixtures/PROVENANCE.md` and the `input_sha256` fields of
/// `reference.json`. A checkout or copy that alters one byte of the
/// corpus — a CRLF rewrite included — turns these red.
const FIXTURE_SHA256: [(&str, &str); 8] = [
    (
        "doc_a",
        "c1eb9f012dcb813e212beb49012408fb26b4bf3b086c0c81c56a4a89ec7977c9",
    ),
    (
        "doc_a_edit",
        "4593fba5e4513fdc84591ef31deabea139481252abdc71ec2f14de056f22e773",
    ),
    (
        "doc_b",
        "5e3f18ad6bf8f6f2a5ebaf63e747d2b95af712439b80348c241c093b3b06e65d",
    ),
    (
        "prose",
        "754d411b311d9243901a0b45c1fea81368a2b252d906fdcf1b6b882f1d7e16ee",
    ),
    (
        "punct_tags",
        "24538fa0872b9c19f005c765fb3b37215d87ee67b43c2cbabff5aad89c7efbe3",
    ),
    (
        "short_two",
        "aaf3183a9fd3134e00b0fdcd1d5fde6394526d371b77827185e328c5d13ee42c",
    ),
    (
        "vi_nfc",
        "dafaca378c617539d844564c9f22743845feb1ed11ca959bc161167b82a62562",
    ),
    (
        "vi_nfd",
        "b6d2a058afc1e9e0ce834a1f97bdae5fdd93f74f9ffeae2bc5d8d9c5d45e98b2",
    ),
];

const FIXTURES: [&str; 8] = [
    "doc_a",
    "doc_a_edit",
    "doc_b",
    "prose",
    "punct_tags",
    "short_two",
    "vi_nfc",
    "vi_nfd",
];

fn fixture(name: &str) -> &'static str {
    match name {
        "doc_a" => include_str!("fixtures/doc_a.txt"),
        "doc_a_edit" => include_str!("fixtures/doc_a_edit.txt"),
        "doc_b" => include_str!("fixtures/doc_b.txt"),
        "prose" => include_str!("fixtures/prose.txt"),
        "punct_tags" => include_str!("fixtures/punct_tags.txt"),
        "short_two" => include_str!("fixtures/short_two.txt"),
        "vi_nfc" => include_str!("fixtures/vi_nfc.txt"),
        "vi_nfd" => include_str!("fixtures/vi_nfd.txt"),
        other => unreachable!("unknown fixture {other}"),
    }
}

/// Every fixture embeds byte-identical to its pinned SHA-256: a stray
/// CRLF rewrite, an editor normalization or a truncated copy turns this
/// red before any vector is trusted.
#[test]
fn fixtures_match_pinned_sha256() {
    for (name, expected) in FIXTURE_SHA256 {
        let bytes = fixture(name).as_bytes();
        assert!(!bytes.is_empty(), "fixture {name} is empty");
        let got = hex_lower(sha256(bytes).expect("sha256 of fixture").as_bytes());
        assert_eq!(got, expected, "fixture {name} drifted from its pin");
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Every fixture yields a 128-word signature, deterministically, and the
/// canonical form is idempotent on the real corpus.
#[test]
fn fixtures_are_deterministic_and_idempotent() {
    for name in FIXTURES {
        let text = fixture(name);
        let sig = signature(text);
        assert_eq!(sig.len(), 128, "{name} signature length");
        assert_eq!(signature(text), sig, "{name} must be deterministic");
        let canon = canonicalize(text);
        assert_eq!(canonicalize(&canon), canon, "{name} must be idempotent");
    }
}

/// The NFC and NFD spellings of the same Vietnamese corpus text fold to
/// the identical canonical form and identical signature — the NFC seam
/// on real multi-line documents, not just one-word samples.
#[test]
fn vietnamese_nfc_and_nfd_fixtures_agree() {
    let nfc_text = fixture("vi_nfc");
    let nfd_text = fixture("vi_nfd");
    assert_ne!(nfc_text, nfd_text, "the two spellings must differ as bytes");
    assert_eq!(canonicalize(nfc_text), canonicalize(nfd_text));
    assert_eq!(signature(nfc_text), signature(nfd_text));
}

/// The near-duplicate pair (one small edit) must score clearly above an
/// unrelated pairing, on real documents.
#[test]
fn near_duplicate_fixture_outscores_unrelated_pair() {
    let a = signature(fixture("doc_a"));
    let a_edit = signature(fixture("doc_a_edit"));
    let b = signature(fixture("doc_b"));
    let near = jaccard_estimate(&a, &a_edit);
    let far = jaccard_estimate(&a, &b);
    assert!(
        near > far,
        "near-duplicate {near} must beat unrelated {far}"
    );
    assert!(near > 0.5, "one-edit near-duplicate estimated {near}");
    assert_eq!(jaccard_estimate(&a, &a), 1.0);
}

/// Punctuation/tag soup and a two-word document still fingerprint
/// without panicking and keep distinct signatures.
#[test]
fn adversarial_and_tiny_fixtures_stay_distinct() {
    let punct = signature(fixture("punct_tags"));
    let tiny = signature(fixture("short_two"));
    let empty = signature("");
    assert_ne!(punct, tiny);
    assert_ne!(punct, empty);
    assert_ne!(tiny, empty, "a two-word document is not the empty set");
    assert_ne!(
        tiny,
        vec![u64::MAX; 128],
        "a two-word document is not empty"
    );
}
