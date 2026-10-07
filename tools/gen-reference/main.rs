//! Regenerates and verifies `reference.json`, the hex-exact cross-SDK
//! test vectors for `pith-text`.
//!
//! Every vector is computed through the crate's public API from inputs
//! that are either the committed text fixtures (`tests/fixtures/*.txt`,
//! embedded, no working-directory dependence) or inline strings built
//! byte-by-byte — no RNG, no time, no platform-dependent bytes — so the
//! output is byte-stable everywhere.
//!
//! A vector pins the full pipeline in observable steps: the canonical
//! UTF-8 bytes (`canonicalize`), the word count and shingle count
//! (`k = min(3, n)` windows, spec §4), the 128-word MinHash signature
//! (first two words plus an FNV-1a 64 and SHA-256 fold over all 128
//! little-endian words) and Jaccard estimates (raw IEEE-754 bits, hex,
//! policy `exact` — both operands are deterministic).
//!
//! Usage:
//! - `gen-reference gen` — recompute every vector and write
//!   `reference.json` at the repository root.
//! - `gen-reference verify` — recompute and compare byte-for-byte
//!   against the committed copy; exit 1 on drift. This is the CI gate.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use pith_digest::{fnv1a64, sha256};
use pith_text::reference::{Canonicalized, measure_signature, pipeline};
use pith_text::{jaccard_estimate, signature};

/// Where the committed copy lives, relative to the repository root.
const REFERENCE_PATH: &str = "reference.json";
/// The text conformance corpus, relative to the repository root.
const FIXTURE_DIR: &str = "tests/fixtures";
/// Fixture stems in canonical (alphabetical) order.
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

// Shingle width of the pipeline lives in `pith_text::reference`
// (`SHINGLE_WORDS`), the single source of truth the FFI shares. The
// canonicalisation measurement and the pipeline that produces it
// (`Canonicalized`, `pipeline`, `SigFold`, `measure_signature`) moved
// verbatim to `pith_text::reference` so the vectors and the SDKs
// cannot drift; this binary imports them.

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `f64` as 16-digit hex of the IEEE-754 bit pattern.
fn f64_bits(v: f64) -> String {
    format!("{:016x}", v.to_bits())
}

fn fixture_text(stem: &str) -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(FIXTURE_DIR)
            .join(format!("{stem}.txt")),
    )
    .unwrap_or_else(|e| panic!("cannot read fixture {stem}: {e}"))
}

/// Serializes one canonicalisation vector from ordered `(key, value)`
/// field lines; the caller supplies the input-identity fields.
fn json_object(fields: &[String]) -> String {
    let mut s = String::from("    {\n");
    s.push_str(&fields.join(",\n"));
    s.push_str("\n    }");
    s
}

/// Serializes one canonicalisation vector. `input_fields` carries the
/// `input_kind`/`input_hex` or `input_path` block, one line each.
fn json_canon_vector(
    name: &str,
    input_fields: &[String],
    d: &Canonicalized,
    with_signature: bool,
) -> String {
    let mut fields = vec![format!("      \"name\": \"{name}\"")];
    fields.extend(input_fields.iter().cloned());
    fields.push(format!(
        "      \"canonical_sha256\": \"{}\"",
        hex(sha256(d.canonical.as_bytes())
            .expect("sha256 of canonical form")
            .as_bytes())
    ));
    fields.push(format!(
        "      \"canonical_fnv1a64\": \"{:016x}\"",
        fnv1a64(d.canonical.as_bytes())
    ));
    fields.push(format!("      \"word_count\": {}", d.word_count));
    fields.push(format!("      \"shingle_count\": {}", d.shingle_count));
    if with_signature {
        let sig = measure_signature(&d.canonical);
        fields.push(format!(
            "      \"signature_word_0\": \"{:016x}\"",
            sig.first
        ));
        fields.push(format!(
            "      \"signature_word_1\": \"{:016x}\"",
            sig.second
        ));
        fields.push(format!(
            "      \"signature_fnv1a64\": \"{:016x}\"",
            sig.fnv1a64
        ));
        fields.push(format!("      \"signature_sha256\": \"{}\"", sig.sha256));
    }
    json_object(&fields)
}

/// The inline canonicalisation edge inputs, in pinned order: empty input,
/// whitespace-only, trailing CRLF, mixed case, an NFD Vietnamese spelling,
/// and the Turkish dotted capital whose lowercase expands by one
/// combining dot (`İ` → `i` + U+0307).
fn inline_canon_inputs() -> Vec<(&'static str, &'static str)> {
    vec![
        ("canon-empty", ""),
        ("canon-whitespace-only", "   \n \t "),
        ("canon-trailing-crlf", "text\r\n"),
        ("canon-mixed-case", "Hello WORLD"),
        (
            "canon-vietnamese-nfd",
            "Ti\u{00EA}\u{0301}ng Vi\u{00EA}\u{0323}t",
        ),
        ("canon-turkish-dotted-capital", "\u{0130}STANBUL"),
        ("canon-multi-paragraph", "one two three\n\nfour five\n"),
    ]
}

/// Builds the whole reference.json text.
fn reference_json() -> String {
    let mut vectors: Vec<String> = Vec::new();

    // --- canonicalisation vectors: inline edges first, then fixtures ---
    for (name, input) in inline_canon_inputs() {
        vectors.push(json_canon_vector(
            name,
            &[
                "      \"input_kind\": \"inline-hex\"".to_owned(),
                format!("      \"input_hex\": \"{}\"", hex(input.as_bytes())),
            ],
            &pipeline(input),
            false,
        ));
    }
    for stem in FIXTURES {
        let text = fixture_text(stem);
        let d = pipeline(&text);
        vectors.push(json_canon_vector(
            &format!("fixture-{stem}"),
            &[
                "      \"input_kind\": \"fixture-file\"".to_owned(),
                format!("      \"input_path\": \"{FIXTURE_DIR}/{stem}.txt\""),
                format!(
                    "      \"input_sha256\": \"{}\"",
                    hex(sha256(text.as_bytes())
                        .expect("sha256 of fixture")
                        .as_bytes())
                ),
            ],
            &d,
            true,
        ));
    }

    // --- full-signature vectors: the golden-pin input, then the sentinel ---
    {
        let sig = measure_signature("alpha beta gamma");
        let mut fields = vec![
            "      \"name\": \"signature-alpha-beta-gamma\"".to_owned(),
            "      \"input_kind\": \"inline-hex\"".to_owned(),
            format!(
                "      \"input_hex\": \"{}\"",
                hex("alpha beta gamma".as_bytes())
            ),
        ];
        let words: Vec<String> = sig
            .words
            .iter()
            .map(|w| format!("        \"{w:016x}\""))
            .collect();
        fields.push(format!(
            "      \"signature_words_hex\": [\n{}\n      ]",
            words.join(",\n")
        ));
        fields.push(format!(
            "      \"signature_fnv1a64\": \"{:016x}\"",
            sig.fnv1a64
        ));
        fields.push(format!("      \"signature_sha256\": \"{}\"", sig.sha256));
        vectors.push(json_object(&fields));
    }
    {
        let sig = measure_signature("");
        assert_eq!(sig.first, u64::MAX, "empty input pins the sentinel word");
        vectors.push(json_object(&[
            "      \"name\": \"signature-empty-sentinel\"".to_owned(),
            "      \"input_kind\": \"inline-hex\"".to_owned(),
            "      \"input_hex\": \"\"".to_owned(),
            "      \"signature_word_0\": \"ffffffffffffffff\"".to_owned(),
            "      \"signature_word_1\": \"ffffffffffffffff\"".to_owned(),
            format!("      \"signature_fnv1a64\": \"{:016x}\"", sig.fnv1a64),
            format!("      \"signature_sha256\": \"{}\"", sig.sha256),
        ]));
    }

    // --- Jaccard vectors: raw IEEE-754 bits, policy exact ---
    let pairs: [(&str, &str, &str, &str); 5] = [
        ("jaccard-near-duplicate", "doc_a", "doc_a_edit", "fixture"),
        ("jaccard-unrelated", "doc_a", "doc_b", "fixture"),
        ("jaccard-identical", "prose", "prose", "fixture"),
        ("jaccard-cross-language", "vi_nfc", "doc_b", "fixture"),
        ("jaccard-against-empty", "doc_a", "", "empty"),
    ];
    for (name, a, b, kind_b) in pairs {
        let sa = signature(fixture_text(a).as_str());
        let sb = match kind_b {
            "fixture" => signature(fixture_text(b).as_str()),
            _ => Vec::new(),
        };
        let v = jaccard_estimate(&sa, &sb);
        let b_ref = match kind_b {
            "fixture" => format!("fixture:{FIXTURE_DIR}/{b}.txt"),
            _ => "empty-signature".to_owned(),
        };
        vectors.push(json_object(&[
            format!("      \"name\": \"{name}\""),
            format!("      \"a\": \"fixture:{FIXTURE_DIR}/{a}.txt\""),
            format!("      \"b\": \"{b_ref}\""),
            "      \"value_kind\": \"f64-ieee754-bits-hex\"".to_owned(),
            "      \"policy\": \"exact\"".to_owned(),
            format!("      \"value_bits\": \"{}\"", f64_bits(v)),
        ]));
    }

    let mut s = String::new();
    s.push_str("{\n");
    s.push_str("  \"suite\": \"pith\",\n");
    s.push_str("  \"crate\": \"pith-text\",\n");
    s.push_str("  \"format_version\": 1,\n");
    s.push_str("  \"generator\": \"cargo run --bin gen-reference -- gen\",\n");
    s.push_str("  \"description\": \"Hex-exact tokenization, shingling and MinHash vectors for pith-text: canonical UTF-8 bytes, word and shingle counts, 128-word signature folds and Jaccard estimates (IEEE-754 bits, exact) over the committed text fixtures and inline edge inputs.\",\n");
    s.push_str("  \"vectors\": [\n");
    s.push_str(&vectors.join(",\n"));
    s.push_str("\n  ]\n");
    s.push_str("}\n");
    s
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    let path = args.next().map(PathBuf::from);
    run(&mode, path.as_deref())
}

/// One CLI invocation, split out of [`main`] so the mode dispatch is
/// unit-testable. `path` overrides the repository-root `reference.json`.
fn run(mode: &str, path: Option<&std::path::Path>) -> ExitCode {
    let path = path
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root().join(REFERENCE_PATH));
    match mode {
        "gen" => {
            let json = reference_json();
            fs::write(&path, &json).unwrap_or_else(|e| panic!("cannot write {path:?}: {e}"));
            println!("wrote {} ({} bytes)", path.display(), json.len());
            ExitCode::SUCCESS
        }
        "verify" => {
            let json = reference_json();
            let committed = match fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("FAIL: cannot read {path:?}: {e}");
                    return ExitCode::FAILURE;
                }
            };
            if committed == json.as_bytes() {
                println!("reference.json is current");
                ExitCode::SUCCESS
            } else {
                let off = committed
                    .iter()
                    .zip(json.as_bytes())
                    .position(|(a, b)| a != b)
                    .unwrap_or(committed.len().min(json.len()));
                eprintln!(
                    "FAIL: reference.json is stale: committed {} bytes, computed {} bytes, first difference at byte {off}",
                    committed.len(),
                    json.len()
                );
                ExitCode::FAILURE
            }
        }
        _ => {
            eprintln!("usage: gen-reference <gen|verify> [PATH] (got {mode:?})");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The golden pipeline pin, ported byte-for-byte from the monorepo
    /// conformance suite (spec §4): shingle FNV-1a, first two signature
    /// words and the 128-word fold are hard constants there; the
    /// generator must reproduce them through the same public API.
    #[test]
    fn golden_pin_input_measures_reference_values() {
        let d = pipeline("alpha beta gamma");
        assert_eq!(d.canonical, "alpha beta gamma\n");
        assert_eq!(d.word_count, 3);
        assert_eq!(d.shingle_count, 1);
        let sig = measure_signature("alpha beta gamma");
        assert_eq!(sig.first, 0x5409_aadb_22bb_8479);
        assert_eq!(sig.second, 0xb2e6_ff4e_debf_53c6);
        assert_eq!(sig.fnv1a64, 0x46f8_ab1a_50c6_1813);
    }

    /// The tokenization/shingling counts pin the `k = min(3, n)` rule on
    /// short and long inputs.
    #[test]
    fn shingle_counts_follow_the_min_rule() {
        assert_eq!(pipeline("").shingle_count, 0);
        assert_eq!(pipeline("one").shingle_count, 1);
        assert_eq!(pipeline("one two").shingle_count, 1);
        assert_eq!(pipeline("one two three").shingle_count, 1);
        assert_eq!(pipeline("one two three four").shingle_count, 2);
        assert_eq!(pipeline("one two three four five").shingle_count, 3);
        assert_eq!(pipeline("one two three four five").word_count, 5);
    }

    /// Jaccard bits: 1.0 is exact and the empty-against-empty pin holds.
    #[test]
    fn jaccard_bits_pins_the_edges() {
        assert_eq!(f64_bits(1.0), "3ff0000000000000");
        assert_eq!(f64_bits(jaccard_estimate(&[], &[])), "3ff0000000000000");
        assert_eq!(
            f64_bits(jaccard_estimate(&[], &[1, 2, 3])),
            "3ff0000000000000"
        );
    }

    /// Every fixture resolves through the embedded path and yields a
    /// non-empty canonical form with at least one signature fold.
    #[test]
    fn all_fixtures_resolve_and_measure() {
        for stem in FIXTURES {
            let text = fixture_text(stem);
            assert!(!text.is_empty(), "{stem} must not be empty");
            let d = pipeline(&text);
            assert!(d.word_count >= 1, "{stem} must tokenize");
            let sig = measure_signature(&d.canonical);
            assert_eq!(sig.words.len(), 128);
        }
    }

    /// The JSON header is the cross-SDK identity block.
    #[test]
    fn json_carries_suite_identity() {
        let json = reference_json();
        assert!(json.contains("\"suite\": \"pith\""));
        assert!(json.contains("\"crate\": \"pith-text\""));
        assert!(json.contains("\"format_version\": 1"));
        assert!(json.ends_with("}\n"));
        assert!(json.contains("\"policy\": \"exact\""));
    }

    /// `gen` rewrites the committed root copy and `verify` stays green on
    /// it immediately after — the same-run gen→verify roundtrip the CD
    /// artifacts rely on.
    #[test]
    fn gen_then_verify_roundtrip_on_the_root_copy() {
        assert_eq!(run("gen", None), ExitCode::SUCCESS);
        assert_eq!(run("verify", None), ExitCode::SUCCESS);
    }
}
