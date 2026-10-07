<p align="center">
  <img src="https://pith-text.n24q02m.com/logo.svg" alt="pith-text" width="120">
</p>

<h1 align="center">pith-text</h1>

<p align="center">
  <strong>Text fingerprints: NFC canonicalisation, word 3-shingles and a 128-word MinHash signature</strong>
</p>

<p align="center">
  <a href="https://github.com/pith-hash/pith-text/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/pith-hash/pith-text/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/pith-hash/pith-text/actions/workflows/cd.yml"><img alt="CD" src="https://github.com/pith-hash/pith-text/actions/workflows/cd.yml/badge.svg"></a>
  <a href="https://github.com/pith-hash/pith-text/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/pith-hash/pith-text?display_name=tag&sort=semver"></a>
  <a href="https://github.com/n24q02m/better-semantic-release"><img alt="semantic-release" src="https://img.shields.io/badge/semantic--release-e10079?logo=semantic-release&logoColor=white"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/github/license/pith-hash/pith-text"></a>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#the-pith-suite-contract">Suite contract</a>
</p>

<!-- BEGIN: AUTO-GENERATED-CROSS-PROMO -->
<!-- END: AUTO-GENERATED-CROSS-PROMO -->

## The pith suite contract

pith-text is part of the **pith** suite (pith-hash). Every suite repository
follows the same rules; CI enforces them mechanically:

- **Naming**: a library is always `pith-<domain>` (`pith-image`, `pith-audio`,
  `pith-zip`, ...). The curator/repository of repositories is the bare
  `pith-hash`. Never invent a second naming scheme inside the suite.
- **Version pinning**: cross-library dependencies pin `~0.1` (e.g.
  `pith-image = { version = "~0.1", path = "../pith-image" }`). The whole suite
  moves together inside 0.1.x; breaking changes require a suite-wide version
  bump, never a silent minor drift.
- **Zero third-party dependencies**: every crate depends only on other
  `pith-*` crates plus `std`. `scripts/check-zero-deps.py` (run in CI) fails
  the build on any other crate, for normal, build and dev dependencies alike.
- **No unsafe**: every crate root carries `#![forbid(unsafe_code)]`.
- **Hex-exact vectors**: `reference.json` at the repo root is the
  cross-language source of truth. The `gen-reference` binary regenerates it;
  CI verifies the committed copy is current (`gen-reference verify`), and CD
  ships the regenerated file with every SDK artifact. Python, Node and Go SDKs
  MUST test against the same bytes.

## Repository layout

```
src/               the pith-text library (canonicalize, signature, jaccard_estimate)
tests/fixtures/    the text conformance corpus (include_str!, LF byte contract)
tests/             conformance and reference-vector tests
tools/gen-reference  the vector generator binary (bin name: gen-reference)
reference.json     hex-exact cross-SDK test vectors
```

## Install

Rust (the core library):

```bash
cargo add pith-text
```

Python / Node / Go SDKs are published from the same cdylib on every release;
see the release assets or the package registries for the matching version.

## Quick start

```rust
use pith_text::{canonicalize, jaccard_estimate, signature};

// NFC, lowercase and one trailing newline — every spelling converges:
assert_eq!(canonicalize("Hello WORLD"), "hello world\n");
assert_eq!(canonicalize("Ti\u{00EA}\u{0301}ng Vi\u{00EA}\u{0323}t"), "ti\u{1EBF}ng vi\u{1EC7}t\n");

// The 128-word MinHash signature over word 3-shingles:
let a = signature("The quick brown fox jumps over the lazy dog");
let b = signature("the quick brown fox jumps over the lazy cat");
assert_eq!(a.len(), 128);
let estimate = jaccard_estimate(&a, &b); // near-duplicates score high
```

Regenerate/verify the cross-SDK vectors:

```bash
cargo run --locked --bin gen-reference -- verify   # CI runs this
cargo run --locked --bin gen-reference -- gen      # rewrite reference.json
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © pith-hash
