# Fixture provenance

Text fixtures embedded by `tests/conformance.rs` via `include_str!` and
hashed into `reference.json`. Their bytes are a crate contract: the
`.gitattributes` `* text=auto eol=lf` pin keeps every checkout LF, and a
CRLF checkout would silently change every vector derived from them.

Source: `n24q02m/modhash` @ `main` (89ed581), `lab/differential/corpus/text/`,
copied byte-identical. SHA-256 at copy time:

| file | sha256 |
| --- | --- |
| doc_a.txt | c1eb9f012dcb813e212beb49012408fb26b4bf3b086c0c81c56a4a89ec7977c9 |
| doc_a_edit.txt | 4593fba5e4513fdc84591ef31deabea139481252abdc71ec2f14de056f22e773 |
| doc_b.txt | 5e3f18ad6bf8f6f2a5ebaf63e747d2b95af712439b80348c241c093b3b06e65d |
| prose.txt | 754d411b311d9243901a0b45c1fea81368a2b252d906fdcf1b6b882f1d7e16ee |
| punct_tags.txt | 24538fa0872b9c19f005c765fb3b37215d87ee67b43c2cbabff5aad89c7efbe3 |
| short_two.txt | aaf3183a9fd3134e00b0fdcd1d5fde6394526d371b77827185e328c5d13ee42c |
| vi_nfc.txt | dafaca378c617539d844564c9f22743845feb1ed11ca959bc161167b82a62562 |
| vi_nfd.txt | b6d2a058afc1e9e0ce834a1f97bdae5fdd93f74f9ffeae2bc5d8d9c5d45e98b2 |
