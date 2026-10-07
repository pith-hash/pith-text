# SPDX-License-Identifier: MIT
# Copyright (c) 2026 pith-hash
"""Hex-exact conformance: the committed reference vectors through ctypes.

Every vector in the repository-root ``reference.json`` is replayed
through the cdylib and compared hex-exact — the canonical digests and
counts, the pinned signature words and the FNV-1a 64 / SHA-256 folds
over the 1024-byte little-endian tail (the SDK-side standard FNV-1a 64
plus the stdlib SHA-256), and the Jaccard estimates as raw IEEE-754
bits. The same vectors the Rust ``gen-reference verify`` gate and the
Node/Go SDKs check.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from pith_text import (
    FfiError,
    SIGNATURE_WORDS,
    find_cdylib,
    fingerprint_stream,
    jaccard_bits,
    parse_fingerprint,
)

REPO_ROOT = Path(__file__).resolve().parents[3]

#: Standard FNV-1a 64 (offset 0xcbf29ce484222325, prime 0x100000001b3).
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3


def fnv1a64(data: bytes) -> int:
    """The standard FNV-1a 64 the Rust side folds with."""
    h = FNV_OFFSET
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h


def vectors() -> list[dict]:
    """The committed vectors, in their pinned order (the reference file
    stores a list of named objects)."""
    raw = json.loads((REPO_ROOT / "reference.json").read_text(encoding="utf-8"))
    return raw["vectors"]


def fixture_bytes(stem: str) -> bytes:
    """The committed fixture bytes (LF by the ``.gitattributes``
    contract — the same bytes ``gen-reference`` embedded)."""
    return (REPO_ROOT / "tests" / "fixtures" / f"{stem}.txt").read_bytes()


def vector_input(v: dict) -> bytes:
    """The raw input bytes a fingerprint vector is defined over."""
    if v["input_kind"] == "inline-hex":
        return bytes.fromhex(v["input_hex"])
    stem = Path(v["input_path"]).stem
    return fixture_bytes(stem)


def signature_operand(path: str) -> list[int]:
    """The u64 word operand a jaccard vector names: a fixture path
    yields the 128 words of its fingerprint tail; ``empty-signature``
    is the EMPTY slice — ``Vec::new()`` on the Rust side, **not**
    ``signature("")``, whose all-``u64::MAX`` words would score ≈ 0."""
    if path == "empty-signature":
        return []
    stem = Path(path.removeprefix("fixture:")).stem
    return list(parse_fingerprint(fingerprint_stream(fixture_bytes(stem))).signature)


def assert_fingerprint_fields(v: dict, raw: bytes) -> None:
    """Every pinned fingerprint field of one vector, hex-exact."""
    fp = parse_fingerprint(raw)
    assert fp.word_count == v["word_count"], v["name"]
    assert fp.shingle_count == v["shingle_count"], v["name"]
    assert hashlib.sha256(fp.canonical).hexdigest() == v["canonical_sha256"], v["name"]
    assert fnv1a64(fp.canonical) == int(v["canonical_fnv1a64"], 16), v["name"]
    if "signature_word_0" not in v:
        return
    assert len(fp.signature) == SIGNATURE_WORDS, v["name"]
    assert f"{fp.signature[0]:016x}" == v["signature_word_0"], v["name"]
    assert f"{fp.signature[1]:016x}" == v["signature_word_1"], v["name"]
    tail = raw[len(raw) - SIGNATURE_WORDS * 8 :]
    assert fnv1a64(tail) == int(v["signature_fnv1a64"], 16), v["name"]
    assert hashlib.sha256(tail).hexdigest() == v["signature_sha256"], v["name"]


def test_cdylib_is_discoverable() -> None:
    path = find_cdylib()
    assert path.is_file(), path


@pytest.mark.parametrize("v", [x for x in vectors() if x["name"].startswith(("canon-", "fixture-"))])
def test_canonicalisation_vector_is_reproduced_hex_exact(v: dict) -> None:
    raw = fingerprint_stream(vector_input(v))
    assert_fingerprint_fields(v, raw)


def test_full_signature_vector_is_reproduced_hex_exact() -> None:
    v = next(x for x in vectors() if x["name"] == "signature-alpha-beta-gamma")
    raw = fingerprint_stream(bytes.fromhex(v["input_hex"]))
    fp = parse_fingerprint(raw)
    assert [f"{w:016x}" for w in fp.signature] == v["signature_words_hex"]
    tail = raw[len(raw) - SIGNATURE_WORDS * 8 :]
    assert fnv1a64(tail) == int(v["signature_fnv1a64"], 16)
    assert hashlib.sha256(tail).hexdigest() == v["signature_sha256"]


def test_empty_sentinel_vector_is_reproduced_hex_exact() -> None:
    v = next(x for x in vectors() if x["name"] == "signature-empty-sentinel")
    raw = fingerprint_stream(bytes.fromhex(v["input_hex"]))  # the EMPTY input
    fp = parse_fingerprint(raw)
    assert fp.word_count == 0 and fp.shingle_count == 0
    assert fp.canonical == b"\n"  # canonicalize("") == "\n"
    assert set(fp.signature) == {0xFFFFFFFFFFFFFFFF}
    assert f"{fp.signature[0]:016x}" == v["signature_word_0"]
    assert f"{fp.signature[1]:016x}" == v["signature_word_1"]
    tail = raw[len(raw) - SIGNATURE_WORDS * 8 :]
    assert fnv1a64(tail) == int(v["signature_fnv1a64"], 16)
    assert hashlib.sha256(tail).hexdigest() == v["signature_sha256"]


@pytest.mark.parametrize("v", [x for x in vectors() if x["name"].startswith("jaccard-")])
def test_jaccard_vector_is_reproduced_bit_exact(v: dict) -> None:
    a = signature_operand(v["a"])
    b = signature_operand(v["b"])
    assert jaccard_bits(a, b) == int(v["value_bits"], 16), v["name"]


def test_every_vector_kind_is_consumed() -> None:
    """No vector silently skips replay: 17 fingerprint vectors (7 canon
    + 8 fixture + 2 signature) and 5 jaccard vectors."""
    names = [x["name"] for x in vectors()]
    assert len(names) == 22
    assert sum(n.startswith(("canon-", "fixture-")) for n in names) == 15
    assert sum(n.startswith("signature-") for n in names) == 2
    assert sum(n.startswith("jaccard-") for n in names) == 5


def test_non_utf8_bytes_are_refused() -> None:
    with pytest.raises(FfiError) as err:
        fingerprint_stream(b"one \xff two")
    assert err.value.status == -2


def test_empty_input_is_valid_not_refused() -> None:
    raw = fingerprint_stream(b"")
    assert len(raw) == 8 + 1 + 1024  # header + "\n" + signature tail
    assert set(parse_fingerprint(raw).signature) == {0xFFFFFFFFFFFFFFFF}


def test_stream_matches_a_rust_pinned_value() -> None:
    # "alpha beta gamma"'s stream, pinned in the committed reference.json
    # and re-derived by the Rust unit tests (plus the empty-sentinel
    # folds, likewise Rust-derived): these fail loudly even if
    # reference.json were regenerated wrongly.
    fp = parse_fingerprint(fingerprint_stream("alpha beta gamma"))
    assert fp.word_count == 3
    assert fp.shingle_count == 1
    assert fp.signature[0] == 0x5409AADB22BB8479
    assert fp.signature[1] == 0xB2E6FF4EDEBF53C6
    tail = fp.raw[len(fp.raw) - SIGNATURE_WORDS * 8 :]
    assert f"{fnv1a64(tail):016x}" == "46f8ab1a50c61813"
    assert (
        hashlib.sha256(tail).hexdigest()
        == "5a3e4c4a48d55a405faced9c28d4bf12b78af5661102eb2ac3dcab843485d8df"
    )
    sentinel = parse_fingerprint(fingerprint_stream(b""))
    stail = sentinel.raw[len(sentinel.raw) - SIGNATURE_WORDS * 8 :]
    assert f"{fnv1a64(stail):016x}" == "89bfa3a928539725"
    assert (
        hashlib.sha256(stail).hexdigest()
        == "5f4ecdb7b71c3e403983fe405cddcdc2f2576b655fdb3e80d94a6f7c32e58bc2"
    )
