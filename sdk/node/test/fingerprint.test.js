// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash
"use strict";

// Hex-exact conformance: the committed reference vectors through koffi.
// The 15 canonicalisation vectors (7 canon-* + 8 fixture-*) are replayed
// through fingerprintStream and compared hex-exact — the canonical
// SHA-256 and FNV-1a 64 over the canonical bytes, the header counts and,
// where recorded, the signature words and the FNV-1a 64 / SHA-256 folds
// over the 1024-byte little-endian tail (the SDK-side standard FNV-1a 64
// plus node:crypto SHA-256). The same vectors the Rust gen-reference
// verify gate and the Python/Go SDKs check.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const {
  FfiError,
  SIGNATURE_WORDS,
  findCdylib,
  fingerprintStream,
  parseFingerprint,
} = require("../index.js");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");

const REFERENCE = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "reference.json"), "utf8")).vectors;

// Standard FNV-1a 64 (offset 0xcbf29ce484222325, prime 0x100000001b3).
const FNV_OFFSET = 0xcbf29ce484222325n;
const FNV_PRIME = 0x100000001b3n;
const MASK64 = (1n << 64n) - 1n;

function fnv1a64(buf) {
  let h = FNV_OFFSET;
  for (const b of buf) {
    h = ((h ^ BigInt(b)) * FNV_PRIME) & MASK64;
  }
  return h;
}

function hex64(n) {
  return n.toString(16).padStart(16, "0");
}

function sha256hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function vectorByName(name) {
  return REFERENCE.find((v) => v.name === name);
}

function fixtureBytes(stem) {
  return fs.readFileSync(path.join(REPO_ROOT, "tests", "fixtures", `${stem}.txt`));
}

function vectorInput(v) {
  if (v.input_kind === "inline-hex") return Buffer.from(v.input_hex, "hex");
  return fixtureBytes(path.basename(v.input_path, ".txt"));
}

function assertFingerprintFields(v, raw) {
  const fp = parseFingerprint(raw);
  assert.equal(fp.wordCount, v.word_count, v.name);
  assert.equal(fp.shingleCount, v.shingle_count, v.name);
  assert.equal(sha256hex(fp.canonical), v.canonical_sha256, v.name);
  assert.equal(hex64(fnv1a64(fp.canonical)), v.canonical_fnv1a64, v.name);
  if (v.signature_word_0 === undefined) return;
  assert.equal(fp.signature.length, SIGNATURE_WORDS, v.name);
  assert.equal(hex64(fp.signature[0]), v.signature_word_0, v.name);
  assert.equal(hex64(fp.signature[1]), v.signature_word_1, v.name);
  const tail = raw.subarray(raw.length - SIGNATURE_WORDS * 8);
  assert.equal(hex64(fnv1a64(tail)), v.signature_fnv1a64, v.name);
  assert.equal(sha256hex(tail), v.signature_sha256, v.name);
}

test("cdylib is discoverable", () => {
  assert.ok(fs.statSync(findCdylib()).isFile());
});

for (const v of REFERENCE) {
  if (!v.name.startsWith("canon-") && !v.name.startsWith("fixture-")) continue;
  test(`reference vector ${v.name} is reproduced hex-exact`, () => {
    assertFingerprintFields(v, fingerprintStream(vectorInput(v)));
  });
}

test("reference vector signature-alpha-beta-gamma is reproduced hex-exact", () => {
  const v = vectorByName("signature-alpha-beta-gamma");
  const raw = fingerprintStream(Buffer.from(v.input_hex, "hex"));
  const fp = parseFingerprint(raw);
  assert.deepEqual(
    fp.signature.map((w) => hex64(w)),
    v.signature_words_hex,
  );
  const tail = raw.subarray(raw.length - SIGNATURE_WORDS * 8);
  assert.equal(hex64(fnv1a64(tail)), v.signature_fnv1a64);
  assert.equal(sha256hex(tail), v.signature_sha256);
});

test("reference vector signature-empty-sentinel is reproduced hex-exact", () => {
  const v = vectorByName("signature-empty-sentinel");
  const raw = fingerprintStream(Buffer.from(v.input_hex, "hex")); // the EMPTY input
  const fp = parseFingerprint(raw);
  assert.equal(fp.wordCount, 0);
  assert.equal(fp.shingleCount, 0);
  assert.equal(fp.canonical.toString("utf8"), "\n");
  assert.ok(fp.signature.every((w) => w === 0xffffffffffffffffn));
  assert.equal(hex64(fp.signature[0]), v.signature_word_0);
  assert.equal(hex64(fp.signature[1]), v.signature_word_1);
  const tail = raw.subarray(raw.length - SIGNATURE_WORDS * 8);
  assert.equal(hex64(fnv1a64(tail)), v.signature_fnv1a64);
  assert.equal(sha256hex(tail), v.signature_sha256);
});

test("non-UTF-8 bytes are refused, not crashing", () => {
  assert.throws(() => fingerprintStream(Buffer.from([0x6f, 0x6e, 0x65, 0xff])), (err) => {
    assert.ok(err instanceof FfiError);
    assert.equal(err.status, -2);
    return true;
  });
});

test("empty input is valid, not refused", () => {
  const raw = fingerprintStream(Buffer.alloc(0));
  assert.equal(raw.length, 8 + 1 + SIGNATURE_WORDS * 8); // header + "\n" + tail
  const fp = parseFingerprint(raw);
  assert.ok(fp.signature.every((w) => w === 0xffffffffffffffffn));
});

test("stream matches a rust-pinned value", () => {
  // "alpha beta gamma"'s stream, pinned in the committed reference.json
  // and re-derived by the Rust unit tests (plus the empty-sentinel
  // folds, likewise Rust-derived): these fail loudly even if
  // reference.json were regenerated wrongly.
  const fp = parseFingerprint(fingerprintStream("alpha beta gamma"));
  assert.equal(fp.wordCount, 3);
  assert.equal(fp.shingleCount, 1);
  assert.equal(fp.signature[0], 0x5409aadb22bb8479n);
  assert.equal(fp.signature[1], 0xb2e6ff4edebf53c6n);
  const tail = fp.raw.subarray(fp.raw.length - SIGNATURE_WORDS * 8);
  assert.equal(hex64(fnv1a64(tail)), "46f8ab1a50c61813");
  assert.equal(sha256hex(tail), "5a3e4c4a48d55a405faced9c28d4bf12b78af5661102eb2ac3dcab843485d8df");
  const sentinel = parseFingerprint(fingerprintStream(Buffer.alloc(0)));
  const stail = sentinel.raw.subarray(sentinel.raw.length - SIGNATURE_WORDS * 8);
  assert.equal(hex64(fnv1a64(stail)), "89bfa3a928539725");
  assert.equal(sha256hex(stail), "5f4ecdb7b71c3e403983fe405cddcdc2f2576b655fdb3e80d94a6f7c32e58bc2");
});
