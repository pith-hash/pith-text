// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash
"use strict";

// Bit-exact conformance: the 5 committed jaccard vectors through koffi.
// Each operand is the 128-word little-endian tail of that side's
// fingerprint stream (fixture texts via tests/fixtures/<stem>.txt;
// `empty-signature` is the EMPTY slice — Vec::new() on the Rust side,
// NOT signature(""), whose all-u64::MAX words would score ≈ 0) — and
// the returned f64 bit pattern must equal value_bits EXACTLY.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { SIGNATURE_WORDS, fingerprintStream, jaccardBits, jaccard, parseFingerprint } = require("../index.js");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const REFERENCE = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "reference.json"), "utf8")).vectors;

function fixtureBytes(stem) {
  return fs.readFileSync(path.join(REPO_ROOT, "tests", "fixtures", `${stem}.txt`));
}

function signatureOperand(spec) {
  if (spec === "empty-signature") return [];
  const stem = path.basename(spec.replace(/^fixture:/, ""), ".txt");
  return parseFingerprint(fingerprintStream(fixtureBytes(stem))).signature;
}

for (const v of REFERENCE) {
  if (!v.name.startsWith("jaccard-")) continue;
  test(`jaccard vector ${v.name} is reproduced bit-exact`, () => {
    const a = signatureOperand(v.a);
    const b = signatureOperand(v.b);
    assert.equal(a.length <= 128 && b.length <= 128, true, v.name);
    assert.equal(jaccardBits(a, b), BigInt("0x" + v.value_bits), v.name);
    // The float reinterpretation of the same bits agrees.
    const wantFloat = Buffer.from(v.value_bits, "hex").readDoubleBE(0);
    assert.equal(jaccard(a, b), wantFloat, v.name);
  });
}

test("jaccard vector count is complete", () => {
  assert.equal(REFERENCE.filter((v) => v.name.startsWith("jaccard-")).length, 5);
});
