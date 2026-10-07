// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash
"use strict";

/**
 * pith-text SDK: text fingerprints through koffi.
 *
 * The single Rust core (built by `cargo build --release`) is loaded at
 * runtime; the package carries one runtime dependency (koffi).
 *
 * Discovery order (the suite's cdylib convention):
 *
 *  1. PITH_CDYLIB — an explicit cdylib file path;
 *  2. PITH_CDYLIB_DIR — a directory scanned for the cdylib names (the
 *     CD pipeline points this at target/release);
 *  3. prebuilds/<platform>-<arch>/ then prebuilds/ — the packaged
 *     prebuilt cdylib;
 *  4. <repo root>/target/release — the repository working-tree layout,
 *     so a source checkout runs against a local cargo build
 *     unconfigured.
 *
 * The FFI surface is two operations plus one free:
 *
 *  - `pith_text_fingerprint` takes the UTF-8 bytes of a string (the
 *    `len` argument is a **byte** length) and hands out the canonical
 *    fingerprint stream the reference.json vectors are defined over:
 *    word_count u32 big-endian, shingle_count u32 big-endian, the
 *    canonical UTF-8 bytes, then 128 u64 little-endian signature
 *    words — so canonical_sha256 == sha256(stream[8..8+C]) and the
 *    reference folds are the standard folds over the 1024-byte tail.
 *    The empty input is valid and pins the sentinel stream (zero
 *    counts, the one-byte canonical form "\n", 128 u64::MAX words) —
 *    it is *not* a refusal.
 *  - `pith_text_jaccard` takes two u64 word slices (byte blobs of
 *    little-endian words; alignment is not guaranteed on the Rust
 *    side) and writes the estimate through a u64 out-parameter as its
 *    f64 bit pattern — no float crosses the ABI. An empty slice is
 *    the legal sentinel operand (reference.json's `empty-signature`
 *    arm passes Vec::new(), *not* signature(""), whose all-u64::MAX
 *    words would score ≈ 0).
 *  - `pith_text_free` releases a handed-out fingerprint buffer (same
 *    pointer *and* length).
 */

const koffi = require("koffi");
const fs = require("node:fs");
const path = require("node:path");

const STATUS_OK = 0;
const STATUS_INVALID = -1;
const STATUS_REJECTED = -2;

/** Length of a full signature in u64 words (the stream tail's size in words). */
const SIGNATURE_WORDS = 128;

/** Every cdylib file name cargo may drop into the build directory, per platform. */
const CDYLIB_NAMES = ["pith_text.dll", "libpith_text.so", "libpith_text.dylib"];

const PKG_ROOT = path.join(__dirname);
const REPO_ROOT = path.resolve(__dirname, "..", "..");

/** FfiError: a non-zero status code came back from the cdylib. */
class FfiError extends Error {
  /**
   * @param {string} op the FFI operation name
   * @param {number} status the raw status code
   */
  constructor(op, status) {
    const kind = { [STATUS_INVALID]: "invalid argument", [STATUS_REJECTED]: "input rejected" }[status] ?? "unknown failure";
    super(`${op} failed: ${kind} (status ${status})`);
    this.name = "FfiError";
    /** The raw status code the FFI returned. */
    this.status = status;
  }
}

/**
 * Locates the cdylib through the suite's discovery chain.
 * @returns {string} an absolute path to the cdylib file
 * @throws {Error} when nothing is found
 */
function findCdylib() {
  const explicit = process.env.PITH_CDYLIB;
  if (explicit && fs.statSync(explicit, { throwIfNoEntry: false })?.isFile()) {
    return path.resolve(explicit);
  }
  /** @type {string[]} */
  const dirs = [];
  const envDir = process.env.PITH_CDYLIB_DIR;
  if (envDir) {
    dirs.push(envDir);
    if (!path.isAbsolute(envDir)) {
      dirs.push(path.join(REPO_ROOT, envDir));
    }
  }
  const osArch = `${process.platform}-${process.arch}`;
  dirs.push(path.join(PKG_ROOT, "prebuilds", osArch));
  dirs.push(path.join(PKG_ROOT, "prebuilds"));
  dirs.push(path.join(REPO_ROOT, "target", "release"));
  for (const dir of dirs) {
    for (const name of CDYLIB_NAMES) {
      const p = path.join(dir, name);
      if (fs.statSync(p, { throwIfNoEntry: false })?.isFile()) return p;
    }
  }
  throw new Error(
    "no pith-text cdylib found (searched PITH_CDYLIB, PITH_CDYLIB_DIR, prebuilds/ and <repo>/target/release); " +
      "run `cargo build --release` first",
  );
}

let cached = undefined;

/**
 * Loads the cdylib and binds the exported symbols (lazily, once).
 * @returns {{fingerprint: Function, jaccard: Function, free: Function}}
 */
function loadLibrary() {
  if (cached) return cached;
  const lib = koffi.load(findCdylib());
  const fingerprint = lib.func("pith_text_fingerprint", "int32_t", [
    "const uint8_t *",
    "size_t",
    koffi.out(koffi.pointer("void *")),
    koffi.out(koffi.pointer("size_t")),
  ]);
  const jaccard = lib.func("pith_text_jaccard", "int32_t", [
    "const uint8_t *",
    "size_t",
    "const uint8_t *",
    "size_t",
    koffi.out(koffi.pointer("uint64_t")),
  ]);
  const free = lib.func("void pith_text_free(void *ptr, size_t len)");
  cached = { fingerprint, jaccard, free };
  return cached;
}

/** @param {Buffer|bigint[]|number[]} words a word sequence to serialize */
function wordsBlob(words) {
  if (Buffer.isBuffer(words)) return words;
  const out = Buffer.alloc(words.length * 8);
  for (let i = 0; i < words.length; i++) {
    out.writeBigUInt64LE(BigInt(words[i]), i * 8);
  }
  return out;
}

/**
 * Computes the full fingerprint of a UTF-8 string into the canonical
 * byte stream the reference.json vectors are defined over. A string is
 * encoded UTF-8; a Buffer passes through as-is, so a non-UTF-8 probe
 * throws FfiError with status === -2 — the empty input is valid and
 * pins the sentinel stream, it is *not* a refusal. The handed-out
 * cdylib buffer is copied into a Buffer and released before returning.
 *
 * @param {Buffer|string} data the UTF-8 text (or its exact bytes)
 * @returns {Buffer} the canonical stream (8-byte header + canonical
 *   bytes + 1024-byte little-endian signature tail)
 * @throws {FfiError} with `status === -2` for non-UTF-8 bytes
 */
function fingerprintStream(data) {
  const blob = Buffer.isBuffer(data) ? data : Buffer.from(data, "utf8");
  const { fingerprint, free } = loadLibrary();
  const out = [null];
  const outLen = [0];
  const status = fingerprint(blob, blob.length, out, outLen);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_text_fingerprint", status);
  }
  try {
    // koffi.decode hands back a Uint8Array view over the external
    // buffer; copy it into a Buffer before the cdylib buffer is freed.
    return Buffer.from(koffi.decode(out[0], "uint8_t", Number(outLen[0])));
  } finally {
    free(out[0], Number(outLen[0]));
  }
}

/**
 * Re-expresses the canonical byte stream as a plain object.
 *
 * @param {Buffer} raw the canonical stream
 * @returns {{wordCount: number, shingleCount: number, canonical: Buffer,
 *   signature: BigInt[], raw: Buffer}} the header counts, the canonical
 *   UTF-8 bytes and the 128 signature words (little-endian stream order;
 *   BigInt, u64 does not fit in a JS number)
 */
function parseFingerprint(raw) {
  if (!Buffer.isBuffer(raw) || raw.length < 8 + SIGNATURE_WORDS * 8) {
    throw new TypeError("canonical stream is shorter than the header plus signature tail");
  }
  const canonicalLen = raw.length - 8 - SIGNATURE_WORDS * 8;
  const signature = [];
  for (let i = 0; i < SIGNATURE_WORDS; i++) {
    signature.push(raw.readBigUInt64LE(8 + canonicalLen + i * 8));
  }
  return {
    wordCount: raw.readUInt32BE(0),
    shingleCount: raw.readUInt32BE(4),
    canonical: raw.subarray(8, 8 + canonicalLen),
    signature,
    raw,
  };
}

/**
 * Estimates the Jaccard index of the two shingle sets that produced
 * the `a` and `b` word sequences, returned as the raw f64 **bit
 * pattern** (a BigInt u64) — the exact form the reference.json
 * `value_bits` fields pin, comparable via `BigInt("0x" + value_bits)`.
 * Callers comparing signatures pass full 128-word signatures; the
 * empty sequence is the legal sentinel operand and scores 1.0
 * (0x3ff0000000000000) against anything.
 *
 * @param {Buffer|bigint[]|number[]} a left word sequence
 * @param {Buffer|bigint[]|number[]} b right word sequence
 * @returns {BigInt} the f64 bit pattern of the estimate
 * @throws {FfiError} on a non-zero status
 */
function jaccardBits(a, b) {
  const aBlob = wordsBlob(a);
  const bBlob = wordsBlob(b);
  const { jaccard } = loadLibrary();
  const bits = [null];
  const status = jaccard(aBlob, aBlob.length / 8, bBlob, bBlob.length / 8, bits);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_text_jaccard", status);
  }
  // koffi hands small u64 values back as Numbers; normalize to BigInt
  // (u64 is the contract and does not fit in a JS number in general).
  return BigInt(bits[0]);
}

/**
 * The jaccardBits estimate as a JS number: the u64 crossing the ABI is
 * an IEEE-754 bit pattern, reinterpreted natively — the value is exact.
 *
 * @param {Buffer|bigint[]|number[]} a left word sequence
 * @param {Buffer|bigint[]|number[]} b right word sequence
 * @returns {number}
 */
function jaccard(a, b) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(jaccardBits(a, b), 0);
  return buf.readDoubleLE(0);
}

module.exports = {
  STATUS_OK,
  STATUS_INVALID,
  STATUS_REJECTED,
  SIGNATURE_WORDS,
  CDYLIB_NAMES,
  FfiError,
  findCdylib,
  fingerprintStream,
  parseFingerprint,
  jaccardBits,
  jaccard,
};
