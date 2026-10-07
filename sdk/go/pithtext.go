// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

// Package pithtext provides Go bindings for the pith-text Rust cdylib:
// text fingerprints and Jaccard estimates.
//
// The single Rust core (built by `cargo build --release`) is loaded at
// runtime; the package carries zero module dependencies. On unix the
// cdylib is opened with dlopen through cgo, on Windows with
// LoadLibrary through the standard syscall package — both resolve the
// library through the same discovery chain, so `go build ./... &&
// go test ./...` works unchanged on every OS the CD matrix builds.
//
// Discovery order (the suite's cdylib convention):
//
//  1. PITH_CDYLIB — an explicit cdylib file path;
//  2. PITH_CDYLIB_DIR — a directory scanned for the cdylib names (the
//     CD pipeline points this at target/release);
//  3. <repo root>/target/release — the repository working-tree layout,
//     anchored at this package's source directory, so a source
//     checkout runs against a local cargo build unconfigured.
//
// The FFI surface is two operations plus one free:
//
//   - pith_text_fingerprint takes the UTF-8 bytes of a string (the len
//     argument is a BYTE length) and hands out the canonical
//     fingerprint stream the reference.json vectors are defined over:
//
//     [0..4)    word_count     u32 big-endian
//     [4..8)    shingle_count  u32 big-endian
//     [8..8+C)  canonical      the canonical UTF-8 bytes (C bytes)
//     [8+C..)   signature      128 u64 little-endian words (1024 bytes)
//
//     so canonical_sha256 == sha256(stream[8..8+C]) and the
//     signature_fnv1a64 / signature_sha256 folds of reference.json are
//     the standard folds over the 1024-byte little-endian tail. The
//     empty input is valid and pins the sentinel stream (zero counts,
//     the one-byte canonical form "\n", 128 u64::MAX words) — it is
//     *not* a refusal.
//
//   - pith_text_jaccard takes two u64 word slices (the little-endian
//     tails of two fingerprint streams) and writes the estimate
//     through a u64 out-parameter as its f64 bit pattern — no float
//     crosses the ABI. An empty slice is the legal sentinel operand
//     (reference.json's empty-signature arm passes Vec::new(), *not*
//     signature(""), whose all-u64::MAX words would score ≈ 0).
//
//   - pith_text_free releases a handed-out fingerprint buffer (same
//     pointer *and* length).
package pithtext

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"
)

// float64frombits reinterprets an IEEE-754 bit pattern as a float64.
func float64frombits(bits uint64) float64 { return math.Float64frombits(bits) }

// Status codes returned by the cdylib's C ABI.
const (
	// StatusOK: success.
	StatusOK int32 = 0
	// StatusInvalid: a caller argument is invalid (a null pointer, or
	// a null buffer carrying a nonzero length).
	StatusInvalid int32 = -1
	// StatusRejected: the core pipeline refused the input (the bytes
	// are not valid UTF-8).
	StatusRejected int32 = -2
)

// SignatureWords is the length of a full signature in u64 words (and
// of the little-endian tail of every fingerprint stream).
const SignatureWords = 128

// cdylibNames are the file names cargo may drop into the build
// directory, per platform (windows / linux / macOS).
var cdylibNames = []string{"pith_text.dll", "libpith_text.so", "libpith_text.dylib"}

// FfiError reports a non-zero status code from the cdylib.
type FfiError struct {
	// Op is the FFI operation name.
	Op string
	// Status is the raw status code the FFI returned.
	Status int32
}

func (e *FfiError) Error() string {
	kind := "unknown failure"
	switch e.Status {
	case StatusInvalid:
		kind = "invalid argument"
	case StatusRejected:
		kind = "input rejected"
	}
	return fmt.Sprintf("%s failed: %s (status %d)", e.Op, kind, e.Status)
}

// FindCdylib locates the cdylib through the suite's discovery chain.
func FindCdylib() (string, error) {
	if p := os.Getenv("PITH_CDYLIB"); p != "" {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return filepath.Abs(p)
		}
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("pithtext: cannot locate the package source directory")
	}
	pkgDir := filepath.Dir(thisFile)
	repoRoot := filepath.Dir(filepath.Dir(pkgDir)) // sdk/go -> sdk -> repo root

	var dirs []string
	if env := os.Getenv("PITH_CDYLIB_DIR"); env != "" {
		dirs = append(dirs, env)
		if !filepath.IsAbs(env) {
			dirs = append(dirs, filepath.Join(repoRoot, env))
		}
	}
	dirs = append(dirs, filepath.Join(repoRoot, "target", "release"))
	for _, dir := range dirs {
		for _, name := range cdylibNames {
			p := filepath.Join(dir, name)
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf(
		"pithtext: no cdylib found (searched PITH_CDYLIB, PITH_CDYLIB_DIR and <repo>/target/release); run `cargo build --release` first",
	)
}

// locate resolves the cdylib path once per process.
var locate = sync.OnceValues(FindCdylib)

// Fingerprint is the fingerprint of one text, re-expressed from the
// canonical byte stream: the header counts, the canonical UTF-8 bytes
// and the 128-word MinHash signature.
type Fingerprint struct {
	// WordCount is the whitespace-separated word count of the
	// canonical form.
	WordCount uint32
	// ShingleCount is the consecutive k-word window count,
	// k = min(3, n).
	ShingleCount uint32
	// Canonical is the NFC-lowercased, whitespace-normalised UTF-8
	// form with exactly one trailing newline — the bytes
	// canonical_sha256 covers.
	Canonical []byte
	// Signature is the 128 signature words, little-endian stream order.
	Signature []uint64
	// Raw is the canonical byte stream the digests are computed over.
	Raw []byte
}

// FingerprintStream computes the full fingerprint of a UTF-8 string
// into the canonical byte stream the reference.json vectors are
// defined over (layout in the package doc). The returned slice is a
// Go copy; the handed-out cdylib buffer is released before returning.
// A nil or empty slice is the valid empty input (the sentinel
// stream); non-UTF-8 bytes are StatusRejected, never a crash.
func FingerprintStream(data []byte) ([]byte, error) {
	libPath, err := locate()
	if err != nil {
		return nil, err
	}
	var out *byte
	var outLen uintptr
	var dataPtr *byte
	if len(data) > 0 {
		dataPtr = &data[0]
	}
	status, err := ffiFingerprint(libPath, dataPtr, len(data), &out, &outLen)
	if err != nil {
		return nil, err
	}
	if status != StatusOK {
		return nil, &FfiError{Op: "pith_text_fingerprint", Status: status}
	}
	buf := make([]byte, outLen)
	copy(buf, unsafe.Slice(out, outLen))
	ffiFree(libPath, out, outLen)
	return buf, nil
}

// ParseFingerprint re-expresses the canonical byte stream as a
// Fingerprint.
func ParseFingerprint(raw []byte) (Fingerprint, error) {
	tail := SignatureWords * 8
	if len(raw) < 8+tail {
		return Fingerprint{}, fmt.Errorf("pithtext: canonical stream is shorter than the header plus signature tail")
	}
	canonicalLen := len(raw) - 8 - tail
	signature := make([]uint64, SignatureWords)
	for i := range signature {
		signature[i] = binary.LittleEndian.Uint64(raw[8+canonicalLen+i*8:])
	}
	return Fingerprint{
		WordCount:    binary.BigEndian.Uint32(raw[0:4]),
		ShingleCount: binary.BigEndian.Uint32(raw[4:8]),
		Canonical:    raw[8 : 8+canonicalLen],
		Signature:    signature,
		Raw:          raw,
	}, nil
}

// JaccardBits estimates the Jaccard index of the two shingle sets that
// produced the a and b word slices, returned as the raw f64 bit
// pattern — the exact form the reference.json value_bits fields pin.
// Callers comparing signatures pass full 128-word signatures; the
// empty slice is the legal sentinel operand and scores 1.0
// (0x3ff0000000000000) against anything.
func JaccardBits(a, b []uint64) (uint64, error) {
	libPath, err := locate()
	if err != nil {
		return 0, err
	}
	var aPtr, bPtr *uint64
	if len(a) > 0 {
		aPtr = &a[0]
	}
	if len(b) > 0 {
		bPtr = &b[0]
	}
	var bits uint64
	status, err := ffiJaccard(libPath, aPtr, len(a), bPtr, len(b), &bits)
	if err != nil {
		return 0, err
	}
	if status != StatusOK {
		return 0, &FfiError{Op: "pith_text_jaccard", Status: status}
	}
	return bits, nil
}

// Jaccard is the JaccardBits estimate as a float64: the u64 crossing
// the ABI is an IEEE-754 bit pattern, reinterpreted natively — the
// value is exact.
func Jaccard(a, b []uint64) (float64, error) {
	bits, err := JaccardBits(a, b)
	if err != nil {
		return 0, err
	}
	return float64frombits(bits), nil
}
