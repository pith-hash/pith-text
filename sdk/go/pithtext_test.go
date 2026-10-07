// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

package pithtext

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// repoRoot resolves the repository root relative to this package
// (sdk/go -> sdk -> repo root), the anchor for reference.json and the
// committed fixtures.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(root, "reference.json")); err != nil || st.IsDir() {
		t.Fatalf("reference.json not found at %s", root)
	}
	return root
}

// vector mirrors one reference.json entry across all four vector kinds
// (the file stores a list of named objects, in pinned order).
type vector struct {
	Name              string   `json:"name"`
	InputKind         string   `json:"input_kind"`
	InputHex          string   `json:"input_hex"`
	InputPath         string   `json:"input_path"`
	CanonicalSha      string   `json:"canonical_sha256"`
	CanonicalFnv      string   `json:"canonical_fnv1a64"`
	WordCount         int      `json:"word_count"`
	ShingleCount      int      `json:"shingle_count"`
	SignatureWord0    string   `json:"signature_word_0"`
	SignatureWord1    string   `json:"signature_word_1"`
	SignatureFnv      string   `json:"signature_fnv1a64"`
	SignatureSha      string   `json:"signature_sha256"`
	SignatureWordsHex []string `json:"signature_words_hex"`
	A                 string   `json:"a"`
	B                 string   `json:"b"`
	ValueBits         string   `json:"value_bits"`
}

// vectors parses the committed reference.json vectors.
func vectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "reference.json"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed.Vectors
}

func vectorByName(t *testing.T, name string) vector {
	t.Helper()
	for _, v := range vectors(t) {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("vector %s not found", name)
	return vector{}
}

// fnv1a64 is the standard FNV-1a 64 (offset 0xcbf29ce484222325, prime
// 0x100000001b3) — the fold the Rust side applies.
func fnv1a64(data []byte) uint64 {
	const (
		offset = uint64(0xcbf29ce484222325)
		prime  = uint64(0x100000001b3)
	)
	h := offset
	for _, b := range data {
		h = (h ^ uint64(b)) * prime
	}
	return h
}

// vectorInput resolves the raw input bytes a fingerprint vector is
// defined over.
func vectorInput(t *testing.T, v vector) []byte {
	t.Helper()
	if v.InputKind == "inline-hex" {
		raw, err := hex.DecodeString(v.InputHex)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	data, err := os.ReadFile(filepath.Join(repoRoot(t), v.InputPath))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// assertFingerprintFields checks every pinned fingerprint field of one
// vector, hex-exact.
func assertFingerprintFields(t *testing.T, v vector, raw []byte) {
	t.Helper()
	fp, err := ParseFingerprint(raw)
	if err != nil {
		t.Fatalf("%s: %v", v.Name, err)
	}
	// The signature-only vectors (the sentinel arm) record no
	// canonicalisation fields.
	if v.CanonicalSha != "" {
		if int(fp.WordCount) != v.WordCount || int(fp.ShingleCount) != v.ShingleCount {
			t.Errorf("%s: counts %d/%d, want %d/%d", v.Name, fp.WordCount, fp.ShingleCount, v.WordCount, v.ShingleCount)
		}
		if got := hex.EncodeToString(sha256Sum(fp.Canonical)); got != v.CanonicalSha {
			t.Errorf("%s: canonical sha256 %s, want %s", v.Name, got, v.CanonicalSha)
		}
		if got := fmt.Sprintf("%016x", fnv1a64(fp.Canonical)); got != v.CanonicalFnv {
			t.Errorf("%s: canonical fnv1a64 %s, want %s", v.Name, got, v.CanonicalFnv)
		}
	}
	if v.SignatureWord0 == "" {
		return
	}
	if len(fp.Signature) != SignatureWords {
		t.Fatalf("%s: signature length %d, want %d", v.Name, len(fp.Signature), SignatureWords)
	}
	if got := fmt.Sprintf("%016x", fp.Signature[0]); got != v.SignatureWord0 {
		t.Errorf("%s: signature_word_0 %s, want %s", v.Name, got, v.SignatureWord0)
	}
	if got := fmt.Sprintf("%016x", fp.Signature[1]); got != v.SignatureWord1 {
		t.Errorf("%s: signature_word_1 %s, want %s", v.Name, got, v.SignatureWord1)
	}
	tail := raw[len(raw)-SignatureWords*8:]
	if got := fmt.Sprintf("%016x", fnv1a64(tail)); got != v.SignatureFnv {
		t.Errorf("%s: signature fnv1a64 %s, want %s", v.Name, got, v.SignatureFnv)
	}
	if got := hex.EncodeToString(sha256Sum(tail)); got != v.SignatureSha {
		t.Errorf("%s: signature sha256 %s, want %s", v.Name, got, v.SignatureSha)
	}
}

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// signatureOperand resolves the u64 word operand a jaccard vector
// names: a fixture path yields the 128 words of its fingerprint tail;
// empty-signature is the EMPTY slice — Vec::new() on the Rust side,
// NOT signature(""), whose all-u64::MAX words would score ≈ 0.
func signatureOperand(t *testing.T, spec string) []uint64 {
	t.Helper()
	if spec == "empty-signature" {
		return []uint64{}
	}
	stem := filepath.Base(spec)
	stem = stem[:len(stem)-len(".txt")]
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "tests", "fixtures", stem+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := FingerprintStream(data)
	if err != nil {
		t.Fatalf("FingerprintStream(%s): %v", stem, err)
	}
	return tailWords(raw)
}

// tailWords decodes the little-endian u64 signature tail of a stream.
func tailWords(raw []byte) []uint64 {
	tail := raw[len(raw)-SignatureWords*8:]
	words := make([]uint64, SignatureWords)
	for i := range words {
		words[i] = binary.LittleEndian.Uint64(tail[i*8:])
	}
	return words
}

// TestCdylibIsDiscoverable checks the discovery chain before any call.
func TestCdylibIsDiscoverable(t *testing.T) {
	path, err := FindCdylib()
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path); err != nil || st.IsDir() {
		t.Fatalf("cdylib %s is not a regular file", path)
	}
}

// TestReferenceVectorsHexExact replays every committed reference.json
// vector through the cdylib and compares hex-exact — the canonical
// digests and counts, the pinned signature words and the FNV-1a 64 /
// SHA-256 folds over the 1024-byte little-endian tail, and the
// Jaccard estimates as raw IEEE-754 bits. The same vectors the Rust
// gen-reference verify gate and the Python/Node SDKs check.
func TestReferenceVectorsHexExact(t *testing.T) {
	seen := 0
	for _, v := range vectors(t) {
		name := v.Name
		switch {
		case len(name) > 7 && (name[:6] == "canon-" || name[:8] == "fixture-"):
			seen++
			t.Run(name, func(t *testing.T) {
				raw, err := FingerprintStream(vectorInput(t, v))
				if err != nil {
					t.Fatalf("FingerprintStream: %v", err)
				}
				assertFingerprintFields(t, v, raw)
			})
		case name == "signature-alpha-beta-gamma":
			seen++
			t.Run(name, func(t *testing.T) {
				raw, err := FingerprintStream(vectorInput(t, v))
				if err != nil {
					t.Fatal(err)
				}
				fp, err := ParseFingerprint(raw)
				if err != nil {
					t.Fatal(err)
				}
				if len(fp.Signature) != len(v.SignatureWordsHex) {
					t.Fatalf("signature length %d, want %d", len(fp.Signature), len(v.SignatureWordsHex))
				}
				for i, want := range v.SignatureWordsHex {
					if got := fmt.Sprintf("%016x", fp.Signature[i]); got != want {
						t.Fatalf("signature word %d = %s, want %s", i, got, want)
					}
				}
				tail := raw[len(raw)-SignatureWords*8:]
				if got := fmt.Sprintf("%016x", fnv1a64(tail)); got != v.SignatureFnv {
					t.Errorf("signature fnv1a64 %s, want %s", got, v.SignatureFnv)
				}
				if got := hex.EncodeToString(sha256Sum(tail)); got != v.SignatureSha {
					t.Errorf("signature sha256 %s, want %s", got, v.SignatureSha)
				}
			})
		case name == "signature-empty-sentinel":
			seen++
			t.Run(name, func(t *testing.T) {
				raw, err := FingerprintStream(vectorInput(t, v)) // the EMPTY input
				if err != nil {
					t.Fatal(err)
				}
				assertFingerprintFields(t, v, raw)
				fp, err := ParseFingerprint(raw)
				if err != nil {
					t.Fatal(err)
				}
				if fp.WordCount != 0 || fp.ShingleCount != 0 {
					t.Errorf("sentinel counts %d/%d, want 0/0", fp.WordCount, fp.ShingleCount)
				}
				if string(fp.Canonical) != "\n" {
					t.Errorf(`sentinel canonical %q, want "\n"`, fp.Canonical)
				}
				for i, w := range fp.Signature {
					if w != ^uint64(0) {
						t.Fatalf("sentinel word %d = %x, want ffffffffffffffff", i, w)
					}
				}
			})
		case len(name) > 8 && name[:8] == "jaccard-":
			seen++
			t.Run(name, func(t *testing.T) {
				a := signatureOperand(t, v.A)
				b := signatureOperand(t, v.B)
				bits, err := JaccardBits(a, b)
				if err != nil {
					t.Fatalf("JaccardBits: %v", err)
				}
				want, err := strconv.ParseUint(v.ValueBits, 16, 64)
				if err != nil {
					t.Fatal(err)
				}
				if bits != want {
					t.Errorf("%s: bits %016x, want %s", name, bits, v.ValueBits)
				}
				value, err := Jaccard(a, b)
				if err != nil {
					t.Fatal(err)
				}
				if value != math.Float64frombits(want) {
					t.Errorf("%s: float %v, want %v", name, value, math.Float64frombits(want))
				}
			})
		default:
			t.Fatalf("vector %s matches no known kind — the replay must consume every vector", name)
		}
	}
	if seen != 22 {
		t.Errorf("replayed %d of 22 vectors", seen)
	}
}

// TestRustPinnedLiteral pins one stream the Rust unit tests re-derive
// (plus the empty-sentinel folds, likewise Rust-derived), so the
// binding fails loudly even if reference.json were regenerated wrongly.
func TestRustPinnedLiteral(t *testing.T) {
	raw, err := FingerprintStream([]byte("alpha beta gamma"))
	if err != nil {
		t.Fatal(err)
	}
	fp, err := ParseFingerprint(raw)
	if err != nil {
		t.Fatal(err)
	}
	if fp.WordCount != 3 || fp.ShingleCount != 1 {
		t.Fatalf("counts %d/%d, want 3/1", fp.WordCount, fp.ShingleCount)
	}
	if fp.Signature[0] != 0x5409aadb22bb8479 || fp.Signature[1] != 0xb2e6ff4edebf53c6 {
		t.Fatalf("pinned words %016x/%016x drifted", fp.Signature[0], fp.Signature[1])
	}
	tail := raw[len(raw)-SignatureWords*8:]
	if got := fnv1a64(tail); got != 0x46f8ab1a50c61813 {
		t.Fatalf("pinned fnv1a64 %016x drifted", got)
	}
	if got := hex.EncodeToString(sha256Sum(tail)); got != "5a3e4c4a48d55a405faced9c28d4bf12b78af5661102eb2ac3dcab843485d8df" {
		t.Fatalf("pinned sha256 %s drifted", got)
	}
	sentinel, err := FingerprintStream(nil)
	if err != nil {
		t.Fatal(err)
	}
	stail := sentinel[len(sentinel)-SignatureWords*8:]
	if got := fnv1a64(stail); got != 0x89bfa3a928539725 {
		t.Fatalf("sentinel fnv1a64 %016x drifted", got)
	}
	if got := hex.EncodeToString(sha256Sum(stail)); got != "5f4ecdb7b71c3e403983fe405cddcdc2f2576b655fdb3e80d94a6f7c32e58bc2" {
		t.Fatalf("sentinel sha256 %s drifted", got)
	}
}

// TestNonUTF8BytesAreRefused checks the refusal path: a status code,
// never a crash. The empty input is valid (the sentinel), not a
// refusal.
func TestNonUTF8BytesAreRefused(t *testing.T) {
	_, err := FingerprintStream([]byte{'o', 'n', 'e', 0xFF})
	var ffi *FfiError
	if e, ok := err.(*FfiError); ok {
		ffi = e
	} else {
		t.Fatalf("want FfiError, got %v", err)
	}
	if ffi.Status != StatusRejected {
		t.Errorf("want StatusRejected, got %d", ffi.Status)
	}

	raw, err := FingerprintStream(nil)
	if err != nil {
		t.Fatalf("empty input must be valid: %v", err)
	}
	if len(raw) != 8+1+SignatureWords*8 {
		t.Fatalf("sentinel stream length %d, want %d", len(raw), 8+1+SignatureWords*8)
	}
}
