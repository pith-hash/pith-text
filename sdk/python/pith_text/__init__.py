# SPDX-License-Identifier: MIT
# Copyright (c) 2026 pith-hash
"""pith-text SDK: text fingerprints through ctypes.

The single Rust core (built by ``cargo build --release``) is loaded at
runtime; the package carries zero runtime dependencies beyond the
standard library.

Discovery order (the suite's cdylib convention):

1. ``PITH_CDYLIB`` — an explicit cdylib file path;
2. ``PITH_CDYLIB_DIR`` — a directory scanned for the cdylib names
   (the CD pipeline points this at ``target/release``);
3. the package directory — the packaged wheel's own cdylib copy;
4. ``<repo root>/target/release`` — the repository working-tree
   layout, so a source checkout runs against a local cargo build
   unconfigured.

The FFI surface is two operations plus one free:

* ``pith_text_fingerprint`` takes the UTF-8 bytes of a string (the
  ``len`` argument is a **byte** length) and hands out the canonical
  fingerprint stream the ``reference.json`` vectors are defined over:

  ::

      [0..4)    word_count     u32 big-endian
      [4..8)    shingle_count  u32 big-endian
      [8..8+C)  canonical      the canonical UTF-8 bytes (C bytes)
      [8+C..)   signature      128 u64 little-endian words (1024 bytes)

  so ``canonical_sha256 == sha256(stream[8..8+C])`` and the
  ``signature_fnv1a64`` / ``signature_sha256`` folds of
  ``reference.json`` are the standard folds over the 1024-byte
  little-endian tail. The empty input is valid and pins the sentinel
  stream (zero counts, the one-byte canonical form ``"\\n"``, 128
  ``u64::MAX`` words) — it is *not* a refusal.

* ``pith_text_jaccard`` takes two u64 word slices (the little-endian
  tails of two fingerprint streams) and writes the estimate through a
  ``u64`` out-parameter as its ``f64`` bit pattern — no float crosses
  the ABI. An empty slice is the legal sentinel operand
  (``reference.json``'s ``empty-signature`` arm passes ``Vec::new()``,
  *not* ``signature("")``, whose all-``u64::MAX`` words would score
  ≈ 0).
"""

from __future__ import annotations

import ctypes
import os
import struct as _struct
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "Fingerprint",
    "FfiError",
    "LibraryNotFoundError",
    "SIGNATURE_WORDS",
    "STATUS_OK",
    "STATUS_INVALID",
    "STATUS_REJECTED",
    "find_cdylib",
    "fingerprint_stream",
    "parse_fingerprint",
    "jaccard_bits",
    "jaccard",
]

#: Status: success.
STATUS_OK = 0
#: Status: a caller argument is invalid (a null pointer, or a null
#: buffer carrying a nonzero length).
STATUS_INVALID = -1
#: Status: the core pipeline refused the input (the bytes are not
#: valid UTF-8).
STATUS_REJECTED = -2

#: Length of a full signature in ``u64`` words (and of the little-)
#: endian tail of every fingerprint stream).
SIGNATURE_WORDS = 128

#: Every cdylib file name cargo may drop into the build directory, per
#: platform (windows / linux / macOS).
CDYLIB_NAMES = ("pith_text.dll", "libpith_text.so", "libpith_text.dylib")


@dataclass(frozen=True)
class Fingerprint:
    """The fingerprint of one text, re-expressed from the canonical
    byte stream.

    ``canonical`` is the NFC-lowercased, whitespace-normalised UTF-8
    form with exactly one trailing newline — exactly the bytes the
    ``canonical_sha256`` digest covers. ``signature`` is the 128-word
    MinHash signature in little-endian stream order.
    """

    #: Whitespace-separated word count of the canonical form.
    word_count: int
    #: Consecutive ``k``-word window count, ``k = min(3, n)``.
    shingle_count: int
    #: The canonical UTF-8 bytes (everything between the header and
    #: the signature tail).
    canonical: bytes
    #: The 128 signature words, little-endian stream order.
    signature: tuple[int, ...]
    #: The canonical byte stream the digests are computed over.
    raw: bytes


class LibraryNotFoundError(OSError):
    """No cdylib was found through the discovery chain."""


class FfiError(Exception):
    """A non-zero status code came back from the cdylib."""

    def __init__(self, op: str, status: int) -> None:
        kind = {
            STATUS_INVALID: "invalid argument",
            STATUS_REJECTED: "input rejected",
        }.get(status, "unknown failure")
        super().__init__(f"{op} failed: {kind} (status {status})")
        #: The raw status code the FFI returned.
        self.status = status


def find_cdylib() -> Path:
    """Locates the cdylib through the suite's discovery chain."""
    explicit = os.environ.get("PITH_CDYLIB")
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return p
    env_dir = os.environ.get("PITH_CDYLIB_DIR")
    candidates: list[Path] = []
    if env_dir:
        env_dir_path = Path(env_dir)
        candidates.append(env_dir_path)
        if not env_dir_path.is_absolute():
            # CD and local runs invoke tools from the repository root or
            # from sdk/<lang>; resolve the env value against both.
            candidates.append(Path.cwd() / env_dir_path)
            candidates.append(Path(__file__).resolve().parents[3] / env_dir_path)
    candidates.append(Path(__file__).resolve().parent)  # packaged wheel
    candidates.append(Path(__file__).resolve().parents[3] / "target" / "release")
    for directory in candidates:
        for name in CDYLIB_NAMES:
            p = directory / name
            if p.is_file():
                return p
    raise LibraryNotFoundError(
        "no pith-text cdylib found (searched PITH_CDYLIB, PITH_CDYLIB_DIR, "
        "the package directory and <repo>/target/release); "
        "run `cargo build --release` first"
    )


_lib: ctypes.CDLL | None = None


def _load() -> ctypes.CDLL:
    global _lib
    if _lib is None:
        lib = ctypes.CDLL(str(find_cdylib()))
        lib.pith_text_fingerprint.argtypes = [
            ctypes.c_void_p,  # data (UTF-8 bytes)
            ctypes.c_size_t,  # len (BYTE length)
            ctypes.POINTER(ctypes.c_void_p),  # out buffer
            ctypes.POINTER(ctypes.c_size_t),  # out length
        ]
        lib.pith_text_fingerprint.restype = ctypes.c_int32
        lib.pith_text_jaccard.argtypes = [
            ctypes.c_void_p,  # a words
            ctypes.c_size_t,  # a word count
            ctypes.c_void_p,  # b words
            ctypes.c_size_t,  # b word count
            ctypes.POINTER(ctypes.c_uint64),  # out f64 bits
        ]
        lib.pith_text_jaccard.restype = ctypes.c_int32
        lib.pith_text_free.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        lib.pith_text_free.restype = None
        _lib = lib
    return _lib


def _as_bytes(data: bytes | str) -> bytes:
    """The FFI takes UTF-8 bytes; ``str`` is encoded, ``bytes`` passes
    through untouched (so callers can probe the non-UTF-8 refusal)."""
    if isinstance(data, str):
        return data.encode("utf-8")
    return data


def fingerprint_stream(data: bytes | str) -> bytes:
    """Computes the full fingerprint of a UTF-8 string into the
    canonical byte stream the ``reference.json`` vectors are defined
    over (layout in the module docstring).

    A ``str`` is encoded UTF-8; ``bytes`` are passed through as-is, so
    a non-UTF-8 probe raises :class:`FfiError` with ``status ==
    STATUS_REJECTED`` — the empty input is valid and pins the
    sentinel stream, it is *not* a refusal. The handed-out cdylib
    buffer is copied and released before returning.
    """
    blob = _as_bytes(data)
    out = ctypes.c_void_p()
    out_len = ctypes.c_size_t()
    status = _load().pith_text_fingerprint(blob, len(blob), ctypes.byref(out), ctypes.byref(out_len))
    if status != STATUS_OK:
        raise FfiError("pith_text_fingerprint", status)
    try:
        return ctypes.string_at(out, out_len.value)
    finally:
        _load().pith_text_free(out, out_len.value)


def parse_fingerprint(raw: bytes) -> Fingerprint:
    """Re-expresses the canonical byte stream as a :class:`Fingerprint`."""
    tail = SIGNATURE_WORDS * 8
    if len(raw) < 8 + tail:
        raise ValueError("canonical stream is shorter than the header plus signature tail")
    canonical_len = len(raw) - 8 - tail
    signature = tuple(
        int.from_bytes(raw[8 + canonical_len + i * 8 : 8 + canonical_len + (i + 1) * 8], "little")
        for i in range(SIGNATURE_WORDS)
    )
    return Fingerprint(
        word_count=int.from_bytes(raw[0:4], "big"),
        shingle_count=int.from_bytes(raw[4:8], "big"),
        canonical=raw[8 : 8 + canonical_len],
        signature=signature,
        raw=raw,
    )


def _words_blob(words) -> bytes:
    """Serializes a sequence of ``u64`` words into the little-endian
    byte blob the jaccard FFI reads (alignment is not guaranteed on
    the Rust side, so a plain bytes buffer is the contract)."""
    return b"".join((int(w) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little") for w in words)


def jaccard_bits(a, b) -> int:
    """Estimates the Jaccard index of the two shingle sets that
    produced the ``a`` and ``b`` word sequences, returned as the raw
    ``f64`` **bit pattern** (a ``u64``) — the exact form the
    ``reference.json`` ``value_bits`` fields pin, comparable with
    ``int(value_bits, 16)``.

    Callers comparing signatures pass full 128-word signatures (the
    little-endian tail of :func:`fingerprint_stream`); the empty
    sequence is the legal sentinel operand and scores ``1.0``
    (``0x3ff0000000000000``) against anything.
    """
    a_blob = _words_blob(a)
    b_blob = _words_blob(b)
    out = ctypes.c_uint64()
    status = _load().pith_text_jaccard(
        a_blob, len(a_blob) // 8, b_blob, len(b_blob) // 8, ctypes.byref(out)
    )
    if status != STATUS_OK:
        raise FfiError("pith_text_jaccard", status)
    return out.value


def jaccard(a, b) -> float:
    """The :func:`jaccard_bits` estimate as a Python ``float``: the
    u64 crossing the ABI is an IEEE-754 bit pattern, reinterpreted
    natively — the value is exact."""
    return _struct.unpack("=d", _struct.pack("=Q", jaccard_bits(a, b)))[0]
