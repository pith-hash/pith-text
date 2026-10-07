// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

//go:build !windows && cgo

package pithtext

/*
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef int32_t (*pith_fingerprint_fn)(const uint8_t *, size_t, uint8_t **, size_t *);
typedef int32_t (*pith_jaccard_fn)(const uint64_t *, size_t, const uint64_t *, size_t, uint64_t *);
typedef void (*pith_free_fn)(uint8_t *, size_t);

static int32_t pith_call_fingerprint(void *fn, const uint8_t *data, size_t len,
                                     uint8_t **out, size_t *out_len) {
    return ((pith_fingerprint_fn)fn)(data, len, out, out_len);
}

static int32_t pith_call_jaccard(void *fn, const uint64_t *a, size_t a_words,
                                 const uint64_t *b, size_t b_words, uint64_t *bits) {
    return ((pith_jaccard_fn)fn)(a, a_words, b, b_words, bits);
}

static void pith_call_free(void *fn, uint8_t *ptr, size_t len) {
    ((pith_free_fn)fn)(ptr, len);
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// ffiSymbols resolves the three exported symbols of one open cdylib
// handle.
func ffiSymbols(handle unsafe.Pointer, libPath string) (fingerprint, jaccard, freeSym unsafe.Pointer, err error) {
	for _, sym := range []struct {
		name string
		dst  *unsafe.Pointer
	}{
		{"pith_text_fingerprint", &fingerprint},
		{"pith_text_jaccard", &jaccard},
		{"pith_text_free", &freeSym},
	} {
		cSym := C.CString(sym.name)
		addr := C.dlsym(handle, cSym)
		C.free(unsafe.Pointer(cSym))
		if addr == nil {
			return nil, nil, nil, fmt.Errorf("pithtext: symbol %s missing from %s", sym.name, libPath)
		}
		*sym.dst = addr
	}
	return fingerprint, jaccard, freeSym, nil
}

// openCdylib dlopens libPath with error text surfaced verbatim.
func openCdylib(libPath string) (unsafe.Pointer, error) {
	cPath := C.CString(libPath)
	defer C.free(unsafe.Pointer(cPath))
	handle := C.dlopen(cPath, C.RTLD_NOW|C.RTLD_LOCAL)
	if handle == nil {
		msg := "unknown dlopen failure"
		if e := C.dlerror(); e != nil {
			msg = C.GoString(e)
		}
		return nil, fmt.Errorf("pithtext: dlopen(%s): %s", libPath, msg)
	}
	return handle, nil
}

// ffiFingerprint opens the cdylib, resolves pith_text_fingerprint and
// calls it. The handle is released before returning; repeated calls
// reuse the loader's own refcount. dataPtr is nil for the legal empty
// input.
func ffiFingerprint(libPath string, dataPtr *byte, n int, out **byte, outLen *uintptr) (int32, error) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return 0, err
	}
	defer C.dlclose(handle)

	fingerprintSym, _, _, err := ffiSymbols(handle, libPath)
	if err != nil {
		return 0, err
	}
	var cOut *C.uint8_t
	var cLen C.size_t
	rc := C.pith_call_fingerprint(fingerprintSym, (*C.uint8_t)(unsafe.Pointer(dataPtr)), C.size_t(n), &cOut, &cLen)
	*out = (*byte)(unsafe.Pointer(cOut))
	*outLen = uintptr(cLen)
	return int32(rc), nil
}

// ffiJaccard resolves pith_text_jaccard and calls it with the two word
// slices (nil pointers are the legal empty slices) and one typed u64
// out-slot for the f64 bit pattern.
func ffiJaccard(libPath string, aPtr *uint64, aLen int, bPtr *uint64, bLen int, bits *uint64) (int32, error) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return 0, err
	}
	defer C.dlclose(handle)

	_, jaccardSym, _, err := ffiSymbols(handle, libPath)
	if err != nil {
		return 0, err
	}
	var cBits C.uint64_t
	rc := C.pith_call_jaccard(jaccardSym,
		(*C.uint64_t)(unsafe.Pointer(aPtr)), C.size_t(aLen),
		(*C.uint64_t)(unsafe.Pointer(bPtr)), C.size_t(bLen),
		&cBits)
	*bits = uint64(cBits)
	return int32(rc), nil
}

// ffiFree releases a buffer handed out by ffiFingerprint. Null is
// accepted (the cdylib ignores it), matching the C contract.
func ffiFree(libPath string, ptr *byte, n uintptr) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return // the library vanished mid-flight; nothing to free
	}
	defer C.dlclose(handle)
	if _, _, freeSym, err := ffiSymbols(handle, libPath); err == nil {
		C.pith_call_free(freeSym, (*C.uint8_t)(unsafe.Pointer(ptr)), C.size_t(n))
	}
}
