// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

//go:build windows

package pithtext

import (
	"fmt"
	"syscall"
	"unsafe"
)

// openProc loads libPath and resolves name. The library is released
// before returning: on Windows FreeLibrary unmaps the cdylib, so the
// proc must be used (and its buffer copied out) inside the caller.
func openProc(libPath, name string) (proc uintptr, release func(), err error) {
	lib, err := syscall.LoadLibrary(libPath)
	if err != nil {
		return 0, nil, fmt.Errorf("pithtext: LoadLibrary(%s): %w", libPath, err)
	}
	release = func() { syscall.FreeLibrary(lib) }
	proc, err = syscall.GetProcAddress(lib, name)
	if err != nil {
		release()
		return 0, nil, fmt.Errorf("pithtext: symbol %s missing from %s: %w", name, libPath, err)
	}
	return proc, release, nil
}

// ffiFingerprint loads the cdylib with LoadLibrary (absolute path, no
// PATH involvement), resolves pith_text_fingerprint and calls it. The
// returned buffer stays alive in the cdylib until ffiFree. dataPtr is
// nil for the legal empty input.
func ffiFingerprint(libPath string, dataPtr *byte, n int, out **byte, outLen *uintptr) (int32, error) {
	proc, release, err := openProc(libPath, "pith_text_fingerprint")
	if err != nil {
		return 0, err
	}
	defer release()

	var cOut *byte
	var cLen uintptr
	rc, _, _ := syscall.SyscallN(proc,
		uintptr(unsafe.Pointer(dataPtr)),
		uintptr(n),
		uintptr(unsafe.Pointer(&cOut)),
		uintptr(unsafe.Pointer(&cLen)),
	)
	*out = cOut
	*outLen = cLen
	return int32(rc), nil
}

// ffiJaccard resolves pith_text_jaccard and calls it with the two
// word slices (nil pointers are the legal empty slices) and one typed
// u64 out-slot for the f64 bit pattern.
func ffiJaccard(libPath string, aPtr *uint64, aLen int, bPtr *uint64, bLen int, bits *uint64) (int32, error) {
	proc, release, err := openProc(libPath, "pith_text_jaccard")
	if err != nil {
		return 0, err
	}
	defer release()

	var cBits uint64
	rc, _, _ := syscall.SyscallN(proc,
		uintptr(unsafe.Pointer(aPtr)),
		uintptr(aLen),
		uintptr(unsafe.Pointer(bPtr)),
		uintptr(bLen),
		uintptr(unsafe.Pointer(&cBits)),
	)
	*bits = cBits
	return int32(rc), nil
}

// ffiFree resolves pith_text_free and releases a buffer handed out by
// ffiFingerprint. Null is accepted (the cdylib ignores it).
func ffiFree(libPath string, ptr *byte, n uintptr) {
	proc, release, err := openProc(libPath, "pith_text_free")
	if err != nil {
		return // the library vanished mid-flight; nothing to free
	}
	defer release()
	syscall.SyscallN(proc, uintptr(unsafe.Pointer(ptr)), n)
}
