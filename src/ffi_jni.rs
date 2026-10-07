//! The JNI surface of `pith-text`: the `Java_hash_pith_text_PithText_*`
//! exports the Java SDK (`sdk/java`) binds its `native` methods through.
//!
//! The C ABI of [`crate::ffi`] is untouched: JNI requires exports named
//! `Java_<package>_<Class>_<method>`, so the Java-facing shims live here
//! and forward every call to the existing `pith_*` C exports — same
//! status codes, same refusals, no second implementation of the
//! pipeline. The module is compiled out of the unit-test build
//! (`#[cfg(all(not(test), feature = "std"))]` at the registration site
//! in `lib.rs`); the integration tests in `tests/java_ffi.rs` exercise
//! every export against a synthetic environment so the coverage gate
//! still sees the glue.
//!
//! JNI conventions of this module (the Java-side contract):
//!
//! * every export takes the JNI environment first and the receiving
//!   class second (the methods are static), then the Java arguments;
//! * the status code crosses back through a trailing one-element
//!   `int[]` — the same `PITH_OK` / `PITH_E_INVALID` /
//!   `PITH_E_REJECTED` values the C ABI returns;
//! * the operation result crosses back as the return value: a fresh
//!   `byte[]` for `fingerprint` (null unless the status is
//!   `PITH_OK`), the estimate's `f64` bit pattern as a `jdouble` for
//!   `jaccard`;
//! * the fingerprint buffer the C ABI hands out is copied into the
//!   Java array and released with [`pith_text_free`] before the export
//!   returns — Java never sees a raw pointer;
//! * a null `data` array maps to `PITH_E_INVALID` exactly as the C ABI
//!   maps a null pointer (the empty-slice jaccard operand is the empty
//!   Java array, never null); a null environment or status array
//!   short-circuits to a zero return without touching memory.
//!
//! The suite is zero-third-party (CI's `check-zero-deps.py` fails any
//! registry crate), so the JNI function table is hand-declared below:
//! every slot is pointer-sized and the positions are the fixed
//! `JNINativeInterface_` member order of `jni.h`. The slot indices were
//! parsed mechanically from the JDK 21 header and are validated
//! end-to-end against a live JVM every time the Java suite runs.

#![allow(unsafe_code)]
// The JNI typedefs keep the jni.h spelling (jint, jbyte, ...).
#![allow(non_camel_case_types)]

use alloc::vec::Vec;

use core::ffi::c_void;

use crate::ffi::{
    PITH_E_INVALID, PITH_E_REJECTED, PITH_OK, pith_text_fingerprint, pith_text_free,
    pith_text_jaccard,
};

/// A JNI environment handle — C-mode `JNIEnv*`, a pointer to the
/// function table.
type JNIEnv = *const JniTable;

/// Any Java array reference; the glue only checks nullness before
/// handing arrays through the table.
type JArray = *mut c_void;

/// A Java `int[]` reference.
type JIntArray = *mut c_void;

/// A Java class object reference (static methods receive the class).
type JClass = *mut c_void;

/// `jbyte` per `jni.h`.
type jbyte = i8;
/// `jint`/`jsize` per `jni.h`.
type jint = i32;
/// `jlong` per `jni.h`.
type jlong = i64;
/// `jdouble` per `jni.h`.
type jdouble = f64;

/// The JNI function-table slots this module calls.
///
/// Underscore-prefixed gap fields hold the slots between the used ones
/// (slot = field position; the four reserved pointers are part of the
/// prefix). Slot indices parsed from the JDK 21 `include/jni.h`:
/// `GetArrayLength` = 171, `NewByteArray` = 176,
/// `GetByteArrayRegion` = 200, `GetLongArrayRegion` = 204,
/// `SetByteArrayRegion` = 208, `SetIntArrayRegion` = 211.
#[repr(C)]
struct JniTable {
    /// Slots 0..=170: the four reserved pointers through
    /// `ReleaseStringUTFChars`.
    _prefix: [*mut c_void; 171],
    /// Slot 171.
    get_array_length: unsafe extern "system" fn(env: *mut JNIEnv, array: JArray) -> jint,
    /// Slots 172..=175.
    _gap_before_new_byte_array: [*mut c_void; 4],
    /// Slot 176.
    new_byte_array: unsafe extern "system" fn(env: *mut JNIEnv, len: jint) -> JArray,
    /// Slots 177..=199.
    _gap_before_byte_region: [*mut c_void; 23],
    /// Slot 200.
    get_byte_array_region: unsafe extern "system" fn(
        env: *mut JNIEnv,
        array: JArray,
        start: jint,
        len: jint,
        buf: *mut jbyte,
    ),
    /// Slots 201..=203.
    _gap_before_long_region: [*mut c_void; 3],
    /// Slot 204.
    get_long_array_region: unsafe extern "system" fn(
        env: *mut JNIEnv,
        array: JArray,
        start: jint,
        len: jint,
        buf: *mut jlong,
    ),
    /// Slots 205..=207.
    _gap_before_set_byte_region: [*mut c_void; 3],
    /// Slot 208.
    set_byte_array_region: unsafe extern "system" fn(
        env: *mut JNIEnv,
        array: JArray,
        start: jint,
        len: jint,
        buf: *const jbyte,
    ),
    /// Slots 209..=210.
    _gap_before_set_int_region: [*mut c_void; 2],
    /// Slot 211.
    set_int_array_region: unsafe extern "system" fn(
        env: *mut JNIEnv,
        array: JIntArray,
        start: jint,
        len: jint,
        buf: *const jint,
    ),
}

/// The function table behind an environment handle.
///
/// # Safety
///
/// `env` must be a live JNI environment pointer.
unsafe fn table<'a>(env: *mut JNIEnv) -> &'a JniTable {
    // `env` points at the function-table pointer (C-mode `JNIEnv*`):
    // deref twice to reach the table itself.
    unsafe { &**env }
}

/// Copies a Java `byte[]` through the environment into an owned
/// buffer.
///
/// # Safety
///
/// `env` must be a live JNI environment and `array` a live `byte[]`
/// reference for the duration of the call; a null array is
/// [`PITH_E_INVALID`], mirroring the C ABI's null-pointer rule.
unsafe fn java_bytes(env: *mut JNIEnv, array: JArray) -> Result<Vec<u8>, i32> {
    if array.is_null() {
        return Err(PITH_E_INVALID);
    }
    let functions = unsafe { table(env) };
    let len = unsafe { (functions.get_array_length)(env, array) };
    if len < 0 {
        return Err(PITH_E_INVALID);
    }
    let mut bytes = vec![0u8; len as usize];
    unsafe { (functions.get_byte_array_region)(env, array, 0, len, bytes.as_mut_ptr().cast()) };
    Ok(bytes)
}

/// Copies a Java `long[]` through the environment into an owned
/// buffer of `u64` words (the bit patterns pass through untouched).
///
/// # Safety
///
/// `env` must be a live JNI environment and `array` a live `long[]`
/// reference for the duration of the call; a null array is
/// [`PITH_E_INVALID`] (the empty-slice operand is the empty array).
unsafe fn java_words(env: *mut JNIEnv, array: JArray) -> Result<Vec<u64>, i32> {
    if array.is_null() {
        return Err(PITH_E_INVALID);
    }
    let functions = unsafe { table(env) };
    let len = unsafe { (functions.get_array_length)(env, array) };
    if len < 0 {
        return Err(PITH_E_INVALID);
    }
    let mut words: Vec<u64> = vec![0; len as usize];
    unsafe {
        (functions.get_long_array_region)(env, array, 0, len, words.as_mut_ptr().cast::<jlong>())
    };
    Ok(words)
}

/// Builds a fresh Java `byte[]` holding `bytes`, or `None` if the
/// environment refuses the allocation.
///
/// # Safety
///
/// `env` must be a live JNI environment.
unsafe fn new_java_bytes(env: *mut JNIEnv, bytes: &[u8]) -> Option<JArray> {
    let functions = unsafe { table(env) };
    let array = unsafe { (functions.new_byte_array)(env, bytes.len() as jint) };
    if array.is_null() {
        return None;
    }
    unsafe {
        (functions.set_byte_array_region)(env, array, 0, bytes.len() as jint, bytes.as_ptr().cast())
    };
    Some(array)
}

/// Writes `value` into the one-element `int[]` status slot.
///
/// # Safety
///
/// `status` must be a live `int[]` of length ≥ 1 (checked by the
/// caller).
unsafe fn set_status(env: *mut JNIEnv, status: JIntArray, value: jint) {
    let functions = unsafe { table(env) };
    unsafe { (functions.set_int_array_region)(env, status, 0, 1, &value) };
}

/// The Java binding of [`pith_text_fingerprint`]: the canonical
/// fingerprint stream of a UTF-8 string.
///
/// `data` is the UTF-8 **bytes** of the input (a byte length, so
/// multi-ordinal inputs pass whole); on success the export returns the
/// stream the `reference.json` vectors are defined over — `[0..4)`
/// `word_count` u32 big-endian, `[4..8)` `shingle_count` u32
/// big-endian, `[8..8+C)` the canonical UTF-8 bytes, then 128 u64
/// little-endian signature words — and `PITH_OK` through `status[0]`.
/// Invalid UTF-8 is `PITH_E_REJECTED`; the empty input is valid (the
/// canon-empty sentinel), not a refusal.
///
/// # Safety
///
/// `env` must be a live JNI environment and `data`/`status` live Java
/// array references for the duration of the call.
//
// Private: the JVM links the export by symbol name; a public Rust
// signature over the private table type would trip
// `private_interfaces`.
#[unsafe(no_mangle)]
unsafe extern "system" fn Java_hash_pith_text_PithText_fingerprintNative(
    env: *mut JNIEnv,
    _class: JClass,
    data: JArray,
    status: JIntArray,
) -> JArray {
    if env.is_null() || status.is_null() {
        return core::ptr::null_mut();
    }
    let bytes = match unsafe { java_bytes(env, data) } {
        Ok(bytes) => bytes,
        Err(status_code) => {
            unsafe { set_status(env, status, status_code) };
            return core::ptr::null_mut();
        }
    };
    // The C export hands out an owned exact-length buffer; copy it into
    // the Java array and release it before returning.
    let mut stream_ptr: *mut u8 = core::ptr::null_mut();
    let mut stream_len: usize = 0;
    let code = unsafe {
        pith_text_fingerprint(
            bytes.as_ptr(),
            bytes.len(),
            &mut stream_ptr,
            &mut stream_len,
        )
    };
    if code != PITH_OK {
        unsafe { set_status(env, status, code) };
        return core::ptr::null_mut();
    }
    let stream = unsafe { core::slice::from_raw_parts(stream_ptr, stream_len) };
    let array = match unsafe { new_java_bytes(env, stream) } {
        Some(array) => array,
        None => {
            unsafe { pith_text_free(stream_ptr, stream_len) };
            // The only failure left is the environment refusing the
            // array allocation; there is no dedicated code for it, so
            // it surfaces as a rejection, never as a panic.
            unsafe { set_status(env, status, PITH_E_REJECTED) };
            return core::ptr::null_mut();
        }
    };
    unsafe { pith_text_free(stream_ptr, stream_len) };
    unsafe { set_status(env, status, PITH_OK) };
    array
}

/// The Java binding of [`pith_text_jaccard`]: the Jaccard index of two
/// shingle sets over their signature words.
///
/// `a` and `b` are Java `long[]` signature words (the little-endian
/// tails of fingerprint streams; the empty array is the legal sentinel
/// operand and scores `1.0` against anything). The estimate crosses
/// back as its `f64` bit pattern in the `jdouble` return — the exact
/// form `value_bits` pins — and the status through `status[0]`.
///
/// # Safety
///
/// `env` must be a live JNI environment and `a`/`b`/`status` live Java
/// array references for the duration of the call.
//
// Private: the JVM links the export by symbol name; a public Rust
// signature over the private table type would trip
// `private_interfaces`.
#[unsafe(no_mangle)]
unsafe extern "system" fn Java_hash_pith_text_PithText_jaccardNative(
    env: *mut JNIEnv,
    _class: JClass,
    a: JArray,
    b: JArray,
    status: JIntArray,
) -> jdouble {
    if env.is_null() || status.is_null() {
        return 0.0;
    }
    let a_words = match unsafe { java_words(env, a) } {
        Ok(words) => words,
        Err(status_code) => {
            unsafe { set_status(env, status, status_code) };
            return 0.0;
        }
    };
    let b_words = match unsafe { java_words(env, b) } {
        Ok(words) => words,
        Err(status_code) => {
            unsafe { set_status(env, status, status_code) };
            return 0.0;
        }
    };
    let mut bits: u64 = 0;
    let code = unsafe {
        pith_text_jaccard(
            a_words.as_ptr(),
            a_words.len(),
            b_words.as_ptr(),
            b_words.len(),
            &mut bits,
        )
    };
    unsafe { set_status(env, status, code) };
    if code == PITH_OK {
        f64::from_bits(bits)
    } else {
        0.0
    }
}
