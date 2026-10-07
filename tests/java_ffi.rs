//! Fake-JNI-environment coverage for the glue in `src/ffi_jni.rs`.
//!
//! `src/ffi_jni.rs` is compiled out of the unit-test build (the
//! `#[no_mangle]` exports would collide with the unit-test binary), so
//! this integration test drives every export through an `unsafe extern`
//! declaration against a synthetic environment: a zeroed function
//! table whose slots the glue calls carry test-local implementations
//! backed by a registry of fake Java arrays. The real-JVM proof is the
//! Java suite (`sdk/java`, `mvn test` against the built cdylib); this
//! file keeps the glue executed and visible to the coverage gate with
//! zero new dependencies (the suite's `check-zero-deps.py` gate forbids
//! registry crates, so the plain `std` mutexes stay unwrapped here).

#![allow(unsafe_code)]
// The JNI typedefs keep the jni.h spelling.
#![allow(non_camel_case_types)]

use core::ffi::c_void;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use pith_text::ffi::{
    PITH_E_INVALID, PITH_E_REJECTED, PITH_OK, pith_text_fingerprint, pith_text_free,
};
use pith_text::{SIGNATURE_WORDS, jaccard_estimate};

type JNIEnv = *const FakeTable;
type JArray = *mut c_void;
type JIntArray = *mut c_void;
type JClass = *mut c_void;
type jbyte = i8;
type jint = i32;
type jlong = i64;
type jdouble = f64;

/// Mirror of `src/ffi_jni.rs`'s function table — the same slot
/// positions (171, 176, 200, 204, 208, 211; four reserved pointers in
/// the prefix).
#[repr(C)]
struct FakeTable {
    /// Slots 0..=170.
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

// The exported symbols under test (linked from the crate's rlib).
unsafe extern "system" {
    fn Java_hash_pith_text_PithText_fingerprintNative(
        env: *mut JNIEnv,
        class: JClass,
        data: JArray,
        status: JIntArray,
    ) -> JArray;

    fn Java_hash_pith_text_PithText_jaccardNative(
        env: *mut JNIEnv,
        class: JClass,
        a: JArray,
        b: JArray,
        status: JIntArray,
    ) -> jdouble;
}

/// A fake Java array's content.
#[derive(Clone)]
enum Content {
    Bytes(Vec<u8>),
    Longs(Vec<i64>),
}

impl Content {
    fn len(&self) -> jint {
        match self {
            Content::Bytes(bytes) => bytes.len() as jint,
            Content::Longs(words) => words.len() as jint,
        }
    }
}

/// The state of one native call under test.
struct FakeCall {
    arrays: HashMap<usize, Content>,
    next_handle: usize,
    out_bytes: Vec<u8>,
    out_ints: Vec<i32>,
    fail_new_byte_array: bool,
}

static CALL: LazyLock<Mutex<Option<FakeCall>>> = LazyLock::new(|| Mutex::new(None));
static SERIAL: Mutex<()> = Mutex::new(());

fn with_state<T>(f: impl FnOnce(&mut FakeCall) -> T) -> T {
    let mut guard = CALL.lock().unwrap();
    let state = guard.as_mut().expect("no fake call state installed");
    f(state)
}

/// Registers a fake `byte[]`; returns its opaque handle.
fn byte_array(bytes: Vec<u8>) -> JArray {
    with_state(|state| {
        state.next_handle += 8;
        let handle = state.next_handle;
        state.arrays.insert(handle, Content::Bytes(bytes));
        handle as JArray
    })
}

/// Registers a fake `long[]`; returns its opaque handle.
fn long_array(words: Vec<i64>) -> JArray {
    with_state(|state| {
        state.next_handle += 8;
        let handle = state.next_handle;
        state.arrays.insert(handle, Content::Longs(words));
        handle as JArray
    })
}

/// `GetArrayLength` (slot 171).
unsafe extern "system" fn fake_get_array_length(_env: *mut JNIEnv, array: JArray) -> jint {
    with_state(|state| state.arrays.get(&(array as usize)).map_or(-1, Content::len))
}

/// `NewByteArray` (slot 176).
unsafe extern "system" fn fake_new_byte_array(_env: *mut JNIEnv, len: jint) -> JArray {
    let fresh = with_state(|state| {
        if state.fail_new_byte_array {
            return None;
        }
        state.next_handle += 8;
        let handle = state.next_handle;
        state
            .arrays
            .insert(handle, Content::Bytes(vec![0; len as usize]));
        Some(handle as JArray)
    });
    fresh.unwrap_or_else(std::ptr::null_mut)
}

/// `GetByteArrayRegion` (slot 200).
unsafe extern "system" fn fake_get_byte_array_region(
    _env: *mut JNIEnv,
    array: JArray,
    start: jint,
    len: jint,
    buf: *mut jbyte,
) {
    let bytes = with_state(|state| match state.arrays.get(&(array as usize)) {
        Some(Content::Bytes(bytes)) => {
            bytes[start as usize..start as usize + len as usize].to_vec()
        }
        _ => panic!("not a byte array"),
    });
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast(), bytes.len()) };
}

/// `GetLongArrayRegion` (slot 204).
unsafe extern "system" fn fake_get_long_array_region(
    _env: *mut JNIEnv,
    array: JArray,
    start: jint,
    len: jint,
    buf: *mut jlong,
) {
    let words = with_state(|state| match state.arrays.get(&(array as usize)) {
        Some(Content::Longs(words)) => {
            words[start as usize..start as usize + len as usize].to_vec()
        }
        _ => panic!("not a long array"),
    });
    unsafe { std::ptr::copy_nonoverlapping(words.as_ptr(), buf, words.len()) };
}

/// `SetByteArrayRegion` (slot 208): copies into the target array —
/// faithful to the JVM — and records the written bytes.
unsafe extern "system" fn fake_set_byte_array_region(
    _env: *mut JNIEnv,
    array: JArray,
    start: jint,
    len: jint,
    buf: *const jbyte,
) {
    let written = unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), len as usize) }.to_vec();
    with_state(|state| match state.arrays.get_mut(&(array as usize)) {
        Some(Content::Bytes(bytes)) => {
            bytes[start as usize..start as usize + len as usize].copy_from_slice(&written);
            state.out_bytes.extend_from_slice(&written);
        }
        _ => panic!("not a byte array"),
    });
}

/// `SetIntArrayRegion` (slot 211): copies into the target array —
/// faithful to the JVM — and records the written values.
unsafe extern "system" fn fake_set_int_array_region(
    _env: *mut JNIEnv,
    array: JIntArray,
    _start: jint,
    len: jint,
    buf: *const jint,
) {
    unsafe { std::ptr::copy_nonoverlapping(buf, array as *mut jint, len as usize) };
    let mut guard = CALL.lock().unwrap();
    let state = guard.as_mut().expect("no fake call state installed");
    for i in 0..len as usize {
        state.out_ints.push(unsafe { *buf.add(i) });
    }
}

/// A zero-initialized `FakeTable`, leaked.
///
/// Raw `alloc_zeroed` bytes rather than `mem::zeroed`: the latter
/// runtime-refuses zeroed fn-pointer fields, while the former is just
/// memory — every slot the glue calls is assigned below before use.
fn zeroed_table() -> *mut FakeTable {
    let raw = unsafe { std::alloc::alloc_zeroed(std::alloc::Layout::new::<FakeTable>()) };
    assert!(!raw.is_null(), "alloc_zeroed failed");
    raw.cast::<FakeTable>()
}

/// Runs `f` against a synthetic environment; returns its result, the
/// bytes the glue wrote into Java arrays, and the int slots it wrote.
fn with_fake_env<T>(f: impl FnOnce(*mut JNIEnv) -> T) -> (T, Vec<u8>, Vec<i32>) {
    let _serial = SERIAL.lock().unwrap();
    *CALL.lock().unwrap() = Some(FakeCall {
        arrays: HashMap::new(),
        next_handle: 0,
        out_bytes: Vec::new(),
        out_ints: Vec::new(),
        fail_new_byte_array: false,
    });

    let table = zeroed_table();
    unsafe {
        (*table).get_array_length = fake_get_array_length;
        (*table).new_byte_array = fake_new_byte_array;
        (*table).get_byte_array_region = fake_get_byte_array_region;
        (*table).get_long_array_region = fake_get_long_array_region;
        (*table).set_byte_array_region = fake_set_byte_array_region;
        (*table).set_int_array_region = fake_set_int_array_region;
    }
    let functions: *const FakeTable = table;
    let env: *mut JNIEnv = Box::into_raw(Box::new(functions));

    let result = f(env);
    let state = CALL.lock().unwrap().take().expect("fake call state");
    (result, state.out_bytes, state.out_ints)
}

/// A live one-element status array; read it back with [`read_status`].
fn status_slot() -> JIntArray {
    Box::into_raw(Box::new([i32::MIN; 1])) as JIntArray
}

/// Reads the slot's content and releases it.
fn read_status(slot: JIntArray) -> i32 {
    let value = unsafe { *(slot as *mut jint) };
    unsafe { drop(Box::from_raw(slot as *mut jint)) };
    value
}

/// The canonical stream the C export produces for `data`.
fn c_stream(data: &[u8]) -> Vec<u8> {
    let mut stream_ptr: *mut u8 = std::ptr::null_mut();
    let mut stream_len: usize = 0;
    let code = unsafe {
        pith_text_fingerprint(data.as_ptr(), data.len(), &mut stream_ptr, &mut stream_len)
    };
    assert_eq!(code, PITH_OK);
    let stream = unsafe { std::slice::from_raw_parts(stream_ptr, stream_len) }.to_vec();
    unsafe { pith_text_free(stream_ptr, stream_len) };
    stream
}

#[test]
fn jni_fingerprint_matches_the_c_export() {
    let input = b"alpha beta gamma";
    let expected = c_stream(input);
    let ((stream, status), produced, _recorded) = with_fake_env(|env| unsafe {
        let data = byte_array(input.to_vec());
        let slot = status_slot();
        let stream =
            Java_hash_pith_text_PithText_fingerprintNative(env, std::ptr::null_mut(), data, slot);
        (stream, read_status(slot))
    });
    assert_eq!(status, PITH_OK, "status");
    assert!(!stream.is_null(), "stream array");
    assert_eq!(produced, expected, "stream bytes");
}

#[test]
fn jni_fingerprint_empty_input_is_the_sentinel() {
    let ((stream, status), produced, _recorded) = with_fake_env(|env| unsafe {
        let data = byte_array(Vec::new());
        let slot = status_slot();
        (
            Java_hash_pith_text_PithText_fingerprintNative(env, std::ptr::null_mut(), data, slot),
            read_status(slot),
        )
    });
    assert_eq!(status, PITH_OK, "status");
    assert!(!stream.is_null(), "stream array");
    assert_eq!(produced.len(), 8 + 1 + SIGNATURE_WORDS * 8);
    assert_eq!(produced[8], b'\n', "canonical empty");
    // word 0 little-endian = u64::MAX = all-ff bytes.
    assert!(produced[9..17].iter().all(|&b| b == 0xff), "sentinel word");
}

#[test]
fn jni_fingerprint_non_utf8_is_rejected() {
    let ((stream, status), _produced, _recorded) = with_fake_env(|env| unsafe {
        let data = byte_array(b"one \xff two".to_vec());
        let slot = status_slot();
        let stream =
            Java_hash_pith_text_PithText_fingerprintNative(env, std::ptr::null_mut(), data, slot);
        (stream, read_status(slot))
    });
    assert_eq!(status, PITH_E_REJECTED, "status");
    assert!(stream.is_null(), "no stream on refusal");
}

#[test]
fn jni_fingerprint_null_data_is_invalid() {
    let ((stream, status), _produced, _recorded) = with_fake_env(|env| unsafe {
        let slot = status_slot();
        let stream = Java_hash_pith_text_PithText_fingerprintNative(
            env,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            slot,
        );
        (stream, read_status(slot))
    });
    assert_eq!(status, PITH_E_INVALID, "status");
    assert!(stream.is_null());
}

#[test]
fn jni_fingerprint_environment_refusing_the_array_is_rejected() {
    let ((stream, status), _produced, _recorded) = with_fake_env(|env| unsafe {
        let data = byte_array(b"alpha beta gamma".to_vec());
        let slot = status_slot();
        with_state(|state| state.fail_new_byte_array = true);
        let stream =
            Java_hash_pith_text_PithText_fingerprintNative(env, std::ptr::null_mut(), data, slot);
        (stream, read_status(slot))
    });
    assert_eq!(status, PITH_E_REJECTED, "status");
    assert!(stream.is_null());
}

#[test]
fn jni_fingerprint_null_status_short_circuits() {
    let (stream, _produced, _recorded) = with_fake_env(|env| unsafe {
        let data = byte_array(b"alpha beta gamma".to_vec());
        Java_hash_pith_text_PithText_fingerprintNative(
            env,
            std::ptr::null_mut(),
            data,
            std::ptr::null_mut(),
        )
    });
    assert!(stream.is_null());
}

#[test]
fn jni_jaccard_matches_the_safe_core() {
    let a: Vec<i64> = (0..64)
        .map(|i| (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) as i64)
        .collect();
    let b: Vec<i64> = (8..72)
        .map(|i| (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) as i64)
        .collect();
    let expected = jaccard_estimate(
        &a.iter().map(|&w| w as u64).collect::<Vec<_>>(),
        &b.iter().map(|&w| w as u64).collect::<Vec<_>>(),
    );
    let ((value, status), _produced, _recorded) = with_fake_env(|env| unsafe {
        let arr_a = long_array(a);
        let arr_b = long_array(b);
        let slot = status_slot();
        let value = Java_hash_pith_text_PithText_jaccardNative(
            env,
            std::ptr::null_mut(),
            arr_a,
            arr_b,
            slot,
        );
        (value, read_status(slot))
    });
    assert_eq!(status, PITH_OK, "status");
    assert_eq!(value.to_bits(), expected.to_bits(), "estimate bits");
}

#[test]
fn jni_jaccard_empty_operand_scores_one() {
    let ((value, status), _produced, _recorded) = with_fake_env(|env| unsafe {
        let arr_a = long_array(vec![1, 2, 3]);
        let arr_b = long_array(Vec::new());
        let slot = status_slot();
        let value = Java_hash_pith_text_PithText_jaccardNative(
            env,
            std::ptr::null_mut(),
            arr_a,
            arr_b,
            slot,
        );
        (value, read_status(slot))
    });
    assert_eq!(status, PITH_OK, "status");
    assert_eq!(value.to_bits(), 0x3ff0_0000_0000_0000, "1.0 bits");
}

#[test]
fn jni_jaccard_null_operand_is_invalid() {
    let ((value, status), _produced, _recorded) = with_fake_env(|env| unsafe {
        let arr_b = long_array(vec![1, 2, 3]);
        let slot = status_slot();
        let value = Java_hash_pith_text_PithText_jaccardNative(
            env,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            arr_b,
            slot,
        );
        (value, read_status(slot))
    });
    assert_eq!(status, PITH_E_INVALID, "status");
    assert_eq!(value, 0.0);
}

#[test]
fn jni_jaccard_null_status_short_circuits() {
    let (value, _produced, _recorded) = with_fake_env(|env| unsafe {
        let arr_a = long_array(vec![1]);
        let arr_b = long_array(vec![1]);
        Java_hash_pith_text_PithText_jaccardNative(
            env,
            std::ptr::null_mut(),
            arr_a,
            arr_b,
            std::ptr::null_mut(),
        )
    });
    assert_eq!(value, 0.0);
}

#[test]
fn jni_null_environment_short_circuits() {
    let ((stream, value), _produced, _recorded) = with_fake_env(|_env| unsafe {
        let slot = status_slot();
        let data = byte_array(b"alpha beta gamma".to_vec());
        let stream = Java_hash_pith_text_PithText_fingerprintNative(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            data,
            slot,
        );
        let arr_a = long_array(vec![1]);
        let value = Java_hash_pith_text_PithText_jaccardNative(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            arr_a,
            arr_a,
            slot,
        );
        (stream, value)
    });
    assert!(stream.is_null());
    assert_eq!(value, 0.0);
}
