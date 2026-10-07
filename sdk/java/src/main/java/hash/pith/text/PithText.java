// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash
package hash.pith.text;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * Java JNI bindings for the {@code pith-text} cdylib: text
 * fingerprinting and Jaccard similarity over the same wire formats as
 * the C ABI ({@code pith_text_fingerprint}, {@code pith_text_jaccard}).
 *
 * <p>The pipeline is canonicalisation (NFC, lowercase, trailing
 * whitespace collapsed to one {@code \n}) &rarr; UTF-8 word hashing
 * (FNV-1a 64 per word) &rarr; 128-word MinHash. All offsets are in
 * bytes, so multi-ordinal inputs pass through whole.</p>
 *
 * <p>Wire format of a fingerprint stream (the form the
 * {@code reference.json} vectors are defined over):
 * {@code [0..4)} word count, u32 big-endian &middot; {@code [4..8)}
 * shingle count, u32 big-endian &middot; {@code [8..8+C)} the
 * canonical UTF-8 bytes &middot; then 128 u64 signature words,
 * little-endian. An empty input is valid — the sentinel signature
 * {@code 0xffffffffffffffff} &times;128 over the one-byte canonical
 * form {@code "\n"} — not a refusal. Invalid UTF-8 raises
 * {@link FfiError} with status {@code -2}.</p>
 *
 * <p>The cdylib is resolved once at class-load time, mirroring the
 * discovery chain of the other SDKs: {@code PITH_CDYLIB} — the
 * explicit file, or {@code PITH_CDYLIB_DIR} — a directory holding one
 * of the platform library names, or {@code target/release} at or above
 * the working directory.</p>
 */
public final class PithText {
    /** Status: success. */
    public static final int PITH_OK = 0;
    /** Status: the C ABI judged the input invalid. */
    public static final int PITH_E_INVALID = -1;
    /** Status: the core pipeline refused the input. */
    public static final int PITH_E_REJECTED = -2;

    /** MinHash signature width in u64 words. */
    public static final int SIGNATURE_WORDS = 128;

    private static final String[] CDYLIB_NAMES = {"pith_text.dll", "libpith_text.so", "libpith_text.dylib"};
    private static final String CDYLIB_PATH = findCdylib();

    static {
        System.load(CDYLIB_PATH);
    }

    private PithText() { }

    /**
     * The absolute path of the loaded cdylib (tests and diagnostics).
     */
    public static String cdylibPath() {
        return CDYLIB_PATH;
    }

    /**
     * Computes the canonical fingerprint stream of a UTF-8 string.
     *
     * @param data the UTF-8 bytes (an empty array is the valid
     *             canon-empty input, never a refusal)
     * @return the stream: two u32 big-endian counts, the canonical
     *         bytes, 128 u64 little-endian signature words
     * @throws FfiError on a native refusal (invalid UTF-8)
     */
    public static byte[] fingerprint(byte[] data) {
        int[] status = new int[1];
        byte[] stream = fingerprintNative(data, status);
        if (status[0] != PITH_OK) {
            throw new FfiError("pith_text_fingerprint", status[0]);
        }
        return stream;
    }

    /**
     * The Jaccard index of two shingle sets over their signature
     * words, as the raw {@code f64} bit pattern. The empty array is
     * the legal sentinel operand (scores {@code 1.0} against
     * anything), not a refusal.
     */
    public static long jaccardBits(long[] a, long[] b) {
        int[] status = new int[1];
        double value = jaccardNative(a, b, status);
        if (status[0] != PITH_OK) {
            throw new FfiError("pith_text_jaccard", status[0]);
        }
        return Double.doubleToRawLongBits(value);
    }

    private static native byte[] fingerprintNative(byte[] data, int[] status);

    private static native double jaccardNative(long[] a, long[] b, int[] status);

    /**
     * The fingerprint stream parsed into its parts.
     */
    public static final class Fingerprint {
        /** Number of words in the canonical form. */
        public final int wordCount;
        /** Number of shingles hashed. */
        public final int shingleCount;
        /** The canonical UTF-8 bytes. */
        public final byte[] canonical;
        /** The 128 MinHash words, host order. */
        public final long[] signature;

        Fingerprint(byte[] stream) {
            int canonicalLen = stream.length - 8 - SIGNATURE_WORDS * 8;
            java.nio.ByteBuffer head = java.nio.ByteBuffer.wrap(stream);
            this.wordCount = head.getInt();
            this.shingleCount = head.getInt();
            this.canonical = Arrays.copyOfRange(stream, 8, 8 + canonicalLen);
            java.nio.ByteBuffer tail = java.nio.ByteBuffer
                .wrap(stream, 8 + canonicalLen, SIGNATURE_WORDS * 8)
                .order(java.nio.ByteOrder.LITTLE_ENDIAN);
            this.signature = new long[SIGNATURE_WORDS];
            for (int i = 0; i < SIGNATURE_WORDS; i++) {
                this.signature[i] = tail.getLong();
            }
        }
    }

    /**
     * A native refusal or failure, carrying the C ABI status code.
     */
    public static final class FfiError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        /** The refusing operation (its C ABI name). */
        public final String op;
        /** The C ABI status code ({@code -1} invalid, {@code -2} rejected). */
        public final int status;

        FfiError(String op, int status) {
            super(op + " failed: status " + status);
            this.op = op;
            this.status = status;
        }
    }

    private static String findCdylib() {
        String explicitFile = System.getenv("PITH_CDYLIB");
        if (explicitFile != null && !explicitFile.isEmpty() && Files.isRegularFile(Paths.get(explicitFile))) {
            return Paths.get(explicitFile).toAbsolutePath().toString();
        }
        String explicitDir = System.getenv("PITH_CDYLIB_DIR");
        if (explicitDir != null && !explicitDir.isEmpty()) {
            for (String name : CDYLIB_NAMES) {
                Path candidate = Paths.get(explicitDir).toAbsolutePath().resolve(name);
                if (Files.isRegularFile(candidate)) {
                    return candidate.toString();
                }
            }
        }
        Path cwd = Paths.get("").toAbsolutePath();
        for (int up = 0; up <= 6; up++) {
            Path base = cwd;
            for (int i = 0; i < up; i++) {
                base = base.getParent();
                if (base == null) {
                    break;
                }
            }
            if (base == null) {
                break;
            }
            for (String name : CDYLIB_NAMES) {
                Path candidate = base.resolve(Paths.get("target", "release")).resolve(name);
                if (Files.isRegularFile(candidate)) {
                    return candidate.toString();
                }
            }
        }
        throw new LinkageError(
            "cannot locate the pith-text cdylib; set PITH_CDYLIB or PITH_CDYLIB_DIR"
                + " (probed PITH_CDYLIB, PITH_CDYLIB_DIR, and target/release at "
                + cwd + " and its ancestors)");
    }
}
