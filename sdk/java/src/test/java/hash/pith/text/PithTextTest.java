// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash
package hash.pith.text;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Hex-exact conformance: the committed reference vectors, replayed
 * through the Java JNI surface of the pith-text cdylib.
 */
class PithTextTest {
    private static final Path REPO_ROOT = findRepoRoot();
    private static final Map<String, JsonNode> VECTORS = new LinkedHashMap<>();

    static {
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(REPO_ROOT.resolve("reference.json").toFile());
            for (JsonNode v : root.get("vectors")) {
                VECTORS.put(v.get("name").asText(), v);
            }
        } catch (Exception e) {
            throw new IllegalStateException("reference.json", e);
        }
        assertTrue(Files.isRegularFile(PithText.cdylibPath().isEmpty() ? null : Paths.get(PithText.cdylibPath())),
            "cdylib should be discoverable");
    }

    /** Every canonicalisation + fixture + full-signature vector. */
    @org.junit.jupiter.api.Test
    void every_reference_vector_is_reproduced_hex_exact() throws Exception {
        int checked = 0;
        for (Map.Entry<String, JsonNode> e : VECTORS.entrySet()) {
            JsonNode v = e.getValue();
            if (!v.has("input_kind")) {
                continue;
            }
            byte[] input = inputBytes(v);
            PithText.Fingerprint fp = new PithText.Fingerprint(PithText.fingerprint(input));
            if (v.has("word_count")) {
                assertEquals(v.get("word_count").asInt(), fp.wordCount, e.getKey() + " word_count");
                assertEquals(v.get("shingle_count").asInt(), fp.shingleCount, e.getKey() + " shingle_count");
                assertEquals(v.get("canonical_sha256").asText(), sha256(fp.canonical), e.getKey() + " sha256");
                assertEquals(v.get("canonical_fnv1a64").asText(), hex64(fnv1a64(fp.canonical)), e.getKey() + " fnv1a64");
            }
            if (v.has("signature_word_0")) {
                assertEquals(v.get("signature_word_0").asText(), hex64(fp.signature[0]), e.getKey() + " word_0");
                assertEquals(v.get("signature_word_1").asText(), hex64(fp.signature[1]), e.getKey() + " word_1");
                assertEquals(v.get("signature_fnv1a64").asText(),
                    hex64(fnv1a64(tailBytes(fp))), e.getKey() + " signature_fnv1a64");
                assertEquals(v.get("signature_sha256").asText(), sha256(tailBytes(fp)), e.getKey() + " signature_sha256");
            }
            if (v.has("signature_words_hex")) {
                JsonNode words = v.get("signature_words_hex");
                assertEquals(PithText.SIGNATURE_WORDS, words.size(), e.getKey() + " word count");
                for (int i = 0; i < PithText.SIGNATURE_WORDS; i++) {
                    assertEquals(words.get(i).asText(), hex64(fp.signature[i]), e.getKey() + " word[" + i + "]");
                }
            }
            checked++;
        }
        assertEquals(17, checked, "fingerprint vectors checked");
    }

    /** Every Jaccard vector: operands through the Java surface. */
    @org.junit.jupiter.api.Test
    void every_jaccard_vector_is_reproduced_hex_exact() throws Exception {
        int checked = 0;
        for (Map.Entry<String, JsonNode> e : VECTORS.entrySet()) {
            JsonNode v = e.getValue();
            if (!v.has("value_bits")) {
                continue;
            }
            long[] a = operandSignature(v.get("a").asText());
            long[] b = operandSignature(v.get("b").asText());
            assertEquals(v.get("value_bits").asText(), hex64(PithText.jaccardBits(a, b)), e.getKey());
            checked++;
        }
        assertEquals(5, checked, "jaccard vectors checked");
    }

    /** One rust-derived literal pin, byte-independent of reference.json. */
    @org.junit.jupiter.api.Test
    void alpha_beta_gamma_matches_a_rust_pinned_value() throws Exception {
        PithText.Fingerprint fp = new PithText.Fingerprint(
            PithText.fingerprint("alpha beta gamma".getBytes(StandardCharsets.UTF_8)));
        assertEquals(3, fp.wordCount);
        assertEquals(1, fp.shingleCount);
        assertEquals("5409aadb22bb8479", hex64(fp.signature[0]));
        assertEquals("b2e6ff4edebf53c6", hex64(fp.signature[1]));
        assertEquals("46f8ab1a50c61813", hex64(fnv1a64(tailBytes(fp))));
        assertEquals("5a3e4c4a48d55a405faced9c28d4bf12b78af5661102eb2ac3dcab843485d8df",
            sha256(tailBytes(fp)));
    }

    /** The empty input is valid: the sentinel signature over "\n". */
    @org.junit.jupiter.api.Test
    void empty_input_is_the_sentinel_signature() throws Exception {
        PithText.Fingerprint fp = new PithText.Fingerprint(PithText.fingerprint(new byte[0]));
        assertEquals(0, fp.wordCount);
        assertEquals(0, fp.shingleCount);
        assertEquals("\n", new String(fp.canonical, StandardCharsets.UTF_8));
        for (int i = 0; i < PithText.SIGNATURE_WORDS; i++) {
            assertEquals("ffffffffffffffff", hex64(fp.signature[i]), "word[" + i + "]");
        }
        assertEquals("89bfa3a928539725", hex64(fnv1a64(tailBytes(fp))));
        assertEquals("5f4ecdb7b71c3e403983fe405cddcdc2f2576b655fdb3e80d94a6f7c32e58bc2",
            sha256(tailBytes(fp)));
    }

    /** Invalid UTF-8 is refused (status -2), not crashing. */
    @org.junit.jupiter.api.Test
    void non_utf8_input_is_refused() {
        PithText.FfiError err = assertThrows(PithText.FfiError.class,
            () -> PithText.fingerprint(new byte[] {'o', 'n', 'e', ' ', (byte) 0xFF}));
        assertEquals(-2, err.status);
        assertEquals("pith_text_fingerprint", err.op);
    }

    /** The cdylib resolves without environment hints. */
    @org.junit.jupiter.api.Test
    void cdylib_is_discoverable() {
        assertTrue(Paths.get(PithText.cdylibPath()).isAbsolute());
    }

    private static byte[] inputBytes(JsonNode v) throws Exception {
        String kind = v.get("input_kind").asText();
        if ("inline-hex".equals(kind)) {
            return hex(v.get("input_hex").asText());
        }
        return Files.readAllBytes(REPO_ROOT.resolve(v.get("input_path").asText()));
    }

    private static long[] operandSignature(String operand) throws Exception {
        if ("empty-signature".equals(operand)) {
            return new long[0];
        }
        if (operand.startsWith("fixture:")) {
            byte[] bytes = Files.readAllBytes(REPO_ROOT.resolve(operand.substring("fixture:".length())));
            return new PithText.Fingerprint(PithText.fingerprint(bytes)).signature;
        }
        throw new IllegalArgumentException("operand " + operand);
    }

    private static byte[] tailBytes(PithText.Fingerprint fp) {
        int len = PithText.SIGNATURE_WORDS * 8;
        byte[] out = new byte[len];
        for (int i = 0; i < PithText.SIGNATURE_WORDS; i++) {
            for (int b = 0; b < 8; b++) {
                out[i * 8 + b] = (byte) (fp.signature[i] >>> (8 * b));
            }
        }
        return out;
    }

    private static long fnv1a64(byte[] data) {
        long hash = 0xcbf29ce484222325L;
        for (byte b : data) {
            hash = (hash ^ (b & 0xffL)) * 0x100000001b3L;
        }
        return hash;
    }

    private static String sha256(byte[] data) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(data));
    }

    private static String hex64(long value) {
        return String.format("%016x", value);
    }

    private static String hex(byte[] data) {
        StringBuilder out = new StringBuilder(data.length * 2);
        for (byte b : data) {
            out.append(String.format("%02x", b));
        }
        return out.toString();
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static Path findRepoRoot() {
        Path dir = Paths.get("").toAbsolutePath();
        for (int up = 0; up <= 6 && dir != null; up++) {
            if (Files.isRegularFile(dir.resolve("reference.json"))) {
                return dir;
            }
            dir = dir.getParent();
        }
        throw new IllegalStateException("repo root with reference.json not found");
    }
}
