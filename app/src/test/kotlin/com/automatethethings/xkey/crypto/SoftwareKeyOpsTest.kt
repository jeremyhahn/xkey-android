// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.

package com.automatethethings.xkey.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.security.SecureRandom

/**
 * Unit tests for [SoftwareKeyOps], the software (non-Keystore) symmetric crypto
 * used for exportable software-backed keys. Uses the JVM JCE provider.
 */
class SoftwareKeyOpsTest {

    private fun randomKey(bytes: Int) = ByteArray(bytes).also { SecureRandom().nextBytes(it) }

    @Test
    fun `aes-gcm round trips`() {
        val key = randomKey(32)
        val plaintext = "hello world".toByteArray()
        val ct = SoftwareKeyOps.aesGcmEncrypt(key, plaintext, null)
        assertArrayEquals(plaintext, SoftwareKeyOps.aesGcmDecrypt(key, ct, null))
    }

    @Test
    fun `aes-gcm round trips with aad`() {
        val key = randomKey(16)
        val plaintext = "data".toByteArray()
        val aad = "context".toByteArray()
        val ct = SoftwareKeyOps.aesGcmEncrypt(key, plaintext, aad)
        assertArrayEquals(plaintext, SoftwareKeyOps.aesGcmDecrypt(key, ct, aad))
    }

    @Test
    fun `aes-gcm ciphertext differs each call due to random iv`() {
        val key = randomKey(32)
        val plaintext = "x".toByteArray()
        assertNotEquals(
            SoftwareKeyOps.aesGcmEncrypt(key, plaintext, null).toList(),
            SoftwareKeyOps.aesGcmEncrypt(key, plaintext, null).toList()
        )
    }

    @Test(expected = Exception::class)
    fun `aes-gcm decrypt fails on wrong aad`() {
        val key = randomKey(32)
        val ct = SoftwareKeyOps.aesGcmEncrypt(key, "d".toByteArray(), "a".toByteArray())
        SoftwareKeyOps.aesGcmDecrypt(key, ct, "b".toByteArray())
    }

    // -----------------------------------------------------------------------
    // RFC 4231 HMAC vectors
    // -----------------------------------------------------------------------

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    @Test
    fun `hmac sha256 matches RFC 4231 test case 1`() {
        assertEquals(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            hex(SoftwareKeyOps.hmac(ByteArray(20) { 0x0b }, "Hi There".toByteArray(), "HMAC-SHA256"))
        )
    }

    @Test
    fun `hmac sha512 matches RFC 4231 test case 1`() {
        assertEquals(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde" +
                "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            hex(SoftwareKeyOps.hmac(ByteArray(20) { 0x0b }, "Hi There".toByteArray(), "HMAC-SHA512"))
        )
    }

    @Test
    fun `hmac selects sha512 only when the algorithm mentions 512`() {
        val key = ByteArray(20) { 0x0b }
        val data = "Hi There".toByteArray()
        // Any spelling containing "512" selects HmacSHA512.
        assertArrayEquals(
            SoftwareKeyOps.hmac(key, data, "HMAC-SHA512"),
            SoftwareKeyOps.hmac(key, data, "HmacSHA512")
        )
        // Everything else — including SHA-384 — falls back to HmacSHA256.
        assertEquals(32, SoftwareKeyOps.hmac(key, data, "HMAC-SHA384").size)
        assertArrayEquals(
            SoftwareKeyOps.hmac(key, data, "HMAC-SHA256"),
            SoftwareKeyOps.hmac(key, data, "HMAC-SHA384")
        )
        assertArrayEquals(
            SoftwareKeyOps.hmac(key, data, "HMAC-SHA256"),
            SoftwareKeyOps.hmac(key, data, "nonsense")
        )
    }

    // -----------------------------------------------------------------------
    // AES-GCM layout and integrity
    // -----------------------------------------------------------------------

    @Test
    fun `aes-gcm output is iv plus ciphertext plus a 16 byte tag`() {
        val plaintext = ByteArray(37) { it.toByte() }
        val out = SoftwareKeyOps.aesGcmEncrypt(randomKey(32), plaintext, null)
        assertEquals(12 + plaintext.size + 16, out.size)
    }

    @Test
    fun `aes-gcm encrypts an empty plaintext to iv plus tag`() {
        val key = randomKey(32)
        val out = SoftwareKeyOps.aesGcmEncrypt(key, ByteArray(0), null)
        assertEquals(28, out.size)
        assertEquals(0, SoftwareKeyOps.aesGcmDecrypt(key, out, null).size)
    }

    @Test
    fun `aes-gcm treats an empty aad as no aad`() {
        val key = randomKey(32)
        val plaintext = "d".toByteArray()
        val out = SoftwareKeyOps.aesGcmEncrypt(key, plaintext, ByteArray(0))
        assertArrayEquals(plaintext, SoftwareKeyOps.aesGcmDecrypt(key, out, null))
    }

    @Test
    fun `aes-gcm decrypt rejects input that cannot hold an iv`() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            SoftwareKeyOps.aesGcmDecrypt(randomKey(32), ByteArray(12), null)
        }
        assertEquals("ciphertext too short", error.message)
    }

    @Test
    fun `aes-gcm decrypt rejects empty input`() {
        assertThrows(IllegalArgumentException::class.java) {
            SoftwareKeyOps.aesGcmDecrypt(randomKey(32), ByteArray(0), null)
        }
    }
}
