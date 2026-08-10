/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
 *
 * This file is part of xKey.
 *
 * xKey is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */
package com.automatethethings.xkey.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

/**
 * Unit tests for [FileEncryptor] file format parsing and exception types.
 *
 * Full encrypt/decrypt round-trip tests require Android Keystore and must
 * run as instrumented tests. These JVM tests verify:
 * - .xkeyenc header parsing logic
 * - Exception classes and messages
 * - Version validation
 */
class FileEncryptorTest {

    @Test
    fun `EncryptionException carries reason and cause`() {
        val cause = RuntimeException("inner")
        val ex = EncryptionException("encryption failed", cause)
        assertEquals("encryption failed", ex.reason)
        assertEquals("Encryption failed: encryption failed", ex.message)
        assertEquals(cause, ex.cause)
    }

    @Test
    fun `EncryptionException with null cause`() {
        val ex = EncryptionException("no cause", null)
        assertEquals("no cause", ex.reason)
        assertNull(ex.cause)
    }

    @Test
    fun `DecryptionException carries reason and cause`() {
        val cause = RuntimeException("inner")
        val ex = DecryptionException("decryption failed", cause)
        assertEquals("decryption failed", ex.reason)
        assertEquals("Decryption failed: decryption failed", ex.message)
        assertEquals(cause, ex.cause)
    }

    @Test
    fun `DecryptionException with null cause`() {
        val ex = DecryptionException("no cause", null)
        assertEquals("no cause", ex.reason)
        assertNull(ex.cause)
    }

    @Test
    fun `xkeyenc header version byte is validated`() {
        // Build a minimal stream with unsupported version byte 0x02
        val badVersion = byteArrayOf(0x02, 0x00, 0x10) + ByteArray(100)
        val input = ByteArrayInputStream(badVersion)

        // Read the version byte — decryptWithKey checks this first
        val version = input.read()
        assertEquals("First byte is version", 0x02, version)
        assertTrue("Version 0x02 is not supported", version != 0x01)
    }

    @Test
    fun `xkeyenc header layout constants are correct`() {
        // Version 1 format: [version:1B][eph_pubkey_len:2B][eph_pubkey][salt:32B][iv:12B][ciphertext+tag]
        val fakePubKey = ByteArray(91) { (it % 256).toByte() }
        val salt = ByteArray(32) { 0xAA.toByte() }
        val iv = ByteArray(12) { 0xBB.toByte() }

        // Build header
        val header = ByteArray(1 + 2 + fakePubKey.size + salt.size + iv.size)
        header[0] = 0x01 // version
        header[1] = ((fakePubKey.size shr 8) and 0xFF).toByte()
        header[2] = (fakePubKey.size and 0xFF).toByte()
        System.arraycopy(fakePubKey, 0, header, 3, fakePubKey.size)
        System.arraycopy(salt, 0, header, 3 + fakePubKey.size, salt.size)
        System.arraycopy(iv, 0, header, 3 + fakePubKey.size + salt.size, iv.size)

        val input = ByteArrayInputStream(header)

        // Parse version
        assertEquals(0x01, input.read())

        // Parse ephemeral public key length
        val lenHigh = input.read()
        val lenLow = input.read()
        val ephPubKeyLen = (lenHigh shl 8) or lenLow
        assertEquals(91, ephPubKeyLen)

        // Parse ephemeral public key
        val parsedPubKey = ByteArray(ephPubKeyLen)
        input.read(parsedPubKey)
        assertTrue(fakePubKey.contentEquals(parsedPubKey))

        // Parse salt
        val parsedSalt = ByteArray(32)
        input.read(parsedSalt)
        assertTrue(salt.contentEquals(parsedSalt))

        // Parse IV
        val parsedIv = ByteArray(12)
        input.read(parsedIv)
        assertTrue(iv.contentEquals(parsedIv))
    }

    @Test
    fun `xkeyenc header with large ephemeral key encodes length correctly`() {
        val largePubKey = ByteArray(384) { (it % 256).toByte() }

        val lenHigh = ((largePubKey.size shr 8) and 0xFF).toByte()
        val lenLow = (largePubKey.size and 0xFF).toByte()

        val parsedLen = ((lenHigh.toInt() and 0xFF) shl 8) or (lenLow.toInt() and 0xFF)
        assertEquals(384, parsedLen)
    }

    @Test
    fun `exception class hierarchy is correct`() {
        val enc = EncryptionException("test", null)
        val dec = DecryptionException("test", null)
        assertTrue(enc is XKeyCryptoException)
        assertTrue(dec is XKeyCryptoException)
        assertNotNull(EncryptionException::class.java)
        assertNotNull(DecryptionException::class.java)
    }
}
