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
package com.automatethethings.xkey.piv

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec

/**
 * Unit tests for [PivPublicKeyEncoding]: the PIV tag 0x86 value a YubiKey
 * returns inside TLV 0x7F49, taken from a SubjectPublicKeyInfo.
 */
class PivPublicKeyEncodingTest {

    /** RFC 8032 section 7.1, TEST 1 public key. */
    private val rfc8032Test1Public = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

    /** RFC 7748 section 6.1, Alice's public key. */
    private val rfc7748AlicePublic = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

    @Test
    fun `Ed25519 SPKI yields the raw 32-byte key`() {
        val spki = ed25519SpkiPrefix + rfc8032Test1Public

        assertArrayEquals(rfc8032Test1Public, PivPublicKeyEncoding.pivPublicKeyValue(spki))
    }

    @Test
    fun `X25519 SPKI yields the raw 32-byte key`() {
        val spki = x25519SpkiPrefix + rfc7748AlicePublic

        assertArrayEquals(rfc7748AlicePublic, PivPublicKeyEncoding.pivPublicKeyValue(spki))
    }

    @Test
    fun `the SPKI built from a raw key is the one the JDK encodes`() {
        val jdkEd = KeyFactory.getInstance("Ed25519")
            .generatePublic(X509EncodedKeySpec(ed25519SpkiPrefix + rfc8032Test1Public))
        val jdkX = KeyFactory.getInstance("XDH")
            .generatePublic(X509EncodedKeySpec(x25519SpkiPrefix + rfc7748AlicePublic))

        assertArrayEquals(jdkEd.encoded, PivPublicKeyEncoding.ed25519Spki(rfc8032Test1Public))
        assertArrayEquals(jdkX.encoded, PivPublicKeyEncoding.x25519Spki(rfc7748AlicePublic))
    }

    @Test
    fun `JDK generated curve 25519 keys round trip`() {
        listOf("Ed25519", "X25519").forEach { name ->
            val key = KeyPairGenerator.getInstance(name).generateKeyPair().public
            val raw = PivPublicKeyEncoding.pivPublicKeyValue(key.encoded)
            assertEquals("$name raw key length", 32, raw.size)
        }
    }

    @Test
    fun `EC P-256 SPKI yields the uncompressed point`() {
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair().public as ECPublicKey

        val value = PivPublicKeyEncoding.pivPublicKeyValue(key.encoded)

        assertArrayEquals(byteArrayOf(0x04) + fixed(key.w.affineX, 32) + fixed(key.w.affineY, 32), value)
    }

    @Test
    fun `EC P-384 SPKI yields the uncompressed point`() {
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp384r1")) }
            .generateKeyPair().public as ECPublicKey

        val value = PivPublicKeyEncoding.pivPublicKeyValue(key.encoded)

        assertArrayEquals(byteArrayOf(0x04) + fixed(key.w.affineX, 48) + fixed(key.w.affineY, 48), value)
    }

    @Test
    fun `a truncated Ed25519 key is refused`() {
        // The BIT STRING claims 33 bytes but holds 31: the DER is cut short.
        val truncated = (ed25519SpkiPrefix + rfc8032Test1Public).copyOf(ed25519SpkiPrefix.size + 31)

        assertRefused(truncated)
    }

    @Test
    fun `a curve 25519 key that is not 32 bytes is refused`() {
        // Well-formed DER whose key is 31 bytes long.
        val short = byteArrayOf(0x30, 0x29, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x20, 0x00) +
            rfc8032Test1Public.copyOf(31)

        assertRefused(short)
    }

    @Test
    fun `trailing bytes after the SPKI are refused`() {
        assertRefused(ed25519SpkiPrefix + rfc8032Test1Public + byteArrayOf(0))
    }

    @Test
    fun `an RSA key has no tag 0x86 value and is refused`() {
        val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair().public

        assertRefused(rsa.encoded)
    }

    @Test
    fun `a raw key that is not 32 bytes cannot be wrapped`() {
        assertTrue(runCatching { PivPublicKeyEncoding.x25519Spki(ByteArray(31)) }.exceptionOrNull() is IllegalArgumentException)
        assertTrue(runCatching { PivPublicKeyEncoding.ed25519Spki(ByteArray(33)) }.exceptionOrNull() is IllegalArgumentException)
    }

    private fun assertRefused(spki: ByteArray) {
        val error = runCatching { PivPublicKeyEncoding.pivPublicKeyValue(spki) }.exceptionOrNull()
        assertTrue("got $error", error is IllegalArgumentException)
    }

    private fun fixed(value: BigInteger, size: Int): ByteArray {
        val bytes = value.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        return ByteArray(size - bytes.size) + bytes
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private companion object {
        /** SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (33 bytes, 0 unused bits) }. */
        val ed25519SpkiPrefix = byteArrayOf(0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00)

        /** SEQUENCE { SEQUENCE { OID 1.3.101.110 }, BIT STRING (33 bytes, 0 unused bits) }. */
        val x25519SpkiPrefix = byteArrayOf(0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00)
    }
}
