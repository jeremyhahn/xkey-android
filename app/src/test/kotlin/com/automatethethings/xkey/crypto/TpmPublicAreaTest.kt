/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.math.BigInteger
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

/**
 * Direct tests of the TPMT_PUBLIC parser.
 *
 * Every public area reaches the phone from the desktop, and the Name computed
 * over it is what the quote and certify checks compare. The areas here are
 * written byte for byte so each field can be bent on its own; nothing is
 * produced by the parser under test.
 */
class TpmPublicAreaTest {

    // ---------------------------------------------------------------
    // Builders
    // ---------------------------------------------------------------

    private fun u16(v: Int) = byteArrayOf((v ushr 8).toByte(), v.toByte())

    private fun u32(v: Int) =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    private fun b2(v: ByteArray) = u16(v.size) + v

    private fun unsigned(value: BigInteger): ByteArray {
        val bytes = value.toByteArray()
        return if (bytes[0].toInt() == 0) bytes.copyOfRange(1, bytes.size) else bytes
    }

    private fun fixed(value: BigInteger, size: Int): ByteArray {
        val bytes = unsigned(value)
        return ByteArray(size - bytes.size) + bytes
    }

    private val noSymmetric = u16(TpmAlg.NULL)
    private val aes128Cfb = u16(TpmAlg.AES) + u16(128) + u16(TpmAlg.CFB)

    private fun header(type: Int, nameAlg: Int) =
        u16(type) + u16(nameAlg) + u32(TpmTestStructures.IAK_ATTRIBUTES) + b2(ByteArray(0))

    private fun rsaArea(
        modulus: ByteArray,
        exponent: Int = 0,
        keyBits: Int = modulus.size * 8,
        nameAlg: Int = TpmAlg.SHA256,
        symmetric: ByteArray = noSymmetric,
        scheme: ByteArray = u16(TpmAlg.RSASSA) + u16(TpmAlg.SHA256),
        unique: ByteArray = b2(modulus)
    ) = header(TpmAlg.RSA, nameAlg) + symmetric + scheme + u16(keyBits) + u32(exponent) + unique

    private fun eccArea(
        curveId: Int,
        x: ByteArray,
        y: ByteArray,
        nameAlg: Int = TpmAlg.SHA256,
        symmetric: ByteArray = noSymmetric,
        scheme: ByteArray = u16(TpmAlg.ECDSA) + u16(TpmAlg.SHA256),
        kdf: ByteArray = u16(TpmAlg.NULL)
    ) = header(TpmAlg.ECC, nameAlg) + symmetric + scheme + u16(curveId) + kdf + b2(x) + b2(y)

    private val rsaKey = TpmTestStructures.generateRsaKeyPair().public as RSAPublicKey
    private val modulus = unsigned(rsaKey.modulus)

    private fun eccAreaFor(curve: String, curveId: Int, size: Int, kdf: ByteArray = u16(TpmAlg.NULL),
                           symmetric: ByteArray = noSymmetric): Pair<ECPublicKey, ByteArray> {
        val key = TpmTestStructures.generateEcKeyPair(curve).public as ECPublicKey
        val area = eccArea(
            curveId, fixed(key.w.affineX, size), fixed(key.w.affineY, size),
            kdf = kdf, symmetric = symmetric
        )
        return key to area
    }

    /** Runs [block] and insists it throws exactly [TpmStructureException]. */
    private fun refused(block: () -> Unit): TpmStructureException {
        try {
            block()
        } catch (e: Throwable) {
            assertEquals("exception type", TpmStructureException::class.java, e.javaClass)
            return e as TpmStructureException
        }
        fail("expected TpmStructureException")
        throw AssertionError("unreachable")
    }

    // ---------------------------------------------------------------
    // RSA
    // ---------------------------------------------------------------

    @Test
    fun `an RSA exponent of zero reads as 65537`() {
        val area = TpmPublicArea.parse(rsaArea(modulus, exponent = 0))
        val key = area.publicKey as RSAPublicKey
        assertEquals(TpmAlg.RSA, area.type)
        assertEquals(BigInteger.valueOf(65537), key.publicExponent)
        assertEquals(rsaKey.modulus, key.modulus)
        assertEquals(TpmAlg.RSASSA, area.scheme)
        assertEquals(TpmAlg.SHA256, area.schemeHashAlg)
    }

    @Test
    fun `an explicit RSA exponent is kept`() {
        val area = TpmPublicArea.parse(rsaArea(modulus, exponent = 3))
        assertEquals(BigInteger.valueOf(3), (area.publicKey as RSAPublicKey).publicExponent)
    }

    @Test
    fun `refuses keyBits that disagree with the modulus length`() {
        val e = refused { TpmPublicArea.parse(rsaArea(modulus, keyBits = 1024)) }
        assertTrue(e.message!!.contains("declares 1024"))
    }

    @Test
    fun `refuses an empty modulus`() {
        val e = refused { TpmPublicArea.parse(rsaArea(ByteArray(0), keyBits = 0)) }
        assertTrue(e.message!!.contains("no modulus"))
    }

    @Test
    fun `refuses a modulus size that runs past the end`() {
        val e = refused {
            TpmPublicArea.parse(rsaArea(modulus, unique = u16(modulus.size + 1) + modulus))
        }
        assertTrue(e.message!!.contains("remain"))
    }

    @Test
    fun `reads past a non-NULL symmetric definition on an RSA key`() {
        val area = TpmPublicArea.parse(rsaArea(modulus, symmetric = aes128Cfb))
        assertEquals(TpmAlg.AES, area.symmetricAlg)
        assertEquals(128, area.symmetricKeyBits)
        assertEquals(TpmAlg.CFB, area.symmetricMode)
        assertEquals(rsaKey.modulus, (area.publicKey as RSAPublicKey).modulus)
    }

    @Test
    fun `a 1024-bit RSA key parses (recorded, no minimum size)`() {
        val small = TpmTestStructures.generateRsaKeyPair(1024).public as RSAPublicKey
        val area = TpmPublicArea.parse(rsaArea(unsigned(small.modulus)))
        assertEquals(1024, (area.publicKey as RSAPublicKey).modulus.bitLength())
    }

    // ---------------------------------------------------------------
    // ECC
    // ---------------------------------------------------------------

    @Test
    fun `parses P-256, P-384 and P-521 with the right point`() {
        listOf(
            Triple("secp256r1", 0x0003, 32),
            Triple("secp384r1", 0x0004, 48),
            Triple("secp521r1", 0x0005, 66)
        ).forEach { (curve, id, size) ->
            val (key, bytes) = eccAreaFor(curve, id, size)
            val area = TpmPublicArea.parse(bytes)
            assertEquals(TpmAlg.ECC, area.type)
            assertEquals(curve, key.w, (area.publicKey as ECPublicKey).w)
            assertEquals(curve, key.params.curve, (area.publicKey as ECPublicKey).params.curve)
        }
    }

    @Test
    fun `refuses an unsupported curve`() {
        val e = refused { TpmPublicArea.parse(eccArea(0x0010, ByteArray(32) { 1 }, ByteArray(32) { 2 })) }
        assertTrue(e.message!!.contains("curve 0x0010"))
    }

    @Test
    fun `refuses an unsupported object type`() {
        val bytes = u16(0x0008) + u16(TpmAlg.SHA256) + u32(0) + b2(ByteArray(0)) + u16(TpmAlg.NULL)
        val e = refused { TpmPublicArea.parse(bytes) }
        assertTrue(e.message!!.contains("type 0x0008"))
    }

    @Test
    fun `reads past a non-NULL symmetric definition and ECC KDF`() {
        val kdf = u16(0x0020) + u16(TpmAlg.SHA256) // KDF1_SP800_56A
        val (key, bytes) = eccAreaFor("secp256r1", 0x0003, 32, kdf = kdf, symmetric = aes128Cfb)
        val area = TpmPublicArea.parse(bytes)
        assertEquals(TpmAlg.AES, area.symmetricAlg)
        assertEquals(128, area.symmetricKeyBits)
        assertEquals(TpmAlg.CFB, area.symmetricMode)
        assertEquals(key.w, (area.publicKey as ECPublicKey).w)
    }

    @Test
    fun `a point not on the curve parses (recorded, no on-curve check)`() {
        val area = TpmPublicArea.parse(eccArea(0x0003, byteArrayOf(1), byteArrayOf(2)))
        assertEquals(BigInteger.ONE, (area.publicKey as ECPublicKey).w.affineX)
    }

    @Test
    fun `zero-length coordinates parse as the point (0, 0) (recorded)`() {
        val area = TpmPublicArea.parse(eccArea(0x0003, ByteArray(0), ByteArray(0)))
        val w = (area.publicKey as ECPublicKey).w
        assertEquals(BigInteger.ZERO, w.affineX)
        assertEquals(BigInteger.ZERO, w.affineY)
    }

    // ---------------------------------------------------------------
    // Names
    // ---------------------------------------------------------------

    @Test
    fun `name is nameAlg followed by the digest of the raw bytes`() {
        listOf(
            TpmAlg.SHA1 to "SHA-1",
            TpmAlg.SHA256 to "SHA-256",
            TpmAlg.SHA384 to "SHA-384"
        ).forEach { (alg, digest) ->
            val bytes = rsaArea(modulus, nameAlg = alg)
            val expected = u16(alg) + MessageDigest.getInstance(digest).digest(bytes)
            assertArrayEquals(digest, expected, TpmPublicArea.parse(bytes).name())
        }
    }

    @Test
    fun `name under an unsupported nameAlg is refused`() {
        val area = TpmPublicArea.parse(rsaArea(modulus, nameAlg = 0x0012)) // SM3_256
        val e = refused { area.name() }
        assertTrue(e.message!!.contains("0x0012"))
    }

    @Test
    fun `trailing bytes after a valid area parse and change the name (recorded)`() {
        val bytes = rsaArea(modulus)
        val padded = bytes + byteArrayOf(0)
        val area = TpmPublicArea.parse(padded)
        assertArrayEquals(padded, area.raw)
        assertFalse(TpmPublicArea.parse(bytes).name().contentEquals(area.name()))
    }

    // ---------------------------------------------------------------
    // Truncation
    // ---------------------------------------------------------------

    @Test
    fun `every prefix of a valid area is refused as a structure error`() {
        val areas = listOf(
            rsaArea(modulus),
            rsaArea(modulus, symmetric = aes128Cfb),
            eccAreaFor("secp256r1", 0x0003, 32).second,
            eccAreaFor(
                "secp384r1", 0x0004, 48,
                kdf = u16(0x0020) + u16(TpmAlg.SHA384), symmetric = aes128Cfb
            ).second
        )
        areas.forEach { area ->
            TpmPublicArea.parse(area)
            for (n in 0 until area.size) {
                refused { TpmPublicArea.parse(area.copyOf(n)) }
            }
        }
    }
}
