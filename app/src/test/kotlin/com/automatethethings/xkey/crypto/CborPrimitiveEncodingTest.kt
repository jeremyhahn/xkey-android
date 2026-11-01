/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
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
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.lang.reflect.InvocationTargetException

/**
 * RFC 8949 head-encoding conformance for the three primitive writers inside
 * [CborEncoder].
 *
 * [CborEncoderTest] covers the one public entry point, `encodeCOSEEC2Key`, but
 * that entry point only ever feeds the writers five compile-time constants and
 * two 32-byte coordinates. Every value it passes lands in the shortest head
 * form, so the 1-, 2-, 4- and 5-byte forms the writers implement have never
 * been executed at all -- an off-by-one in any of them would produce a
 * COSE_Key no relying party could parse, and nothing would notice.
 *
 * The writers are private because nothing outside the object needs them; they
 * are reached here by reflection rather than by widening their visibility for
 * a test. The assertions are on exact bytes, because the encoded form *is* the
 * contract: CTAP2 requires canonical (shortest-form) CBOR, so "some encoding
 * that decodes correctly" is not good enough.
 */
class CborPrimitiveEncodingTest {

    // ------------------------------------------------------------------
    // Unsigned integers (major type 0)
    // ------------------------------------------------------------------

    @Test
    fun `unsigned values up to 23 are packed into the head byte`() {
        assertArrayEquals(byteArrayOf(0x00), unsigned(0))
        assertArrayEquals(byteArrayOf(0x01), unsigned(1))
        assertArrayEquals(byteArrayOf(0x17), unsigned(23))
    }

    @Test
    fun `unsigned 24 is the first value needing a following byte`() {
        assertArrayEquals(byteArrayOf(0x18, 0x18), unsigned(24))
    }

    @Test
    fun `unsigned values up to 255 use the one-byte follower`() {
        assertArrayEquals(byteArrayOf(0x18, 0x64), unsigned(100))
        assertArrayEquals(byteArrayOf(0x18, 0xFF.toByte()), unsigned(255))
    }

    @Test
    fun `unsigned 256 crosses to the two-byte follower`() {
        assertArrayEquals(byteArrayOf(0x19, 0x01, 0x00), unsigned(256))
        assertArrayEquals(byteArrayOf(0x19, 0xFF.toByte(), 0xFF.toByte()), unsigned(65535))
    }

    @Test
    fun `unsigned 65536 crosses to the four-byte follower`() {
        assertArrayEquals(byteArrayOf(0x1A, 0x00, 0x01, 0x00, 0x00), unsigned(65536))
    }

    @Test
    fun `the largest positive int keeps its high byte`() {
        assertArrayEquals(
            byteArrayOf(0x1A, 0x7F, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()),
            unsigned(Int.MAX_VALUE)
        )
    }

    @Test
    fun `unsigned encoding refuses a negative value`() {
        val failure = failureFrom { unsigned(-1) }
        assertTrue(
            "expected an IllegalArgumentException, got $failure",
            failure is IllegalArgumentException
        )
    }

    // ------------------------------------------------------------------
    // Negative integers (major type 1)
    // ------------------------------------------------------------------

    /**
     * CBOR stores a negative integer n as the unsigned value -1 - n, so -1 is
     * the *smallest* encoded payload and the boundaries sit one further out
     * than the unsigned ones.
     */
    @Test
    fun `negative values down to -24 are packed into the head byte`() {
        assertArrayEquals(byteArrayOf(0x20), negative(-1))
        assertArrayEquals(byteArrayOf(0x26), negative(-7))
        assertArrayEquals(byteArrayOf(0x37), negative(-24))
    }

    @Test
    fun `negative 25 is the first value needing a following byte`() {
        assertArrayEquals(byteArrayOf(0x38, 0x18), negative(-25))
        assertArrayEquals(byteArrayOf(0x38, 0xFF.toByte()), negative(-256))
    }

    @Test
    fun `negative 257 crosses to the two-byte follower`() {
        assertArrayEquals(byteArrayOf(0x39, 0x01, 0x00), negative(-257))
        assertArrayEquals(byteArrayOf(0x39, 0xFF.toByte(), 0xFF.toByte()), negative(-65536))
    }

    @Test
    fun `negative 65537 crosses to the four-byte follower`() {
        assertArrayEquals(byteArrayOf(0x3A, 0x00, 0x01, 0x00, 0x00), negative(-65537))
    }

    @Test
    fun `the most negative int does not overflow its payload`() {
        // -1 - Int.MIN_VALUE is Int.MAX_VALUE, which still fits.
        assertArrayEquals(
            byteArrayOf(0x3A, 0x7F, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()),
            negative(Int.MIN_VALUE)
        )
    }

    @Test
    fun `negative encoding refuses zero and positive values`() {
        assertTrue(failureFrom { negative(0) } is IllegalArgumentException)
        assertTrue(failureFrom { negative(1) } is IllegalArgumentException)
    }

    // ------------------------------------------------------------------
    // Byte strings (major type 2)
    // ------------------------------------------------------------------

    @Test
    fun `an empty byte string is a bare head byte`() {
        assertArrayEquals(byteArrayOf(0x40), byteString(ByteArray(0)))
    }

    @Test
    fun `byte string lengths up to 23 are packed into the head byte`() {
        val encoded = byteString(ByteArray(23) { 0x11 })
        assertEquals(0x57.toByte(), encoded[0])
        assertEquals(24, encoded.size)
    }

    @Test
    fun `byte string length 24 is the first needing a following byte`() {
        val encoded = byteString(ByteArray(24) { 0x22 })
        assertArrayEquals(byteArrayOf(0x58, 0x18), encoded.copyOfRange(0, 2))
        assertEquals(26, encoded.size)
    }

    @Test
    fun `byte string length 256 crosses to the two-byte follower`() {
        val encoded = byteString(ByteArray(256))
        assertArrayEquals(byteArrayOf(0x59, 0x01, 0x00), encoded.copyOfRange(0, 3))
        assertEquals(259, encoded.size)
    }

    @Test
    fun `byte string length 65536 crosses to the four-byte follower`() {
        val encoded = byteString(ByteArray(65536))
        assertArrayEquals(
            byteArrayOf(0x5A, 0x00, 0x01, 0x00, 0x00),
            encoded.copyOfRange(0, 5)
        )
        assertEquals(65541, encoded.size)
    }

    @Test
    fun `every byte string head form declares the payload it carries`() {
        for (length in intArrayOf(0, 1, 23, 24, 255, 256, 65535, 65536)) {
            val payload = ByteArray(length) { (it and 0xFF).toByte() }
            val encoded = byteString(payload)
            val declared = decodeHead(encoded, expectedMajorType = 2)
            assertEquals("length $length must be declared verbatim", length.toLong(), declared)
            assertArrayEquals(
                "length $length must be followed by its payload",
                payload,
                encoded.copyOfRange(encoded.size - length, encoded.size)
            )
        }
    }

    /**
     * The writers share one buffer in real use, so appending has to leave what
     * came before untouched -- which is the only reason `encodeCOSEEC2Key`
     * produces a parseable map at all.
     */
    @Test
    fun `writers append to a shared buffer without disturbing earlier output`() {
        val buffer = ByteArrayOutputStream()
        invokeUnsigned(buffer, 65536)
        invokeNegative(buffer, -257)
        invokeByteString(buffer, byteArrayOf(0x0A, 0x0B))

        assertArrayEquals(
            byteArrayOf(
                0x1A, 0x00, 0x01, 0x00, 0x00,
                0x39, 0x01, 0x00,
                0x42, 0x0A, 0x0B
            ),
            buffer.toByteArray()
        )
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private fun unsigned(value: Int): ByteArray {
        val buffer = ByteArrayOutputStream()
        invokeUnsigned(buffer, value)
        return buffer.toByteArray()
    }

    private fun negative(value: Int): ByteArray {
        val buffer = ByteArrayOutputStream()
        invokeNegative(buffer, value)
        return buffer.toByteArray()
    }

    private fun byteString(bytes: ByteArray): ByteArray {
        val buffer = ByteArrayOutputStream()
        invokeByteString(buffer, bytes)
        return buffer.toByteArray()
    }

    private fun invokeUnsigned(buffer: ByteArrayOutputStream, value: Int) {
        intWriter("encodeUnsignedInt").invoke(CborEncoder, buffer, value)
    }

    private fun invokeNegative(buffer: ByteArrayOutputStream, value: Int) {
        intWriter("encodeNegativeInt").invoke(CborEncoder, buffer, value)
    }

    private fun invokeByteString(buffer: ByteArrayOutputStream, bytes: ByteArray) {
        CborEncoder.javaClass
            .getDeclaredMethod("encodeByteString", ByteArrayOutputStream::class.java, ByteArray::class.java)
            .apply { isAccessible = true }
            .invoke(CborEncoder, buffer, bytes)
    }

    private fun intWriter(name: String) =
        CborEncoder.javaClass
            .getDeclaredMethod(name, ByteArrayOutputStream::class.java, Int::class.javaPrimitiveType)
            .apply { isAccessible = true }

    /** Runs [block] and returns whatever it threw, unwrapped from reflection. */
    private fun failureFrom(block: () -> Unit): Throwable? {
        return try {
            block()
            null
        } catch (e: InvocationTargetException) {
            e.targetException
        } catch (e: Throwable) {
            e
        }
    }

    /**
     * A minimal RFC 8949 head reader: checks the major type and returns the
     * argument, whichever of the four head forms carries it.
     */
    private fun decodeHead(encoded: ByteArray, expectedMajorType: Int): Long {
        val head = encoded[0].toInt() and 0xFF
        assertEquals(
            "major type",
            expectedMajorType,
            head shr 5
        )
        val additional = head and 0x1F
        return when {
            additional <= 23 -> additional.toLong()
            additional == 24 -> readBigEndian(encoded, 1, 1)
            additional == 25 -> readBigEndian(encoded, 1, 2)
            additional == 26 -> readBigEndian(encoded, 1, 4)
            else -> throw AssertionError("unexpected additional information $additional")
        }
    }

    private fun readBigEndian(bytes: ByteArray, offset: Int, count: Int): Long {
        var value = 0L
        for (i in 0 until count) {
            value = (value shl 8) or (bytes[offset + i].toLong() and 0xFF)
        }
        return value
    }
}
