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
package com.automatethethings.xkey.pin

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Ignore
import org.junit.Test

/**
 * Unit tests for [PinHasher].
 *
 * PIN length validation tests run purely in the JVM without native dependencies.
 * Hash-based tests require the Signal Argon2 native library (JNI), which is
 * unavailable in unit tests and are annotated with [Ignore]. Those tests should
 * be verified through instrumented/integration tests on a real device.
 */
class PinHasherTest {

    // -------------------------------------------------------------------------
    // hashPin tests (require native Argon2 JNI -- skipped in unit tests)
    // -------------------------------------------------------------------------

    @Ignore("Requires Signal Argon2 native library (JNI) -- run as instrumented test")
    @Test
    fun `hashPin produces consistent output for same input`() {
        val pin = "123456"
        val salt = ByteArray(16) { it.toByte() }

        val hash1 = PinHasher.hashPin(pin, salt)
        val hash2 = PinHasher.hashPin(pin, salt)

        assertTrue(
            "Hashing the same PIN with the same salt must produce identical output",
            hash1.contentEquals(hash2)
        )
    }

    @Ignore("Requires Signal Argon2 native library (JNI) -- run as instrumented test")
    @Test
    fun `hashPin produces different output for different pins`() {
        val salt = ByteArray(16) { it.toByte() }

        val hash1 = PinHasher.hashPin("123456", salt)
        val hash2 = PinHasher.hashPin("654321", salt)

        assertFalse(
            "Different PINs with the same salt must produce different hashes",
            hash1.contentEquals(hash2)
        )
    }

    @Ignore("Requires Signal Argon2 native library (JNI) -- run as instrumented test")
    @Test
    fun `hashPin produces different output for different salts`() {
        val pin = "123456"
        val salt1 = ByteArray(16) { it.toByte() }
        val salt2 = ByteArray(16) { (it + 1).toByte() }

        val hash1 = PinHasher.hashPin(pin, salt1)
        val hash2 = PinHasher.hashPin(pin, salt2)

        assertFalse(
            "Same PIN with different salts must produce different hashes",
            hash1.contentEquals(hash2)
        )
    }

    // -------------------------------------------------------------------------
    // verifyPin tests (require native Argon2 JNI -- skipped in unit tests)
    // -------------------------------------------------------------------------

    @Ignore("Requires Signal Argon2 native library (JNI) -- run as instrumented test")
    @Test
    fun `verifyPin returns true for correct pin`() {
        val pin = "123456"
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hashPin(pin, salt)

        assertTrue(
            "verifyPin must return true for the correct PIN",
            PinHasher.verifyPin(pin, salt, hash)
        )
    }

    @Ignore("Requires Signal Argon2 native library (JNI) -- run as instrumented test")
    @Test
    fun `verifyPin returns false for wrong pin`() {
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hashPin("123456", salt)

        assertFalse(
            "verifyPin must return false for an incorrect PIN",
            PinHasher.verifyPin("wrong-pin", salt, hash)
        )
    }

    // -------------------------------------------------------------------------
    // generateSalt tests
    // -------------------------------------------------------------------------

    @Test
    fun `generateSalt returns 16 bytes`() {
        val salt = PinHasher.generateSalt()

        assertNotNull(salt)
        assertEquals(
            "Salt must be 16 bytes (SALT_LENGTH)",
            16,
            salt.size
        )
    }

    @Test
    fun `generateSalt returns unique salts`() {
        val salt1 = PinHasher.generateSalt()
        val salt2 = PinHasher.generateSalt()

        assertFalse(
            "Two consecutive generateSalt calls must produce different values",
            salt1.contentEquals(salt2)
        )
    }

    // -------------------------------------------------------------------------
    // validatePinLength tests
    // -------------------------------------------------------------------------

    @Test(expected = IllegalArgumentException::class)
    fun `validatePinLength rejects too short pin`() {
        PinHasher.validatePinLength("12345") // 5 bytes -- below MIN_PIN_LENGTH (6)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `validatePinLength rejects too long pin`() {
        // 64 ASCII characters = 64 UTF-8 bytes, exceeding MAX_PIN_LENGTH (63)
        val longPin = "a".repeat(64)
        PinHasher.validatePinLength(longPin)
    }

    @Test
    fun `validatePinLength accepts minimum length pin`() {
        // 6 ASCII characters = 6 UTF-8 bytes = MIN_PIN_LENGTH
        PinHasher.validatePinLength("123456")
        // No exception means pass
    }

    @Test
    fun `validatePinLength accepts maximum length pin`() {
        // 63 ASCII characters = 63 UTF-8 bytes = MAX_PIN_LENGTH
        val maxPin = "a".repeat(63)
        PinHasher.validatePinLength(maxPin)
        // No exception means pass
    }

    // -------------------------------------------------------------------------
    // Constant verification tests
    // -------------------------------------------------------------------------

    @Test
    fun `MIN_PIN_LENGTH is 6`() {
        assertEquals(6, PinHasher.MIN_PIN_LENGTH)
    }

    @Test
    fun `MAX_PIN_LENGTH is 63`() {
        assertEquals(63, PinHasher.MAX_PIN_LENGTH)
    }
}
