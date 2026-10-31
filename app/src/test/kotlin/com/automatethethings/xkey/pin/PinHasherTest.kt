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
import org.junit.Test

/**
 * Unit tests for [PinHasher].
 *
 * PIN length validation and salt generation run purely in the JVM. Hashing
 * needs the Signal Argon2 native library (JNI), which unit tests cannot load.
 */
class PinHasherTest {

    // -------------------------------------------------------------------------
    // generateSalt tests
    // -------------------------------------------------------------------------

    @Test
    fun `generateSalt returns 16 bytes`() {
        val salt = PinHasher.generateSalt()

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
}
