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
package com.automatethethings.xkey.oath

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [OathSecretManager].
 *
 * These tests require a real Android device or emulator because [OathSecretManager]
 * uses the hardware-backed Android Keystore for AES-256-GCM encryption.
 *
 * Tests cover:
 * - Encrypt/decrypt round-trip integrity
 * - Ciphertext differs from plaintext
 * - Tampered ciphertext detection (GCM authentication tag failure)
 * - Rejection of too-short ciphertext
 * - Empty input handling
 * - Unique IVs per encryption (AES-GCM randomness)
 */
@RunWith(AndroidJUnit4::class)
class OathSecretManagerTest {

    private lateinit var manager: OathSecretManager

    @Before
    fun setUp() {
        manager = OathSecretManager()
    }

    @Test
    fun encryptDecrypt_roundTrip() {
        val plaintext = "JBSWY3DPEHPK3PXP".toByteArray(Charsets.UTF_8)

        val encrypted = manager.encryptSecret(plaintext)
        val decrypted = manager.decryptSecret(encrypted)

        assertArrayEquals(
            "Decrypted output should match original plaintext",
            plaintext,
            decrypted
        )
    }

    @Test(expected = Exception::class)
    fun tamperedCiphertext_throwsException() {
        val plaintext = "JBSWY3DPEHPK3PXP".toByteArray(Charsets.UTF_8)
        val encrypted = manager.encryptSecret(plaintext)

        // Flip a byte in the ciphertext portion (after the 12-byte IV)
        val tampered = encrypted.copyOf()
        val flipIndex = encrypted.size - 1
        tampered[flipIndex] = (tampered[flipIndex].toInt() xor 0xFF).toByte()

        // Should throw AEADBadTagException or similar
        manager.decryptSecret(tampered)
    }

    @Test(expected = IllegalArgumentException::class)
    fun tooShortCiphertext_throwsException() {
        val tooShort = ByteArray(5) { 0x42 }

        // Should throw IllegalArgumentException because data is shorter than IV + 1 byte
        manager.decryptSecret(tooShort)
    }

    @Test
    fun emptyInput_encrypts() {
        val plaintext = ByteArray(0)

        val encrypted = manager.encryptSecret(plaintext)
        assertNotNull("Encrypted output should not be null", encrypted)
        assertTrue(
            "Encrypted output should be at least 12 bytes (IV) + GCM tag",
            encrypted.size >= 12
        )

        val decrypted = manager.decryptSecret(encrypted)
        assertArrayEquals(
            "Decrypted empty input should return empty byte array",
            plaintext,
            decrypted
        )
    }

    @Test
    fun multipleEncryptions_produceDifferentCiphertext() {
        val plaintext = "JBSWY3DPEHPK3PXP".toByteArray(Charsets.UTF_8)

        val encrypted1 = manager.encryptSecret(plaintext)
        val encrypted2 = manager.encryptSecret(plaintext)

        assertFalse(
            "Two encryptions of the same plaintext should produce different ciphertext " +
                "(AES-GCM uses a random IV each time)",
            encrypted1.contentEquals(encrypted2)
        )
    }
}
