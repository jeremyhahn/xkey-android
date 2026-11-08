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
package com.automatethethings.xkey.pin

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [PinHasher].
 *
 * [PinHasher] hashes through the Signal Argon2 library, a JNI library that only
 * loads on Android, so the hash and verify paths cannot run in the unit suite.
 * These tests run them on a device: the hash/verify behaviours, a known answer
 * for the stored-hash parameters, and a cross-check against Bouncy Castle's
 * Argon2id for a random salt.
 *
 * The known answer was computed with Bouncy Castle's [Argon2BytesGenerator],
 * after that generator reproduced the Argon2id v1.3 test vector of RFC 9106
 * section 5.3.
 */
@RunWith(AndroidJUnit4::class)
class PinHasherInstrumentedTest {

    @Test
    fun hashPinIsDeterministicForSameInput() {
        val salt = PinHasher.generateSalt()
        val first = PinHasher.hashPin("123456", salt)
        val second = PinHasher.hashPin("123456", salt)

        assertEquals(HASH_LENGTH, first.size)
        assertArrayEquals(first, second)
    }

    @Test
    fun hashPinDiffersForDifferentPins() {
        val salt = PinHasher.generateSalt()

        assertFalse(PinHasher.hashPin("123456", salt).contentEquals(PinHasher.hashPin("654321", salt)))
    }

    @Test
    fun hashPinDiffersForDifferentSalts() {
        val first = PinHasher.hashPin("123456", PinHasher.generateSalt())
        val second = PinHasher.hashPin("123456", PinHasher.generateSalt())

        assertFalse(first.contentEquals(second))
    }

    @Test
    fun verifyPinAcceptsTheRightPin() {
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hashPin("123456", salt)

        assertTrue(PinHasher.verifyPin("123456", salt, hash))
    }

    @Test
    fun verifyPinRejectsAWrongPin() {
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hashPin("123456", salt)

        assertFalse(PinHasher.verifyPin("123457", salt, hash))
    }

    @Test
    fun hashPinMatchesTheKnownAnswer() {
        val hash = PinHasher.hashPin(KNOWN_PIN, hexToBytes(KNOWN_SALT_HEX))

        assertEquals(KNOWN_HASH_HEX, bytesToHex(hash))
    }

    @Test
    fun hashPinMatchesBouncyCastleArgon2id() {
        val pin = "Correct-Horse-9"
        val salt = PinHasher.generateSalt()

        assertEquals(SALT_LENGTH, salt.size)
        assertEquals(bytesToHex(bouncyCastleArgon2id(pin, salt)), bytesToHex(PinHasher.hashPin(pin, salt)))
    }

    private fun bouncyCastleArgon2id(pin: String, salt: ByteArray): ByteArray {
        val parameters = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(MEMORY_COST_KIB)
            .withIterations(TIME_COST)
            .withParallelism(PARALLELISM)
            .withSalt(salt)
            .build()
        val generator = Argon2BytesGenerator()
        generator.init(parameters)
        val out = ByteArray(HASH_LENGTH)
        generator.generateBytes(pin.toByteArray(Charsets.UTF_8), out)
        return out
    }

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { i -> hex.substring(2 * i, 2 * i + 2).toInt(16).toByte() }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private companion object {
        // Argon2id v1.3 parameters of every stored PIN hash: a change to any of them breaks every stored PIN hash.
        const val MEMORY_COST_KIB = 65536
        const val TIME_COST = 3
        const val PARALLELISM = 4
        const val HASH_LENGTH = 32
        const val SALT_LENGTH = 16

        const val KNOWN_PIN = "123456"
        const val KNOWN_SALT_HEX = "000102030405060708090a0b0c0d0e0f"
        const val KNOWN_HASH_HEX = "f3d65df8ca135f936c3005aa8adec6d002e3bf2cf01e98052ae00385630b94af"
    }
}
