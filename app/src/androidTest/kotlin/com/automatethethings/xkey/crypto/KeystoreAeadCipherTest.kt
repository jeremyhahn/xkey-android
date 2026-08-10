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

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.AEADBadTagException

/**
 * Instrumented tests for [KeystoreAeadCipher], the shared AES-256-GCM at-rest
 * primitive behind the OATH secret store and the password manager.
 *
 * These exercise the real Android Keystore, so the tests own two per-run aliases
 * and delete both in `@After`. Beyond the round trip they prove the properties
 * the callers depend on: the IV is fresh per message, the 128-bit GCM tag is
 * actually enforced (any mutation of IV, ciphertext or tag must fail closed),
 * and keys are isolated per alias so one store cannot read another's data.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreAeadCipherTest {

    private val alias = "xkey_test_aead_${System.nanoTime()}"
    private val otherAlias = "${alias}_other"

    private lateinit var cipher: KeystoreAeadCipher

    /** Layout: [IV: 12][ciphertext][GCM tag: 16]. */
    private val ivSize = 12
    private val tagSize = 16

    @Before
    fun setUp() {
        cipher = KeystoreAeadCipher(alias)
    }

    @After
    fun tearDown() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        listOf(alias, otherAlias).forEach {
            if (keyStore.containsAlias(it)) keyStore.deleteEntry(it)
        }
    }

    private fun randomBytes(size: Int) = ByteArray(size).also { SecureRandom().nextBytes(it) }

    @Test
    fun encryptDecryptRoundTripsArbitraryBytes() {
        val plaintext = randomBytes(1024)

        val decrypted = cipher.decrypt(cipher.encrypt(plaintext))

        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun emptyPlaintextRoundTripsToTheIvPlusTagOnly() {
        val encrypted = cipher.encrypt(ByteArray(0))

        assertEquals(ivSize + tagSize, encrypted.size)
        assertEquals(0, cipher.decrypt(encrypted).size)
    }

    @Test
    fun ciphertextLayoutIsIvPlusPlaintextPlusTag() {
        val plaintext = randomBytes(37)

        val encrypted = cipher.encrypt(plaintext)

        assertEquals(ivSize + plaintext.size + tagSize, encrypted.size)
        assertFalse(
            "plaintext must not appear verbatim in the output",
            encrypted.toList().windowed(plaintext.size).contains(plaintext.toList())
        )
    }

    @Test
    fun everyEncryptionUsesAFreshIvSoCiphertextsDiffer() {
        val plaintext = "same message every time".toByteArray()

        val first = cipher.encrypt(plaintext)
        val second = cipher.encrypt(plaintext)

        assertFalse(
            "IVs must not repeat",
            first.copyOfRange(0, ivSize).contentEquals(second.copyOfRange(0, ivSize))
        )
        assertFalse("ciphertexts must differ", first.contentEquals(second))
        assertArrayEquals(plaintext, cipher.decrypt(first))
        assertArrayEquals(plaintext, cipher.decrypt(second))
    }

    @Test
    fun aTamperedCiphertextByteFailsTheGcmTag() {
        val encrypted = cipher.encrypt(randomBytes(64))
        encrypted[ivSize + 3] = (encrypted[ivSize + 3].toInt() xor 0x01).toByte()

        assertThrows(AEADBadTagException::class.java) { cipher.decrypt(encrypted) }
    }

    @Test
    fun aTamperedTagFailsTheGcmTag() {
        val encrypted = cipher.encrypt(randomBytes(64))
        val last = encrypted.size - 1
        encrypted[last] = (encrypted[last].toInt() xor 0xFF).toByte()

        assertThrows(AEADBadTagException::class.java) { cipher.decrypt(encrypted) }
    }

    @Test
    fun aTamperedIvFailsTheGcmTag() {
        val encrypted = cipher.encrypt(randomBytes(64))
        encrypted[0] = (encrypted[0].toInt() xor 0x80).toByte()

        assertThrows(AEADBadTagException::class.java) { cipher.decrypt(encrypted) }
    }

    @Test
    fun truncatedCiphertextFailsTheGcmTag() {
        val encrypted = cipher.encrypt(randomBytes(64))

        assertThrows(AEADBadTagException::class.java) {
            cipher.decrypt(encrypted.copyOfRange(0, encrypted.size - 1))
        }
    }

    @Test
    fun inputShorterThanTheIvIsRejectedBeforeAnyCryptography() {
        assertThrows(IllegalArgumentException::class.java) { cipher.decrypt(ByteArray(ivSize)) }
        assertThrows(IllegalArgumentException::class.java) { cipher.decrypt(ByteArray(0)) }
        assertThrows(IllegalArgumentException::class.java) { cipher.decrypt(ByteArray(ivSize - 1)) }
    }

    @Test
    fun aDifferentAliasCannotDecryptAnotherStoresCiphertext() {
        val plaintext = randomBytes(48)
        val encrypted = cipher.encrypt(plaintext)

        val foreign = KeystoreAeadCipher(otherAlias)

        assertThrows(AEADBadTagException::class.java) { foreign.decrypt(encrypted) }
        // ...and the foreign store still works with its own key.
        assertArrayEquals(plaintext, foreign.decrypt(foreign.encrypt(plaintext)))
    }

    @Test
    fun theKeyPersistsSoANewInstanceOnTheSameAliasCanDecrypt() {
        val plaintext = "persisted across instances".toByteArray()
        val encrypted = cipher.encrypt(plaintext)

        val reopened = KeystoreAeadCipher(alias)

        assertArrayEquals(plaintext, reopened.decrypt(encrypted))
    }

    @Test
    fun theKeyIsCreatedInTheAndroidKeystoreOnFirstUse() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse("alias must not pre-exist", keyStore.containsAlias(alias))

        cipher.encrypt("first use".toByteArray())

        val reloaded = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue("first encrypt must create the key", reloaded.containsAlias(alias))
    }
}
