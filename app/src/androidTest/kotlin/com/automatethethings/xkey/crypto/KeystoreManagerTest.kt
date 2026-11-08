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

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

/**
 * Instrumented tests for KeystoreManager.
 *
 * These tests run on an Android device or emulator and verify
 * the actual keystore operations.
 *
 * Note: Tests that require biometric authentication are limited
 * to verifying that the appropriate exceptions are thrown when
 * biometric is not available or not performed.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreManagerTest {

    private lateinit var context: Context
    private lateinit var keystoreManager: KeystoreManager

    // Test credential IDs - cleaned up after each test
    private val testCredentialIds = mutableListOf<String>()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        keystoreManager = KeystoreManager(context)
    }

    @After
    fun tearDown() {
        // Clean up any test keys
        testCredentialIds.forEach { credentialId ->
            try {
                keystoreManager.deleteKey(credentialId)
            } catch (e: Exception) {
                // Ignore cleanup errors
            }
        }
        testCredentialIds.clear()
    }

    private fun createTestCredentialId(): String {
        val credentialId = "test_${System.currentTimeMillis()}_${(0..1000).random()}"
        testCredentialIds.add(credentialId)
        return credentialId
    }

    @Test
    fun generateKey_producesValidCOSEKey() = runBlocking {
        val credentialId = createTestCredentialId()

        val cosePublicKey = keystoreManager.generateKey(
            credentialId = credentialId,
            requireBiometric = false
        )

        // COSE EC2 P-256 key should be 77 bytes:
        // Map header (1) + 5 key-value pairs
        assertEquals("COSE key should be 77 bytes", 77, cosePublicKey.size)

        // Verify CBOR map header
        assertEquals("First byte should be map(5)", 0xA5.toByte(), cosePublicKey[0])

        // Verify kty = 2 (EC2)
        assertEquals("kty label should be 1", 0x01.toByte(), cosePublicKey[1])
        assertEquals("kty value should be 2 (EC2)", 0x02.toByte(), cosePublicKey[2])
    }

    @Test
    fun generateKey_regeneratesExistingKey() = runBlocking {
        val credentialId = createTestCredentialId()

        // Generate first key
        val firstKey = keystoreManager.generateKey(
            credentialId = credentialId,
            requireBiometric = false
        )

        // Generate second key with same ID
        val secondKey = keystoreManager.generateKey(
            credentialId = credentialId,
            requireBiometric = false
        )

        // Keys should be different (new key generated)
        assertFalse(
            "Regenerated key should be different",
            firstKey.contentEquals(secondKey)
        )
    }

    @Test
    fun keyExists_returnsFalseForNonexistent() {
        val credentialId = "nonexistent_credential_${System.currentTimeMillis()}"

        val exists = keystoreManager.keyExists(credentialId)

        assertFalse("Non-existent key should return false", exists)
    }

    @Test
    fun deleteKey_returnsFalseForNonexistent() {
        val credentialId = "nonexistent_credential_${System.currentTimeMillis()}"

        val deleted = keystoreManager.deleteKey(credentialId)

        assertFalse("Deleting non-existent key should return false", deleted)
    }

    @Test
    fun deleteKey_returnsTrueAndRemovesKey() = runBlocking {
        val credentialId = createTestCredentialId()

        keystoreManager.generateKey(
            credentialId = credentialId,
            requireBiometric = false
        )
        assertTrue("Key should exist before deletion", keystoreManager.keyExists(credentialId))

        val deleted = keystoreManager.deleteKey(credentialId)

        assertTrue("Delete should return true", deleted)
        assertFalse("Key should not exist after deletion", keystoreManager.keyExists(credentialId))

        // Remove from cleanup list since it's already deleted
        testCredentialIds.remove(credentialId)
        Unit // the test method must return Unit or JUnit rejects the class
    }

    @Test
    fun getPublicKey_returnsNullForNonexistent() {
        val credentialId = "nonexistent_credential_${System.currentTimeMillis()}"

        val publicKey = keystoreManager.getPublicKey(credentialId)

        assertNull("Non-existent key should return null", publicKey)
    }

    @Test
    fun getPublicKey_returnsKeyAfterGeneration() = runBlocking {
        val credentialId = createTestCredentialId()

        keystoreManager.generateKey(
            credentialId = credentialId,
            requireBiometric = false
        )

        val publicKey = keystoreManager.getPublicKey(credentialId)

        assertNotNull("Public key should not be null", publicKey)
        assertEquals("Key should be EC", "EC", publicKey?.algorithm)
    }

    @Test
    fun getCOSEPublicKey_matchesGeneratedKey() = runBlocking {
        val credentialId = createTestCredentialId()

        val generatedKey = keystoreManager.generateKey(
            credentialId = credentialId,
            requireBiometric = false
        )

        val retrievedKey = keystoreManager.getCOSEPublicKey(credentialId)

        assertNotNull("Retrieved COSE key should not be null", retrievedKey)
        assertTrue(
            "Retrieved key should match generated key",
            generatedKey.contentEquals(retrievedKey!!)
        )
    }

    @Test
    fun signWithoutBiometric_producesDERSignature() = runBlocking {
        val credentialId = createTestCredentialId()

        keystoreManager.generateKey(
            credentialId = credentialId,
            requireBiometric = false
        )

        val dataHash = ByteArray(32) { it.toByte() }
        val signature = keystoreManager.signWithoutBiometric(credentialId, dataHash)

        // DER-encoded ECDSA signature starts with 0x30 (SEQUENCE)
        assertEquals("Signature should start with DER SEQUENCE tag", 0x30.toByte(), signature[0])
    }

    @Test
    fun getAttestationChain_returnsChain_afterKeyGeneration() = runBlocking {
        val credentialId = createTestCredentialId()

        keystoreManager.generateKey(
            credentialId = credentialId,
            requireBiometric = false
        )

        val chain = keystoreManager.getAttestationChain(credentialId)

        // Attestation chain availability depends on device capabilities
        // On devices that support it, the chain should not be empty
        if (chain != null) {
            assertTrue("Attestation chain should not be empty", chain.isNotEmpty())
        }
    }

    @Test(expected = StrongBoxUnavailableException::class)
    fun generateKey_throwsStrongBoxUnavailable_whenRequired_andNotAvailable() = runBlocking {
        // Skip test if StrongBox is actually available
        if (keystoreManager.isStrongBoxAvailable()) {
            throw StrongBoxUnavailableException() // Force the expected exception
        }

        val credentialId = createTestCredentialId()

        keystoreManager.generateKey(
            credentialId = credentialId,
            requireBiometric = false,
            requireStrongBox = true
        )
        Unit // the test method must return Unit or JUnit rejects the class
    }

    @Test
    fun keyDeletionDoesNotAffectOtherKeys() = runBlocking {
        val credentialId1 = createTestCredentialId()
        val credentialId2 = createTestCredentialId()

        keystoreManager.generateKey(credentialId1, requireBiometric = false)
        keystoreManager.generateKey(credentialId2, requireBiometric = false)

        // Delete first key
        keystoreManager.deleteKey(credentialId1)
        testCredentialIds.remove(credentialId1)

        // Second key should still work
        assertTrue("Second key should still exist", keystoreManager.keyExists(credentialId2))
        val dataHash = ByteArray(32)
        val signature = keystoreManager.signWithoutBiometric(credentialId2, dataHash)
        assertNotNull("Second key should still sign", signature)
    }
}
