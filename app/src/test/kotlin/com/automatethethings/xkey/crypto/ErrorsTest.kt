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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for Passkey crypto error types.
 *
 * These tests verify that exception types have correct messages,
 * preserve causes, and can be properly caught and handled.
 */
class ErrorsTest {

    @Test
    fun `KeyNotFoundException contains credential ID`() {
        val credentialId = "test-credential-123"
        val exception = KeyNotFoundException(credentialId)

        assertEquals(credentialId, exception.credentialId)
        assertTrue(exception.message!!.contains(credentialId))
    }

    @Test
    fun `KeyGenerationException contains reason and cause`() {
        val reason = "StrongBox not available"
        val cause = RuntimeException("Hardware error")
        val exception = KeyGenerationException(reason, cause)

        assertEquals(reason, exception.reason)
        assertEquals(cause, exception.cause)
        assertTrue(exception.message!!.contains(reason))
    }

    @Test
    fun `KeyGenerationException works without cause`() {
        val reason = "Invalid parameters"
        val exception = KeyGenerationException(reason)

        assertEquals(reason, exception.reason)
        assertNull(exception.cause)
    }

    @Test
    fun `SigningException contains reason and cause`() {
        val reason = "Key invalidated"
        val cause = SecurityException("User not authenticated")
        val exception = SigningException(reason, cause)

        assertEquals(reason, exception.reason)
        assertEquals(cause, exception.cause)
        assertTrue(exception.message!!.contains(reason))
    }

    @Test
    fun `BiometricRequiredException has correct message`() {
        val exception = BiometricRequiredException()

        assertNotNull(exception.message)
        assertTrue(exception.message!!.contains("Biometric"))
    }

    @Test
    fun `UserCancelledException has correct message`() {
        val exception = UserCancelledException()

        assertNotNull(exception.message)
        assertTrue(exception.message!!.contains("cancel"))
    }

    @Test
    fun `BiometricLockoutException distinguishes permanent lockout`() {
        val temporaryLockout = BiometricLockoutException(isPermanent = false)
        val permanentLockout = BiometricLockoutException(isPermanent = true)

        assertFalse(temporaryLockout.isPermanent)
        assertTrue(permanentLockout.isPermanent)

        assertTrue(temporaryLockout.message!!.contains("temporarily"))
        assertTrue(permanentLockout.message!!.contains("permanently"))
    }

    @Test
    fun `BiometricException contains error code and message`() {
        val errorCode = 7
        val errorMessage = "Too many attempts"
        val exception = BiometricException(errorCode, errorMessage)

        assertEquals(errorCode, exception.errorCode)
        assertTrue(exception.message!!.contains(errorCode.toString()))
        assertTrue(exception.message!!.contains(errorMessage))
    }

    @Test
    fun `BiometricUnavailableException contains reason`() {
        val reason = "No biometric hardware"
        val exception = BiometricUnavailableException(reason)

        assertEquals(reason, exception.reason)
        assertTrue(exception.message!!.contains(reason))
    }

    @Test
    fun `StrongBoxUnavailableException has correct message`() {
        val exception = StrongBoxUnavailableException()

        assertNotNull(exception.message)
        assertTrue(exception.message!!.contains("StrongBox"))
    }

    @Test
    fun `CborEncodingException contains reason and cause`() {
        val reason = "Invalid coordinate length"
        val cause = IllegalArgumentException("Expected 32 bytes")
        val exception = CborEncodingException(reason, cause)

        assertEquals(reason, exception.reason)
        assertEquals(cause, exception.cause)
    }

    @Test
    fun `AttestationException contains reason and cause`() {
        val reason = "Attestation not supported"
        val exception = AttestationException(reason)

        assertEquals(reason, exception.reason)
        assertNull(exception.cause)
    }

    @Test
    fun `CredentialStorageException contains operation`() {
        val operation = "save"
        val exception = CredentialStorageException(operation)

        assertEquals(operation, exception.operation)
        assertTrue(exception.message!!.contains(operation))
    }

    @Test
    fun `all exceptions are XKeyCryptoException subclasses`() {
        val exceptions = listOf<XKeyCryptoException>(
            KeyNotFoundException("test"),
            KeyGenerationException("test"),
            SigningException("test"),
            BiometricRequiredException(),
            UserCancelledException(),
            BiometricLockoutException(),
            BiometricException(1, "test"),
            BiometricUnavailableException("test"),
            StrongBoxUnavailableException(),
            CborEncodingException("test"),
            AttestationException("test"),
            CredentialStorageException("test")
        )

        exceptions.forEach { exception ->
            assertTrue(
                "${exception::class.simpleName} should be XKeyCryptoException",
                exception is XKeyCryptoException
            )
        }
    }

    @Test
    fun `exceptions can be caught as XKeyCryptoException`() {
        var caught = false

        try {
            throw KeyNotFoundException("test")
        } catch (e: XKeyCryptoException) {
            caught = true
        }

        assertTrue("KeyNotFoundException should be catchable as XKeyCryptoException", caught)
    }

    @Test
    fun `specific exceptions can be caught individually`() {
        var caughtKeyNotFound = false
        var caughtUserCancelled = false

        try {
            throw KeyNotFoundException("test")
        } catch (e: KeyNotFoundException) {
            caughtKeyNotFound = true
        } catch (e: XKeyCryptoException) {
            // Should not reach here
        }

        try {
            throw UserCancelledException()
        } catch (e: UserCancelledException) {
            caughtUserCancelled = true
        } catch (e: XKeyCryptoException) {
            // Should not reach here
        }

        assertTrue(caughtKeyNotFound)
        assertTrue(caughtUserCancelled)
    }

    @Test
    fun `exception messages are not empty`() {
        val exceptions = listOf<XKeyCryptoException>(
            KeyNotFoundException("test"),
            KeyGenerationException("test"),
            SigningException("test"),
            BiometricRequiredException(),
            UserCancelledException(),
            BiometricLockoutException(),
            BiometricException(1, "test"),
            BiometricUnavailableException("test"),
            StrongBoxUnavailableException(),
            CborEncodingException("test"),
            AttestationException("test"),
            CredentialStorageException("test")
        )

        exceptions.forEach { exception ->
            assertNotNull(
                "${exception::class.simpleName} message should not be null",
                exception.message
            )
            assertTrue(
                "${exception::class.simpleName} message should not be empty",
                exception.message!!.isNotEmpty()
            )
        }
    }

    // -----------------------------------------------------------------------
    // Symmetric / agreement operation errors
    // -----------------------------------------------------------------------

    @Test
    fun `EncryptionException prefixes the reason and keeps the cause`() {
        val cause = IllegalStateException("cipher not initialised")
        val exception = EncryptionException("AES-GCM failed", cause)

        assertEquals("AES-GCM failed", exception.reason)
        assertEquals("Encryption failed: AES-GCM failed", exception.message)
        assertEquals(cause, exception.cause)
    }

    @Test
    fun `DecryptionException prefixes the reason and defaults to no cause`() {
        val exception = DecryptionException("tag mismatch")

        assertEquals("tag mismatch", exception.reason)
        assertEquals("Decryption failed: tag mismatch", exception.message)
        assertNull(exception.cause)
    }

    @Test
    fun `HMACException prefixes the reason and keeps the cause`() {
        val cause = java.security.InvalidKeyException("bad key")
        val exception = HMACException("unsupported key", cause)

        assertEquals("unsupported key", exception.reason)
        assertEquals("HMAC computation failed: unsupported key", exception.message)
        assertEquals(cause, exception.cause)
    }

    @Test
    fun `ECDHException prefixes the reason`() {
        val exception = ECDHException("peer key on wrong curve")

        assertEquals("peer key on wrong curve", exception.reason)
        assertEquals("ECDH key agreement failed: peer key on wrong curve", exception.message)
        assertNull(exception.cause)
    }

    @Test
    fun `UnsupportedAlgorithmException names the algorithm`() {
        val exception = UnsupportedAlgorithmException("RS512")

        assertEquals("RS512", exception.algorithm)
        assertEquals("Unsupported algorithm: RS512", exception.message)
    }

    @Test
    fun `symmetric operation errors identify their origin in the message`() {
        val expectedPrefixes = mapOf<XKeyCryptoException, String>(
            EncryptionException("x") to "Encryption failed: ",
            DecryptionException("x") to "Decryption failed: ",
            HMACException("x") to "HMAC computation failed: ",
            ECDHException("x") to "ECDH key agreement failed: ",
            UnsupportedAlgorithmException("x") to "Unsupported algorithm: "
        )

        expectedPrefixes.forEach { (exception, prefix) ->
            assertFalse(
                "${exception::class.simpleName} message should not be empty",
                exception.message.isNullOrEmpty()
            )
            assertEquals(
                "${exception::class.simpleName} message prefix",
                prefix + "x",
                exception.message
            )
        }
    }

    @Test
    fun `a crypto error can be caught as its sealed supertype`() {
        var caught: String? = null
        try {
            throw UnsupportedAlgorithmException("Ed448")
        } catch (e: XKeyCryptoException) {
            caught = e.message
        }
        assertEquals("Unsupported algorithm: Ed448", caught)
    }
}
