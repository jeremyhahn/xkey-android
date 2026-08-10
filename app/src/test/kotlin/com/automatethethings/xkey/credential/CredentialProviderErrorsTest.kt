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
package com.automatethethings.xkey.credential

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the [CredentialProviderException] hierarchy.
 *
 * These exceptions cross the boundary into the Android Credential Manager,
 * where only the *message* survives — the framework wraps whatever is thrown
 * into its own `CreateCredentialUnknownException` / `GetCredentialUnknownException`
 * carrying just the text. So the prefixes are the contract: they are what a user
 * and a bug report actually see, and the structured `reason` is what a test or a
 * caller matches on. Both are pinned here, along with the sealed hierarchy that
 * lets a single `catch` cover the whole family.
 */
class CredentialProviderErrorsTest {

    // -------------------------------------------------------------------------
    // Messages
    // -------------------------------------------------------------------------

    @Test
    fun `an invalid request names the reason behind a stable prefix`() {
        val e = InvalidRequestException("missing rp.id")

        assertEquals("Invalid request: missing rp.id", e.message)
        assertEquals("missing rp.id", e.reason)
    }

    @Test
    fun `a missing credential names the relying party`() {
        val e = NoCredentialsFoundException("example.com")

        assertEquals("No credentials found for relying party: example.com", e.message)
        assertEquals("example.com", e.rpId)
    }

    @Test
    fun `a failed creation names the reason`() {
        val e = CredentialCreationException("keystore rejected the alias")

        assertEquals("Credential creation failed: keystore rejected the alias", e.message)
        assertEquals("keystore rejected the alias", e.reason)
    }

    @Test
    fun `a failed assertion names the reason`() {
        val e = CredentialAssertionException("no matching credential")

        assertEquals("Credential assertion failed: no matching credential", e.message)
        assertEquals("no matching credential", e.reason)
    }

    @Test
    fun `a failed user verification names the reason`() {
        val e = UserVerificationException("no biometric enrolled")

        assertEquals("User verification failed: no biometric enrolled", e.message)
        assertEquals("no biometric enrolled", e.reason)
    }

    @Test
    fun `cancellation and disablement carry fixed messages`() {
        assertEquals(
            "User cancelled the credential operation",
            UserCancelledCredentialException().message
        )
        assertEquals(
            "Credential provider is not enabled",
            ProviderNotEnabledException().message
        )
    }

    @Test
    fun `an empty reason still produces a readable message`() {
        assertEquals("Invalid request: ", InvalidRequestException("").message)
    }

    // -------------------------------------------------------------------------
    // Causes
    // -------------------------------------------------------------------------

    @Test
    fun `the underlying cause is preserved where one is accepted`() {
        val cause = IllegalStateException("keystore locked")

        assertSame(cause, InvalidRequestException("bad json", cause).cause)
        assertSame(cause, CredentialCreationException("keygen", cause).cause)
        assertSame(cause, CredentialAssertionException("sign", cause).cause)
        assertSame(cause, UserVerificationException("biometric", cause).cause)
    }

    @Test
    fun `omitting the cause leaves it null rather than fabricating one`() {
        assertNull(InvalidRequestException("bad json").cause)
        assertNull(NoCredentialsFoundException("example.com").cause)
        assertNull(UserCancelledCredentialException().cause)
        assertNull(ProviderNotEnabledException().cause)
    }

    // -------------------------------------------------------------------------
    // Hierarchy
    // -------------------------------------------------------------------------

    @Test
    fun `every failure mode is catchable as one provider exception`() {
        val all: List<CredentialProviderException> = listOf(
            InvalidRequestException("r"),
            NoCredentialsFoundException("example.com"),
            CredentialCreationException("r"),
            CredentialAssertionException("r"),
            UserVerificationException("r"),
            UserCancelledCredentialException(),
            ProviderNotEnabledException()
        )

        for (e in all) {
            assertTrue(e is Exception)
            assertNotNull(e.message)
        }
    }

    @Test
    fun `a provider exception can be caught by its sealed base type`() {
        val caught = try {
            throw NoCredentialsFoundException("example.com")
        } catch (e: CredentialProviderException) {
            e
        }

        assertTrue(caught is NoCredentialsFoundException)
    }

    @Test
    fun `the seven failures are distinguishable in a when over the base type`() {
        val labels = listOf<CredentialProviderException>(
            InvalidRequestException("r"),
            NoCredentialsFoundException("example.com"),
            CredentialCreationException("r"),
            CredentialAssertionException("r"),
            UserVerificationException("r"),
            UserCancelledCredentialException(),
            ProviderNotEnabledException()
        ).map { failure ->
            when (failure) {
                is InvalidRequestException -> "invalid"
                is NoCredentialsFoundException -> "none-found"
                is CredentialCreationException -> "create"
                is CredentialAssertionException -> "assert"
                is UserVerificationException -> "verify"
                is UserCancelledCredentialException -> "cancelled"
                is ProviderNotEnabledException -> "disabled"
            }
        }

        assertEquals(
            listOf("invalid", "none-found", "create", "assert", "verify", "cancelled", "disabled"),
            labels
        )
    }
}
