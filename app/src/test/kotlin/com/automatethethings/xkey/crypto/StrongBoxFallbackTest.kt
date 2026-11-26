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

import android.app.Application
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStoreException
import java.security.ProviderException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The device attestation key and the user verification key prefer StrongBox
 * and fall back to the TEE. Only a StrongBox-unavailable failure may take the
 * fallback; any other generation failure (a Keystore fault, a missing
 * attestation chain) propagates instead of silently minting a TEE key.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class StrongBoxFallbackTest {

    @Test
    fun strongBoxUnavailableFallsBackToTee() {
        val unavailable = mutableListOf<Throwable>()
        val result = StrongBoxFallback.generate(
            strongBox = { throw StrongBoxUnavailableException("no StrongBox") },
            onUnavailable = { unavailable += it },
            tee = { "tee" }
        )
        assertEquals("tee", result)
        assertEquals("the cleanup runs once before the TEE attempt", 1, unavailable.size)
    }

    @Test
    fun aWrappedStrongBoxUnavailableFallsBackToTee() {
        val result = StrongBoxFallback.generate(
            strongBox = { throw ProviderException("Failed to generate key pair", StrongBoxUnavailableException("no StrongBox")) },
            onUnavailable = {},
            tee = { "tee" }
        )
        assertEquals("tee", result)
    }

    @Test
    fun aHardwareTypeUnavailableKeystoreErrorFallsBackToTee() {
        val result = StrongBoxFallback.generate(
            strongBox = { throw ProviderException("Failed to generate key pair", KeyStoreException("-68 (HARDWARE_TYPE_UNAVAILABLE)")) },
            onUnavailable = {},
            tee = { "tee" }
        )
        assertEquals("tee", result)
    }

    @Test
    fun strongBoxSuccessNeverTouchesTheTee() {
        val result = StrongBoxFallback.generate(
            strongBox = { "strongbox" },
            onUnavailable = { fail("no fallback after a StrongBox key") },
            tee = { fail("no TEE key after a StrongBox key"); "tee" }
        )
        assertEquals("strongbox", result)
    }

    @Test
    fun anOtherProviderFailurePropagates() {
        assertPropagates(ProviderException("Failed to generate key pair", KeyStoreException("-1000 (SYSTEM_ERROR)")))
    }

    @Test
    fun aMissingAttestationChainPropagates() {
        assertPropagates(AttestationException("no attestation chain"))
    }

    @Test
    fun anUncheckedFailurePropagates() {
        assertPropagates(IllegalStateException("keystore locked"))
    }

    @Test
    fun theUnavailablePredicateRecognisesOnlyStrongBoxShapes() {
        assertTrue(StrongBoxFallback.isStrongBoxUnavailable(StrongBoxUnavailableException("x")))
        assertFalse(StrongBoxFallback.isStrongBoxUnavailable(ProviderException("Failed to generate key pair")))
        assertFalse(StrongBoxFallback.isStrongBoxUnavailable(KeyStoreException("-68")))
    }

    private fun assertPropagates(failure: Exception) {
        var teeCalled = false
        try {
            StrongBoxFallback.generate(
                strongBox = { throw failure },
                onUnavailable = { fail("not a StrongBox-unavailable failure") },
                tee = { teeCalled = true; "tee" }
            )
            fail("expected the failure to propagate")
        } catch (e: Exception) {
            assertSame(failure, e)
        }
        assertFalse("no TEE fallback for an unrelated failure", teeCalled)
    }
}
