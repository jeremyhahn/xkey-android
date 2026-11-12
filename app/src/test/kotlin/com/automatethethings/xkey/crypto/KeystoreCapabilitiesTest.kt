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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * API floors of [KeystoreCapabilities]: Keystore key agreement
 * (`PURPOSE_AGREE_KEY`) exists only from API 31, Ed25519 generation from 33,
 * and minSdk is 28.
 */
class KeystoreCapabilitiesTest {

    @Test
    fun `ECDH is unsupported below API 31`() {
        for (sdk in 28..30) {
            assertFalse("API $sdk has no PURPOSE_AGREE_KEY", KeystoreCapabilities.supportsEcdh(sdk))
        }
    }

    @Test
    fun `ECDH is supported from API 31`() {
        for (sdk in 31..37) {
            assertTrue("API $sdk supports Keystore ECDH", KeystoreCapabilities.supportsEcdh(sdk))
        }
    }

    @Test
    fun `the ECDH refusal names Android 12 and API 31`() {
        val reason = KeystoreCapabilities.ecdhUnsupportedReason(30)
        assertTrue(reason, reason.contains("requires Android 12 (API 31)"))
        assertTrue("the refusal names the device's level: $reason", reason.contains("API 30"))
    }

    @Test
    fun `Ed25519 is left out below API 33`() {
        for (sdk in 28..32) {
            assertFalse(
                "API $sdk cannot generate Ed25519",
                KeystoreCapabilities.supportedAlgorithms(sdk).contains("Ed25519")
            )
        }
    }

    @Test
    fun `Ed25519 is listed from API 33`() {
        assertTrue(KeystoreCapabilities.supportedAlgorithms(33).contains("Ed25519"))
        assertTrue(KeystoreCapabilities.supportedAlgorithms(37).contains("Ed25519"))
    }

    @Test
    fun `every release lists the Keystore algorithms available since minSdk`() {
        for (sdk in 28..37) {
            val algorithms = KeystoreCapabilities.supportedAlgorithms(sdk)
            assertTrue(
                "API $sdk lists every base algorithm",
                algorithms.containsAll(KeystoreCapabilities.BASE_ALGORITHMS)
            )
        }
        assertEquals(KeystoreCapabilities.BASE_ALGORITHMS, KeystoreCapabilities.supportedAlgorithms(28))
    }
}
