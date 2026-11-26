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
 * (`PURPOSE_AGREE_KEY`) exists only from API 31, Ed25519 is not advertised
 * until the protocol can create it, and minSdk is 28.
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
    fun `Ed25519 is never advertised`() {
        // local.generateKey parses names through CoseAlgorithms.fromName,
        // which has no Ed25519, so no release can create one over the protocol.
        for (sdk in 28..37) {
            assertFalse(
                "API $sdk must not advertise Ed25519",
                KeystoreCapabilities.supportedAlgorithms(sdk).contains("Ed25519")
            )
        }
    }

    @Test
    fun `every release lists P-521, AES-192, HMAC-SHA384 and every RSA hash`() {
        for (sdk in 28..37) {
            val algorithms = KeystoreCapabilities.supportedAlgorithms(sdk)
            for (name in listOf("ES512", "AES192", "HMAC-SHA384", "RS256", "RS384", "RS512")) {
                assertTrue("API $sdk lists $name", algorithms.contains(name))
            }
        }
    }

    @Test
    fun `every listed algorithm is one local generateKey parses`() {
        for (name in KeystoreCapabilities.BASE_ALGORITHMS) {
            com.automatethethings.xkey.protocol.CoseAlgorithms.fromName(name)
        }
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
        for (sdk in 28..32) {
            assertEquals(KeystoreCapabilities.BASE_ALGORITHMS, KeystoreCapabilities.supportedAlgorithms(sdk))
        }
        for (sdk in 33..37) {
            assertEquals(KeystoreCapabilities.BASE_ALGORITHMS + "EdDSA", KeystoreCapabilities.supportedAlgorithms(sdk))
        }
    }

    @Test
    fun `every release lists the three ML-DSA parameter sets`() {
        for (sdk in 28..37) {
            val algorithms = KeystoreCapabilities.supportedAlgorithms(sdk)
            for (name in listOf("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")) {
                assertTrue("API $sdk lists $name", algorithms.contains(name))
            }
        }
    }

    @Test
    fun `hardwareAlgorithms is empty with no hardware backend`() {
        val saved = PqcHardware.backend
        try {
            PqcHardware.backend = null
            assertEquals(emptyList<String>(), KeystoreCapabilities.hardwareAlgorithms())
        } finally {
            PqcHardware.backend = saved
        }
    }

    @Test
    fun `hardwareAlgorithms lists only the sets the backend makes, in order`() {
        val saved = PqcHardware.backend
        try {
            PqcHardware.backend = object : PqcHardwareBackend {
                override fun supportedParameterSets() =
                    setOf(MlDsaParameterSet.ML_DSA_87, MlDsaParameterSet.ML_DSA_44)
                override fun generate(
                    alias: String,
                    set: MlDsaParameterSet,
                    authDurationSeconds: Int,
                    preferStrongBox: Boolean
                ): ByteArray = throw UnsupportedOperationException()
                override fun jcaSignatureAlgorithm(set: MlDsaParameterSet) = set.wireName
            }
            assertEquals(listOf("ML-DSA-44", "ML-DSA-87"), KeystoreCapabilities.hardwareAlgorithms())
        } finally {
            PqcHardware.backend = saved
        }
    }
}
