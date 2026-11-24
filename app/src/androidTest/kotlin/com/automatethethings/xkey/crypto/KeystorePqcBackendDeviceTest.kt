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

import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.signers.MLDSASigner
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature

/**
 * [KeystorePqcBackend] on a real Keystore. Skipped on a device whose probe
 * finds no ML-DSA set in the TEE or StrongBox (every device below API 37).
 * For each set the probe reports: generate, read the level back, sign with
 * the Keystore key, verify with Bouncy Castle from the returned SPKI, and
 * delete. Keys need no user authentication: the test device enrolls none.
 */
@RunWith(AndroidJUnit4::class)
class KeystorePqcBackendDeviceTest {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private lateinit var backend: KeystorePqcBackend
    private lateinit var supported: Set<MlDsaParameterSet>

    @Before
    fun setUp() {
        assumeTrue("ML-DSA needs API ${KeystorePqcBackend.MIN_SDK}", Build.VERSION.SDK_INT >= KeystorePqcBackend.MIN_SDK)
        backend = KeystorePqcBackend()
        backend.startProbe(scope)
        supported = backend.awaitProbe(PROBE_TIMEOUT_MS)
        assumeTrue("no hardware ML-DSA on this device", supported.isNotEmpty())
    }

    @After
    fun tearDown() {
        for (set in MlDsaParameterSet.entries) {
            runCatching { keyStore.deleteEntry(alias(set)) }
        }
        scope.cancel()
    }

    @Test
    fun probeKeysAreDeleted() {
        for (set in MlDsaParameterSet.entries) {
            assertFalse(set.wireName, keyStore.containsAlias(KeystorePqcBackend.probeAlias(set)))
        }
    }

    @Test
    fun eachSupportedSetSignsInHardwareAndVerifiesWithBouncyCastle() {
        for (set in supported) {
            val alias = alias(set)
            val spki = backend.generate(alias, set, authDurationSeconds = -1, preferStrongBox = false)

            val info = SubjectPublicKeyInfo.getInstance(spki)
            assertEquals(set.wireName, set.oid, info.algorithm.algorithm.id)
            assertEquals(set.wireName, set.publicKeyBytes, info.publicKeyData.bytes.size)

            val privateKey = keyStore.getKey(alias, null) as PrivateKey
            val keyInfo = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
                .getKeySpec(privateKey, KeyInfo::class.java)
            assertTrue(
                "${set.wireName} level ${keyInfo.securityLevel}",
                keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                    keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
            )

            val message = "xkey ML-DSA ${set.wireName}".toByteArray()
            val signature = Signature.getInstance(backend.jcaSignatureAlgorithm(set)).run {
                initSign(privateKey)
                update(message)
                sign()
            }
            assertEquals(set.wireName, set.signatureBytes, signature.size)

            val verifier = MLDSASigner()
            verifier.init(false, PublicKeyFactory.createKey(spki))
            verifier.update(message, 0, message.size)
            assertTrue("${set.wireName} verifies", verifier.verifySignature(signature))

            keyStore.deleteEntry(alias)
            assertFalse(keyStore.containsAlias(alias))
        }
    }

    @Test
    fun generateReplacesAnExistingEntry() {
        val set = supported.first()
        val alias = alias(set)
        val first = backend.generate(alias, set, authDurationSeconds = -1, preferStrongBox = false)
        val second = backend.generate(alias, set, authDurationSeconds = -1, preferStrongBox = false)
        assertFalse(first.contentEquals(second))
        assertTrue(keyStore.containsAlias(alias))
    }

    @Test
    fun preferStrongBoxFallsBackToTheTee() {
        val set = supported.first()
        val spki = backend.generate(alias(set), set, authDurationSeconds = -1, preferStrongBox = true)
        assertEquals(set.oid, SubjectPublicKeyInfo.getInstance(spki).algorithm.algorithm.id)
    }

    private fun alias(set: MlDsaParameterSet) = "xkey_key_pqc_hw_test_${set.name.lowercase()}"

    private companion object {
        const val PROBE_TIMEOUT_MS = 60_000L
    }
}
