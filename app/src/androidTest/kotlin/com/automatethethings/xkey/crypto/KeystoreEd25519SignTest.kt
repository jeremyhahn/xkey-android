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
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.KeyStore
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/** An EdDSA general key is made in the device's Android Keystore and signs through signWithAlgorithm. */
@RunWith(AndroidJUnit4::class)
class KeystoreEd25519SignTest {

    private lateinit var context: Context
    private lateinit var keystoreManager: KeystoreManager
    private val keyId = "ed25519-sign-${System.nanoTime()}"
    private val otherKeyId = "ed25519-other-${System.nanoTime()}"

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        keystoreManager = KeystoreManager(context)
    }

    @After
    fun tearDown() {
        runCatching { keystoreManager.deleteGeneralKey(keyId) }
        runCatching { keystoreManager.deleteGeneralKey(otherKeyId) }
    }

    @Test
    fun anEdDsaKeyIsAKeystoreKeyThatSignsVerifiably() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            assertThrows(UnsupportedAlgorithmException::class.java) {
                runBlocking { keystoreManager.generateKeyForAlgorithm(keyId, "EdDSA", -1, false) }
            }
            return
        }

        val der = runBlocking { keystoreManager.generateKeyForAlgorithm(keyId, "EdDSA", -1, false) }
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue("the key is a Keystore entry", keyStore.containsAlias(KeystoreManager.generalKeyAlias(keyId)))

        val message = "xKey Ed25519 Keystore key".toByteArray()
        val signature = runBlocking { keystoreManager.signWithAlgorithm(keyId, message, "EdDSA") }

        assertEquals(64, signature.size)
        val publicKey = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(der))
        val verifies = Signature.getInstance("Ed25519").run {
            initVerify(publicKey)
            update(message)
            verify(signature)
        }
        assertTrue("the Keystore's Ed25519 signature verifies under the returned key", verifies)
    }

    /**
     * The check signApproved runs on a per-operation key's signature, on the
     * device's own providers: a Keystore Ed25519 key's signature verifies
     * under its public key, and another Keystore Ed25519 key's does not.
     */
    @Test
    fun theApprovedKeyCheckAcceptsAKeystoreEd25519KeysOwnSignatureOnly() {
        assumeTrue("Keystore Ed25519 keys need API 33", Build.VERSION.SDK_INT >= 33)
        val approvedDer = runBlocking { keystoreManager.generateKeyForAlgorithm(keyId, "EdDSA", -1, false) }
        runBlocking { keystoreManager.generateKeyForAlgorithm(otherKeyId, "EdDSA", -1, false) }
        val algorithm = KeystoreManager.jcaSignatureAlgorithm("EdDSA")
        val message = "xKey approved Ed25519 key".toByteArray()

        val own = runBlocking { keystoreManager.signWithAlgorithm(keyId, message, "EdDSA") }
        val other = runBlocking { keystoreManager.signWithAlgorithm(otherKeyId, message, "EdDSA") }

        assertTrue(
            "the approved key's signature verifies",
            keystoreManager.verifiesUnder(approvedDer, algorithm, null, message, own)
        )
        assertFalse(
            "another Keystore Ed25519 key's signature is refused",
            keystoreManager.verifiesUnder(approvedDer, algorithm, null, message, other)
        )
    }
}
