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
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
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

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        keystoreManager = KeystoreManager(context)
    }

    @After
    fun tearDown() {
        runCatching { keystoreManager.deleteGeneralKey(keyId) }
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
}
