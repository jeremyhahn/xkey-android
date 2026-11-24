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

import android.app.Application
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.automatethethings.xkey.audit.AuditLogger
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.AlgorithmParameterSpec
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * When a device claims StrongBox but cannot make the key there, the key is
 * made in the TEE with the same user-authentication policy it would have had
 * in StrongBox.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class KeystoreManagerStrongBoxFallbackTest {

    private val ecKeyPair: KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()

    private val specs = mutableListOf<KeyGenParameterSpec>()
    private var generations = 0

    /** Answers each generateKeyPair call in turn. */
    private var answers: List<() -> KeyPair> = emptyList()

    private lateinit var keystoreManager: KeystoreManager

    @Before
    fun setUp() {
        val app = RuntimeEnvironment.getApplication()
        shadowOf(app.packageManager).setSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE, true)
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns mockk(relaxed = true)
        mockkObject(AuditLogger)
        every { AuditLogger.logKeyCreated(any(), any(), any(), any(), any(), any(), any(), any()) } returns Unit

        val generator = mockk<KeyPairGenerator>(relaxed = true)
        every { generator.initialize(any<AlgorithmParameterSpec>()) } answers {
            specs += firstArg<KeyGenParameterSpec>()
        }
        every { generator.generateKeyPair() } answers { answers[generations++]() }
        mockkStatic(KeyPairGenerator::class)
        every { KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore") } returns generator

        keystoreManager = KeystoreManager(app)
    }

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `a per-operation key made in the TEE accepts biometric or device credential`() = runTest {
        answers = listOf(
            { throw android.security.keystore.StrongBoxUnavailableException() },
            { ecKeyPair },
        )

        keystoreManager.generateKeyWithAuthDuration("c", authDurationSeconds = 0)

        assertEquals(2, specs.size)
        assertTrue(specs[0].isStrongBoxBacked)
        assertFalse(specs[1].isStrongBoxBacked)
        assertEquals(
            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            specs[1].userAuthenticationType
        )
        assertEquals(specs[0].userAuthenticationType, specs[1].userAuthenticationType)
        assertEquals(0, specs[1].userAuthenticationValidityDurationSeconds)
    }
}
