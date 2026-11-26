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

package com.automatethethings.xkey.credential.handler

import android.app.Application
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.ProviderGetCredentialRequest
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.BiometricHelper
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.BiometricSettingsRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.security.KeyStore
import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * UV=1 is reported only for verification that happened in this ceremony.
 * A time-window key signs silently while its window is open, so its
 * signature proves nothing about this ceremony: the user is prompted
 * explicitly. A per-operation key is verified by its own CryptoObject
 * prompt and gets no second one.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class PasskeyTimeWindowUvTest {

    private lateinit var keystoreManager: KeystoreManager
    private lateinit var helper: BiometricHelper
    private lateinit var keyDao: KeyDao
    private var signedFlags: Int = -1

    @Before
    fun setUp() {
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns mockk(relaxed = true)
        keystoreManager = mockk(relaxed = true)
        // The key is inside its auth window: Keystore signs with no prompt.
        coEvery { keystoreManager.sign(any(), any(), any(), any(), any(), any(), any()) } answers {
            signedFlags = thirdArg<ByteArray>()[32].toInt() and 0xFF
            ByteArray(8)
        }
        helper = mockk(relaxed = true)
        every { helper.isBiometricAvailable() } returns true

        val credentialDao = mockk<CredentialMetadataDao>(relaxed = true)
        coEvery { credentialDao.getByCredentialId(CREDENTIAL_ID) } returns CredentialMetadataEntity(
            credentialId = CREDENTIAL_ID,
            rpId = RP_ID,
            rpName = "Example",
            userId = "dXNlcg",
            userName = "user",
            userDisplayName = "User",
            publicKeyCose = ByteArray(0),
        )
        keyDao = mockk(relaxed = true)
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.credentialMetadataDao() } returns credentialDao
        every { database.keyDao() } returns keyDao
        // No key has a pending deletion or a policy row.
        every { database.keyPolicyDao() } returns mockk<com.automatethethings.xkey.storage.dao.KeyPolicyDao>(relaxed = true) {
            coEvery { deletion(any()) } returns null
            coEvery { policyRow(any()) } returns null
        }
        every { keystoreManager.soleKind(CREDENTIAL_ID) } returns com.automatethethings.xkey.crypto.UserKeyKind.CREDENTIAL
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database
        mockkObject(AuditLogger)
        every { AuditLogger.logFido2Authentication(any(), any(), any(), any(), any(), any()) } returns Unit
    }

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `a time-window key is prompted for before UV is reported`() = runTest {
        authBoundKey(authDurationSeconds = 5)

        assertion("preferred")

        coVerify(exactly = 1) { helper.authenticateWithoutCrypto(any(), any(), any(), any(), any()) }
        assertEquals(UV or UP, signedFlags and (UV or UP))
    }

    @Test
    fun `a per-operation key is verified by its own signing prompt only`() = runTest {
        authBoundKey(authDurationSeconds = 0)

        assertion("preferred")

        coVerify(exactly = 0) { helper.authenticateWithoutCrypto(any(), any(), any(), any(), any()) }
        coVerify(exactly = 1) { keystoreManager.sign(CREDENTIAL_ID, any(), any(), helper, any(), any(), any()) }
        assertEquals(UV or UP, signedFlags and (UV or UP))
    }

    private fun authBoundKey(authDurationSeconds: Int) {
        val key = mockk<KeyEntity>(relaxed = true) {
            every { biometricRequired } returns true
            every { this@mockk.authDurationSeconds } returns authDurationSeconds
        }
        coEvery { keyDao.getByKeyId(any()) } returns key
    }

    private suspend fun assertion(userVerification: String): String {
        val json = JSONObject()
            .put("rpId", RP_ID)
            .put("challenge", "Y2hhbGxlbmdl")
            .put("userVerification", userVerification)
            .toString()
        val option = GetPublicKeyCredentialOption(json, clientDataHash = ByteArray(32) { 7 })
        val browser = mockk<CallingAppInfo>(relaxed = true) {
            every { isOriginPopulated() } returns true
            every { getOrigin(any()) } returns "https://$RP_ID"
        }
        val request = mockk<ProviderGetCredentialRequest>(relaxed = true) {
            every { credentialOptions } returns listOf(option)
            every { callingAppInfo } returns browser
        }
        val settings = mockk<BiometricSettingsRepository> {
            coEvery { getSettings() } returns BiometricSettingsData()
        }
        val handler = GetCredentialHandler(RuntimeEnvironment.getApplication(), helper, keystoreManager, settings)
        return handler.handleGetCredential(request, CREDENTIAL_ID)
    }

    private companion object {
        const val CREDENTIAL_ID = "Y3JlZGVudGlhbA"
        const val RP_ID = "example.com"
        const val UP = 0x01
        const val UV = 0x04
    }
}
