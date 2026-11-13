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

package com.automatethethings.xkey.credential.handler

import android.app.Application
import androidx.credentials.GetPublicKeyCredentialOption
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
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.security.KeyStore
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.test.runCurrent
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
 * Two assertions for one credential, each waiting on its user-verification
 * prompt, sign distinct, increasing counters: the counter is read and bumped
 * only once an assertion's queue turn has come, one credential at a time.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class AssertionSignCountTest {

    private var stored = 7L
    private val signedCounters = mutableListOf<Long>()

    /** Each prompt the helper shows, answered when the test completes it. */
    private val prompts = Channel<CompletableDeferred<Unit>>(Channel.UNLIMITED)

    private val credential = CredentialMetadataEntity(
        credentialId = CREDENTIAL_ID,
        rpId = RP_ID,
        rpName = "Example",
        userId = "dXNlcg",
        userName = "user",
        userDisplayName = "User",
        publicKeyCose = ByteArray(0),
    )

    private lateinit var helper: BiometricHelper

    @Before
    fun setUp() {
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns mockk(relaxed = true)
        mockkConstructor(KeystoreManager::class)
        coEvery { anyConstructed<KeystoreManager>().sign(any(), any(), any(), any(), any(), any()) } answers {
            val data = secondArg<ByteArray>()
            // authData = rpIdHash (32) || flags (1) || signCount (4, big-endian)
            signedCounters += (33..36).fold(0L) { acc, i -> (acc shl 8) or (data[i].toLong() and 0xFF) }
            ByteArray(8)
        }
        mockkConstructor(BiometricSettingsRepository::class)
        coEvery { anyConstructed<BiometricSettingsRepository>().getSettings() } returns BiometricSettingsData()

        val credentialDao = mockk<CredentialMetadataDao>(relaxed = true)
        coEvery { credentialDao.getByCredentialId(CREDENTIAL_ID) } answers { credential.copy(signCount = stored) }
        coEvery { credentialDao.updateSignCount(CREDENTIAL_ID, any(), any()) } answers { stored = secondArg() }
        val keyDao = mockk<KeyDao>(relaxed = true)
        coEvery { keyDao.getByKeyId(any()) } returns null
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.credentialMetadataDao() } returns credentialDao
        every { database.keyDao() } returns keyDao
        // No key has a pending deletion.
        every { database.keyPolicyDao() } returns mockk<com.automatethethings.xkey.storage.dao.KeyPolicyDao>(relaxed = true) { io.mockk.coEvery { deletion(any()) } returns null }
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database
        mockkObject(AuditLogger)
        every { AuditLogger.logFido2Authentication(any(), any(), any(), any(), any(), any()) } returns Unit

        helper = mockk(relaxed = true)
        every { helper.isBiometricAvailable() } returns true
        coEvery { helper.authenticateWithoutCrypto(any(), any(), any(), any()) } coAnswers {
            CompletableDeferred<Unit>().also { prompts.send(it) }.await()
        }
    }

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `two queued assertions for one credential sign distinct increasing counters`() = runTest {
        val handler = GetCredentialHandler(RuntimeEnvironment.getApplication(), helper)

        val assertions = List(2) { async { handler.handleGetCredential(request(), CREDENTIAL_ID) } }
        runCurrent()
        repeat(2) {
            prompts.receive().complete(Unit)
            runCurrent()
        }
        assertions.awaitAll()

        assertEquals(listOf(8L, 9L), signedCounters)
        assertEquals(9L, stored)
    }

    private fun request(): ProviderGetCredentialRequest {
        val json = JSONObject()
            .put("rpId", RP_ID)
            .put("challenge", "Y2hhbGxlbmdl")
            .put("userVerification", "required")
            .toString()
        val option = GetPublicKeyCredentialOption(json, clientDataHash = ByteArray(32))
        return mockk(relaxed = true) { every { credentialOptions } returns listOf(option) }
    }

    private companion object {
        const val CREDENTIAL_ID = "Y3JlZGVudGlhbA"
        const val RP_ID = "example.com"
    }
}
