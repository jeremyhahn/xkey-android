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
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.credentials.provider.ProviderGetCredentialRequest
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.credential.CredentialAssertionException
import com.automatethethings.xkey.credential.CredentialCreationException
import com.automatethethings.xkey.crypto.BiometricHelper
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.BiometricSettingsRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.security.KeyStore
import kotlinx.coroutines.test.runTest
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * A caller that hands the provider its own clientDataHash decides what the
 * relying party will believe the origin was. Such a hash is taken only from a
 * privileged browser whose framework-verified origin the RP ID is valid for;
 * any other caller is refused before anything is signed or generated.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class PasskeyCallerOriginTest {

    private lateinit var keystoreManager: KeystoreManager
    private lateinit var settings: BiometricSettingsRepository
    private val generationReached = IllegalStateException("key generation reached")

    @Before
    fun setUp() {
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns mockk(relaxed = true)
        keystoreManager = mockk(relaxed = true)
        coEvery { keystoreManager.signWithoutBiometric(any(), any(), any()) } returns ByteArray(8)
        every { keystoreManager.soleKind(CREDENTIAL_ID) } returns com.automatethethings.xkey.crypto.UserKeyKind.CREDENTIAL
        coEvery { keystoreManager.generateKeyWithAuthDuration(any(), any(), any()) } throws generationReached
        settings = mockk { coEvery { getSettings() } returns BiometricSettingsData() }

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
        val keyDao = mockk<KeyDao>(relaxed = true)
        coEvery { keyDao.getByKeyId(any()) } returns null
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.credentialMetadataDao() } returns credentialDao
        every { database.keyDao() } returns keyDao
        // No key has a pending deletion or a policy row.
        every { database.keyPolicyDao() } returns mockk<com.automatethethings.xkey.storage.dao.KeyPolicyDao>(relaxed = true) {
            coEvery { deletion(any()) } returns null
            coEvery { policyRow(any()) } returns null
        }
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database
        mockkObject(AuditLogger)
        every { AuditLogger.logFido2Authentication(any(), any(), any(), any(), any(), any()) } returns Unit
    }

    @After
    fun tearDown() = unmockkAll()

    // ---------------------------------------------------------------
    // Assertion
    // ---------------------------------------------------------------

    @Test
    fun `an app with no verified origin and its own hash gets no assertion`() = runTest {
        val result = runCatching { assertion(nonBrowserApp()) }

        assertTrue("got $result", result.exceptionOrNull() is CredentialAssertionException)
        coVerify(exactly = 0) { keystoreManager.signWithoutBiometric(any(), any(), any()) }
        coVerify(exactly = 0) { keystoreManager.sign(any(), any(), any(), any(), any(), any(), any()) }
    }

    @Test
    fun `an app off the privileged allowlist with its own hash gets no assertion`() = runTest {
        val result = runCatching { assertion(unlistedApp()) }

        assertTrue("got $result", result.exceptionOrNull() is CredentialAssertionException)
        coVerify(exactly = 0) { keystoreManager.signWithoutBiometric(any(), any(), any()) }
    }

    @Test
    fun `a privileged browser on another site with its own hash gets no assertion`() = runTest {
        val result = runCatching { assertion(browser("https://attacker.test")) }

        assertTrue("got $result", result.exceptionOrNull() is CredentialAssertionException)
        coVerify(exactly = 0) { keystoreManager.signWithoutBiometric(any(), any(), any()) }
    }

    @Test
    fun `a privileged browser on the relying party with its own hash is signed`() = runTest {
        assertion(browser("https://login.$RP_ID"))

        coVerify(exactly = 1) { keystoreManager.signWithoutBiometric(CREDENTIAL_ID, com.automatethethings.xkey.crypto.UserKeyKind.CREDENTIAL, any()) }
    }

    // ---------------------------------------------------------------
    // Registration
    // ---------------------------------------------------------------

    @Test
    fun `an app with no verified origin and its own hash gets no passkey`() = runTest {
        val result = runCatching { create(nonBrowserApp()) }

        assertTrue("got $result", result.exceptionOrNull() is CredentialCreationException)
        assertTrue("refused after generation: $result", result.exceptionOrNull()?.cause !== generationReached)
        coVerify(exactly = 0) { keystoreManager.generateKeyWithAuthDuration(any(), any(), any()) }
    }

    @Test
    fun `an app off the privileged allowlist with its own hash gets no passkey`() = runTest {
        val result = runCatching { create(unlistedApp()) }

        assertTrue("got $result", result.exceptionOrNull() is CredentialCreationException)
        coVerify(exactly = 0) { keystoreManager.generateKeyWithAuthDuration(any(), any(), any()) }
    }

    @Test
    fun `a privileged browser on another site with its own hash gets no passkey`() = runTest {
        val result = runCatching { create(browser("https://attacker.test")) }

        assertTrue("got $result", result.exceptionOrNull() is CredentialCreationException)
        coVerify(exactly = 0) { keystoreManager.generateKeyWithAuthDuration(any(), any(), any()) }
    }

    @Test
    fun `a privileged browser on the relying party with its own hash reaches key generation`() = runTest {
        val result = runCatching { create(browser("https://$RP_ID")) }

        assertSame("got $result", generationReached, result.exceptionOrNull()?.cause)
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private suspend fun assertion(caller: CallingAppInfo): String {
        val json = JSONObject()
            .put("rpId", RP_ID)
            .put("challenge", "Y2hhbGxlbmdl")
            .put("userVerification", "discouraged")
            .toString()
        val option = GetPublicKeyCredentialOption(json, clientDataHash = ByteArray(32) { 7 })
        val request = mockk<ProviderGetCredentialRequest>(relaxed = true) {
            every { credentialOptions } returns listOf(option)
            every { callingAppInfo } returns caller
        }
        val helper = mockk<BiometricHelper>(relaxed = true)
        val handler = GetCredentialHandler(RuntimeEnvironment.getApplication(), helper, keystoreManager, settings)
        return handler.handleGetCredential(request, CREDENTIAL_ID)
    }

    private suspend fun create(caller: CallingAppInfo): String {
        val json = JSONObject()
            .put("rp", JSONObject().put("id", RP_ID).put("name", "Example"))
            .put("user", JSONObject().put("id", "dXNlcg").put("name", "user").put("displayName", "User"))
            .put("challenge", "Y2hhbGxlbmdl")
            .put("pubKeyCredParams", JSONArray().put(JSONObject().put("type", "public-key").put("alg", -7)))
            .toString()
        val callingRequest = CreatePublicKeyCredentialRequest(json, clientDataHash = ByteArray(32) { 7 })
        val request = mockk<ProviderCreateCredentialRequest>(relaxed = true) {
            every { this@mockk.callingRequest } returns callingRequest
            every { callingAppInfo } returns caller
        }
        val handler = CreateCredentialHandler(RuntimeEnvironment.getApplication(), keystoreManager, settings)
        return handler.handleCreateCredential(request, userVerified = false)
    }

    /** An ordinary app: the framework populated no origin for it. */
    private fun nonBrowserApp(): CallingAppInfo = mockk(relaxed = true) {
        every { packageName } returns "com.example.app"
        every { isOriginPopulated() } returns false
        every { getOrigin(any()) } returns null
    }

    /** An app that set an origin but is not on the privileged allowlist. */
    private fun unlistedApp(): CallingAppInfo = mockk(relaxed = true) {
        every { packageName } returns "com.example.fakebrowser"
        every { isOriginPopulated() } returns true
        every { getOrigin(any()) } throws IllegalStateException("not a privileged caller")
    }

    /** A privileged browser whose framework-verified origin is [origin]. */
    private fun browser(origin: String): CallingAppInfo = mockk(relaxed = true) {
        every { packageName } returns "com.android.chrome"
        every { isOriginPopulated() } returns true
        every { getOrigin(any()) } returns origin
    }

    private companion object {
        const val CREDENTIAL_ID = "Y3JlZGVudGlhbA"
        const val RP_ID = "example.com"
    }
}
