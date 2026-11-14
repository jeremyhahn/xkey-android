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
package com.automatethethings.xkey.credential

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.os.Looper
import android.util.Log
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.provider.ProviderGetCredentialRequest
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.credential.handler.GetCredentialHandler
import com.automatethethings.xkey.crypto.BiometricHelper
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.UserCancelledException
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.BiometricSettingsRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.security.MessageDigest
import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The shared passkey counter, driven through the two real assertion handlers:
 * the credential provider ([GetCredentialHandler.handleGetCredential]) and the
 * phone backend (`local.signFido2Assertion` on [RequestHandler]).
 *
 * Both handlers run over one pair of faked DAOs, so they see the same passkey.
 * The counter each signed is read from the authenticator data it returned, and
 * the faked signer records every input it was asked to sign.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PasskeySignCounterHandlerTest {

    /** The two stores the passkey's counter lives in. */
    @Volatile private var metadataCount = 0L
    @Volatile private var keyCount = 0L
    @Volatile private var failCounterWrite = false

    /** Every input a handler handed to the signer. */
    private val signed = mutableListOf<ByteArray>()

    private lateinit var context: Context
    private lateinit var keystoreManager: KeystoreManager
    private lateinit var biometricHelper: BiometricHelper
    private lateinit var biometricLauncher: BiometricActivityLauncher

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0

        mockkStatic(android.util.Base64::class)
        every { android.util.Base64.encodeToString(any(), any()) } answers {
            Base64.getUrlEncoder().withoutPadding().encodeToString(firstArg<ByteArray>())
        }

        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)
        Dispatchers.setMain(UnconfinedTestDispatcher())

        mockkObject(AuditLogger)
        every {
            AuditLogger.logFido2Authentication(any(), any(), any(), any(), any(), any(), any(), any())
        } returns Unit

        val credentialDao = fakeCredentialDao()
        val keyDao = fakeKeyDao()
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns mockk(relaxed = true) {
            every { credentialMetadataDao() } returns credentialDao
            every { keyDao() } returns keyDao
        }

        context = mockk(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        keystoreManager = mockk(relaxed = true)
        coEvery { keystoreManager.signWithoutBiometric(ID, any()) } answers {
            signed += secondArg<ByteArray>()
            SIGNATURE
        }
        // The phone backend signs the passkey the owner approved, under the
        // alias its approval read (#177): the same faked signer records it.
        every { keystoreManager.resolveKeystoreAlias(ID) } returns ALIAS
        every { keystoreManager.publicKeyDERAt(ALIAS) } returns APPROVED_DER
        coEvery { keystoreManager.signApproved(ALIAS, APPROVED_DER, any(), any()) } answers {
            signed += thirdArg<ByteArray>()
            SIGNATURE
        }
        biometricHelper = mockk(relaxed = true)
        every { biometricHelper.isBiometricAvailable() } returns true
        biometricLauncher = mockk(relaxed = true)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    // -----------------------------------------------------------------
    // Both paths, one counter
    // -----------------------------------------------------------------

    @Test
    fun providerThenPhoneBackendSignRisingCounters() = runTest {
        metadataCount = 7
        keyCount = 7

        val provider = providerAssertion()
        val phoneBackend = phoneBackendAssertion()

        assertEquals(8L, provider)
        assertTrue("phone backend signed $phoneBackend after $provider", phoneBackend > provider)
        assertEquals(2, signed.size)
    }

    @Test
    fun phoneBackendThenProviderSignRisingCounters() = runTest {
        metadataCount = 3
        keyCount = 3

        val phoneBackend = phoneBackendAssertion()
        val provider = providerAssertion()

        assertEquals(4L, phoneBackend)
        assertTrue("provider signed $provider after $phoneBackend", provider > phoneBackend)
        assertEquals(2, signed.size)
    }

    // -----------------------------------------------------------------
    // Neither path keeps a counter of its own
    // -----------------------------------------------------------------

    /**
     * Only the shared counter continues from the larger store; a provider
     * counter of its own would read credential_metadata alone and sign 3.
     */
    @Test
    fun providerSignsFromTheSharedCounterNotItsOwnStore() = runTest {
        metadataCount = 2
        keyCount = 9

        assertEquals(10L, providerAssertion())
        assertEquals(10L, metadataCount)
        assertEquals(10L, keyCount)
    }

    /**
     * Only the shared counter continues from the larger store; a phone
     * backend counter of its own would read keys alone and sign 3.
     */
    @Test
    fun phoneBackendSignsFromTheSharedCounterNotItsOwnStore() = runTest {
        metadataCount = 9
        keyCount = 2

        assertEquals(10L, phoneBackendAssertion())
        assertEquals(10L, metadataCount)
        assertEquals(10L, keyCount)
    }

    // -----------------------------------------------------------------
    // A refusal consumes no value
    // -----------------------------------------------------------------

    @Test
    fun aRefusedProviderAssertionLeavesTheCounterAlone() = runTest {
        metadataCount = 5
        keyCount = 5
        coEvery { biometricHelper.authenticateWithoutCrypto(any(), any(), any()) } throws
            IllegalStateException("user cancelled")

        val result = runCatching { providerAssertion(userVerification = "required") }

        assertTrue(
            "a refused verification must refuse the assertion, got $result",
            result.exceptionOrNull() is CredentialAssertionException
        )
        assertEquals(5L, metadataCount)
        assertEquals(5L, keyCount)
        assertTrue("a refused assertion signed something", signed.isEmpty())
        assertEquals("the next assertion takes the next value", 6L, providerAssertion())
    }

    @Test
    fun aRefusedPhoneBackendAssertionLeavesTheCounterAlone() = runTest {
        metadataCount = 5
        keyCount = 5
        coEvery { biometricLauncher.requestAuthentication(any(), any(), any(), any(), any()) } throws
            UserCancelledException()

        val response = phoneBackend(userVerificationRequired = true)

        assertNotNull("a refused verification must be an error", response.error)
        assertEquals(ErrorCodes.USER_CANCELLED, response.error!!.code)
        assertEquals(5L, metadataCount)
        assertEquals(5L, keyCount)
        assertTrue("a refused assertion signed something", signed.isEmpty())
    }

    // -----------------------------------------------------------------
    // A counter that cannot be persisted signs nothing
    // -----------------------------------------------------------------

    @Test
    fun anUnpersistedCounterSignsNoProviderAssertion() = runTest {
        failCounterWrite = true

        val result = runCatching { providerAssertion() }

        assertTrue(
            "a counter that cannot be persisted must refuse the assertion, got $result",
            result.exceptionOrNull() is CredentialAssertionException
        )
        assertTrue("an unpersisted counter was signed", signed.isEmpty())
    }

    @Test
    fun anUnpersistedCounterSignsNoPhoneBackendAssertion() = runTest {
        failCounterWrite = true

        val response = phoneBackend()

        assertNotNull("a counter that cannot be persisted must be an error", response.error)
        assertTrue("an unpersisted counter was signed", signed.isEmpty())
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /** One provider assertion; returns the counter its authenticator data carries. */
    private suspend fun providerAssertion(userVerification: String = "discouraged"): Long {
        val option = mockk<GetPublicKeyCredentialOption>(relaxed = true) {
            every { requestJson } returns JSONObject()
                .put("rpId", RP_ID)
                .put("challenge", "Y2hhbGxlbmdl")
                .put("userVerification", userVerification)
                .toString()
            every { clientDataHash } returns CLIENT_DATA_HASH
        }
        val request = mockk<ProviderGetCredentialRequest>(relaxed = true) {
            every { credentialOptions } returns listOf(option)
        }
        val settings = mockk<BiometricSettingsRepository> {
            coEvery { getSettings() } returns BiometricSettingsData()
        }
        val handler = GetCredentialHandler(context, biometricHelper, keystoreManager, settings)

        val response = JSONObject(handler.handleGetCredential(request, ID))
        val authData = Base64.getUrlDecoder()
            .decode(response.getJSONObject("response").getString("authenticatorData"))
        assertArrayEquals("the provider signed other data", authData + CLIENT_DATA_HASH, signed.last())
        return counterOf(authData)
    }

    /** One successful phone-backend assertion; returns the counter its authenticator data carries. */
    private suspend fun phoneBackendAssertion(): Long {
        val response = phoneBackend()
        assertEquals("no error expected: ${response.error?.message}", null, response.error)
        val result = response.result!!
        val authData = Base64.getDecoder().decode(result.getString("authenticatorData"))
        val digest = MessageDigest.getInstance("SHA-256").digest(authData + CLIENT_DATA_HASH)
        assertArrayEquals("the phone backend signed other data", digest, signed.last())
        assertEquals(result.getLong("signCount"), counterOf(authData))
        return counterOf(authData)
    }

    private suspend fun phoneBackend(userVerificationRequired: Boolean = false): Response {
        val handler = RequestHandler(
            context = context,
            keystoreManager = keystoreManager,
            biometricLauncher = biometricLauncher,
            sessionAuthManager = null
        )
        val params = JSONObject()
            .put("credentialId", ID)
            .put("clientDataHash", Base64.getEncoder().encodeToString(CLIENT_DATA_HASH))
            .put("rpId", RP_ID)
            .put("userVerificationRequired", userVerificationRequired)
        val request = Request(id = 1, method = MethodNames.LOCAL_SIGN_FIDO2_ASSERTION, params = params)
        return Response.fromJson(handler.handleRawRequest(request.toJson()))
    }

    /** The signature counter: the four big-endian bytes after rpIdHash and flags. */
    private fun counterOf(authData: ByteArray): Long =
        (33..36).fold(0L) { acc, i -> (acc shl 8) or (authData[i].toLong() and 0xFF) }

    private fun fakeCredentialDao(): CredentialMetadataDao {
        val entity = mockk<CredentialMetadataEntity>(relaxed = true) {
            every { credentialId } returns ID
            every { rpId } returns RP_ID
            every { rpName } returns "Example"
            every { userId } returns "dXNlcg"
            every { userDisplayName } returns "user"
            every { signCount } answers { metadataCount }
        }
        return mockk(relaxed = true) {
            coEvery { getByCredentialId(ID) } returns entity
            coEvery { updateSignCount(ID, any(), any()) } answers {
                if (failCounterWrite) throw IllegalStateException("metadata store unavailable")
                metadataCount = secondArg()
            }
        }
    }

    private fun fakeKeyDao(): KeyDao {
        val entity = mockk<KeyEntity>(relaxed = true) {
            every { keyId } returns ID
            every { keyType } returns "fido2"
            every { rpId } returns RP_ID
            every { rpName } returns "Example"
            every { userId } returns "dXNlcg"
            every { sharingPolicy } returns SharingPolicyType.ALL_PEERS
            every { biometricRequired } returns false
            every { signCount } answers { keyCount }
        }
        return mockk(relaxed = true) {
            coEvery { getByKeyId(ID) } returns entity
            coEvery { updateSignCount(ID, any(), any()) } answers {
                if (failCounterWrite) throw IllegalStateException("key store unavailable")
                keyCount = secondArg()
            }
        }
    }

    private companion object {
        const val ID = "credential-216"
        const val RP_ID = "example.com"
        val CLIENT_DATA_HASH = ByteArray(32) { 0x21 }
        val SIGNATURE = byteArrayOf(0x30, 0x00)
        const val ALIAS = "xkey_credential_credential-216"
        val APPROVED_DER = ByteArray(91) { 3 }
    }
}
