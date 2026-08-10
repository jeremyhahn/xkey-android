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

package com.automatethethings.xkey.credential

import android.content.Context
import android.os.Build
import android.os.Bundle
import androidx.credentials.CreatePasswordRequest
import androidx.credentials.provider.BeginCreatePasswordCredentialRequest
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.credential.handler.CreateCredentialHandler
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.settings.BiometricSettingsRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec

/**
 * Instrumented tests for [CreateCredentialHandler], the WebAuthn registration
 * (makeCredential) half of the credential provider.
 *
 * These drive the real handler against the real Android Keystore and the real
 * Room database, with request objects built exactly as the framework builds
 * them — `ProviderCreateCredentialRequest`, `CreatePublicKeyCredentialRequest`
 * and `CallingAppInfo` are all publicly constructible in androidx.credentials
 * 1.3.0, so nothing here is a stand-in for the production path.
 *
 * Every credential this suite mints is removed in [tearDown]: its Keystore
 * alias, its `credential_metadata` row and its mirror row in `keys`.
 */
@RunWith(AndroidJUnit4::class)
@SdkSuppress(minSdkVersion = Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class CreateCredentialHandlerTest {

    private lateinit var context: Context
    private lateinit var handler: CreateCredentialHandler
    private lateinit var keystoreManager: KeystoreManager
    private lateinit var credentialDao: CredentialMetadataDao
    private lateinit var keyDao: KeyDao
    private lateinit var settingsRepository: BiometricSettingsRepository

    /** Relying parties this test touched; everything under them is removed. */
    private val touchedRpIds = linkedSetOf<String>()

    private var rpCounter = 0

    @Before
    fun setUp() {
        assumeTrue(
            "The credential provider requires Android 14",
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
        )
        context = ApplicationProvider.getApplicationContext()
        AuditLogger.initialize(context)
        handler = CreateCredentialHandler(context)
        keystoreManager = KeystoreManager(context)
        val database = XKeyDatabase.getInstance(context)
        credentialDao = database.credentialMetadataDao()
        keyDao = database.keyDao()
        settingsRepository = BiometricSettingsRepository(context)
    }

    @After
    fun tearDown() {
        if (!this::credentialDao.isInitialized) return
        runBlocking {
            for (rpId in touchedRpIds) {
                for (row in credentialDao.getByRpId(rpId)) {
                    runCatching { keystoreManager.deleteKey(row.credentialId) }
                    credentialDao.deleteByCredentialId(row.credentialId)
                    keyDao.deleteByKeyId(row.credentialId)
                }
            }
        }
        touchedRpIds.clear()
    }

    // ---------------------------------------------------------------------
    // Begin phase
    // ---------------------------------------------------------------------

    @Test
    fun beginCreateCredential_offersACreateEntryForTheRequestedAccount() {
        val rpId = nextRpId()
        val request = CredentialRequestFixtures.beginCreateRequest(
            CredentialRequestFixtures.createRequestJson(
                rpId = rpId,
                userName = "grace@example.com",
                userDisplayName = "Grace Hopper"
            )
        )

        val response = runBlocking { handler.handleBeginCreateCredential(request) }

        assertEquals(
            "The system UI should be offered exactly one account to create under",
            1,
            response.createEntries.size
        )
        assertEquals("Grace Hopper", response.createEntries.first().accountName.toString())
    }

    @Test
    fun beginCreateCredential_rejectsNonPublicKeyRequests() {
        val request = BeginCreatePasswordCredentialRequest(
            CredentialRequestFixtures.appWithoutOrigin(),
            Bundle()
        )

        assertThrows(InvalidRequestException::class.java) {
            runBlocking { handler.handleBeginCreateCredential(request) }
        }
    }

    // ---------------------------------------------------------------------
    // Origin policy
    // ---------------------------------------------------------------------

    @Test
    fun privilegedBrowserRequest_producesAWebAuthnAttestationResponse() {
        val rpId = nextRpId()

        val response = JSONObject(register(rpId))

        assertEquals("public-key", response.getString("type"))
        assertEquals("platform", response.getString("authenticatorAttachment"))
        assertEquals(
            "id and rawId identify the same credential",
            response.getString("id"),
            response.getString("rawId")
        )
        assertTrue(response.has("clientExtensionResults"))

        val inner = response.getJSONObject("response")
        assertTrue(inner.has("attestationObject"))
        assertTrue(inner.has("authenticatorData"))
        assertTrue(inner.has("publicKey"))
        assertEquals(-7, inner.getInt("publicKeyAlgorithm"))
        assertEquals("internal", inner.getJSONArray("transports").getString(0))
        assertFalse(
            "The browser authored the client data, so the provider must not " +
                "return a clientDataJSON of its own",
            inner.has("clientDataJSON")
        )
    }

    @Test
    fun selfBuiltClientData_isRefusedWhenTheCallerHasNoVerifiedOrigin() {
        val rpId = nextRpId()
        val request = CredentialRequestFixtures.providerCreateRequest(
            requestJson = CredentialRequestFixtures.createRequestJson(rpId),
            clientDataHash = null,
            callingAppInfo = CredentialRequestFixtures.appWithoutOrigin()
        )

        val failure = assertThrows(CredentialCreationException::class.java) {
            runBlocking { handler.handleCreateCredential(request, userVerified = true) }
        }

        assertTrue(
            "The refusal should name the missing origin, not invent one: ${failure.message}",
            failure.message!!.contains("verified web origin")
        )
        assertTrue(
            "A refused ceremony must not leave a credential behind",
            runBlocking { credentialDao.getByRpId(rpId) }.isEmpty()
        )
    }

    @Test
    fun selfBuiltClientData_isRefusedWhenTheCallerIsNotAPrivilegedBrowser() {
        val rpId = nextRpId()
        val request = CredentialRequestFixtures.providerCreateRequest(
            requestJson = CredentialRequestFixtures.createRequestJson(rpId),
            clientDataHash = null,
            callingAppInfo = CredentialRequestFixtures.unprivilegedAppClaimingOrigin()
        )

        val failure = assertThrows(CredentialCreationException::class.java) {
            runBlocking { handler.handleCreateCredential(request, userVerified = true) }
        }

        assertTrue(
            "Origin verification should be the reported cause: ${failure.message}",
            failure.message!!.contains("origin")
        )
        assertNotNull("The framework failure should be preserved", failure.cause)
        assertTrue(
            "A refused ceremony must not leave a credential behind",
            runBlocking { credentialDao.getByRpId(rpId) }.isEmpty()
        )
    }

    // ---------------------------------------------------------------------
    // Authenticator data
    // ---------------------------------------------------------------------

    @Test
    fun verifiedRegistration_setsTheUserVerifiedFlag() {
        val authData = authenticatorDataOf(register(nextRpId(), userVerified = true))

        assertEquals(
            "UP|UV|AT must be set when the user really was verified",
            0x45,
            authData.flags
        )
    }

    @Test
    fun unverifiedRegistration_clearsTheUserVerifiedFlag() {
        val response = register(
            rpId = nextRpId(),
            userVerified = false,
            userVerification = "discouraged"
        )

        val authData = authenticatorDataOf(response)

        assertEquals(
            "UP|AT only — the UV bit is what a relying party trusts and must " +
                "never be asserted for a ceremony that did not verify anyone",
            0x41,
            authData.flags
        )
        assertTrue(authData.userPresent)
        assertFalse(authData.userVerified)
        assertTrue(authData.attestedCredentialData)
    }

    @Test
    fun authenticatorData_bindsTheRelyingPartyByRpIdHash() {
        val rpId = nextRpId()

        val authData = authenticatorDataOf(register(rpId))

        assertArrayEquals(
            MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray()),
            authData.rpIdHash
        )
    }

    @Test
    fun authenticatorData_startsAtSignCountZeroWithTheAllZeroAaguid() {
        val authData = authenticatorDataOf(register(nextRpId()))

        assertEquals("A freshly minted credential has never been used", 0L, authData.signCount)
        assertArrayEquals(
            "\"none\" attestation identifies no authenticator model",
            ByteArray(16),
            authData.aaguid
        )
    }

    @Test
    fun authenticatorData_lengthPrefixesTheCredentialId() {
        val rpId = nextRpId()
        val response = JSONObject(register(rpId))
        val credentialId = CredentialRequestFixtures.decodeUrl(response.getString("rawId"))

        val authData = AuthenticatorData(
            CredentialRequestFixtures.decodeUrl(
                response.getJSONObject("response").getString("authenticatorData")
            )
        )

        assertEquals(credentialId.size, authData.credentialIdLength)
        assertArrayEquals(
            "The embedded credential id must be the one the response advertises",
            credentialId,
            authData.credentialId
        )
    }

    @Test
    fun authenticatorData_carriesTheCoseKeyThatWasPersisted() {
        val rpId = nextRpId()
        val response = JSONObject(register(rpId))
        val credentialId = response.getString("id")

        val authData = AuthenticatorData(
            CredentialRequestFixtures.decodeUrl(
                response.getJSONObject("response").getString("authenticatorData")
            )
        )
        val stored = runBlocking { credentialDao.getByCredentialId(credentialId) }

        assertNotNull("The credential should have been persisted", stored)
        assertArrayEquals(
            "The attested COSE key and the stored COSE key are the same key",
            stored!!.publicKeyCose,
            authData.coseKey
        )
    }

    @Test
    fun attestationObject_isValidCborWithNoneAttestation() {
        val rpId = nextRpId()
        val response = JSONObject(register(rpId)).getJSONObject("response")

        val attestation = parseAttestationObject(
            CredentialRequestFixtures.decodeUrl(response.getString("attestationObject"))
        )

        assertEquals("none", attestation.fmt)
        assertEquals(
            "\"none\" attestation carries an empty statement",
            0,
            attestation.attestationStatementEntryCount
        )
        assertArrayEquals(
            "The attestation object must wrap the same authenticator data the " +
                "response reports separately",
            CredentialRequestFixtures.decodeUrl(response.getString("authenticatorData")),
            attestation.authData
        )
    }

    @Test
    fun publicKeyField_isTheDerSpkiOfTheGeneratedKeystoreKey() {
        val rpId = nextRpId()
        val response = JSONObject(register(rpId))
        val credentialId = response.getString("id")
        val inner = response.getJSONObject("response")

        val advertised = CredentialRequestFixtures.decodeUrl(inner.getString("publicKey"))
        val fromKeystore = keystoreManager.getPublicKey(credentialId)

        assertNotNull("The Keystore should hold the generated key", fromKeystore)
        assertArrayEquals(
            "Chromium requires SubjectPublicKeyInfo here, not the COSE key",
            fromKeystore!!.encoded,
            advertised
        )

        val reparsed = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(advertised))
        assertTrue("The advertised key must parse as an EC public key", reparsed is ECPublicKey)

        val authData = AuthenticatorData(
            CredentialRequestFixtures.decodeUrl(inner.getString("authenticatorData"))
        )
        assertFalse(
            "publicKey (DER) and the attested key (COSE) are different encodings",
            advertised.contentEquals(authData.coseKey)
        )
    }

    // ---------------------------------------------------------------------
    // Credential ids
    // ---------------------------------------------------------------------

    @Test
    fun credentialIds_are32BytesAndUniquePerRegistration() {
        val rpId = nextRpId()

        val first = JSONObject(register(rpId)).getString("rawId")
        val second = JSONObject(register(rpId)).getString("rawId")

        assertEquals(32, CredentialRequestFixtures.decodeUrl(first).size)
        assertEquals(32, CredentialRequestFixtures.decodeUrl(second).size)
        assertNotEquals(
            "Two registrations for the same relying party must not collide",
            first,
            second
        )
    }

    // ---------------------------------------------------------------------
    // Algorithm negotiation
    // ---------------------------------------------------------------------

    @Test
    fun requestWithoutEs256_isRejected() {
        val rpId = nextRpId()
        val request = CredentialRequestFixtures.providerCreateRequest(
            CredentialRequestFixtures.createRequestJson(
                rpId = rpId,
                algorithms = listOf(CredentialRequestFixtures.COSE_RS256)
            )
        )

        assertThrows(InvalidRequestException::class.java) {
            runBlocking { handler.handleCreateCredential(request, userVerified = true) }
        }
        assertTrue(runBlocking { credentialDao.getByRpId(rpId) }.isEmpty())
    }

    @Test
    fun requestListingEs256AmongOtherAlgorithms_isAccepted() {
        val rpId = nextRpId()

        val response = JSONObject(
            register(
                rpId = rpId,
                algorithms = listOf(
                    CredentialRequestFixtures.COSE_RS256,
                    CredentialRequestFixtures.COSE_ES256
                )
            )
        )

        assertEquals(-7, response.getJSONObject("response").getInt("publicKeyAlgorithm"))
    }

    // ---------------------------------------------------------------------
    // excludeCredentials
    // ---------------------------------------------------------------------

    @Test
    fun registeringAnExcludedCredential_isRefused() {
        val rpId = nextRpId()
        val existing = JSONObject(register(rpId)).getString("id")

        val request = CredentialRequestFixtures.providerCreateRequest(
            CredentialRequestFixtures.createRequestJson(
                rpId = rpId,
                excludeCredentialIds = listOf(existing)
            )
        )

        val failure = assertThrows(CredentialCreationException::class.java) {
            runBlocking { handler.handleCreateCredential(request, userVerified = true) }
        }
        assertTrue(failure.message!!.contains("already exists"))
        assertEquals(
            "The excluded registration must not have added a second credential",
            1,
            runBlocking { credentialDao.getByRpId(rpId) }.size
        )
    }

    @Test
    fun excludeCredentialsListingUnknownIds_doesNotBlockRegistration() {
        val rpId = nextRpId()
        val unknown = CredentialRequestFixtures.encodeUrl(ByteArray(32) { 0x5A.toByte() })

        val response = JSONObject(
            register(rpId = rpId, excludeCredentialIds = listOf(unknown))
        )

        assertNotEquals(unknown, response.getString("id"))
    }

    // ---------------------------------------------------------------------
    // Discoverability
    // ---------------------------------------------------------------------

    @Test
    fun residentKeyRequired_storesADiscoverableCredential() {
        val rpId = nextRpId()

        val credentialId = JSONObject(register(rpId, residentKey = "required")).getString("id")

        assertTrue(runBlocking { credentialDao.getByCredentialId(credentialId) }!!.isDiscoverable)
    }

    @Test
    fun residentKeyDiscouraged_storesANonDiscoverableCredential() {
        val rpId = nextRpId()

        val credentialId = JSONObject(register(rpId, residentKey = "discouraged")).getString("id")

        assertFalse(runBlocking { credentialDao.getByCredentialId(credentialId) }!!.isDiscoverable)
    }

    // ---------------------------------------------------------------------
    // User verification policy
    // ---------------------------------------------------------------------

    @Test
    fun requiredUserVerificationWithoutVerification_isRefusedAndPersistsNothing() {
        val rpId = nextRpId()
        val request = CredentialRequestFixtures.providerCreateRequest(
            CredentialRequestFixtures.createRequestJson(rpId, userVerification = "required")
        )

        assertThrows(UserVerificationRequiredException::class.java) {
            runBlocking { handler.handleCreateCredential(request, userVerified = false) }
        }
        assertTrue(
            "Refusal must happen before any key is minted",
            runBlocking { credentialDao.getByRpId(rpId) }.isEmpty()
        )
    }

    @Test
    fun requiredUserVerificationWithoutVerification_proceedsWithUv0WhenStrictModeIsOff() {
        val rpId = nextRpId()
        val request = CredentialRequestFixtures.providerCreateRequest(
            CredentialRequestFixtures.createRequestJson(rpId, userVerification = "required")
        )

        val authData = withStrictUserVerification(false) {
            authenticatorDataOf(
                runBlocking { handler.handleCreateCredential(request, userVerified = false) }
            )
        }

        assertFalse(
            "Relaxing strictness relaxes the refusal, never the honesty of the UV bit",
            authData.userVerified
        )
        assertEquals(0x41, authData.flags)
    }

    @Test
    fun requiredUserVerificationWithVerification_isAccepted() {
        val rpId = nextRpId()

        val authData = authenticatorDataOf(
            register(rpId, userVerified = true, userVerification = "required")
        )

        assertTrue(authData.userVerified)
    }

    // ---------------------------------------------------------------------
    // Persistence
    // ---------------------------------------------------------------------

    @Test
    fun registration_mirrorsTheCredentialIntoTheUnifiedKeyStore() {
        val rpId = nextRpId()
        val credentialId = JSONObject(
            register(rpId, residentKey = "required", userName = "ada@example.com")
        ).getString("id")

        val key = runBlocking { keyDao.getByKeyId(credentialId) }

        assertNotNull("The passkey should also appear in the unified key store", key)
        assertEquals("fido2", key!!.keyType)
        assertEquals("ES256", key.algorithm)
        assertEquals(256, key.keySizeBits)
        assertEquals("local", key.source)
        assertEquals(rpId, key.rpId)
        assertEquals("ada@example.com", key.userName)
        assertTrue(key.isDiscoverable)
        assertEquals(0L, key.signCount)
    }

    @Test
    fun registration_persistsTheRelyingPartyAndUserItWasAskedFor() {
        val rpId = nextRpId()
        val credentialId = JSONObject(
            register(
                rpId = rpId,
                rpName = "Fixture Bank",
                userId = "dXNlci03",
                userName = "ada@example.com",
                userDisplayName = "Ada Lovelace"
            )
        ).getString("id")

        val stored = runBlocking { credentialDao.getByCredentialId(credentialId) }!!

        assertEquals(rpId, stored.rpId)
        assertEquals("Fixture Bank", stored.rpName)
        assertEquals("dXNlci03", stored.userId)
        assertEquals("ada@example.com", stored.userName)
        assertEquals("Ada Lovelace", stored.userDisplayName)
        assertEquals(0L, stored.signCount)
    }

    // ---------------------------------------------------------------------
    // Malformed input
    // ---------------------------------------------------------------------

    @Test
    fun nonPublicKeyCallingRequest_isRejected() {
        val request = ProviderCreateCredentialRequest(
            CreatePasswordRequest("user@example.com", "hunter2"),
            CredentialRequestFixtures.appWithoutOrigin()
        )

        assertThrows(InvalidRequestException::class.java) {
            runBlocking { handler.handleCreateCredential(request, userVerified = true) }
        }
    }

    @Test
    fun requestWithoutARelyingParty_isRejectedAndPersistsNothing() {
        val rpId = nextRpId()
        val request = CredentialRequestFixtures.providerCreateRequest(
            CredentialRequestFixtures.createRequestJson(rpId, omitRp = true)
        )

        // Every mandatory member is read inside one guarded block, so a missing
        // one reports as a malformed request rather than escaping as a raw
        // JSONException that no caller of this handler expects.
        assertThrows(InvalidRequestException::class.java) {
            runBlocking { handler.handleCreateCredential(request, userVerified = true) }
        }
        assertTrue(runBlocking { credentialDao.getByRpId(rpId) }.isEmpty())
    }

    @Test
    fun requestWithoutAChallenge_isRejectedWhenTheProviderMustAuthorClientData() {
        val rpId = nextRpId()
        val json = JSONObject(CredentialRequestFixtures.createRequestJson(rpId))
        json.remove("challenge")
        val request = CredentialRequestFixtures.providerCreateRequest(
            requestJson = json.toString(),
            clientDataHash = null
        )

        assertThrows(InvalidRequestException::class.java) {
            runBlocking { handler.handleCreateCredential(request, userVerified = true) }
        }
        assertTrue(runBlocking { credentialDao.getByRpId(rpId) }.isEmpty())
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /** Registers a credential and returns the raw response JSON. */
    private fun register(
        rpId: String,
        userVerified: Boolean = true,
        rpName: String = "Fixture RP",
        userId: String = "dXNlci1pZA",
        userName: String = "user@example.com",
        userDisplayName: String = "Fixture User",
        algorithms: List<Int> = listOf(CredentialRequestFixtures.COSE_ES256),
        userVerification: String? = null,
        residentKey: String? = null,
        excludeCredentialIds: List<String> = emptyList()
    ): String {
        val request = CredentialRequestFixtures.providerCreateRequest(
            CredentialRequestFixtures.createRequestJson(
                rpId = rpId,
                rpName = rpName,
                userId = userId,
                userName = userName,
                userDisplayName = userDisplayName,
                algorithms = algorithms,
                userVerification = userVerification,
                residentKey = residentKey,
                excludeCredentialIds = excludeCredentialIds
            )
        )
        return runBlocking { handler.handleCreateCredential(request, userVerified) }
    }

    private fun authenticatorDataOf(responseJson: String): AuthenticatorData =
        AuthenticatorData(
            CredentialRequestFixtures.decodeUrl(
                JSONObject(responseJson)
                    .getJSONObject("response")
                    .getString("authenticatorData")
            )
        )

    /** Runs [body] with strict user verification forced to [enabled]. */
    private fun <T> withStrictUserVerification(enabled: Boolean, body: () -> T): T {
        val original = runBlocking { settingsRepository.getSettings() }
        runBlocking {
            settingsRepository.updateSettings(original.copy(strictUserVerification = enabled))
        }
        try {
            return body()
        } finally {
            runBlocking { settingsRepository.updateSettings(original) }
        }
    }

    /** A relying party unique to this run, registered for cleanup. */
    private fun nextRpId(): String {
        val rpId = "create-$RUN_ID-${rpCounter++}.xkey.test"
        touchedRpIds += rpId
        return rpId
    }

    private fun <T : Throwable> assertThrows(expected: Class<T>, body: () -> Unit): T {
        try {
            body()
        } catch (thrown: Throwable) {
            if (expected.isInstance(thrown)) {
                @Suppress("UNCHECKED_CAST")
                return thrown as T
            }
            throw AssertionError(
                "Expected ${expected.simpleName} but ${thrown.javaClass.simpleName} was thrown",
                thrown
            )
        }
        fail("Expected ${expected.simpleName} but nothing was thrown")
        throw IllegalStateException("unreachable")
    }

    private companion object {
        /** Keeps relying-party names unique across repeated runs on a device. */
        val RUN_ID: String = java.lang.Long.toString(System.nanoTime(), 36)
    }
}
