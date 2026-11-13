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
import androidx.credentials.GetPasswordOption
import androidx.credentials.provider.BeginGetPasswordOption
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.credential.handler.GetCredentialHandler
import com.automatethethings.xkey.crypto.BiometricHelper
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.settings.BiometricSettingsRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.ui.MainActivity
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature

/**
 * Instrumented tests for [GetCredentialHandler], the WebAuthn assertion
 * (getAssertion) half of the credential provider.
 *
 * Credentials are seeded directly — a real Android Keystore key plus its
 * `credential_metadata` and `keys` rows — so that every test controls whether
 * the key is auth-bound and none of them depends on whether the device under
 * test happens to have a biometric or device credential enrolled.
 *
 * The centrepiece is [assertionSignature_verifiesAgainstTheCredentialPublicKey]:
 * it takes the bytes the relying party would receive and verifies them the way
 * a relying party would, with [Signature].
 */
@RunWith(AndroidJUnit4::class)
@SdkSuppress(minSdkVersion = Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class GetCredentialHandlerTest {

    private lateinit var context: Context
    private lateinit var handler: GetCredentialHandler
    private lateinit var keystoreManager: KeystoreManager
    private lateinit var credentialDao: CredentialMetadataDao
    private lateinit var keyDao: KeyDao
    private lateinit var settingsRepository: BiometricSettingsRepository

    /** Credentials seeded by the running test, removed in [tearDown]. */
    private val seededCredentialIds = linkedSetOf<String>()

    private var rpCounter = 0

    @Before
    fun setUp() {
        assumeTrue(
            "The credential provider requires Android 14",
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
        )
        context = ApplicationProvider.getApplicationContext()
        AuditLogger.initialize(context)
        handler = GetCredentialHandler(context)
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
            for (credentialId in seededCredentialIds) {
                runCatching { keystoreManager.deleteKey(credentialId) }
                credentialDao.deleteByCredentialId(credentialId)
                keyDao.deleteByKeyId(credentialId)
            }
        }
        seededCredentialIds.clear()
    }

    // ---------------------------------------------------------------------
    // Begin phase
    // ---------------------------------------------------------------------

    @Test
    fun beginGetCredential_returnsAnEntryForEachDiscoverableCredential() {
        val rpId = nextRpId()
        seedCredential(rpId, userName = "ada@example.com")
        seedCredential(rpId, userName = "grace@example.com")

        val response = runBlocking {
            handler.handleBeginGetCredential(
                CredentialRequestFixtures.beginGetRequest(
                    listOf(
                        CredentialRequestFixtures.beginGetOption(
                            CredentialRequestFixtures.getRequestJson(rpId)
                        )
                    )
                )
            )
        }

        assertEquals(
            "Both discoverable credentials for this relying party should be offered",
            2,
            response.credentialEntries.size
        )
    }

    @Test
    fun beginGetCredential_filtersToTheAllowedCredentialIds() {
        val rpId = nextRpId()
        val wanted = seedCredential(rpId, userName = "ada@example.com")
        seedCredential(rpId, userName = "grace@example.com")

        val response = runBlocking {
            handler.handleBeginGetCredential(
                CredentialRequestFixtures.beginGetRequest(
                    listOf(
                        CredentialRequestFixtures.beginGetOption(
                            CredentialRequestFixtures.getRequestJson(
                                rpId = rpId,
                                allowCredentialIds = listOf(wanted.credentialId)
                            )
                        )
                    )
                )
            )
        }

        assertEquals(1, response.credentialEntries.size)
    }

    @Test
    fun beginGetCredential_omitsNonDiscoverableCredentialsFromDiscoverableRequests() {
        val rpId = nextRpId()
        seedCredential(rpId, discoverable = false)

        val response = runBlocking {
            handler.handleBeginGetCredential(
                CredentialRequestFixtures.beginGetRequest(
                    listOf(
                        CredentialRequestFixtures.beginGetOption(
                            CredentialRequestFixtures.getRequestJson(rpId)
                        )
                    )
                )
            )
        }

        assertTrue(
            "A non-discoverable credential cannot answer a discoverable request",
            response.credentialEntries.isEmpty()
        )
    }

    @Test
    fun beginGetCredential_ignoresNonPublicKeyOptions() {
        val response = runBlocking {
            handler.handleBeginGetCredential(
                CredentialRequestFixtures.beginGetRequest(
                    listOf(BeginGetPasswordOption(emptySet(), Bundle(), "password-option"))
                )
            )
        }

        assertTrue(response.credentialEntries.isEmpty())
    }

    // ---------------------------------------------------------------------
    // The signature a relying party checks
    // ---------------------------------------------------------------------

    @Test
    fun assertionSignature_verifiesAgainstTheCredentialPublicKey() {
        val rpId = nextRpId()
        val credential = seedCredential(rpId)
        val clientDataHash = CredentialRequestFixtures.BROWSER_CLIENT_DATA_HASH

        val response = assertFor(credential, rpId, clientDataHash = clientDataHash)
        val inner = JSONObject(response).getJSONObject("response")
        val authData = CredentialRequestFixtures.decodeUrl(inner.getString("authenticatorData"))
        val signature = CredentialRequestFixtures.decodeUrl(inner.getString("signature"))

        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(keystoreManager.getPublicKey(credential.credentialId)!!)
        verifier.update(authData + clientDataHash)

        assertTrue(
            "The assertion must verify over authenticatorData || clientDataHash " +
                "with the credential's own public key",
            verifier.verify(signature)
        )
    }

    @Test
    fun assertionSignature_doesNotVerifyOverDifferentClientData() {
        val rpId = nextRpId()
        val credential = seedCredential(rpId)

        val response = assertFor(credential, rpId)
        val inner = JSONObject(response).getJSONObject("response")
        val authData = CredentialRequestFixtures.decodeUrl(inner.getString("authenticatorData"))
        val signature = CredentialRequestFixtures.decodeUrl(inner.getString("signature"))

        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(keystoreManager.getPublicKey(credential.credentialId)!!)
        verifier.update(authData + MessageDigest.getInstance("SHA-256").digest("other".toByteArray()))

        assertFalse(
            "The signature must be bound to the client data it was made over",
            verifier.verify(signature)
        )
    }

    // ---------------------------------------------------------------------
    // Response shape
    // ---------------------------------------------------------------------

    @Test
    fun assertionResponse_hasTheWebAuthnShape() {
        val rpId = nextRpId()
        val credential = seedCredential(rpId, userId = "dXNlci05")

        val response = JSONObject(assertFor(credential, rpId))

        assertEquals(credential.credentialId, response.getString("id"))
        assertEquals(credential.credentialId, response.getString("rawId"))
        assertEquals("public-key", response.getString("type"))
        assertEquals("platform", response.getString("authenticatorAttachment"))
        assertTrue(response.has("clientExtensionResults"))

        val inner = response.getJSONObject("response")
        assertTrue(inner.has("authenticatorData"))
        assertTrue(inner.has("signature"))
        assertEquals("dXNlci05", inner.getString("userHandle"))
    }

    @Test
    fun assertion_omitsClientDataJsonWhenTheBrowserSuppliedTheHash() {
        val rpId = nextRpId()
        val credential = seedCredential(rpId)

        val inner = JSONObject(assertFor(credential, rpId)).getJSONObject("response")

        assertFalse(
            "The browser authored the client data; echoing a different one back " +
                "would not match the hash that was signed",
            inner.has("clientDataJSON")
        )
    }

    // ---------------------------------------------------------------------
    // Origin policy
    // ---------------------------------------------------------------------

    @Test
    fun assertion_isRefusedWhenTheCallerHasNoVerifiedOrigin() {
        val rpId = nextRpId()
        val credential = seedCredential(rpId)
        val request = CredentialRequestFixtures.providerGetRequest(
            requestJson = CredentialRequestFixtures.getRequestJson(rpId),
            clientDataHash = null,
            callingAppInfo = CredentialRequestFixtures.appWithoutOrigin()
        )

        val failure = assertThrows(CredentialAssertionException::class.java) {
            runBlocking { handler.handleGetCredential(request, credential.credentialId) }
        }

        assertTrue(
            "The refusal should name the missing origin: ${failure.message}",
            failure.message!!.contains("verified web origin")
        )
        assertEquals(
            "A refused ceremony must not advance the signature counter",
            0L,
            storedSignCount(credential.credentialId)
        )
    }

    @Test
    fun assertion_isRefusedWhenTheCallerIsNotAPrivilegedBrowser() {
        val rpId = nextRpId()
        val credential = seedCredential(rpId)
        val request = CredentialRequestFixtures.providerGetRequest(
            requestJson = CredentialRequestFixtures.getRequestJson(rpId),
            clientDataHash = null,
            callingAppInfo = CredentialRequestFixtures.unprivilegedAppClaimingOrigin()
        )

        val failure = assertThrows(CredentialAssertionException::class.java) {
            runBlocking { handler.handleGetCredential(request, credential.credentialId) }
        }

        assertNotNull("The framework failure should be preserved", failure.cause)
        assertEquals(0L, storedSignCount(credential.credentialId))
    }

    // ---------------------------------------------------------------------
    // Authenticator data
    // ---------------------------------------------------------------------

    @Test
    fun unverifiedAssertion_clearsTheUserVerifiedFlag() {
        val rpId = nextRpId()
        val credential = seedCredential(rpId, biometricRequired = false)

        val authData = authenticatorDataOf(
            assertFor(credential, rpId, userVerification = "discouraged")
        )

        assertEquals("UP only — no attested credential data, no UV", 0x01, authData.flags)
        assertTrue(authData.userPresent)
        assertFalse(authData.userVerified)
        assertFalse(authData.attestedCredentialData)
    }

    @Test
    fun verifiedAssertion_setsTheUserVerifiedFlagAndStillProducesAVerifiableSignature() {
        val rpId = nextRpId()
        // An auth-bound key record is what makes the handler commit to UV=1
        // before it builds (and therefore signs) the authenticator data.
        val credential = seedCredential(rpId, biometricRequired = true)
        val clientDataHash = CredentialRequestFixtures.BROWSER_CLIENT_DATA_HASH

        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            var helper: BiometricHelper? = null
            scenario.onActivity { activity -> helper = BiometricHelper(activity) }
            val verifyingHandler = GetCredentialHandler(context, helper)

            val response = runBlocking {
                verifyingHandler.handleGetCredential(
                    CredentialRequestFixtures.providerGetRequest(
                        requestJson = CredentialRequestFixtures.getRequestJson(rpId),
                        clientDataHash = clientDataHash
                    ),
                    credential.credentialId
                )
            }

            val inner = JSONObject(response).getJSONObject("response")
            val authData = CredentialRequestFixtures.decodeUrl(inner.getString("authenticatorData"))
            assertEquals("UP|UV", 0x05, AuthenticatorData(authData).flags)

            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(keystoreManager.getPublicKey(credential.credentialId)!!)
            verifier.update(authData + clientDataHash)
            assertTrue(
                "The UV bit is inside the signed authenticator data, so the " +
                    "signature must cover it",
                verifier.verify(CredentialRequestFixtures.decodeUrl(inner.getString("signature")))
            )
        }
    }

    @Test
    fun assertion_refusesToSignSilentlyOnceItHasAssertedUserVerification() {
        val rpId = nextRpId()
        val credential = seedCredential(rpId, biometricRequired = true)

        // No BiometricHelper: the handler has decided UV=1 and has no way to
        // actually verify anyone, so it must fail rather than sign a lie.
        val failure = assertThrows(CredentialAssertionException::class.java) {
            runBlocking {
                handler.handleGetCredential(
                    CredentialRequestFixtures.providerGetRequest(
                        CredentialRequestFixtures.getRequestJson(rpId)
                    ),
                    credential.credentialId
                )
            }
        }

        assertTrue(
            "The message should explain that no prompt was available: ${failure.message}",
            failure.message!!.contains("no biometric prompt is available")
        )
        // The refusal comes before anything is signed, so the counter, which
        // is reserved only once the assertion is going to be signed, stays put.
        assertEquals(
            "A refused ceremony must not advance the signature counter",
            0L,
            storedSignCount(credential.credentialId)
        )
    }

    @Test
    fun authenticatorData_bindsTheRelyingPartyByRpIdHash() {
        val rpId = nextRpId()
        val credential = seedCredential(rpId)

        val authData = authenticatorDataOf(assertFor(credential, rpId))

        assertArrayEquals(
            MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray()),
            authData.rpIdHash
        )
    }

    // ---------------------------------------------------------------------
    // Signature counter
    // ---------------------------------------------------------------------

    @Test
    fun signCount_incrementsAndIsPersistedInBothStores() {
        val rpId = nextRpId()
        val credential = seedCredential(rpId)
        assertEquals(0L, storedSignCount(credential.credentialId))

        val first = authenticatorDataOf(assertFor(credential, rpId))

        assertEquals(
            "The reported counter is the new value, not the stored one",
            1L,
            first.signCount
        )
        assertEquals(1L, storedSignCount(credential.credentialId))
        val key = runBlocking { keyDao.getByKeyId(credential.credentialId) }!!
        assertEquals(
            "The unified key store mirrors the counter",
            1L,
            key.signCount
        )
        assertEquals("Using a passkey counts as a key usage", 1L, key.useCount)

        // A second login on the same, already-used credential must advance
        // from the persisted counter, not report 1 again (relying parties
        // treat a non-increasing counter as a cloned authenticator).
        val second = authenticatorDataOf(assertFor(credential, rpId))

        assertEquals(
            "The second assertion advances the already-used counter",
            2L,
            second.signCount
        )
        assertEquals(2L, storedSignCount(credential.credentialId))
        assertEquals(
            "The unified key store mirrors the advanced counter",
            2L,
            runBlocking { keyDao.getByKeyId(credential.credentialId) }!!.signCount
        )
    }

    // ---------------------------------------------------------------------
    // Failure paths
    // ---------------------------------------------------------------------

    @Test
    fun unknownCredential_isRejected() {
        val rpId = nextRpId()
        val unknown = CredentialRequestFixtures.encodeUrl(ByteArray(32) { 0x3C.toByte() })

        assertThrows(NoCredentialsFoundException::class.java) {
            runBlocking {
                handler.handleGetCredential(
                    CredentialRequestFixtures.providerGetRequest(
                        CredentialRequestFixtures.getRequestJson(rpId)
                    ),
                    unknown
                )
            }
        }
    }

    @Test
    fun rpIdMismatch_isRejectedAndLeavesTheSignCountUntouched() {
        val rpId = nextRpId()
        val otherRpId = nextRpId()
        val credential = seedCredential(rpId)

        val failure = assertThrows(InvalidRequestException::class.java) {
            runBlocking {
                handler.handleGetCredential(
                    CredentialRequestFixtures.providerGetRequest(
                        CredentialRequestFixtures.getRequestJson(otherRpId)
                    ),
                    credential.credentialId
                )
            }
        }

        assertTrue(failure.message!!.contains("RP ID mismatch"))
        assertEquals(
            "A credential must never sign for a relying party it does not belong to",
            0L,
            storedSignCount(credential.credentialId)
        )
    }

    @Test
    fun requestWithoutAPublicKeyOption_isRejected() {
        val rpId = nextRpId()
        val credential = seedCredential(rpId)
        val request = ProviderGetCredentialRequest(
            listOf(GetPasswordOption()),
            CredentialRequestFixtures.appWithoutOrigin()
        )

        assertThrows(InvalidRequestException::class.java) {
            runBlocking { handler.handleGetCredential(request, credential.credentialId) }
        }
        assertEquals(0L, storedSignCount(credential.credentialId))
    }

    @Test
    fun requestWithoutAChallenge_isRejectedWhenTheProviderMustAuthorClientData() {
        val rpId = nextRpId()
        val credential = seedCredential(rpId)
        val request = CredentialRequestFixtures.providerGetRequest(
            requestJson = CredentialRequestFixtures.getRequestJson(rpId, omitChallenge = true),
            clientDataHash = null
        )

        // A missing challenge reports as a malformed request rather than
        // escaping as a raw JSONException that no caller of this handler expects.
        assertThrows(InvalidRequestException::class.java) {
            runBlocking { handler.handleGetCredential(request, credential.credentialId) }
        }
        assertEquals(0L, storedSignCount(credential.credentialId))
    }

    // ---------------------------------------------------------------------
    // User verification policy
    // ---------------------------------------------------------------------

    @Test
    fun requiredUserVerification_isRefusedWhenTheDeviceCannotVerify() {
        val rpId = nextRpId()
        val credential = seedCredential(rpId, biometricRequired = false)

        // No BiometricHelper and a key that is not auth-bound: this device
        // cannot verify the user for this ceremony, whatever it has enrolled.
        assertThrows(UserVerificationRequiredException::class.java) {
            runBlocking {
                handler.handleGetCredential(
                    CredentialRequestFixtures.providerGetRequest(
                        CredentialRequestFixtures.getRequestJson(
                            rpId = rpId,
                            userVerification = "required"
                        )
                    ),
                    credential.credentialId
                )
            }
        }
        assertEquals(0L, storedSignCount(credential.credentialId))
    }

    @Test
    fun requiredUserVerification_proceedsWithUv0WhenStrictModeIsOff() {
        val rpId = nextRpId()
        val credential = seedCredential(rpId, biometricRequired = false)

        val authData = withStrictUserVerification(false) {
            authenticatorDataOf(
                assertFor(credential, rpId, userVerification = "required")
            )
        }

        assertFalse(
            "Relaxing strictness relaxes the refusal, never the honesty of the UV bit",
            authData.userVerified
        )
        assertEquals(0x01, authData.flags)
    }

    @Test
    fun discouragedUserVerification_neverVerifiesEvenWhenTheDeviceCould() {
        val rpId = nextRpId()
        val credential = seedCredential(rpId, biometricRequired = false)

        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            var helper: BiometricHelper? = null
            scenario.onActivity { activity -> helper = BiometricHelper(activity) }
            val verifyingHandler = GetCredentialHandler(context, helper)

            val response = runBlocking {
                verifyingHandler.handleGetCredential(
                    CredentialRequestFixtures.providerGetRequest(
                        CredentialRequestFixtures.getRequestJson(
                            rpId = rpId,
                            userVerification = "discouraged"
                        )
                    ),
                    credential.credentialId
                )
            }

            assertFalse(authenticatorDataOf(response).userVerified)
        }
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /** A credential seeded into the Keystore and both stores. */
    private class SeededCredential(
        val credentialId: String,
        val rpId: String,
        val userId: String
    )

    /**
     * Creates a real, non-auth-bound P-256 Keystore key and both database rows.
     *
     * The key is never auth-bound so that signing is deterministic on any
     * device; [biometricRequired] only sets the recorded policy, which is what
     * the handler consults when deciding whether to assert `UV`.
     */
    private fun seedCredential(
        rpId: String,
        userName: String = "user@example.com",
        userId: String = "dXNlci1pZA",
        discoverable: Boolean = true,
        biometricRequired: Boolean = false
    ): SeededCredential {
        val rawId = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val credentialId = CredentialRequestFixtures.encodeUrl(rawId)
        val publicKeyCose = runBlocking {
            keystoreManager.generateKeyWithAuthDuration(
                credentialId = credentialId,
                authDurationSeconds = -1,
                requireStrongBox = false
            )
        }
        seededCredentialIds += credentialId

        runBlocking {
            credentialDao.insert(
                CredentialMetadataEntity(
                    credentialId = credentialId,
                    rpId = rpId,
                    rpName = "Fixture RP",
                    userId = userId,
                    userName = userName,
                    userDisplayName = "Fixture User",
                    publicKeyCose = publicKeyCose,
                    signCount = 0,
                    isDiscoverable = discoverable
                )
            )
            keyDao.insert(
                KeyEntity(
                    keyId = credentialId,
                    keyType = "fido2",
                    algorithm = "ES256",
                    label = "Fixture RP",
                    publicKeyCose = publicKeyCose,
                    keySizeBits = 256,
                    biometricRequired = biometricRequired,
                    authDurationSeconds = -1,
                    source = "local",
                    rpId = rpId,
                    rpName = "Fixture RP",
                    userId = userId,
                    userName = userName,
                    userDisplayName = "Fixture User",
                    isDiscoverable = discoverable,
                    signCount = 0
                )
            )
        }
        return SeededCredential(credentialId, rpId, userId)
    }

    /** Runs an assertion for [credential] and returns the raw response JSON. */
    private fun assertFor(
        credential: SeededCredential,
        rpId: String,
        userVerification: String? = null,
        clientDataHash: ByteArray = CredentialRequestFixtures.BROWSER_CLIENT_DATA_HASH
    ): String {
        val request = CredentialRequestFixtures.providerGetRequest(
            requestJson = CredentialRequestFixtures.getRequestJson(
                rpId = rpId,
                userVerification = userVerification
            ),
            clientDataHash = clientDataHash
        )
        return runBlocking { handler.handleGetCredential(request, credential.credentialId) }
    }

    private fun authenticatorDataOf(responseJson: String): AuthenticatorData =
        AuthenticatorData(
            CredentialRequestFixtures.decodeUrl(
                JSONObject(responseJson)
                    .getJSONObject("response")
                    .getString("authenticatorData")
            )
        )

    private fun storedSignCount(credentialId: String): Long =
        runBlocking { credentialDao.getByCredentialId(credentialId) }!!.signCount

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

    /** A relying party unique to this run. */
    private fun nextRpId(): String = "get-$RUN_ID-${rpCounter++}.xkey.test"

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
