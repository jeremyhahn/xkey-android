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

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.biometric.BiometricManager
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.exceptions.CreateCredentialInterruptedException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import com.automatethethings.xkey.credential.ui.CredentialSelectorActivity
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.ui.assertActivityDestroyed
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkAll
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The selector's error paths end in an error result and leave no credential.
 *
 * The framework starts [CredentialSelectorActivity] from the pending intent
 * the user picks; a malformed or hostile start must hand back
 * `RESULT_CANCELED` with an exception of the operation's own family, and
 * must neither store nor return a credential. Each case counts the stored
 * credential rows before and after the launch.
 *
 * Only the platform attaches a provider request to the intent, so the cases
 * that name a failure past the retrieval guard (an unknown credential id, a
 * malformed request JSON, a cancelled user verification) stub
 * `PendingIntentHandler`'s retrieval to hand the selector the request the
 * framework would, and assert the error only that failure produces. The
 * other cases stop at the guard and prove that nothing on the way there
 * writes a row or answers with a credential.
 *
 * The user-verification case needs a device that can verify the user: it
 * waits for the selector's prompt and dismisses it. Every other create case
 * needs a device that cannot, since no test can answer the prompt.
 */
@SdkSuppress(minSdkVersion = Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@RunWith(AndroidJUnit4::class)
class CredentialSelectorErrorPathTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    @Before
    fun requireCredentialProviderApi() {
        assumeTrue(Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    }

    @After
    fun tearDown() {
        unmockkAll()
        runBlocking {
            XKeyDatabase.getInstance(context).credentialMetadataDao().deleteByCredentialId(SEEDED_CREDENTIAL_ID)
        }
    }

    // ---------------------------------------------------------------
    // No extras
    // ---------------------------------------------------------------

    @Test
    fun startedWithNoActionOrExtras_failsWithoutACredential() {
        assertFailsWithoutCredential(
            Intent(context, CredentialSelectorActivity::class.java),
            CREATE_MARKER,
        )
    }

    @Test
    fun getStartedWithNoExtras_failsWithoutACredential() {
        assertFailsWithoutCredential(selector(CredentialSelectorActivity.ACTION_GET_CREDENTIAL), GET_MARKER)
    }

    @Test
    fun createStartedWithNoExtras_failsWithoutACredential() {
        assertFailsWithoutCredential(selector(CredentialSelectorActivity.ACTION_CREATE_CREDENTIAL), CREATE_MARKER)
    }

    // ---------------------------------------------------------------
    // Garbled request JSON
    // ---------------------------------------------------------------

    /**
     * A stored credential takes the get past its lookup, so the request JSON
     * is parsed: the malformed-request error, never the missing-request or
     * unknown-credential one.
     */
    @Test
    fun getWithGarbledRequestJson_failsWithoutACredential() {
        seedCredential(SEEDED_CREDENTIAL_ID)

        val result = assertFailsWithoutCredential(
            selector(
                CredentialSelectorActivity.ACTION_GET_CREDENTIAL,
                credentialId = SEEDED_CREDENTIAL_ID,
                requestJson = GARBLED_JSON,
                providerRequestJson = GARBLED_JSON,
            ),
            GET_MARKER,
        )

        assertError(result, GET_MARKER, GetCredentialUnknownException().type, MALFORMED_JSON_ERROR)
    }

    @Test
    fun createWithGarbledRequestJson_failsWithoutACredential() {
        assumeNoAuthenticator()

        assertFailsWithoutCredential(
            selector(CredentialSelectorActivity.ACTION_CREATE_CREDENTIAL, requestJson = GARBLED_JSON),
            CREATE_MARKER,
        )
    }

    @Test
    fun createWithTruncatedRequestJson_failsWithoutACredential() {
        assumeNoAuthenticator()
        val json = CredentialRequestFixtures.createRequestJson(RP_ID)

        assertFailsWithoutCredential(
            selector(CredentialSelectorActivity.ACTION_CREATE_CREDENTIAL, requestJson = json.dropLast(json.length / 2)),
            CREATE_MARKER,
        )
    }

    // ---------------------------------------------------------------
    // Unknown credential id
    // ---------------------------------------------------------------

    /**
     * With a provider request to retrieve, the get reaches the credential
     * lookup: the unknown-credential error naming the id, never the
     * missing-request one.
     */
    @Test
    fun getForAnUnknownCredentialId_failsWithoutACredential() {
        val json = CredentialRequestFixtures.getRequestJson(RP_ID, allowCredentialIds = listOf(UNKNOWN_CREDENTIAL_ID))

        val result = assertFailsWithoutCredential(
            selector(
                CredentialSelectorActivity.ACTION_GET_CREDENTIAL,
                credentialId = UNKNOWN_CREDENTIAL_ID,
                requestJson = json,
                providerRequestJson = json,
            ),
            GET_MARKER,
        )

        assertError(
            result,
            GET_MARKER,
            GetCredentialUnknownException().type,
            "$UNKNOWN_CREDENTIAL_ERROR$UNKNOWN_CREDENTIAL_ID",
        )
    }

    @Test
    fun getWithAnEmptyCredentialId_failsWithoutACredential() {
        assertFailsWithoutCredential(
            selector(
                CredentialSelectorActivity.ACTION_GET_CREDENTIAL,
                credentialId = "",
                requestJson = CredentialRequestFixtures.getRequestJson(RP_ID),
            ),
            GET_MARKER,
        )
    }

    // ---------------------------------------------------------------
    // User verification dismissed
    // ---------------------------------------------------------------

    /**
     * Dismissing the selector's verification prompt cancels the create: an
     * interrupted create error, and no credential row. The selector has a
     * create request to retrieve, so a cancellation that wrongly went on to
     * create would store a row or answer with another error type.
     */
    @Test
    fun createWithUserVerificationDismissed_failsWithoutACredential() {
        assumeTrue("This device cannot verify the user, so no prompt is shown", canVerifyUser())
        val before = storedCredentials()
        val device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
        val json = CredentialRequestFixtures.createRequestJson(RP_ID, userVerification = "required")

        val scenario = ActivityScenario.launchActivityForResult<CredentialSelectorActivity>(
            selector(
                CredentialSelectorActivity.ACTION_CREATE_CREDENTIAL,
                requestJson = json,
                providerRequestJson = json,
            )
        )
        assertTrue(
            "the verification prompt should appear",
            device.wait(Until.hasObject(By.text(PROMPT_TITLE)), PROMPT_TIMEOUT_MS) == true,
        )
        device.pressBack()
        assertActivityDestroyed(scenario)
        val result = scenario.result

        assertEquals(Activity.RESULT_CANCELED, result.resultCode)
        assertExceptionFamily(result, CREATE_MARKER)
        assertError(result, CREATE_MARKER, CreateCredentialInterruptedException(CANCELLED_ERROR).type, CANCELLED_ERROR)
        assertFalse(
            "a cancellation is not an unknown create error",
            errorStrings(result, CREATE_MARKER).contains(CreateCredentialUnknownException().type),
        )
        assertEquals("no credential row may be written", before, storedCredentials())
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /**
     * The intent the framework starts the selector with. Given
     * [providerRequestJson], `PendingIntentHandler`'s retrieval for [action]'s
     * operation hands the selector a provider request carrying that JSON, as
     * the framework's own extras would; without it the selector finds none.
     */
    private fun selector(
        action: String,
        credentialId: String? = null,
        requestJson: String? = null,
        providerRequestJson: String? = null,
    ): Intent {
        providerRequestJson?.let { supplyProviderRequest(action, it) }
        return Intent(context, CredentialSelectorActivity::class.java).apply {
            this.action = action
            credentialId?.let { putExtra(CredentialSelectorActivity.EXTRA_CREDENTIAL_ID, it) }
            requestJson?.let { putExtra(CredentialSelectorActivity.EXTRA_REQUEST_JSON, it) }
        }
    }

    /**
     * Stubs the retrieval the selector makes. The get option is a mock so any
     * JSON, malformed included, reaches the handler as given: the androidx
     * option constructor may refuse a malformed one before the selector sees it.
     */
    private fun supplyProviderRequest(action: String, json: String) {
        mockkObject(PendingIntentHandler)
        if (action == CredentialSelectorActivity.ACTION_GET_CREDENTIAL) {
            val option = mockk<GetPublicKeyCredentialOption>(relaxed = true) {
                every { requestJson } returns json
                every { clientDataHash } returns CredentialRequestFixtures.BROWSER_CLIENT_DATA_HASH
            }
            val request = ProviderGetCredentialRequest(listOf(option), CredentialRequestFixtures.appWithoutOrigin())
            every { PendingIntentHandler.retrieveProviderGetCredentialRequest(any()) } returns request
        } else {
            val request = CredentialRequestFixtures.providerCreateRequest(json)
            every { PendingIntentHandler.retrieveProviderCreateCredentialRequest(any()) } returns request
        }
    }

    private fun assertFailsWithoutCredential(intent: Intent, marker: String): Instrumentation.ActivityResult {
        val before = storedCredentials()

        val scenario = ActivityScenario.launchActivityForResult<CredentialSelectorActivity>(intent)
        assertActivityDestroyed(scenario)
        val result = scenario.result

        assertEquals(Activity.RESULT_CANCELED, result.resultCode)
        assertExceptionFamily(result, marker)
        assertEquals("no credential row may be written", before, storedCredentials())
        return result
    }

    /**
     * The error carries exactly [type] and a message containing [message]; the
     * missing-request guard's own message never matches one of these.
     */
    private fun assertError(result: Instrumentation.ActivityResult, marker: String, type: String, message: String) {
        val strings = errorStrings(result, marker)
        assertTrue("expected error type $type, found $strings", strings.contains(type))
        assertTrue("expected an error message containing '$message', found $strings", strings.any { it.contains(message) })
        assertFalse(
            "the selector stopped at the missing-request guard: $strings",
            strings.any { it.contains(MISSING_REQUEST_ERROR) },
        )
    }

    /**
     * The error type and message `PendingIntentHandler` stored for [marker]'s
     * operation: a platform exception on API 34+, or plain values otherwise.
     */
    private fun errorStrings(result: Instrumentation.ActivityResult, marker: String): List<String> {
        val extras = result.resultData?.extras ?: return emptyList()
        return extras.keySet().filter { it.contains(marker) && it.contains(EXCEPTION) }.flatMap { key ->
            @Suppress("DEPRECATION")
            when (val value = extras.get(key)) {
                is android.credentials.CreateCredentialException -> listOfNotNull(value.type, value.message)
                is android.credentials.GetCredentialException -> listOfNotNull(value.type, value.message)
                is Bundle -> value.keySet().mapNotNull { value.getString(it) }
                null -> emptyList()
                else -> listOf(value.toString())
            }
        }
    }

    private fun seedCredential(credentialId: String) = runBlocking {
        XKeyDatabase.getInstance(context).credentialMetadataDao().insert(
            CredentialMetadataEntity(
                credentialId = credentialId,
                rpId = RP_ID,
                rpName = "Example Inc",
                userId = "dXNlci0x",
                userName = "user@example.com",
                userDisplayName = "A User",
                publicKeyCose = byteArrayOf(0xA5.toByte(), 0x01, 0x02),
                signCount = 0L,
                createdAt = 1_700_000_000_000L,
                lastUsedAt = 1_700_000_500_000L,
                isDiscoverable = true,
            )
        )
    }

    /**
     * `PendingIntentHandler` stores an error under a key naming its operation
     * and a credential under a response key; an error result must carry the
     * former and never the latter.
     */
    private fun assertExceptionFamily(result: Instrumentation.ActivityResult, marker: String) {
        assertNotNull("the selector must return result data", result.resultData)
        val keys = result.resultData?.extras?.keySet()?.toSet() ?: emptySet()
        assertTrue("expected a $marker exception, found $keys", keys.any { it.contains(marker) && it.contains(EXCEPTION) })
        assertFalse("an error result must not carry a credential: $keys", keys.any { it.contains(RESPONSE) })
    }

    private fun storedCredentials(): Int = runBlocking {
        XKeyDatabase.getInstance(context).credentialMetadataDao().countAll()
    }

    private fun canVerifyUser(): Boolean =
        BiometricManager.from(context).canAuthenticate(AUTHENTICATORS) == BiometricManager.BIOMETRIC_SUCCESS

    private fun assumeNoAuthenticator() {
        assumeTrue("This device can verify the user, so the create flow would wait on a prompt", !canVerifyUser())
    }

    private companion object {
        const val CREATE_MARKER = "CREATE"
        const val GET_MARKER = "GET"
        const val EXCEPTION = "EXCEPTION"
        const val RESPONSE = "RESPONSE"
        const val RP_ID = "example.com"
        const val UNKNOWN_CREDENTIAL_ID = "bm90LWEtc3RvcmVkLWNyZWRlbnRpYWw"
        const val SEEDED_CREDENTIAL_ID = "c2VsZWN0b3ItZXJyb3ItcGF0aC1zZWVkZWQ"
        const val GARBLED_JSON = "{\"rpId\":\"example.com\",\"challenge\":"

        // The messages the selector hands back (CredentialSelectorActivity,
        // GetCredentialHandler, Errors.kt).
        const val MISSING_REQUEST_ERROR = "Failed to retrieve"
        const val UNKNOWN_CREDENTIAL_ERROR = "No credentials found for relying party: "
        const val MALFORMED_JSON_ERROR = "Invalid request: Failed to parse request JSON"
        const val CANCELLED_ERROR = "User cancelled"
        const val PROMPT_TITLE = "Create xKey Credential"
        const val PROMPT_TIMEOUT_MS = 10_000L
        const val AUTHENTICATORS = BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
    }
}
