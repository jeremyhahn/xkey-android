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
import androidx.biometric.BiometricManager
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
import com.automatethethings.xkey.ui.assertActivityDestroyed
import kotlinx.coroutines.runBlocking
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
 * Only the platform can build a genuine provider request, so a well-formed
 * request JSON still stops at the retrieval guard here; what these cases
 * prove is that nothing on the way there (request parsing, the credential id,
 * user verification) writes a row or answers with a credential.
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

    @Test
    fun getWithGarbledRequestJson_failsWithoutACredential() {
        assertFailsWithoutCredential(
            selector(
                CredentialSelectorActivity.ACTION_GET_CREDENTIAL,
                credentialId = UNKNOWN_CREDENTIAL_ID,
                requestJson = GARBLED_JSON,
            ),
            GET_MARKER,
        )
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

    @Test
    fun getForAnUnknownCredentialId_failsWithoutACredential() {
        assertFailsWithoutCredential(
            selector(
                CredentialSelectorActivity.ACTION_GET_CREDENTIAL,
                credentialId = UNKNOWN_CREDENTIAL_ID,
                requestJson = CredentialRequestFixtures.getRequestJson(
                    RP_ID,
                    allowCredentialIds = listOf(UNKNOWN_CREDENTIAL_ID),
                ),
            ),
            GET_MARKER,
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
     * Dismissing the selector's verification prompt cancels the create:
     * an interrupted create-family error, and no credential row.
     */
    @Test
    fun createWithUserVerificationDismissed_failsWithoutACredential() {
        assumeTrue("This device cannot verify the user, so no prompt is shown", canVerifyUser())
        val before = storedCredentials()
        val device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())

        val scenario = ActivityScenario.launchActivityForResult<CredentialSelectorActivity>(
            selector(
                CredentialSelectorActivity.ACTION_CREATE_CREDENTIAL,
                requestJson = CredentialRequestFixtures.createRequestJson(RP_ID, userVerification = "required"),
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
        assertEquals("no credential row may be written", before, storedCredentials())
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun selector(action: String, credentialId: String? = null, requestJson: String? = null): Intent =
        Intent(context, CredentialSelectorActivity::class.java).apply {
            this.action = action
            credentialId?.let { putExtra(CredentialSelectorActivity.EXTRA_CREDENTIAL_ID, it) }
            requestJson?.let { putExtra(CredentialSelectorActivity.EXTRA_REQUEST_JSON, it) }
        }

    private fun assertFailsWithoutCredential(intent: Intent, marker: String) {
        val before = storedCredentials()

        val scenario = ActivityScenario.launchActivityForResult<CredentialSelectorActivity>(intent)
        assertActivityDestroyed(scenario)
        val result = scenario.result

        assertEquals(Activity.RESULT_CANCELED, result.resultCode)
        assertExceptionFamily(result, marker)
        assertEquals("no credential row may be written", before, storedCredentials())
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
        const val GARBLED_JSON = "{\"rpId\":\"example.com\",\"challenge\":"
        const val PROMPT_TITLE = "Create xKey Credential"
        const val PROMPT_TIMEOUT_MS = 10_000L
        const val AUTHENTICATORS = BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
    }
}
