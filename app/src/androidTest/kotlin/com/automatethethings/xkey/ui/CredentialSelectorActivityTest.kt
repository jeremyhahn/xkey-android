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
package com.automatethethings.xkey.ui

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
import com.automatethethings.xkey.credential.ui.CredentialSelectorActivity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [CredentialSelectorActivity], the screen the framework
 * launches by PendingIntent when the user picks an xKey passkey in the system
 * credential picker.
 *
 * The activity is transparent and headless — it renders nothing but the system
 * biometric prompt — so the contract under test is its *result*: every failure
 * path must hand back `RESULT_CANCELED` carrying an exception of the right
 * family, because the caller is `androidx.credentials` and it decides what to
 * show the user from the exception type alone. A create flow that reports a
 * get-credential exception (or vice versa) is silently swallowed by the
 * framework, which is why these tests check which exception extra came back
 * rather than just the result code.
 *
 * A genuine provider request can only be built by the platform, so
 * `PendingIntentHandler.retrieveProvider…Request` returns null for every intent
 * a test can construct. That is the point: it drives each flow all the way to
 * its retrieval guard, and on the way the create flow passes through request
 * parsing and user verification.
 *
 * The emulator has no enrolled authenticator, so `attemptUserVerification`
 * continues unverified instead of showing a prompt. The create-flow tests assert
 * that assumption explicitly rather than hanging on a prompt nobody can answer.
 *
 * Coverage:
 * - the unknown-action guard
 * - the create flow: missing request JSON, and all three relying-party name
 *   shapes (named, id-only, unparseable)
 * - the get flow: missing credential id, missing request JSON, and the
 *   retrieval guard
 * - create-family versus get-family exceptions on the way out
 */
@SdkSuppress(minSdkVersion = Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@RunWith(AndroidJUnit4::class)
class CredentialSelectorActivityTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    @Before
    fun requireCredentialProviderApi() {
        assumeTrue(
            "CredentialSelectorActivity requires Android 14+",
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
        )
    }

    // ---------------------------------------------------------------
    // Action dispatch
    // ---------------------------------------------------------------

    /**
     * An unrecognised action is reported as a *create* failure, because
     * `currentAction` is only ever compared against the get action.
     */
    @Test
    fun anUnrecognisedAction_reportsACreateFailure() {
        val result = launchForResult(
            Intent(context, CredentialSelectorActivity::class.java).setAction(
                "com.automatethethings.xkey.credential.ACTION_NOT_A_REAL_ACTION"
            )
        )

        assertEquals(Activity.RESULT_CANCELED, result.resultCode)
        assertExceptionFamily(result, CREATE_MARKER)
    }

    // ---------------------------------------------------------------
    // Create flow
    // ---------------------------------------------------------------

    @Test
    fun create_withoutRequestJson_reportsACreateFailure() {
        val result = launchForResult(createIntent(requestJson = null))

        assertEquals(Activity.RESULT_CANCELED, result.resultCode)
        assertExceptionFamily(result, CREATE_MARKER)
    }

    /** The happy parse: the prompt subtitle names the relying party. */
    @Test
    fun create_withANamedRelyingParty_reachesTheRetrievalGuard() {
        assumeNoAuthenticator()

        val result = launchForResult(
            createIntent(requestJson = """{"rp":{"id":"example.com","name":"Example Inc"}}""")
        )

        assertEquals(Activity.RESULT_CANCELED, result.resultCode)
        assertExceptionFamily(result, CREATE_MARKER)
    }

    /** With no `name`, the relying party id stands in for it. */
    @Test
    fun create_withAnUnnamedRelyingParty_reachesTheRetrievalGuard() {
        assumeNoAuthenticator()

        val result = launchForResult(
            createIntent(requestJson = """{"rp":{"id":"example.com"}}""")
        )

        assertEquals(Activity.RESULT_CANCELED, result.resultCode)
        assertExceptionFamily(result, CREATE_MARKER)
    }

    /** Unparseable JSON must not crash the ceremony; the name falls back. */
    @Test
    fun create_withUnparseableJson_stillFailsCleanly() {
        assumeNoAuthenticator()

        val result = launchForResult(createIntent(requestJson = "not json at all"))

        assertEquals(Activity.RESULT_CANCELED, result.resultCode)
        assertExceptionFamily(result, CREATE_MARKER)
    }

    /** A well-formed request with no `rp` object takes the same fallback. */
    @Test
    fun create_withoutARelyingParty_stillFailsCleanly() {
        assumeNoAuthenticator()

        val result = launchForResult(createIntent(requestJson = """{"challenge":"abc"}"""))

        assertEquals(Activity.RESULT_CANCELED, result.resultCode)
        assertExceptionFamily(result, CREATE_MARKER)
    }

    // ---------------------------------------------------------------
    // Get flow
    // ---------------------------------------------------------------

    @Test
    fun get_withoutACredentialId_reportsAGetFailure() {
        val result = launchForResult(
            getIntent(credentialId = null, requestJson = """{"challenge":"abc"}""")
        )

        assertEquals(Activity.RESULT_CANCELED, result.resultCode)
        assertExceptionFamily(result, GET_MARKER)
    }

    @Test
    fun get_withoutRequestJson_reportsAGetFailure() {
        val result = launchForResult(
            getIntent(credentialId = "credential-under-test", requestJson = null)
        )

        assertEquals(Activity.RESULT_CANCELED, result.resultCode)
        assertExceptionFamily(result, GET_MARKER)
    }

    /**
     * The assertion flow does not prompt up front — verification is bound into
     * the signing operation — so a complete-looking request runs straight to the
     * retrieval guard even on a device that could verify the user.
     */
    @Test
    fun get_withBothExtras_reachesTheRetrievalGuard() {
        val result = launchForResult(
            getIntent(
                credentialId = "credential-under-test",
                requestJson = """{"challenge":"abc","rpId":"example.com"}"""
            )
        )

        assertEquals(Activity.RESULT_CANCELED, result.resultCode)
        assertExceptionFamily(result, GET_MARKER)
    }

    /** The two flows must not report each other's exception type. */
    @Test
    fun theTwoFlowsReportDifferentExceptionFamilies() {
        val createKeys = exceptionKeys(
            launchForResult(Intent(context, CredentialSelectorActivity::class.java))
        )
        val getKeys = exceptionKeys(
            launchForResult(getIntent(credentialId = null, requestJson = null))
        )

        assertTrue("The create flow should return an exception", createKeys.isNotEmpty())
        assertTrue("The get flow should return an exception", getKeys.isNotEmpty())
        assertTrue(
            "A create failure must not be reported as a get failure: $createKeys vs $getKeys",
            createKeys != getKeys
        )
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun createIntent(requestJson: String?): Intent =
        Intent(context, CredentialSelectorActivity::class.java).apply {
            action = CredentialSelectorActivity.ACTION_CREATE_CREDENTIAL
            requestJson?.let {
                putExtra(CredentialSelectorActivity.EXTRA_REQUEST_JSON, it)
            }
        }

    private fun getIntent(credentialId: String?, requestJson: String?): Intent =
        Intent(context, CredentialSelectorActivity::class.java).apply {
            action = CredentialSelectorActivity.ACTION_GET_CREDENTIAL
            credentialId?.let {
                putExtra(CredentialSelectorActivity.EXTRA_CREDENTIAL_ID, it)
            }
            requestJson?.let {
                putExtra(CredentialSelectorActivity.EXTRA_REQUEST_JSON, it)
            }
        }

    /** Launches the selector and waits for it to hand a result back. */
    private fun launchForResult(intent: Intent): Instrumentation.ActivityResult {
        val scenario =
            ActivityScenario.launchActivityForResult<CredentialSelectorActivity>(intent)
        assertActivityDestroyed(scenario)
        return scenario.result
    }

    /**
     * The extras carried back on a result.
     *
     * `PendingIntentHandler` writes the failure under a framework key whose name
     * carries the operation ("…CREATE_CREDENTIAL_EXCEPTION" versus
     * "…GET_CREDENTIAL_EXCEPTION"), which is the only way to tell the two
     * families apart without unparcelling platform types.
     */
    private fun exceptionKeys(result: Instrumentation.ActivityResult): Set<String> =
        result.resultData?.extras?.keySet()?.toSet() ?: emptySet()

    private fun assertExceptionFamily(
        result: Instrumentation.ActivityResult,
        marker: String
    ) {
        assertNotNull("The selector must return result data", result.resultData)
        val keys = exceptionKeys(result)
        assertTrue(
            "Expected a $marker exception on the result, found $keys",
            keys.any { it.contains(marker) }
        )
    }

    /**
     * Skips a create-flow test on a device that can verify the user.
     *
     * The create flow shows a biometric prompt whenever one is available, and no
     * test can answer it; the branch these tests exercise is the unverifiable
     * device, which is what CI emulators are.
     */
    private fun assumeNoAuthenticator() {
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        assumeTrue(
            "This device can verify the user, so the create flow would wait on a prompt",
            BiometricManager.from(context).canAuthenticate(authenticators) !=
                BiometricManager.BIOMETRIC_SUCCESS
        )
    }

    private companion object {
        /** Substring of the framework extra key used for create-credential failures. */
        const val CREATE_MARKER = "CREATE"

        /** Substring of the framework extra key used for get-credential failures. */
        const val GET_MARKER = "GET"
    }
}
