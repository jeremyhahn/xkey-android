/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
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
package com.automatethethings.xkey.e2e

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import android.util.Log
import com.automatethethings.xkey.credential.CredentialProviderSettingsRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TestName
import org.junit.runner.RunWith
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * End-to-end passkey test against the **go-xkms WebAuthn relying party**, not a
 * public site, so the ceremony is deterministic, offline, and proves interop
 * with the actual backend:
 *
 *   Chrome -> go-xkms RP -> CredentialManager -> XKeyCredentialService
 *   -> Keystore -> assertion -> go-xkms verifies it
 *
 * ## Requirements
 *
 * Start the backend and wire it to the device first:
 * ```
 * scripts/webauthn-backend.sh start
 * scripts/webauthn-backend.sh provider
 * ```
 * That builds and runs `go-xkms/examples/webauthn/server` on plain HTTP and
 * runs `adb reverse`, so the RP is reachable at `http://localhost:18443` *on
 * the device*. localhost is a WebAuthn secure context, which is why no TLS
 * certificate has to be trusted on the device.
 *
 * The test skips (rather than fails) when the backend is not reachable, so a
 * plain `connectedDebugAndroidTest` run does not fail for want of a server.
 *
 * ## Emulator notes
 * - Chrome must have completed its first-run flow.
 * - With no biometric enrolled, `CredentialSelectorActivity` skips the prompt
 *   and the created key is not auth-bound (see `CreateCredentialHandler`).
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
class WebAuthnE2ETest {

    companion object {
        /** Must match `WEBAUTHN_PORT` in scripts/webauthn-backend.sh. */
        private const val RP_PORT = 18443
        private const val RP_URL = "http://localhost:$RP_PORT/"

        private const val PAGE_LOAD_TIMEOUT = 15_000L

        /** Chrome's first navigation after a cold start often needs a nudge. */
        private const val PAGE_LOAD_ATTEMPTS = 3
        private const val ELEMENT_TIMEOUT = 10_000L
        private const val CREDENTIAL_MANAGER_TIMEOUT = 15_000L
        private const val POST_ACTION_SETTLE = 2_000L
        private const val E2E_DISPLAY_NAME = "E2E User"
        private const val TAG = "WebAuthnE2ETest"

        /** The provider service the framework must be told about. */
        private const val CREDENTIAL_SERVICE_CLASS =
            "com.automatethethings.xkey.credential.XKeyCredentialService"
    }

    @get:Rule
    val testName = TestName()

    private lateinit var device: UiDevice
    private lateinit var email: String
    private var providerSwitchBefore: Boolean? = null

    @Before
    fun setUp() {
        assumeTrue(
            "go-xkms WebAuthn backend is not reachable on localhost:$RP_PORT — " +
                "run scripts/webauthn-backend.sh start",
            backendIsHealthy()
        )
        device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())

        // The service offers no entries while the in-app switch is off (its
        // default), so turn it on for the ceremony and restore it after.
        val settings = CredentialProviderSettingsRepository(
            ApplicationProvider.getApplicationContext<android.content.Context>()
        )
        runBlocking {
            providerSwitchBefore = settings.isEnabled()
            settings.setEnabled(true)
        }

        // Reinstalling the app drops it from the credential-provider list, which
        // would leave the sheet offering only Google Password Manager. Register
        // it here so the suite does not depend on a manual setup step.
        registerAsCredentialProvider()
        assumeTrue(
            "xKey could not be registered as a credential provider — " +
                "run scripts/webauthn-backend.sh provider",
            xKeyIsRegisteredCredentialProvider()
        )

        email = "e2e-${System.currentTimeMillis()}@example.com"

        device.pressHome()
        device.waitForIdle()
    }

    @After
    fun tearDown() {
        if (::device.isInitialized) device.pressHome()
        // Passkeys created here are real rows in the credential and key
        // stores. Leaving them behind breaks other suites that assert an
        // empty store, so remove exactly what this test created.
        runCatching {
            val context = ApplicationProvider.getApplicationContext<android.content.Context>()
            val database = XKeyDatabase.getInstance(context)
            runBlocking {
                database.credentialMetadataDao().getAll()
                    .filter { it.userName == email || it.userDisplayName == E2E_DISPLAY_NAME }
                    .forEach { credential ->
                        database.credentialMetadataDao().deleteByCredentialId(credential.credentialId)
                        database.keyDao().deleteByKeyId(credential.credentialId)
                    }
            }
        }.onFailure { Log.w(TAG, "passkey cleanup failed: ${it.message}") }
        providerSwitchBefore?.let { before ->
            val context = ApplicationProvider.getApplicationContext<android.content.Context>()
            runBlocking { CredentialProviderSettingsRepository(context).setEnabled(before) }
        }
    }

    /**
     * Registers a passkey with the go-xkms RP, then authenticates with it.
     * Both halves are verified by the RP's own response text, so a signature
     * or user-handle that the RP rejects fails the test.
     */
    @Test
    fun testPasskeyRegistrationAndAuthentication() {
        registerPasskey()
        Thread.sleep(POST_ACTION_SETTLE)
        authenticateWithPasskey()
    }

    private fun registerPasskey() {
        openDemoPage()

        fillField(index = 0, value = email)
        fillField(index = 1, value = E2E_DISPLAY_NAME)
        device.pressBack() // dismiss the keyboard so the buttons are hittable

        clickText("Register")
        confirmCreatePasskeySheet()

        assertNotNull(
            "the RP should confirm registration",
            device.wait(Until.findObject(By.textContains("Registration successful")), PAGE_LOAD_TIMEOUT)
        )
    }

    private fun authenticateWithPasskey() {
        // The page keeps its state, so the email is still populated; only the
        // login ceremony has to run.
        clickText("Login")
        chooseXKeyPasskeySheet()

        assertNotNull(
            "the RP should confirm authentication",
            device.wait(Until.findObject(By.textContains("Login successful")), PAGE_LOAD_TIMEOUT)
        )
    }

    /**
     * Opens the demo page, retrying the navigation.
     *
     * Chrome's first navigation after a cold start regularly does not finish
     * within [PAGE_LOAD_TIMEOUT] on an emulator — the same URL loads immediately
     * on the next attempt. Retrying here keeps that from being reported as an
     * xKey failure; a genuinely unreachable RP still fails, just later.
     */
    private fun openDemoPage() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        repeat(PAGE_LOAD_ATTEMPTS) { attempt ->
            ChromeHelper.launchChromeToUrl(context, device, RP_URL)
            ChromeHelper.waitForPageLoad(device, PAGE_LOAD_TIMEOUT)

            if (device.wait(Until.findObject(By.textContains("WebAuthn Demo")), PAGE_LOAD_TIMEOUT) != null) {
                return
            }
            Log.w(TAG, "the demo page did not load on attempt ${attempt + 1}; retrying")
        }
        failWithDiagnostics(
            "the go-xkms WebAuthn demo page did not load after $PAGE_LOAD_ATTEMPTS attempts"
        )
    }

    /** Fills the nth text field on the page. */
    private fun fillField(index: Int, value: String) {
        device.wait(Until.findObject(By.clazz("android.widget.EditText")), ELEMENT_TIMEOUT)
        val fields = device.findObjects(By.clazz("android.widget.EditText"))
        if (fields.size <= index) {
            failWithDiagnostics("expected at least ${index + 1} text fields, found ${fields.size}")
        }
        fields[index].click()
        device.waitForIdle()
        fields[index].text = value
    }

    private fun clickText(label: String) {
        val target = device.wait(Until.findObject(By.text(label)), ELEMENT_TIMEOUT)
            ?: failWithDiagnostics("could not find '$label' on the page")
        target.click()
        device.waitForIdle()
    }

    /**
     * Confirms the "Create passkey" sheet. It names xKey as the provider and
     * offers a single Continue action — the provider name is a heading, not a
     * tappable choice, so Continue is what advances the ceremony.
     */
    private fun confirmCreatePasskeySheet() {
        val sheet = device.wait(
            Until.findObject(By.textContains("Create passkey")),
            CREDENTIAL_MANAGER_TIMEOUT
        ) ?: failWithDiagnostics("create-passkey sheet never appeared")

        if (!device.hasObject(By.textContains("xKey"))) {
            failWithDiagnostics("create-passkey sheet did not offer xKey as the provider")
        }
        checkNotNull(sheet)

        val continueButton = device.wait(Until.findObject(By.text("Continue")), ELEMENT_TIMEOUT)
            ?: failWithDiagnostics("no Continue button on the create-passkey sheet")
        continueButton.click()
        device.waitForIdle()
        Thread.sleep(POST_ACTION_SETTLE)
    }

    /**
     * Selects the xKey passkey for authentication. The system may open the
     * sheet on a different provider (Google Password Manager also claims the
     * origin), so when xKey is not already listed the choice is made through
     * "Sign-in options".
     */
    private fun chooseXKeyPasskeySheet() {
        val sheetAppeared = device.wait(
            Until.hasObject(By.textContains("passkey")),
            CREDENTIAL_MANAGER_TIMEOUT
        )
        if (!sheetAppeared) {
            failWithDiagnostics("sign-in sheet never appeared")
        }
        // The sheet's first frame carries its title before the provider rows and
        // the "Sign-in options" affordance are composed, so both checks below
        // have to wait rather than probe the instant the title appears.
        device.waitForIdle()
        Thread.sleep(POST_ACTION_SETTLE)

        if (device.wait(Until.hasObject(By.textContains("xKey")), ELEMENT_TIMEOUT) != true) {
            val options = device.wait(
                Until.findObject(By.textContains("Sign-in options")),
                ELEMENT_TIMEOUT
            ) ?: failWithDiagnostics("xKey passkey not offered and no sign-in options to switch")
            options.click()
            device.waitForIdle()
            Thread.sleep(POST_ACTION_SETTLE)
        }

        val xkeyEntry = device.wait(Until.findObject(By.textContains("xKey")), ELEMENT_TIMEOUT)
            ?: failWithDiagnostics("xKey passkey not listed in sign-in options")
        xkeyEntry.click()
        device.waitForIdle()
        Thread.sleep(POST_ACTION_SETTLE)
    }

    private fun failWithDiagnostics(message: String): Nothing {
        ChromeHelper.takeScreenshotOnFailure(device, testName.methodName)
        ChromeHelper.dumpUiHierarchy(device, testName.methodName)
        throw AssertionError(message)
    }

    /**
     * Adds this app to the framework's enabled-credential-provider list.
     *
     * The setting is `secure`, so the app itself cannot write it — but the
     * instrumentation's shell can, which is the same thing
     * `scripts/webauthn-backend.sh provider` does from the host.
     */
    private fun registerAsCredentialProvider() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val service = "${context.packageName}/$CREDENTIAL_SERVICE_CLASS"
        val current = device.executeShellCommand("settings get secure credential_service").trim()
        if (current.contains(service)) return

        val existing = current.takeIf { it.isNotEmpty() && it != "null" }
        val updated = if (existing == null) service else "$existing:$service"
        // Unquoted: `settings put` stores the argument verbatim, so quotes would
        // become part of the value and the framework would not match any provider.
        device.executeShellCommand("settings put secure credential_service $updated")
        device.executeShellCommand("settings put secure credential_service_primary $service")
    }

    /**
     * Reads the framework's enabled-credential-provider list and reports
     * whether this app is on it.
     */
    private fun xKeyIsRegisteredCredentialProvider(): Boolean = try {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val enabled = android.provider.Settings.Secure.getString(
            context.contentResolver, "credential_service"
        )
        // A non-system app cannot always read this setting. Only a readable
        // value that omits this package proves the provider is off; when the
        // value is unavailable, run the test rather than mask a real failure.
        enabled == null || enabled.contains(context.packageName)
    } catch (_: Exception) {
        true
    }

    /**
     * Probes the RP through the adb-reversed tunnel with a raw socket. A plain
     * HTTP request would be blocked by the app's cleartext-traffic policy;
     * Chrome is a separate app and is unaffected, so a successful TCP connect
     * is the right signal that the tunnel and server are up.
     */
    private fun backendIsHealthy(): Boolean = try {
        Socket().use {
            it.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), RP_PORT), 2_000)
            true
        }
    } catch (_: IOException) {
        false
    }
}
