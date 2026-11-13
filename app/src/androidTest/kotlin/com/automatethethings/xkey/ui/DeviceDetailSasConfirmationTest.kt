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

import android.content.Context
import android.content.Intent
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.doesNotExist
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import com.automatethethings.xkey.R
import com.automatethethings.xkey.settings.PairedDeviceRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The real SAS confirmation dialog of a session the phone opens from
 * [DeviceDetailActivity] (#137).
 *
 * The JVM tests drive BleClient with a recording callback; these drive the
 * activity's own callback: the dialog shows the transcript's SAS and the
 * fingerprint, Allow is consent, Deny is refusal, a cancelled prompt takes its
 * dialog down, and leaving the screen with a prompt open shows no fallback
 * dialog and does not crash.
 */
@RunWith(AndroidJUnit4::class)
class DeviceDetailSasConfirmationTest {

    private lateinit var repository: PairedDeviceRepository
    private lateinit var scenario: ActivityScenario<DeviceDetailActivity>
    private val promptScope = CoroutineScope(Dispatchers.Main)

    @Before
    fun setUp() {
        repository = PairedDeviceRepository(ApplicationProvider.getApplicationContext<Context>())
        repository.removeDevice(KEY_HEX)
        repository.addDevice(publicKeyHex = KEY_HEX, deviceName = DEVICE_NAME)
        scenario = ActivityScenario.launch(
            Intent(ApplicationProvider.getApplicationContext(), DeviceDetailActivity::class.java)
                .putExtra(DeviceDetailActivity.EXTRA_PUBLIC_KEY_HEX, KEY_HEX)
        )
    }

    @After
    fun tearDown() {
        scenario.close()
        repository.removeDevice(KEY_HEX)
    }

    @Test
    fun theDialogShowsTheSasAndTheFingerprint() {
        val answer = prompt()

        onView(withText(expectedMessage())).inRoot(isDialog()).check(matches(isDisplayed()))
        onView(withText(R.string.pairing_dialog_title)).inRoot(isDialog()).check(matches(isDisplayed()))

        answer.cancel()
    }

    @Test
    fun allowIsConsent() {
        val answer = prompt()

        onView(withText(R.string.pairing_dialog_allow)).inRoot(isDialog()).perform(click())

        assertEquals(true, await(answer))
    }

    @Test
    fun denyIsRefusal() {
        val answer = prompt()

        onView(withText(R.string.pairing_dialog_deny)).inRoot(isDialog()).perform(click())

        assertEquals(false, await(answer))
    }

    @Test
    fun aCancelledPromptDismissesItsDialog() {
        val answer = prompt()
        onView(withText(expectedMessage())).inRoot(isDialog()).check(matches(isDisplayed()))

        answer.cancel()
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()

        onView(withText(expectedMessage())).check(doesNotExist())
        assertTrue(answer.isCancelled)
    }

    /**
     * onDestroy cancels the activity's scope while the SAS prompt is open. That
     * cancellation must end the re-attest quietly: no "connection failed"
     * fallback dialog on a destroyed activity, and no crash.
     */
    @Test
    fun destroyingTheActivityWithASasPendingShowsNoDialog() {
        val reached = CompletableDeferred<Unit>()
        var job: Job? = null
        scenario.onActivity { activity ->
            job = activity.launchPhoneInitiatedReattest(null) {
                reached.complete(Unit)
                activity.sasConfirmation()
                    .onPairingConfirmationRequired(DEVICE_NAME, FINGERPRINT, SAS)
                fail("The prompt cannot be answered in this test")
            }
        }
        runBlocking { withTimeout(TIMEOUT_MS) { reached.await() } }
        onView(withText(expectedMessage())).inRoot(isDialog()).check(matches(isDisplayed()))
        val texts = withActivity(scenario) {
            listOf(
                it.getString(R.string.device_reattest_title),
                it.getString(R.string.device_reattest_connection_failed),
                it.getString(R.string.pairing_dialog_title)
            )
        }

        scenario.moveToState(Lifecycle.State.DESTROYED)
        runBlocking { withTimeout(TIMEOUT_MS) { job!!.join() } }
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()

        assertTrue("onDestroy must cancel the pending re-attest", job!!.isCancelled)
        val device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
        texts.forEach { text ->
            assertNull("No '$text' may show after the screen is gone", device.findObject(By.text(text)))
        }
    }

    private fun prompt(): Deferred<Boolean> {
        var answer: Deferred<Boolean>? = null
        scenario.onActivity { activity ->
            val callback = activity.sasConfirmation()
            answer = promptScope.async {
                callback.onPairingConfirmationRequired(DEVICE_NAME, FINGERPRINT, SAS)
            }
        }
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()
        return answer!!
    }

    private fun await(answer: Deferred<Boolean>): Boolean = try {
        runBlocking { withTimeout(TIMEOUT_MS) { answer.await() } }
    } catch (e: CancellationException) {
        throw AssertionError("The prompt never answered", e)
    }

    private fun expectedMessage(): String = withActivity(scenario) {
        it.getString(R.string.pairing_dialog_message_sas, DEVICE_NAME, FINGERPRINT, SAS)
    }

    private companion object {
        const val KEY_HEX = "5a5c" + "37" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
        const val DEVICE_NAME = "SAS Test Desktop"
        const val FINGERPRINT = "AB:CD:EF:01:23:45:67:89"
        const val SAS = "482 913"
        const val TIMEOUT_MS = 10_000L
    }
}
