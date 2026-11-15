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

package com.automatethethings.xkey.ble

import android.Manifest
import android.bluetooth.BluetoothDevice
import android.content.Context
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The two [XKeyGattService] entry points that need something outside the
 * service to answer them: the user, and the laptop.
 *
 * `onPairingConfirmationRequired` is the app's whole consent gate. Everything
 * else about pairing is asserted at the protocol layer, but *this* is what
 * decides the boolean those layers act on, and it is pure Android: a dialog
 * shown on the main thread whose three exits — allow, deny, dismiss — each
 * resume a suspended coroutine. A prompt that resumed the wrong way, or twice,
 * or not at all, would either hang the pairing or approve a desktop the user
 * refused.
 *
 * `requestDeviceAttestation` is the mirror image: it asks the *laptop* a
 * question and has to survive any answer. Both of its refusals are asserted
 * here — no transport to ask over, and a laptop that answers with an error —
 * because the caller treats a `false` as "unattested" and a thrown exception as
 * a crash.
 *
 * The service is stood up without `onCreate` — see [XKeyGattServiceProbe] — so
 * nothing here starts a foreground service or touches the radio.
 */
@RunWith(AndroidJUnit4::class)
class XKeyGattServicePairingPromptTest {

    /** `GattServerProbe.establishSession` reads `BluetoothDevice.getName()`. */
    @get:Rule
    val bluetoothPermission: GrantPermissionRule =
        GrantPermissionRule.grant(Manifest.permission.BLUETOOTH_CONNECT)

    private lateinit var context: Context
    private lateinit var probe: XKeyGattServiceProbe

    private var activity: ActivityScenario<MainActivity>? = null
    private var gattProbe: GattServerProbe? = null

    /** Where the prompt is awaited from, so the main thread stays free. */
    private val callerScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        probe = XKeyGattServiceProbe(context)
    }

    @After
    fun tearDown() {
        callerScope.cancel()
        probe.releaseWakeLock()
        gattProbe?.close()
        gattProbe = null
        activity?.close()
        activity = null
    }

    // -----------------------------------------------------------------
    // The consent gate
    // -----------------------------------------------------------------

    /** Nothing may be approved while there is no one to ask. */
    @Test
    fun aPromptWithoutAnActivityIsRefused(): Unit = runBlocking {
        assertFalse(probe.service.onPairingConfirmationRequired("Headless Laptop", "abcd1234"))
    }

    /** Approving the prompt is what grants the desktop its pairing. */
    @Test
    fun approvingThePromptConfirmsTheDesktop(): Unit = runBlocking {
        bindActivity()

        val answer = callerScope.async {
            probe.service.onPairingConfirmationRequired("Approved Laptop", "abcd1234")
        }
        clickDialogButton(android.R.id.button1, answer)

        assertTrue("the user's approval must reach the caller", withTimeout(TIMEOUT_MS) { answer.await() })
    }

    /** And denying it must not. */
    @Test
    fun denyingThePromptRefusesTheDesktop(): Unit = runBlocking {
        bindActivity()

        val answer = callerScope.async {
            probe.service.onPairingConfirmationRequired("Denied Laptop", "abcd1234")
        }
        clickDialogButton(android.R.id.button2, answer)

        assertFalse("the user's refusal must reach the caller", withTimeout(TIMEOUT_MS) { answer.await() })
    }

    /** Unbinding the activity restores the headless refusal. */
    @Test
    fun clearingTheActivityRestoresTheDefaultRefusal(): Unit = runBlocking {
        bindActivity()
        probe.service.setActivity(null)

        assertFalse(probe.service.onPairingConfirmationRequired("Orphaned Laptop", "abcd1234"))
    }

    // -----------------------------------------------------------------
    // Asking the laptop
    // -----------------------------------------------------------------

    /** The state the UI collects is published, whatever it is. */
    @Test
    fun theServiceStateIsPublishedAsAFlow() {
        assertEquals(ServiceState.Stopped, probe.service.serviceState.value)

        probe.serviceState = ServiceState.Advertising

        assertEquals(ServiceState.Advertising, probe.service.serviceState.value)
    }

    /**
     * Attestation is addressed to the *connected* desktop, so a request naming
     * anything else is refused before a byte goes out.
     */
    @Test
    fun attestingSomeOtherDeviceIsRefused(): Unit = runBlocking {
        assertFalse(probe.service.requestDeviceAttestation("00".repeat(32)))
    }

    /**
     * A desktop can be pairing-confirmed while every transport is down —
     * a dropped link leaves the handler's record of it behind. There is then
     * nothing to ask over, and that is a refusal rather than an exception.
     */
    @Test
    fun attestationWithoutAnActiveTransportIsRefused(): Unit = runBlocking {
        val gatt = gattProbe()
        val peerKeyHex = "11".repeat(32)
        gatt.requestHandler.setConnectedDevicePublicKeyHex(peerKeyHex)
        probe.requestHandler = gatt.requestHandler
        // No gattServer, no TCP and no USB: connectedDesktop() has nothing to
        // hand back.

        assertFalse(probe.service.requestDeviceAttestation(peerKeyHex))
    }

    /**
     * And a laptop that cannot attest itself answers with an error. The service
     * reports that as an unattested device rather than letting the exception
     * escape into the pairing flow that called it.
     */
    @Test
    fun anAttestationTheLaptopRefusesIsReportedAsAFailure(): Unit = runBlocking {
        val gatt = gattProbe()
        val device: BluetoothDevice = GattServerProbe.remoteDevice(context, DEVICE_ADDRESS)!!
        gatt.establishSession(device)
        val peerKeyHex = gatt.authenticatedPeerKeyHex!!
        gatt.requestHandler.setConnectedDevicePublicKeyHex(peerKeyHex)

        probe.requestHandler = gatt.requestHandler
        probe.gattServer = gatt.server
        probe.bleMessageRouter = gatt.messageRouter
        assertNotNull("the BLE transport must be the active one", probe.connectedDesktop())

        val attestation = callerScope.async { probe.service.requestDeviceAttestation(peerKeyHex) }

        val refusal = Response.error(
            REMOTE_BASE_REQUEST_ID,
            ErrorCodes.INTERNAL_ERROR,
            "this laptop has no TPM"
        ).toJson()
        val deadline = System.currentTimeMillis() + TIMEOUT_MS
        while (!attestation.isCompleted && System.currentTimeMillis() < deadline) {
            gatt.messageRouter!!.processMessage(refusal)
            delay(POLL_MS)
        }

        assertFalse(
            "a laptop that refuses to attest is unattested, not an error",
            withTimeout(TIMEOUT_MS) { attestation.await() }
        )
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun bindActivity() {
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        activity = scenario
        scenario.onActivity { probe.service.setActivity(it) }
    }

    private fun gattProbe(): GattServerProbe {
        val remote = GattServerProbe.remoteDevice(context, DEVICE_ADDRESS)
        assumeTrue("this device has no Bluetooth adapter", remote != null)
        return GattServerProbe(context).also { gattProbe = it }
    }

    /**
     * Clicks a dialog button once the prompt is actually on screen. The prompt
     * is raised from another coroutine, so it may not exist on the first look.
     */
    private fun clickDialogButton(buttonId: Int, pending: Deferred<*>) {
        val deadline = System.currentTimeMillis() + TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            if (pending.isCompleted) return
            val clicked = runCatching {
                onView(withId(buttonId)).inRoot(isDialog()).perform(click())
            }
            if (clicked.isSuccess) return
            Thread.sleep(POLL_MS)
        }
        throw AssertionError("the pairing prompt never appeared")
    }

    private companion object {
        const val DEVICE_ADDRESS = "AA:BB:CC:DD:EE:FA"

        /** `RemoteKeyClient.BASE_REQUEST_ID`. */
        const val REMOTE_BASE_REQUEST_ID = 1_000_000L

        const val TIMEOUT_MS = 20_000L
        const val POLL_MS = 100L
    }
}
