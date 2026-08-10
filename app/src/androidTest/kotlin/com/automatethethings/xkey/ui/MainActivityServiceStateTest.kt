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
import android.view.View
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogDao
import com.automatethethings.xkey.ble.ServiceState
import com.automatethethings.xkey.storage.XKeyDatabase
import com.google.android.material.bottomnavigation.BottomNavigationView
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The BLE service state machine as [MainActivity] renders it.
 *
 * `MainActivityUiTest` and `MainActivityFlowTest` only ever see the screen at
 * rest, which is the DISCONNECTED arm of `updateConnectionStatus`. Everything
 * the service can report afterwards — advertising, connecting, connected, the
 * connected-device card, the connection timer, the pulse and glow animations and
 * the error snackbar — is unreached, because it takes a bound service and a real
 * peer to produce.
 *
 * `handleServiceStateChange` is the single funnel for all of it, and
 * [ServiceState] is a public sealed class, so this suite feeds the funnel
 * directly. That is the same reflection technique `SettingsFlowSupport` uses to
 * read `SettingsActivity.isInitializing`, and it drives production code exactly
 * as the real `observeServiceState` collector would — the collector's own body
 * is the only thing left uncovered, and it needs a live service.
 *
 * Assertions read the XML-declared views straight off the activity rather than
 * through Espresso. Two of the states start indefinitely-repeating animators,
 * and the hero status text cross-fades over 150 ms in each direction, so every
 * assertion polls.
 *
 * The CONNECTED state writes a `CONNECTION_ESTABLISHED` audit row through
 * `AuditLogger`. That row cannot be cleaned up — it carries no key id, and
 * `AuditLogDao` offers no delete by id or by device — so it is written under a
 * `nanoTime`-derived device name instead, which no other suite can match and no
 * other suite's assertions can be perturbed by: every audit-log test either
 * filters on its own token or reads the live table count.
 */
@RunWith(AndroidJUnit4::class)
class MainActivityServiceStateTest {

    private val runId = System.nanoTime()

    private val deviceName = "UITestDesk$runId"
    private val deviceAddress = "AA:BB:CC:DD:EE:FF"

    private lateinit var context: Context
    private lateinit var auditLogDao: AuditLogDao
    private lateinit var scenario: ActivityScenario<MainActivity>

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        auditLogDao = XKeyDatabase.getInstance(context).auditLogDao()
        scenario = ActivityScenario.launch(MainActivity::class.java)
        awaitStatusLarge(context.getString(R.string.status_disconnected))
    }

    @After
    fun tearDown() {
        // Leave the screen with no animator running so the next suite's launch
        // is not racing an infinite ObjectAnimator on the same views.
        runCatching { dispatch(ServiceState.Stopped) }
        scenario.close()
    }

    // ---------------------------------------------------------------
    // Advertising
    // ---------------------------------------------------------------

    /**
     * Advertising switches the hero, the status card and the advertising line
     * together, and leaves the connected-device card hidden.
     */
    @Test
    fun advertising_announcesItselfAcrossTheHeroAndTheStatusCard() {
        dispatch(ServiceState.Advertising)

        awaitStatusLarge(context.getString(R.string.status_advertising))
        awaitStatusDescription(context.getString(R.string.advertising_waiting))
        assertTextIs(R.id.textConnectionStatus, context.getString(R.string.status_advertising))
        assertTextIs(R.id.textAdvertisingStatus, context.getString(R.string.advertising_on))
        assertConnectedCardShown(false)
        // Any non-disconnected state marks the BLE control active.
        assertTextIs(R.id.textBleStatus, context.getString(R.string.ble_switch_on))
    }

    /** Returning to Stopped tears the advertising presentation back down. */
    @Test
    fun stoppedAfterAdvertising_restoresTheDisconnectedPresentation() {
        dispatch(ServiceState.Advertising)
        awaitStatusLarge(context.getString(R.string.status_advertising))

        dispatch(ServiceState.Stopped)

        awaitStatusLarge(context.getString(R.string.status_disconnected))
        awaitStatusDescription(context.getString(R.string.connection_indicator_disconnected))
        assertTextIs(R.id.textAdvertisingStatus, context.getString(R.string.advertising_off))
        assertTextIs(R.id.textBleStatus, context.getString(R.string.ble_switch_off))
    }

    /**
     * Ready differs from Stopped only in that it leaves the connection timer
     * alone; both present as disconnected and not advertising.
     */
    @Test
    fun ready_presentsAsDisconnectedButNotAdvertising() {
        dispatch(ServiceState.Advertising)
        awaitStatusLarge(context.getString(R.string.status_advertising))

        dispatch(ServiceState.Ready)

        awaitStatusLarge(context.getString(R.string.status_disconnected))
        assertTextIs(R.id.textAdvertisingStatus, context.getString(R.string.advertising_off))
        assertConnectedCardShown(false)
    }

    // ---------------------------------------------------------------
    // Connecting
    // ---------------------------------------------------------------

    /** A handshake in progress reads as connecting and keeps advertising on. */
    @Test
    fun connecting_reportsTheHandshakeAndKeepsAdvertisingOn() {
        dispatch(ServiceState.Connecting)

        awaitStatusLarge(context.getString(R.string.status_connecting))
        awaitStatusDescription(context.getString(R.string.connection_indicator_connecting))
        assertTextIs(R.id.textConnectionStatus, context.getString(R.string.status_connecting))
        assertTextIs(R.id.textAdvertisingStatus, context.getString(R.string.advertising_on))
    }

    // ---------------------------------------------------------------
    // Connected
    // ---------------------------------------------------------------

    /**
     * A connected peer reveals the device card with its name and address, starts
     * the connection timer and records the connection in the audit log.
     */
    @Test
    fun connected_revealsTheDeviceCardAndStartsTheTimer() {
        dispatch(ServiceState.Connected(deviceName, deviceAddress))

        awaitStatusLarge(context.getString(R.string.status_connected))
        awaitStatusDescription(context.getString(R.string.connection_indicator_connected))
        assertTextIs(R.id.textConnectedDeviceName, deviceName)
        assertTextIs(R.id.textConnectedDeviceAddress, deviceAddress)
        assertTextIs(R.id.textAdvertisingStatus, context.getString(R.string.advertising_off))
        assertConnectedCardShown(true)

        assertTrue(
            "The connection timer should start counting",
            awaitActivity(scenario) {
                val timer = it.findViewById<TextView>(R.id.textConnectionDuration)
                timer.visibility == View.VISIBLE &&
                    timer.text?.toString()?.startsWith("Connected for ") == true
            }
        )

        assertTrue(
            "Connecting should be recorded in the audit log",
            awaitDatabaseCondition {
                runBlocking { auditLogDao.getAll() }.any { it.deviceName == deviceName }
            }
        )
    }

    /**
     * Disconnecting hides the device card again and stops the timer.
     *
     * The card fades out over 200 ms before it is marked GONE, which is why the
     * assertion polls rather than reading once.
     */
    @Test
    fun stoppedAfterConnected_hidesTheDeviceCardAndTheTimer() {
        dispatch(ServiceState.Connected(deviceName, deviceAddress))
        assertConnectedCardShown(true)

        dispatch(ServiceState.Stopped)

        assertConnectedCardShown(false)
        assertTrue(
            "The connection timer should be hidden again",
            awaitActivity(scenario) {
                it.findViewById<View>(R.id.textConnectionDuration).visibility == View.GONE
            }
        )
        awaitStatusLarge(context.getString(R.string.status_disconnected))
    }

    /**
     * The connected-device card belongs to the Dashboard: switching tabs must
     * not carry it across, and returning must bring it back.
     */
    @Test
    fun theConnectedDeviceCard_isDashboardOnly() {
        dispatch(ServiceState.Connected(deviceName, deviceAddress))
        assertConnectedCardShown(true)

        selectTab(R.id.nav_management)
        assertConnectedCardShown(false)

        selectTab(R.id.nav_dashboard)
        assertConnectedCardShown(true)
    }

    // ---------------------------------------------------------------
    // Error
    // ---------------------------------------------------------------

    /** A service error surfaces verbatim in a snackbar. */
    @Test
    fun anError_surfacesItsMessageVerbatim() {
        val message = "service exploded $runId"

        dispatch(ServiceState.Error(message))

        assertTrue(
            "The service error message should be shown",
            awaitActivity(scenario) {
                findShownTextViewContaining(it.window.decorView, message) != null
            }
        )
        // An error is not a state change: the hero is left as it was.
        assertTextIs(R.id.textStatusLarge, context.getString(R.string.status_disconnected))
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /** Feeds [state] to the activity exactly as the service collector would. */
    private fun dispatch(state: ServiceState) {
        val method = MainActivity::class.java.getDeclaredMethod(
            "handleServiceStateChange",
            ServiceState::class.java
        ).apply { isAccessible = true }
        scenario.onActivity { method.invoke(it, state) }
        waitForIdle()
    }

    /** Selects a bottom-navigation destination by its menu id. */
    private fun selectTab(itemId: Int) {
        scenario.onActivity { activity ->
            activity.findViewById<BottomNavigationView>(R.id.bottomNavigation).selectedItemId = itemId
        }
        waitForIdle()
    }

    /** Polls until the hero status line reads [text]; it cross-fades to change. */
    private fun awaitStatusLarge(text: String) {
        assertTrue(
            "Expected the hero status to read '$text'",
            awaitActivity(scenario) {
                it.findViewById<TextView>(R.id.textStatusLarge).text?.toString() == text
            }
        )
    }

    /** Polls until the hero description line reads [text]. */
    private fun awaitStatusDescription(text: String) {
        assertTrue(
            "Expected the hero description to read '$text'",
            awaitActivity(scenario) {
                it.findViewById<TextView>(R.id.textStatusDescription).text?.toString() == text
            }
        )
    }

    /** Asserts the [TextView] with [viewId] settles on [text]. */
    private fun assertTextIs(viewId: Int, text: String) {
        assertTrue(
            "Expected ${context.resources.getResourceEntryName(viewId)} to read '$text'",
            awaitActivity(scenario) {
                it.findViewById<TextView>(viewId).text?.toString() == text
            }
        )
    }

    /** Asserts the connected-device card reaches [shown]; it fades both ways. */
    private fun assertConnectedCardShown(shown: Boolean) {
        assertTrue(
            "Expected the connected-device card to be ${if (shown) "shown" else "hidden"}",
            awaitActivity(scenario) {
                it.findViewById<View>(R.id.cardConnectedDevice).isShown == shown
            }
        )
    }

    /**
     * Polls [condition] until it holds, for checks that read the database
     * rather than the view tree.
     *
     * `AuditLogger` writes asynchronously on its own scope, so the row is not
     * there the instant the state handler returns.
     */
    private fun awaitDatabaseCondition(condition: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + UI_AWAIT_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return true
            Thread.sleep(POLL_INTERVAL_MS)
        }
        return false
    }

    private companion object {
        const val POLL_INTERVAL_MS = 50L
    }
}
