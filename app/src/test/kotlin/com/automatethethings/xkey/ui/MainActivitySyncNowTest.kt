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
package com.automatethethings.xkey.ui

import android.Manifest
import android.app.Application
import android.content.ComponentName
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.room.Room
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ble.ServiceState
import com.automatethethings.xkey.ble.XKeyGattService
import com.automatethethings.xkey.remote.RemoteSyncClient
import com.automatethethings.xkey.storage.XKeyDatabase
import com.google.android.material.snackbar.Snackbar
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.lang.reflect.Proxy
import java.time.Duration
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale
import java.util.concurrent.atomic.AtomicReference

/**
 * The home screen's Sync Now card: what it tells the user while a sync runs,
 * when it completes (with the desktop's own last sync line) and when it fails.
 * The bound [XKeyGattService] is a mock; the real service is never started.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class MainActivitySyncNowTest {

    private val app = ApplicationProvider.getApplicationContext<Application>()
    private lateinit var database: XKeyDatabase
    private lateinit var service: XKeyGattService
    private lateinit var binder: XKeyGattService.LocalBinder

    @Before
    fun setUp() {
        resetSnackbarManager()
        FakeAndroidKeyStore.install()
        database = Room.inMemoryDatabaseBuilder(app, XKeyDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        install(database)

        service = mockk(relaxed = true)
        every { service.serviceState } returns MutableStateFlow<ServiceState>(ServiceState.Ready)
        every { service.isAdvertising() } returns false
        binder = mockk()
        every { binder.getService() } returns service
        shadowOf(app).setComponentNameAndServiceForBindService(
            ComponentName(app, XKeyGattService::class.java),
            binder
        )
    }

    @After
    fun tearDown() {
        XKeyDatabase.closeAndClear()
        resetSnackbarManager()
    }

    /**
     * Drops Material's process-wide SnackbarManager. A record a test left
     * current (its timeout dropped with the looper, its view detached
     * mid-animation) is dismissed but never reports back while its weakly
     * held callback lives, so every later Snackbar waits behind it unshown.
     */
    private fun resetSnackbarManager() {
        snackbarManagerType.getDeclaredField("snackbarManager").apply { isAccessible = true }.set(null, null)
    }

    /** Leaves a record current whose dismissal never completes; the callback returned must stay reachable. */
    private fun leaveStuckSnackbar(): Any {
        val callbackType = Class.forName("com.google.android.material.snackbar.SnackbarManager\$Callback")
        val callback = Proxy.newProxyInstance(callbackType.classLoader, arrayOf(callbackType)) { proxy, method, args ->
            when (method.name) {
                "equals" -> proxy === args?.get(0)
                "hashCode" -> System.identityHashCode(proxy)
                else -> null
            }
        }
        val manager = snackbarManagerType.getDeclaredMethod("getInstance").apply { isAccessible = true }.invoke(null)
        snackbarManagerType.getDeclaredMethod("show", Int::class.javaPrimitiveType, callbackType)
            .apply { isAccessible = true }
            .invoke(manager, Snackbar.LENGTH_INDEFINITE, callback)
        return callback
    }

    private val snackbarManagerType = Class.forName("com.google.android.material.snackbar.SnackbarManager")

    /** Makes [db] the instance [XKeyDatabase.getInstance] returns. */
    @Suppress("UNCHECKED_CAST")
    private fun install(db: XKeyDatabase) {
        val field = XKeyDatabase::class.java.getDeclaredField("instanceRef").apply { isAccessible = true }
        (field.get(null) as AtomicReference<XKeyDatabase?>).set(db)
    }

    /** The Bluetooth permissions that let onCreate start and bind the service. */
    private fun grantBluetooth() {
        shadowOf(app).grantPermissions(
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_SCAN
        )
    }

    /**
     * Runs what is due on the main looper and moves time on far enough for a
     * Snackbar to finish animating out, so the next one is shown.
     */
    private fun idleMainLooper(duration: Duration = Duration.ofMillis(400)) {
        shadowOf(Looper.getMainLooper()).idle()
        shadowOf(Looper.getMainLooper()).idleFor(duration)
        shadowOf(Looper.getMainLooper()).idle()
    }

    private fun launch(): ActivityScenario<MainActivity> =
        ActivityScenario.launch(MainActivity::class.java).also { idleMainLooper(Duration.ZERO) }

    private fun tapSyncNow(scenario: ActivityScenario<MainActivity>) {
        scenario.onActivity { it.findViewById<View>(R.id.cardSyncNow).performClick() }
        idleMainLooper()
    }

    /** The text of every Snackbar under [root]. */
    private fun snackbarTexts(root: View): List<String> {
        val texts = mutableListOf<String>()
        fun walk(view: View) {
            if (view is TextView && view.id == com.google.android.material.R.id.snackbar_text) {
                texts += view.text.toString()
            }
            if (view is ViewGroup) (0 until view.childCount).forEach { walk(view.getChildAt(it)) }
        }
        walk(root)
        return texts
    }

    private fun snackbarTexts(scenario: ActivityScenario<MainActivity>): List<String> {
        var texts = emptyList<String>()
        scenario.onActivity { texts = snackbarTexts(it.window.decorView) }
        return texts
    }

    private fun assertShows(scenario: ActivityScenario<MainActivity>, expected: String) {
        val texts = snackbarTexts(scenario)
        assertTrue("no Snackbar says \"$expected\": $texts", expected in texts)
    }

    private fun completeText(pushed: Int, pulled: Int, desktopLine: String) =
        app.getString(R.string.sync_complete, pushed, pulled) + "\n" + desktopLine

    private val result = RemoteSyncClient.SyncResult(
        certsPushed = 1,
        oathPushed = 2,
        passwordsPulled = 4,
        oathPulled = 3
    )

    @Test
    fun `a running sync shows sync in progress`() {
        grantBluetooth()
        val pending = CompletableDeferred<RemoteSyncClient.SyncResult>()
        coEvery { service.syncNow() } coAnswers { pending.await() }

        launch().use { scenario ->
            tapSyncNow(scenario)

            assertShows(scenario, app.getString(R.string.sync_in_progress))
            coVerify(exactly = 1) { service.syncNow() }
        }
    }

    @Test
    fun `a completed sync shows the totals and the desktop's last sync`() {
        grantBluetooth()
        val lastSync = "2026-11-12T12:00:00Z"
        coEvery { service.syncNow() } returns result
        coEvery { service.desktopSyncStatus() } returns
            RemoteSyncClient.DesktopSyncStatus(lastSync = lastSync, deviceId = "d", storeChecksums = emptyMap())
        val shown = OffsetDateTime.parse(lastSync)
            .atZoneSameInstant(ZoneId.systemDefault())
            .format(DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM).withLocale(Locale.getDefault()))

        launch().use { scenario ->
            tapSyncNow(scenario)
            idleMainLooper()

            assertShows(scenario, completeText(3, 7, app.getString(R.string.sync_desktop_last_sync, shown)))
        }
    }

    @Test
    fun `a completed sync with a desktop that never synced says so`() {
        grantBluetooth()
        coEvery { service.syncNow() } returns result
        coEvery { service.desktopSyncStatus() } returns
            RemoteSyncClient.DesktopSyncStatus(lastSync = null, deviceId = "d", storeChecksums = emptyMap())

        launch().use { scenario ->
            tapSyncNow(scenario)
            idleMainLooper()

            assertShows(scenario, completeText(3, 7, app.getString(R.string.sync_desktop_never)))
        }
    }

    @Test
    fun `a desktop status failure still reports the sync complete`() {
        grantBluetooth()
        coEvery { service.syncNow() } returns result
        coEvery { service.desktopSyncStatus() } throws IllegalStateException("status refused")

        launch().use { scenario ->
            tapSyncNow(scenario)
            idleMainLooper()

            assertShows(scenario, completeText(3, 7, app.getString(R.string.sync_desktop_status_unavailable)))
            val failed = app.getString(R.string.sync_failed, "")
            assertTrue(snackbarTexts(scenario).none { it.startsWith(failed) })
        }
    }

    @Test
    fun `a failing sync shows its message`() {
        grantBluetooth()
        coEvery { service.syncNow() } throws IllegalStateException("x")

        launch().use { scenario ->
            tapSyncNow(scenario)
            idleMainLooper()

            assertShows(scenario, app.getString(R.string.sync_failed, "x"))
            assertEquals("Sync failed: x", app.getString(R.string.sync_failed, "x"))
        }
    }

    @Test
    fun `a failing sync without a message shows error`() {
        grantBluetooth()
        coEvery { service.syncNow() } throws IllegalStateException()

        launch().use { scenario ->
            tapSyncNow(scenario)
            idleMainLooper()

            assertShows(scenario, app.getString(R.string.sync_failed, "error"))
        }
    }

    @Test
    fun `without a bound service the card says not connected and calls nothing`() {
        // No Bluetooth permission: onCreate neither starts nor binds the service.
        launch().use { scenario ->
            tapSyncNow(scenario)

            assertShows(scenario, app.getString(R.string.sync_not_connected))
            verify(exactly = 0) { binder.getService() }
            coVerify(exactly = 0) { service.syncNow() }
            coVerify(exactly = 0) { service.desktopSyncStatus() }
        }
    }

    @Test
    fun `a second tap while a sync runs starts no second sync`() {
        grantBluetooth()
        val pending = CompletableDeferred<RemoteSyncClient.SyncResult>()
        coEvery { service.syncNow() } coAnswers { pending.await() }

        launch().use { scenario ->
            tapSyncNow(scenario)
            tapSyncNow(scenario)

            coVerify(exactly = 1) { service.syncNow() }
            assertShows(scenario, app.getString(R.string.sync_in_progress))
        }
    }

    @Test
    fun `a Snackbar an earlier test left current does not hold this test's notices back`() {
        val stuck = leaveStuckSnackbar()
        // What setUp does before every test, here after the leak.
        resetSnackbarManager()
        grantBluetooth()
        val pending = CompletableDeferred<RemoteSyncClient.SyncResult>()
        coEvery { service.syncNow() } coAnswers { pending.await() }

        launch().use { scenario ->
            tapSyncNow(scenario)
            tapSyncNow(scenario)

            assertShows(scenario, app.getString(R.string.sync_in_progress))
        }
        assertNotNull("the stuck record's callback stays reachable", stuck)
    }

    @Test
    fun `closing the screen during a sync shows no sync failure`() {
        grantBluetooth()
        val pending = CompletableDeferred<RemoteSyncClient.SyncResult>()
        coEvery { service.syncNow() } coAnswers { pending.await() }

        val scenario = launch()
        tapSyncNow(scenario)
        var decor: View? = null
        scenario.onActivity { decor = it.window.decorView }

        // Destroying the activity cancels its lifecycleScope, and with it the sync.
        scenario.close()
        idleMainLooper()

        val failed = app.getString(R.string.sync_failed, "")
        val texts = snackbarTexts(requireNotNull(decor))
        assertTrue("a cancelled sync was reported as failed: $texts", texts.none { it.startsWith(failed) })
    }
}
