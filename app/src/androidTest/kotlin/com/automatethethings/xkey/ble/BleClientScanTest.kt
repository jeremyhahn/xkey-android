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
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanResult
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * [BleClient.scan], the one part of the client that cannot be reached from the
 * JVM.
 *
 * Everything else in the client is driven off-device against a mocked stack —
 * see [BleClientHarness] — but `scan` builds a real `ScanFilter` and a real
 * `ScanSettings`, and those framework builders throw outside a device. So the
 * whole scan path, including the timeout that ends it and the wind-down in its
 * `finally`, has no coverage at all.
 *
 * The property asserted is the one that matters on a phone: **however a scan
 * ends, it must leave no scan running.** A scan that is started and not stopped
 * keeps the radio in a duty cycle until the process dies, and Android will
 * eventually refuse further scans from the app for the rest of the boot. That
 * has to hold whether the scan times out with nothing found, is ended early by
 * the stack, or fails outright — which is exactly what varies between an
 * emulator with a simulated controller and a real handset, so the outcome is
 * not asserted, only the invariant.
 */
@RunWith(AndroidJUnit4::class)
class BleClientScanTest {

    @get:Rule
    val bluetoothPermissions: GrantPermissionRule = GrantPermissionRule.grant(
        Manifest.permission.BLUETOOTH_SCAN,
        Manifest.permission.BLUETOOTH_CONNECT
    )

    private lateinit var context: Context
    private lateinit var client: BleClient

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        val adapter = context.getSystemService(BluetoothManager::class.java)?.adapter
        assumeTrue("this device has no Bluetooth adapter", adapter != null)
        assumeTrue("this device's Bluetooth adapter is off", adapter!!.isEnabled)
        assumeTrue("this device has no BLE scanner", adapter.bluetoothLeScanner != null)
        client = BleClient(context)
    }

    @After
    fun tearDown() {
        if (::client.isInitialized) runBlocking { client.destroy() }
    }

    /**
     * A scan that finds nothing runs for its timeout and then stops itself. The
     * result set is whatever the radio saw — on an emulator, nothing — and the
     * scan must be wound down either way.
     */
    @Test
    fun aScanWindsItselfDownHoweverItEnds(): Unit = runBlocking {
        try {
            val results = client.scan(timeoutMs = SCAN_TIMEOUT_MS)
            assertNotNull("a completed scan reports its result set", results)
        } catch (reported: BleClientException) {
            // A controller that refuses to scan is a legitimate outcome here;
            // what must not happen is a scan left running.
        }

        assertFalse("no scan may be left running", isScanning().get())
        assertNull("the scan's deferred must be released", scanDeferred())
    }

    /**
     * Two scans at once would have the second's results delivered into the
     * first's callback and the first's `stopScan` end both. The second is
     * refused instead.
     */
    @Test
    fun aSecondScanIsRefusedWhileOneIsRunning(): Unit = runBlocking {
        isScanning().set(true)
        try {
            client.scan(timeoutMs = SCAN_TIMEOUT_MS)
            fail("a concurrent scan must be refused")
        } catch (expected: BleClientException) {
            assertTrue(expected.message!!.contains("already in progress"))
        } finally {
            isScanning().set(false)
        }
    }

    // -----------------------------------------------------------------
    // Reflection
    // -----------------------------------------------------------------

    // BleClientProbe lives in the JVM source set, so the two fields this suite
    // needs are read here directly. Both name the member they reach.

    private fun isScanning(): AtomicBoolean = field("isScanning") as AtomicBoolean

    @Suppress("UNCHECKED_CAST")
    private fun scanDeferred(): CompletableDeferred<List<ScanResult>>? =
        field("scanDeferred") as CompletableDeferred<List<ScanResult>>?

    private fun field(name: String): Any? = try {
        BleClient::class.java.getDeclaredField(name).apply { isAccessible = true }.get(client)
    } catch (e: NoSuchFieldException) {
        throw AssertionError("BleClient.$name is a seam this scan suite drives", e)
    }

    private companion object {
        /** Long enough to reach the timeout branch, short enough to stay cheap. */
        const val SCAN_TIMEOUT_MS = 1_500L
    }
}
