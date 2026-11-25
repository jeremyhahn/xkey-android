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

package com.automatethethings.xkey.ble

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.content.Context
import com.automatethethings.xkey.testing.ReleaseMocks
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * The xkey [GattServer]'s start against a stop or destroy that runs while the
 * start waits on the stack: a start that finishes after either leaves no
 * server open and reports nothing running.
 */
@RunWith(RobolectricTestRunner::class)
class GattServerStartLifecycleTest {

    @get:Rule
    val releaseMocks = ReleaseMocks()

    private val context = mockk<Context>(relaxed = true)
    private val manager = mockk<BluetoothManager>(relaxed = true)
    private val adapter = mockk<BluetoothAdapter>(relaxed = true)
    private val stack = mockk<BluetoothGattServer>(relaxed = true)
    private val callback = slot<BluetoothGattServerCallback>()

    private lateinit var server: GattServer

    /** Runs once, inside the next openGattServer call, before it returns. */
    private var duringOpen: (() -> Unit)? = null

    /** Runs once, inside the next addService call, before the stack reports it added. */
    private var duringAdd: (() -> Unit)? = null

    @Before
    fun setUp() {
        NoiseTestKeyStore.install()
        every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns manager
        every { manager.adapter } returns adapter
        every { adapter.isEnabled } returns true
        every { manager.openGattServer(context, capture(callback)) } answers {
            duringOpen?.also { duringOpen = null }?.invoke()
            stack
        }
        every { stack.addService(any()) } answers {
            duringAdd?.also { duringAdd = null }?.invoke()
            callback.captured.onServiceAdded(BluetoothGatt.GATT_SUCCESS, firstArg<BluetoothGattService>())
            true
        }
        server = GattServer(context, mockk(relaxed = true))
    }

    @After
    fun tearDown() = server.destroy()

    @Test
    fun `a stop during openGattServer leaves no server open and no service added`() {
        duringOpen = { server.stop() }

        assertFalse(server.start())

        assertFalse(server.isRunning())
        verify(exactly = 0) { stack.addService(any()) }
        verify { stack.close() }
    }

    @Test
    fun `a destroy during openGattServer leaves no server open and no service added`() {
        duringOpen = { server.destroy() }

        assertFalse(server.start())

        assertFalse(server.isRunning())
        verify(exactly = 0) { stack.addService(any()) }
        verify { stack.close() }
    }

    @Test
    fun `a stop while the service is being added leaves the server closed and not running`() {
        duringAdd = { server.stop() }

        assertFalse(server.start())

        assertFalse(server.isRunning())
        verify { stack.close() }
    }

    @Test
    fun `a start after a stop during startup works`() {
        duringOpen = { server.stop() }
        assertFalse(server.start())

        assertTrue(server.start())
        assertTrue(server.isRunning())
    }

    @Test
    fun `no start succeeds after destroy`() {
        server.destroy()

        assertFalse(server.start())
        assertFalse(server.isRunning())
        verify(exactly = 0) { manager.openGattServer(any(), any()) }
    }
}
