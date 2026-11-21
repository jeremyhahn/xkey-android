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

package com.automatethethings.xkey.ble.fido

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
 * [FidoGattServer]'s start against a stop or destroy that runs while the
 * start waits on the stack: a start that finishes after either closes the
 * server it opened and publishes nothing.
 */
@RunWith(RobolectricTestRunner::class)
class FidoGattServerLifecycleTest {

    @get:Rule
    val releaseMocks = ReleaseMocks()

    private val context = mockk<Context>(relaxed = true)
    private val manager = mockk<BluetoothManager>(relaxed = true)
    private val stack = mockk<BluetoothGattServer>(relaxed = true)
    private val callback = slot<BluetoothGattServerCallback>()
    private val added = slot<BluetoothGattService>()

    private lateinit var server: FidoGattServer

    /** Runs once, inside the next openGattServer call, before it returns. */
    private var duringOpen: (() -> Unit)? = null

    /** Runs once, inside the next addService call, before the stack reports it added. */
    private var duringAdd: (() -> Unit)? = null

    @Before
    fun setUp() {
        every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns manager
        every { manager.getConnectedDevices(any()) } returns emptyList()
        every { manager.openGattServer(context, capture(callback)) } answers {
            duringOpen?.also { duringOpen = null }?.invoke()
            stack
        }
        every { stack.addService(capture(added)) } answers {
            duringAdd?.also { duringAdd = null }?.invoke()
            callback.captured.onServiceAdded(BluetoothGatt.GATT_SUCCESS, added.captured)
            true
        }
        server = FidoGattServer(context, mockk(relaxed = true))
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
    fun `a stop while the service is being added closes the server and publishes nothing`() {
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
