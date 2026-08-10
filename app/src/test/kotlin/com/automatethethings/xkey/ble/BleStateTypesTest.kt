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

import java.io.IOException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The state values the BLE layer publishes, and the equality contract the UI
 * depends on.
 *
 * [GattServer.connectionState] and [Advertiser.advertisingState] are
 * `StateFlow`s, and a `StateFlow` **drops a value equal to the one it already
 * holds**. Every screen that reacts to a BLE state change therefore depends on
 * these types comparing by value: if any of them ever became a plain class,
 * reconnecting to a *different* desktop would silently emit nothing, because
 * the two `Connected` values would be different instances of an equal state and
 * the flow would still forward one — while two genuinely identical states would
 * start duplicating work. These assertions pin that contract.
 */
class BleStateTypesTest {

    // -----------------------------------------------------------------
    // Responder-side state (GattServer)
    // -----------------------------------------------------------------

    /** The idle state is a singleton, so an idle flow never re-emits. */
    @Test
    fun theDisconnectedStateIsASingleton() {
        val idle: ConnectionState = ConnectionState.Disconnected
        val connecting: ConnectionState = ConnectionState.Connecting

        assertSame(idle, ConnectionState.Disconnected)
        assertEquals(idle, ConnectionState.Disconnected)
        assertNotEquals(idle, connecting)
    }

    /** A connection carries the identity the UI shows. */
    @Test
    fun aConnectedStateCarriesTheDeviceIdentity() {
        val state = ConnectionState.Connected("Workstation", "AA:BB:CC:DD:EE:FF")

        assertEquals("Workstation", state.deviceName)
        assertEquals("AA:BB:CC:DD:EE:FF", state.deviceAddress)
        assertEquals(state, ConnectionState.Connected("Workstation", "AA:BB:CC:DD:EE:FF"))
    }

    /** Reconnecting to a different device must not look like the same state. */
    @Test
    fun connectionsToDifferentDevicesAreDistinctStates() {
        val first = ConnectionState.Connected("Workstation", "AA:BB:CC:DD:EE:FF")
        val second = ConnectionState.Connected("Workstation", "11:22:33:44:55:66")

        assertNotEquals(first, second)
    }

    /** The property that makes the above matter, asserted on a real flow. */
    @Test
    fun aStateFlowSuppressesAnIdenticalConnectionState() = runBlocking {
        val flow = MutableStateFlow<ConnectionState>(ConnectionState.Disconnected)
        val seen = mutableListOf<ConnectionState>()

        val connected = ConnectionState.Connected("Workstation", "AA:BB:CC:DD:EE:FF")
        seen += flow.value
        flow.value = connected
        seen += flow.value
        flow.value = ConnectionState.Connected("Workstation", "AA:BB:CC:DD:EE:FF")

        assertSame(
            "an equal state must leave the flow holding the value it already had",
            connected,
            flow.value
        )
        assertEquals(2, seen.size)
    }

    // -----------------------------------------------------------------
    // Initiator-side state (BleClient)
    // -----------------------------------------------------------------

    @Test
    fun clientStatesCompareByValue() {
        assertEquals(
            ClientConnectionState.Connecting("AA:BB:CC:DD:EE:FF"),
            ClientConnectionState.Connecting("AA:BB:CC:DD:EE:FF")
        )
        val connecting: ClientConnectionState = ClientConnectionState.Connecting("AA:BB:CC:DD:EE:FF")
        val disconnected: ClientConnectionState = ClientConnectionState.Disconnected
        assertNotEquals(connecting, disconnected)

        val connected = ClientConnectionState.Connected("xKey", "AA:BB:CC:DD:EE:FF")
        assertEquals("xKey", connected.deviceName)
        assertEquals("AA:BB:CC:DD:EE:FF", connected.deviceAddress)
        assertEquals(connected, connected.copy())
    }

    // -----------------------------------------------------------------
    // Advertising state
    // -----------------------------------------------------------------

    @Test
    fun advertisingStatesCompareByValue() {
        assertEquals(
            AdvertisingState.Advertising(connectable = true, txPowerLevel = 2, mode = 1),
            AdvertisingState.Advertising(connectable = true, txPowerLevel = 2, mode = 1)
        )
        assertNotEquals(
            AdvertisingState.Advertising(connectable = true, txPowerLevel = 2, mode = 1),
            AdvertisingState.Advertising(connectable = false, txPowerLevel = 2, mode = 1)
        )
        assertEquals(
            AdvertisingState.Error(AdvertiseError.DATA_TOO_LARGE, "too large"),
            AdvertisingState.Error(AdvertiseError.DATA_TOO_LARGE, "too large")
        )
        val failed: AdvertisingState = AdvertisingState.Error(AdvertiseError.DATA_TOO_LARGE, "too large")
        val stopped: AdvertisingState = AdvertisingState.Stopped
        assertNotEquals(failed, stopped)
    }

    // -----------------------------------------------------------------
    // Failure types
    // -----------------------------------------------------------------

    /**
     * `BleClient` is consumed as an I/O-style API, so its failure type has to
     * stay an [IOException] — callers catch it as one.
     */
    @Test
    fun bleClientFailuresAreIoExceptions() {
        val cause = IllegalStateException("radio off")
        val failure: Throwable = BleClientException("connect failed", cause)

        assertTrue("callers catch BLE client failures as IOException", failure is IOException)
        assertEquals("connect failed", failure.message)
        assertSame(cause, failure.cause)
    }

    @Test
    fun protocolFailuresCarryTheirCause() {
        val cause = IllegalArgumentException("bad tag")

        assertEquals("session not established", NoiseException("session not established").message)
        assertSame(cause, NoiseException("decrypt failed", cause).cause)
        assertEquals("fragment too small", FragmentException("fragment too small").message)
        assertSame(cause, FragmentException("reassembly failed", cause).cause)
    }
}
