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

import android.bluetooth.BluetoothAdapter
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.util.Log
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * [Advertiser] is what makes the phone discoverable, and every one of its
 * failure modes is silent: it returns `false` and parks a reason in
 * [AdvertisingState]. The UI shows that state, so a wrong mapping is a wrong
 * message to the user with nothing else to notice it.
 *
 * The stack under it is entirely framework, so this suite drives the two
 * seams that matter and are reachable off-device:
 *
 *  - `startAdvertising`'s guard chain (no adapter, adapter off, no LE
 *    advertiser), which runs before any framework builder is touched;
 *  - the `AdvertiseCallback` the BLE stack invokes, reached by reflection,
 *    which is where the whole error-code mapping and the success state live.
 *
 * Building the real `AdvertiseSettings`/`AdvertiseData` needs a device; those
 * three builders are the only part of the class this cannot reach.
 */
class AdvertiserTest {

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    // -----------------------------------------------------------------
    // The guard chain
    // -----------------------------------------------------------------

    @Test
    fun aFreshAdvertiserIsStopped() {
        val advertiser = Advertiser(null)

        assertFalse(advertiser.isAdvertising())
        assertEquals(AdvertisingState.Stopped, advertiser.advertisingState.value)
    }

    /** A device with no Bluetooth at all must report the unavailable reason. */
    @Test
    fun aMissingAdapterIsReportedAsUnavailable() {
        val advertiser = Advertiser(null)

        assertFalse(advertiser.startAdvertising())
        assertEquals(
            AdvertiseError.BLUETOOTH_UNAVAILABLE,
            (advertiser.advertisingState.value as AdvertisingState.Error).error
        )
    }

    /** Bluetooth switched off is the same user-visible reason as no Bluetooth. */
    @Test
    fun aDisabledAdapterIsReportedAsUnavailable() {
        val adapter = mockk<BluetoothAdapter>()
        every { adapter.isEnabled } returns false

        val advertiser = Advertiser(adapter)

        assertFalse(advertiser.startAdvertising())
        assertEquals(
            AdvertiseError.BLUETOOTH_UNAVAILABLE,
            (advertiser.advertisingState.value as AdvertisingState.Error).error
        )
    }

    /**
     * Plenty of chipsets can scan but not advertise; the adapter then returns a
     * null LE advertiser and the phone can never act as a key.
     */
    @Test
    fun anAdapterWithoutAnLeAdvertiserIsReportedAsUnsupported() {
        val adapter = mockk<BluetoothAdapter>()
        every { adapter.isEnabled } returns true
        every { adapter.bluetoothLeAdvertiser } returns null

        val advertiser = Advertiser(adapter)

        assertFalse(advertiser.startAdvertising())
        val state = advertiser.advertisingState.value as AdvertisingState.Error
        assertEquals(AdvertiseError.NOT_SUPPORTED, state.error)
        assertTrue(state.message.contains("not supported"))
    }

    /** Stopping when nothing is running must be a no-op, not an error state. */
    @Test
    fun stoppingWhenIdleIsANoOp() {
        val leAdvertiser = mockk<BluetoothLeAdvertiser>(relaxed = true)
        val advertiser = Advertiser(null).withLeAdvertiser(leAdvertiser)

        advertiser.stopAdvertising()

        assertEquals(AdvertisingState.Stopped, advertiser.advertisingState.value)
        verify(exactly = 0) { leAdvertiser.stopAdvertising(any()) }
    }

    // -----------------------------------------------------------------
    // The BLE stack's callback
    // -----------------------------------------------------------------

    /** A successful start publishes the settings the stack actually applied. */
    @Test
    fun startSuccessPublishesTheEffectiveSettings() {
        val advertiser = Advertiser(null)

        advertiser.callback().onStartSuccess(
            advertiseSettings(connectable = true, txPowerLevel = 2, mode = 1)
        )

        assertTrue(advertiser.isAdvertising())
        val state = advertiser.advertisingState.value as AdvertisingState.Advertising
        assertTrue(state.connectable)
        assertEquals(2, state.txPowerLevel)
        assertEquals(1, state.mode)
    }

    /** A second start while already advertising is a success, not a restart. */
    @Test
    fun startingWhileAlreadyAdvertisingIsAcceptedWithoutTouchingTheAdapter() {
        val adapter = mockk<BluetoothAdapter>()
        val advertiser = Advertiser(adapter)
        advertiser.callback().onStartSuccess(advertiseSettings())

        assertTrue(advertiser.startAdvertising())
        verify(exactly = 0) { adapter.isEnabled }
    }

    /** Stopping an active advertisement releases it and returns to Stopped. */
    @Test
    fun stoppingAnActiveAdvertisementReleasesIt() {
        val leAdvertiser = mockk<BluetoothLeAdvertiser>(relaxed = true)
        val advertiser = Advertiser(null).withLeAdvertiser(leAdvertiser)
        val callback = advertiser.callback()
        callback.onStartSuccess(advertiseSettings())

        advertiser.stopAdvertising()

        assertFalse(advertiser.isAdvertising())
        assertEquals(AdvertisingState.Stopped, advertiser.advertisingState.value)
        verify(exactly = 1) { leAdvertiser.stopAdvertising(callback) }
    }

    /** A throwing stack must not propagate out of `stopAdvertising`. */
    @Test
    fun aFailureWhileStoppingIsSwallowed() {
        val leAdvertiser = mockk<BluetoothLeAdvertiser>()
        every { leAdvertiser.stopAdvertising(any()) } throws IllegalStateException("BT off")
        val advertiser = Advertiser(null).withLeAdvertiser(leAdvertiser)
        advertiser.callback().onStartSuccess(advertiseSettings())

        advertiser.stopAdvertising()

        assertEquals(AdvertisingState.Stopped, advertiser.advertisingState.value)
        assertFalse(advertiser.isAdvertising())
    }

    /**
     * Every code the BLE stack can report must map to a distinct, actionable
     * reason. `ADVERTISE_FAILED_DATA_TOO_LARGE` in particular is the one that
     * fires when the advertised payload grows, so it must not be lumped in with
     * the generic internal error.
     */
    @Test
    fun everyAdvertiseFailureCodeMapsToItsOwnReason() {
        val expected = mapOf(
            AdvertiseCallback.ADVERTISE_FAILED_DATA_TOO_LARGE to AdvertiseError.DATA_TOO_LARGE,
            AdvertiseCallback.ADVERTISE_FAILED_TOO_MANY_ADVERTISERS to AdvertiseError.TOO_MANY_ADVERTISERS,
            AdvertiseCallback.ADVERTISE_FAILED_ALREADY_STARTED to AdvertiseError.ALREADY_STARTED,
            AdvertiseCallback.ADVERTISE_FAILED_INTERNAL_ERROR to AdvertiseError.INTERNAL_ERROR,
            AdvertiseCallback.ADVERTISE_FAILED_FEATURE_UNSUPPORTED to AdvertiseError.NOT_SUPPORTED
        )

        for ((code, error) in expected) {
            val advertiser = Advertiser(null)
            advertiser.callback().onStartFailure(code)

            val state = advertiser.advertisingState.value as AdvertisingState.Error
            assertEquals("code $code", error, state.error)
            assertTrue("code $code must carry a message", state.message.isNotEmpty())
        }
    }

    /** An unrecognised code still surfaces, with the raw code for diagnosis. */
    @Test
    fun anUnknownFailureCodeIsSurfacedWithItsRawValue() {
        val advertiser = Advertiser(null)

        advertiser.callback().onStartFailure(9999)

        val state = advertiser.advertisingState.value as AdvertisingState.Error
        assertEquals(AdvertiseError.INTERNAL_ERROR, state.error)
        assertTrue(state.message.contains("9999"))
    }

    /** A failure after a success must clear the advertising flag. */
    @Test
    fun aFailureAfterASuccessClearsTheAdvertisingFlag() {
        val advertiser = Advertiser(null)
        val callback = advertiser.callback()
        callback.onStartSuccess(advertiseSettings())
        assertTrue(advertiser.isAdvertising())

        callback.onStartFailure(AdvertiseCallback.ADVERTISE_FAILED_INTERNAL_ERROR)

        assertFalse(advertiser.isAdvertising())
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /**
     * The callback the BLE stack owns. It is a private field because nothing in
     * the app invokes it, which is exactly why it needs a test.
     */
    private fun Advertiser.callback(): AdvertiseCallback =
        field("advertiseCallback").get(this) as AdvertiseCallback

    /** Installs the LE advertiser `startAdvertising` would have resolved. */
    private fun Advertiser.withLeAdvertiser(leAdvertiser: BluetoothLeAdvertiser): Advertiser =
        apply { field("advertiser").set(this, leAdvertiser) }

    private fun field(name: String) = try {
        Advertiser::class.java.getDeclaredField(name).apply { isAccessible = true }
    } catch (e: NoSuchFieldException) {
        throw AssertionError("Advertiser.$name is the seam this suite drives", e)
    }

    private fun advertiseSettings(
        connectable: Boolean = true,
        txPowerLevel: Int = AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM,
        mode: Int = AdvertiseSettings.ADVERTISE_MODE_BALANCED
    ): AdvertiseSettings = mockk<AdvertiseSettings>().also {
        every { it.isConnectable } returns connectable
        every { it.txPowerLevel } returns txPowerLevel
        every { it.mode } returns mode
        every { it.timeout } returns 0
    }
}
