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
package com.automatethethings.xkey.settings

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.usb.UsbHsmSettingsData
import com.automatethethings.xkey.usb.UsbHsmSettingsRepository
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [UsbHsmSettingsRepository].
 *
 * Both transports default to off, which is the security-relevant part: neither
 * the USB accessory server nor the loopback TCP pairing server may come up
 * unless the user has switched it on. `XKeyGattService` starts and stops those
 * servers from this flow, so the defaults and the round trip are what the rest
 * of the transport stack rests on.
 *
 * The store is shared with the app -- `TcpHsmSettingEnabler` in the e2e suite
 * writes to it -- so the device's own values are snapshotted and restored.
 */
@RunWith(AndroidJUnit4::class)
class UsbHsmSettingsRepositoryTest {

    private lateinit var repository: UsbHsmSettingsRepository
    private lateinit var snapshot: UsbHsmSettingsData

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        repository = UsbHsmSettingsRepository(context)
        runBlocking {
            snapshot = repository.getSettings()
            PreferenceStoreProbe.clear(repository)
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            PreferenceStoreProbe.clear(repository)
            repository.setNativeUsbEnabled(snapshot.nativeUsbEnabled)
            repository.setTcpHsmEnabled(snapshot.tcpHsmEnabled)
        }
    }

    @Test
    fun freshStore_leavesEveryTransportOff() = runBlocking {
        val settings = repository.getSettings()

        assertEquals(UsbHsmSettingsData(), settings)
        assertFalse(settings.nativeUsbEnabled)
        assertFalse(settings.tcpHsmEnabled)
    }

    @Test
    fun setNativeUsbEnabled_roundTrips() = runBlocking {
        repository.setNativeUsbEnabled(true)
        assertTrue(repository.getSettings().nativeUsbEnabled)

        repository.setNativeUsbEnabled(false)

        assertFalse(repository.getSettings().nativeUsbEnabled)
    }

    @Test
    fun setTcpHsmEnabled_roundTrips() = runBlocking {
        repository.setTcpHsmEnabled(true)
        assertTrue(repository.getSettings().tcpHsmEnabled)

        repository.setTcpHsmEnabled(false)

        assertFalse(repository.getSettings().tcpHsmEnabled)
    }

    @Test
    fun theTwoTransportsAreIndependent() = runBlocking {
        repository.setNativeUsbEnabled(true)

        repository.setTcpHsmEnabled(true)
        repository.setNativeUsbEnabled(false)

        val settings = repository.getSettings()
        assertFalse(settings.nativeUsbEnabled)
        assertTrue(settings.tcpHsmEnabled)
    }

    @Test
    fun aSecondInstanceSeesTheSamePersistedValue() = runBlocking {
        repository.setNativeUsbEnabled(true)

        val other = UsbHsmSettingsRepository(ApplicationProvider.getApplicationContext<Context>())

        assertTrue(other.getSettings().nativeUsbEnabled)
    }
}
