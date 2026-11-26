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
package com.automatethethings.xkey.ble

import android.app.Application
import android.hardware.usb.UsbAccessory
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.usb.UsbAccessoryServer
import com.automatethethings.xkey.usb.UsbAccessoryServerSlot
import com.automatethethings.xkey.usb.UsbHsmSettingsData
import com.automatethethings.xkey.usb.UsbHsmSettingsRepository
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import com.automatethethings.xkey.ui.FakeAndroidKeyStore
import io.mockk.Runs
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The native USB gate of [XKeyGattService.onUsbAccessoryAttached]: an
 * attached accessory is opened only when native USB is enabled, and never
 * while a server already holds the slot or before the request handler
 * exists.
 *
 * The service is built without `create()`; its private `requestHandler`,
 * `usbHsmSettingsRepository` and `usbServerSlot` are set by reflection.
 * [UsbAccessoryServer] is mocked by constructor with `connect` stubbed, so an
 * open that gets past the gate reaches `connect` and never touches
 * `UsbManager`.
 *
 * The gate runs on the service's `serviceScope`. Before asserting that nothing
 * was opened, each test joins every child of that scope except the attach
 * path's long-lived observer of the slot.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class UsbAccessoryGateTest {

    private lateinit var service: XKeyGattService
    private val accessory = mockk<UsbAccessory>(relaxed = true)

    @Before
    fun setUp() {
        // The seal store an open builds holds a Keystore cipher.
        FakeAndroidKeyStore.install()
        mockkConstructor(UsbAccessoryServer::class)
        every { anyConstructed<UsbAccessoryServer>().connect(any(), any()) } just Runs
        mockkObject(AuditLogger)
        every { AuditLogger.logConnectionEstablished(any(), any(), any()) } just Runs
        service = Robolectric.buildService(XKeyGattService::class.java).get()
    }

    @After
    fun tearDown() {
        serviceScope().cancel()
        unmockkAll()
    }

    // --- Reflection ---------------------------------------------------------

    private fun setField(name: String, value: Any?) {
        XKeyGattService::class.java.getDeclaredField(name).apply { isAccessible = true }.set(service, value)
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> getField(name: String): T =
        XKeyGattService::class.java.getDeclaredField(name).apply { isAccessible = true }.get(service) as T

    private fun serviceScope(): CoroutineScope = getField("serviceScope")

    private fun slot(): UsbAccessoryServerSlot = getField("usbServerSlot")

    /** The attach path's observer of the slot, which runs until the scope ends. */
    private fun observerJob(): Job? {
        val path = getField<Lazy<*>>("usbAttachPath\$delegate")
        if (!path.isInitialized()) return null
        return UsbAttachPath::class.java.getDeclaredField("observer")
            .apply { isAccessible = true }
            .get(path.value) as Job?
    }

    /** The scope's children other than the observer: the gate's own job. */
    private fun gateJobs(): List<Job> {
        val observer = observerJob()
        return serviceScope().coroutineContext[Job]!!.children.filter { it !== observer }.toList()
    }

    private fun awaitGate() = runBlocking {
        withTimeout(10_000) { gateJobs().forEach { it.join() } }
    }

    // --- Fixtures -----------------------------------------------------------

    private fun repository(nativeUsb: Boolean): UsbHsmSettingsRepository {
        val repo = mockk<UsbHsmSettingsRepository>()
        coEvery { repo.getSettings() } returns UsbHsmSettingsData(nativeUsbEnabled = nativeUsb)
        return repo
    }

    private fun assertNothingOpened() {
        verify(exactly = 0) { anyConstructed<UsbAccessoryServer>().connect(any(), any()) }
        assertFalse("the slot must stay empty", slot().isActive)
    }

    // --- Gate -----------------------------------------------------------------

    @Test
    fun `native USB off opens nothing`() {
        val repo = repository(nativeUsb = false)
        setField("requestHandler", mockk<RequestHandler>(relaxed = true))
        setField("usbHsmSettingsRepository", repo)

        service.onUsbAccessoryAttached(accessory)
        awaitGate()

        coVerify(exactly = 1) { repo.getSettings() }
        assertNothingOpened()
    }

    @Test
    fun `no settings repository opens nothing`() {
        setField("requestHandler", mockk<RequestHandler>(relaxed = true))
        setField("usbHsmSettingsRepository", null)

        service.onUsbAccessoryAttached(accessory)
        awaitGate()

        assertNothingOpened()
    }

    @Test
    fun `native USB on opens the accessory`() {
        val repo = repository(nativeUsb = true)
        setField("requestHandler", mockk<RequestHandler>(relaxed = true))
        setField("usbHsmSettingsRepository", repo)

        service.onUsbAccessoryAttached(accessory)
        awaitGate()

        verify(exactly = 1) { anyConstructed<UsbAccessoryServer>().connect(any(), accessory) }
        assertTrue("the opened server holds the slot", slot().isActive)
    }

    @Test
    fun `no request handler returns before reading the settings`() {
        val repo = repository(nativeUsb = true)
        setField("requestHandler", null)
        setField("usbHsmSettingsRepository", repo)

        service.onUsbAccessoryAttached(accessory)

        assertTrue("nothing is launched", gateJobs().isEmpty())
        coVerify(exactly = 0) { repo.getSettings() }
        assertNothingOpened()
    }

    @Test
    fun `an active slot returns before reading the settings`() {
        val repo = repository(nativeUsb = true)
        val activeSlot = mockk<UsbAccessoryServerSlot>()
        every { activeSlot.isActive } returns true
        setField("usbServerSlot", activeSlot)
        setField("requestHandler", mockk<RequestHandler>(relaxed = true))
        setField("usbHsmSettingsRepository", repo)

        service.onUsbAccessoryAttached(accessory)

        assertTrue("nothing is launched", gateJobs().isEmpty())
        coVerify(exactly = 0) { repo.getSettings() }
        verify(exactly = 0) { anyConstructed<UsbAccessoryServer>().connect(any(), any()) }
    }
}
