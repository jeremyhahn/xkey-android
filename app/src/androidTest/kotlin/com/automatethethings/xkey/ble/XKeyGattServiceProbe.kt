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

import android.app.Notification
import android.bluetooth.BluetoothAdapter
import android.content.Context
import android.content.ContextWrapper
import android.os.PowerManager
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.MessageSender
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.tcp.TcpHsmServer
import com.automatethethings.xkey.usb.UsbAccessoryServer
import com.automatethethings.xkey.usb.UsbAccessoryServerSlot
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * [XKeyGattService] without the radio, the foreground notification lifecycle or
 * `onCreate`'s component graph.
 *
 * The service is the app's transport *arbiter*: it decides which of BLE, TCP
 * and USB an outbound `remote.*` call goes out on, it maps every BLE state
 * change onto the state the UI reads and the rows the audit log keeps, and it
 * owns the wake lock that keeps the radio alive. None of that logic needs
 * Bluetooth — but all of it is unreachable through the normal entry points,
 * because a bound service runs `onCreate` first and that builds a Room
 * database, a Keystore manager, a `GattServer` and an activity-result launcher.
 *
 * A `Service` is a `ContextWrapper` with no base context until the system
 * attaches one, so this constructs the service directly and attaches the
 * instrumentation context. Everything that only needs a `Context` —
 * notifications, `getString`, `PowerManager` — then works exactly as it does in
 * production, while `onCreate`, `onStartCommand` and `startForeground` are
 * never called.
 *
 * Components are injected field by field so each test declares precisely the
 * shape of service it is asserting about: a service with no components at all,
 * one with a BLE session, one with a TCP server, and so on.
 *
 * Every accessor names the member it reaches and fails with a pointed message
 * if it disappears, so a rename reads as "this seam moved".
 */
class XKeyGattServiceProbe(context: Context) {

    val service = XKeyGattService()

    init {
        attachBaseContext.invoke(service, context)
    }

    // -----------------------------------------------------------------
    // Injected components
    // -----------------------------------------------------------------

    var gattServer: GattServer?
        get() = read("gattServer") as GattServer?
        set(value) = write("gattServer", value)

    var advertiser: Advertiser?
        get() = read("advertiser") as Advertiser?
        set(value) = write("advertiser", value)

    var requestHandler: RequestHandler?
        get() = read("requestHandler") as RequestHandler?
        set(value) = write("requestHandler", value)

    var bleMessageRouter: BidirectionalMessageRouter?
        get() = read("bleMessageRouter") as BidirectionalMessageRouter?
        set(value) = write("bleMessageRouter", value)

    var tcpMessageRouter: BidirectionalMessageRouter?
        get() = read("tcpMessageRouter") as BidirectionalMessageRouter?
        set(value) = write("tcpMessageRouter", value)

    var tcpHsmServer: TcpHsmServer?
        get() = read("tcpHsmServer") as TcpHsmServer?
        set(value) = write("tcpHsmServer", value)

    /** The service's USB server slot, which holds the server and its router (#134). */
    val usbServerSlot: UsbAccessoryServerSlot
        get() = read("usbServerSlot") as UsbAccessoryServerSlot

    /**
     * Puts [server] and [router] in [usbServerSlot] as an attach would, without
     * opening an accessory: `UsbAccessoryServerSlot.open` connects, and these
     * tests have no accessory to connect to.
     */
    fun installUsbServer(server: UsbAccessoryServer, router: BidirectionalMessageRouter) {
        val slot = usbServerSlot
        slotFieldOf("server").set(slot, server)
        slotFieldOf("router").set(slot, router)
    }

    var pairedDeviceRepository: PairedDeviceRepository?
        get() = read("pairedDeviceRepository") as PairedDeviceRepository?
        set(value) = write("pairedDeviceRepository", value)

    var bluetoothAdapter: BluetoothAdapter?
        get() = read("bluetoothAdapter") as BluetoothAdapter?
        set(value) = write("bluetoothAdapter", value)

    var isStartingAdvertising: Boolean
        get() = read("isStartingAdvertising") as Boolean
        set(value) = write("isStartingAdvertising", value)

    val wakeLock: PowerManager.WakeLock?
        get() = read("wakeLock") as PowerManager.WakeLock?

    @Suppress("UNCHECKED_CAST")
    private val serviceStateFlow: MutableStateFlow<ServiceState>
        get() = read("_serviceState") as MutableStateFlow<ServiceState>

    var serviceState: ServiceState
        get() = serviceStateFlow.value
        set(value) {
            serviceStateFlow.value = value
        }

    // -----------------------------------------------------------------
    // Private methods under test
    // -----------------------------------------------------------------

    fun initializeBluetooth() {
        invoke(initializeBluetoothMethod)
    }

    fun handleConnectionStateChange(state: ConnectionState) {
        invoke(handleConnectionMethod, state)
    }

    fun handleAdvertisingStateChange(state: AdvertisingState) {
        invoke(handleAdvertisingMethod, state)
    }

    @Suppress("UNCHECKED_CAST")
    fun activeTransport(): Pair<MessageSender, BidirectionalMessageRouter>? =
        invoke(activeTransportMethod) as Pair<MessageSender, BidirectionalMessageRouter>?

    fun startTcpHsmServer() {
        invoke(startTcpMethod)
    }

    fun stopTcpHsmServer() {
        invoke(stopTcpMethod)
    }

    fun createNotification(): Notification = invoke(createNotificationMethod) as Notification

    fun acquireWakeLock() {
        invoke(acquireWakeLockMethod)
    }

    fun releaseWakeLock() {
        invoke(releaseWakeLockMethod)
    }

    /** The title/body pair the foreground notification currently shows. */
    fun notificationText(): Pair<String?, String?> = createNotification().extras.let {
        it.getCharSequence(Notification.EXTRA_TITLE)?.toString() to
            it.getCharSequence(Notification.EXTRA_TEXT)?.toString()
    }

    // -----------------------------------------------------------------
    // Reflection plumbing
    // -----------------------------------------------------------------

    private fun read(name: String): Any? = fieldOf(name).get(service)

    private fun write(name: String, value: Any?) = fieldOf(name).set(service, value)

    private fun invoke(method: Method, vararg args: Any?): Any? = try {
        method.invoke(service, *args)
    } catch (e: InvocationTargetException) {
        throw e.cause ?: e
    }

    private fun fieldOf(name: String) = try {
        XKeyGattService::class.java.getDeclaredField(name).apply { isAccessible = true }
    } catch (e: NoSuchFieldException) {
        throw AssertionError("XKeyGattService.$name is a seam these tests drive", e)
    }

    private fun slotFieldOf(name: String) = try {
        UsbAccessoryServerSlot::class.java.getDeclaredField(name).apply { isAccessible = true }
    } catch (e: NoSuchFieldException) {
        throw AssertionError("UsbAccessoryServerSlot.$name is a seam these tests drive", e)
    }

    companion object {
        private val attachBaseContext: Method =
            ContextWrapper::class.java
                .getDeclaredMethod("attachBaseContext", Context::class.java)
                .apply { isAccessible = true }

        private val initializeBluetoothMethod = declaredMethod("initializeBluetooth")
        private val handleConnectionMethod =
            declaredMethod("handleConnectionStateChange", ConnectionState::class.java)
        private val handleAdvertisingMethod =
            declaredMethod("handleAdvertisingStateChange", AdvertisingState::class.java)
        private val activeTransportMethod = declaredMethod("activeTransport")
        private val startTcpMethod = declaredMethod("startTcpHsmServer")
        private val stopTcpMethod = declaredMethod("stopTcpHsmServer")
        private val createNotificationMethod = declaredMethod("createNotification")
        private val acquireWakeLockMethod = declaredMethod("acquireWakeLock")
        private val releaseWakeLockMethod = declaredMethod("releaseWakeLock")

        private fun declaredMethod(name: String, vararg types: Class<*>): Method = try {
            XKeyGattService::class.java.getDeclaredMethod(name, *types).apply { isAccessible = true }
        } catch (e: NoSuchMethodException) {
            throw AssertionError(
                "XKeyGattService.$name is a seam these tests drive; if it was renamed " +
                    "or resharped, update XKeyGattServiceProbe",
                e
            )
        }
    }
}
