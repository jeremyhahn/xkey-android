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
package com.automatethethings.xkey.usb

import android.content.Context
import android.hardware.usb.UsbAccessory
import com.automatethethings.xkey.ble.PairingConfirmationCallback
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.TransportMethods
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.settings.PairedDeviceRepository

/**
 * The service's one USB accessory server and its message router.
 *
 * A server that closes (a pulled cable, a session that ended by itself, a
 * refused open) drops out of the slot, so the next attach builds a fresh one
 * without a service restart (#134). The server is published before it
 * connects, because connect starts watching for the detach: a close that comes
 * at once finds it and clears it. The attach runs on a worker and the detach
 * broadcast on the main thread, so the slot is guarded by a lock.
 *
 * @param newDetachWatcher Builds the detach watcher for each new server.
 */
class UsbAccessoryServerSlot(
    private val newDetachWatcher: () -> AccessoryDetachWatcher = { BroadcastAccessoryDetachWatcher() },
) {
    private val lock = Any()
    private var server: UsbAccessoryServer? = null
    private var router: BidirectionalMessageRouter? = null

    /** True while a server holds the slot. */
    val isActive: Boolean
        get() = synchronized(lock) { server != null }

    /** The active server and its router, or null. */
    fun current(): Pair<UsbAccessoryServer, BidirectionalMessageRouter>? = synchronized(lock) {
        val s = server ?: return null
        val r = router ?: return null
        s to r
    }

    /**
     * Builds a server for [accessory], publishes it with [router] and connects
     * it. Returns the server, or null when one is already active.
     */
    fun open(
        context: Context,
        accessory: UsbAccessory,
        requestHandler: RequestHandler,
        router: BidirectionalMessageRouter,
        pairingCallback: PairingConfirmationCallback? = null,
        pairedDeviceRepository: PairedDeviceRepository? = null,
        storeMethods: List<TransportMethods> = emptyList(),
    ): UsbAccessoryServer? {
        var published: UsbAccessoryServer? = null
        val server = UsbAccessoryServer(
            requestHandler,
            router,
            pairingCallback,
            pairedDeviceRepository,
            storeMethods,
            detachWatcher = newDetachWatcher(),
            onClosed = { published?.let { closed(it) } },
        )
        published = server
        synchronized(lock) {
            if (this.server != null) return null
            this.server = server
            this.router = router
        }
        server.connect(context, accessory)
        return server
    }

    /** Drops the active server, if any, and disconnects it. */
    fun clear() {
        val active = synchronized(lock) {
            server.also {
                server = null
                router = null
            }
        }
        active?.disconnect()
    }

    /** Drops [closedServer] unless an attach has since replaced it. */
    private fun closed(closedServer: UsbAccessoryServer) {
        synchronized(lock) {
            if (server !== closedServer) return
            server = null
            router = null
        }
    }
}
