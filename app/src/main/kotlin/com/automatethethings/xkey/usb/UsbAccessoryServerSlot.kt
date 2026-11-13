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
import android.util.Log
import com.automatethethings.xkey.ble.PairingConfirmationCallback
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.TransportMethods
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.settings.PairedDeviceRepository
import kotlinx.coroutines.Job
import kotlinx.coroutines.withTimeoutOrNull

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
 * A replacement waits for the closed server's session to finish its teardown:
 * that teardown clears the peer identity on the request handler every
 * transport shares, and must not clear the identity the new session sets.
 *
 * @param newDetachWatcher Builds the detach watcher for each new server.
 * @param afterPublish Runs between publishing a server and connecting it;
 *   tests use it to interleave a [clear].
 */
class UsbAccessoryServerSlot(
    private val newDetachWatcher: () -> AccessoryDetachWatcher = { BroadcastAccessoryDetachWatcher() },
    private val afterPublish: (UsbAccessoryServer) -> Unit = {},
) {
    private val lock = Any()
    private var server: UsbAccessoryServer? = null
    private var router: BidirectionalMessageRouter? = null

    /** The session of the last server to leave the slot, until it ends. */
    private var retiring: Job? = null

    /** Not yet wired: the states of the slot's current server. */
    val states: kotlinx.coroutines.flow.Flow<UsbAccessoryState?> = kotlinx.coroutines.flow.emptyFlow()

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
     * it, once the session of the server before it has ended. Returns the
     * server, or null when one is already active or the new one left the slot
     * (cleared or closed) before the connect returned. A connect that throws
     * leaves the slot empty and rethrows.
     */
    suspend fun open(
        context: Context,
        accessory: UsbAccessory,
        requestHandler: RequestHandler,
        router: BidirectionalMessageRouter,
        pairingCallback: PairingConfirmationCallback? = null,
        pairedDeviceRepository: PairedDeviceRepository? = null,
        storeMethods: List<TransportMethods> = emptyList(),
    ): UsbAccessoryServer? {
        val previous = synchronized(lock) {
            if (this.server != null) return null
            retiring
        }
        if (previous != null && withTimeoutOrNull(TEARDOWN_WAIT_MS) { previous.join() } == null) {
            Log.w(TAG, "The previous USB session is still ending; opening anyway")
        }
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
            retiring = null
            this.server = server
            this.router = router
        }
        afterPublish(server)
        try {
            server.connect(context, accessory)
        } catch (e: Throwable) {
            // A connect that throws (a refused USB permission, a failure after
            // the open) never reaches onClosed: unpublish the server, then stop
            // its detach watcher and close what it opened.
            synchronized(lock) {
                if (this.server === server) {
                    this.server = null
                    this.router = null
                }
            }
            server.disconnect()
            throw e
        }
        // A clear() after the publish retired the server, so the connect
        // opened nothing (or was torn down after it): report no server.
        return synchronized(lock) { server.takeIf { this.server === it } }
    }

    /**
     * Drops the active server, if any, and retires it: a connect that open()
     * has not yet run on it opens nothing, so no session or receiver outlives
     * the clear.
     */
    fun clear() {
        val active = synchronized(lock) {
            server.also {
                if (it != null) retiring = it.sessionJob
                server = null
                router = null
            }
        }
        active?.retire()
    }

    /** Drops [closedServer] unless an attach has since replaced it. */
    private fun closed(closedServer: UsbAccessoryServer) {
        synchronized(lock) {
            if (server !== closedServer) return
            retiring = closedServer.sessionJob
            server = null
            router = null
        }
    }

    private companion object {
        const val TAG = "UsbAccessoryServerSlot"

        /** How long an attach waits for the previous session's teardown. */
        const val TEARDOWN_WAIT_MS = 5_000L
    }
}
