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

import com.automatethethings.xkey.usb.UsbAccessoryServer
import com.automatethethings.xkey.usb.UsbAccessoryServerSlot
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job

/**
 * The service's USB attach path once the native-USB setting allows it: opens
 * a server through [slot] and keeps [tracker] following the slot's server.
 *
 * The desktop is ready only once the USB session is Connected, and is lost as
 * soon as it ends, detached or not. One observer of
 * [UsbAccessoryServerSlot.states], installed on the first attach and kept
 * until [scope] ends, follows whichever server the slot holds. No attach
 * installs or cancels an observer of its own, so an attach that resumes late
 * cannot replace the observer of the server that now holds the slot (#134).
 *
 * @param afterOpen Runs between the open returning and the session refresh;
 *   tests use it to pause one attach while another runs.
 */
class UsbAttachPath(
    private val slot: UsbAccessoryServerSlot,
    private val tracker: DesktopSessionTracker,
    private val scope: CoroutineScope,
    private val afterOpen: suspend (UsbAccessoryServer) -> Unit = {},
) {
    private var observer: Job? = null

    /** Installs the one observer of the slot, if it is not yet installed. */
    @Synchronized
    fun observe() {
        if (observer == null) observer = tracker.follow(scope, slot.states)
    }

    /**
     * Opens a server with [open] (a call to [UsbAccessoryServerSlot.open]) and
     * refreshes the desktop session. Returns the server, or null when the slot
     * refused the open.
     */
    suspend fun attach(open: suspend UsbAccessoryServerSlot.() -> UsbAccessoryServer?): UsbAccessoryServer? {
        observe()
        val server = slot.open() ?: return null
        afterOpen(server)
        tracker.refresh()
        return server
    }
}
