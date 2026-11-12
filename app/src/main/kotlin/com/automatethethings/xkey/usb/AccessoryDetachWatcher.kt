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

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbAccessory
import android.hardware.usb.UsbManager
import androidx.core.content.ContextCompat
import androidx.core.content.IntentCompat

/**
 * Tells [UsbAccessoryServer] when an accessory goes away while one is open.
 *
 * Android delivers `USB_ACCESSORY_ATTACHED` to an activity, but
 * `USB_ACCESSORY_DETACHED` only as a broadcast, so the server watches for it
 * from [start] (when an accessory opens) until [stop] (when it closes).
 */
interface AccessoryDetachWatcher {
    /**
     * Starts watching. [onDetach] gets the detached accessory, or null when
     * the broadcast does not name one.
     */
    fun start(context: Context, onDetach: (UsbAccessory?) -> Unit)

    /** Stops watching. Safe to call when not watching. */
    fun stop()
}

/**
 * The production [AccessoryDetachWatcher]: a receiver for
 * [UsbManager.ACTION_USB_ACCESSORY_DETACHED] registered on the application
 * context, so it does not outlive a destroyed service as a leaked receiver.
 * It is not exported: the detach is a protected system broadcast, and no
 * other app may fake one.
 */
class BroadcastAccessoryDetachWatcher : AccessoryDetachWatcher {
    private var registeredOn: Context? = null
    private var receiver: BroadcastReceiver? = null

    @Synchronized
    override fun start(context: Context, onDetach: (UsbAccessory?) -> Unit) {
        stop()
        val appContext = context.applicationContext ?: context
        val detachReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action != UsbManager.ACTION_USB_ACCESSORY_DETACHED) return
                onDetach(
                    IntentCompat.getParcelableExtra(intent, UsbManager.EXTRA_ACCESSORY, UsbAccessory::class.java)
                )
            }
        }
        ContextCompat.registerReceiver(
            appContext,
            detachReceiver,
            IntentFilter(UsbManager.ACTION_USB_ACCESSORY_DETACHED),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
        registeredOn = appContext
        receiver = detachReceiver
    }

    @Synchronized
    override fun stop() {
        val registered = receiver ?: return
        try {
            registeredOn?.unregisterReceiver(registered)
        } catch (_: IllegalArgumentException) {
            // Already unregistered.
        }
        receiver = null
        registeredOn = null
    }
}
