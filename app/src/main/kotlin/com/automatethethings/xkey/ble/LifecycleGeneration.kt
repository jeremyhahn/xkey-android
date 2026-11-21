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

package com.automatethethings.xkey.ble

/**
 * The one check every BLE start that waits on the stack makes before it
 * publishes what it started: a stop or destroy that ran while it waited wins.
 *
 * A start takes a token with [begin], waits (opening a GATT server, adding a
 * service), and then publishes only through [publish], which runs while the
 * token is still current. A stop calls [advance] and a destroy [end] before
 * they look at what is published, so either a start has published already
 * and the stop takes it down, or the start finds its token stale and closes
 * what it opened itself. Nothing a stale start opened is ever left up.
 */
internal class LifecycleGeneration {
    private val lock = Any()
    private var current = 0L
    private var ended = false

    /** The token a start carries; null once [end] has run, so nothing starts again. */
    fun begin(): Long? = synchronized(lock) { if (ended) null else current }

    /** Whether no stop or destroy has run since [token] was taken. */
    fun isCurrent(token: Long): Boolean = synchronized(lock) { !ended && token == current }

    /** A stop: no start begun before it publishes. Waits for a [publish] in progress. */
    fun advance() {
        synchronized(lock) { current++ }
    }

    /** A destroy: no start, begun before or after it, publishes again. */
    fun end() {
        synchronized(lock) {
            ended = true
            current++
        }
    }

    /**
     * Runs [publish] only while [token] is current, under the same lock as
     * [advance] and [end]; false when it did not run, and the caller closes
     * what it opened.
     */
    fun publish(token: Long, publish: () -> Unit): Boolean = synchronized(lock) {
        if (ended || token != current) {
            false
        } else {
            publish()
            true
        }
    }
}
