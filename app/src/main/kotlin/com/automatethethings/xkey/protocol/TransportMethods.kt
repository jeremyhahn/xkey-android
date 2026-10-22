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
package com.automatethethings.xkey.protocol

import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext

/**
 * A family of JSON-RPC methods that one transport serves ahead of the shared
 * [RequestHandler].
 *
 * The [RequestHandler] instance is shared by BLE, TCP and USB, so a method
 * registered there is reachable on every transport. A family that only one
 * transport may serve (the USB password and seal stores, which go-xkms proxies
 * only over USB) is handed to that transport's session instead.
 */
interface TransportMethods {

    /** Whether [method] belongs to this family. */
    fun handles(method: String): Boolean

    /**
     * Serves a request whose method this family [handles].
     *
     * Never throws: every failure is answered as a typed error [Response].
     */
    suspend fun handle(request: Request): Response

    /**
     * Coroutine-context elements the session adds to every request it routes
     * to the shared [RequestHandler], so a handler there can see this
     * family's session state (the USB password vault's lock) without that
     * state living on the shared handler.
     */
    fun routingContext(): CoroutineContext = EmptyCoroutineContext
}
