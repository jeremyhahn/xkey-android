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
package com.automatethethings.xkey.remote

import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.CoroutineContext

/**
 * Runs [load] in [context] and hands its result, which holds secret
 * material, to the caller. If the caller never receives it, [zero] wipes it.
 *
 * `withContext` discards a block's result when the calling coroutine is
 * cancelled before it resumes, at the dispatcher handoff, so material
 * decrypted there would be dropped with no owner to zero it. Here the result
 * is held until `withContext` returns, and on a cancellation or any other
 * failure after the load it is zeroed before the exception goes on. Once this
 * returns, the caller owns the cleanup.
 */
suspend fun <T : Any> loadZeroedOnCancel(
    context: CoroutineContext,
    zero: (T) -> Unit,
    load: suspend () -> T
): T {
    val loaded = AtomicReference<T?>(null)
    try {
        return withContext(context) { load().also { loaded.set(it) } }
    } catch (e: Throwable) {
        loaded.getAndSet(null)?.let(zero)
        throw e
    }
}
