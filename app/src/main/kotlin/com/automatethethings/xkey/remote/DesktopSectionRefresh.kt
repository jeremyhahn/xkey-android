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

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Keeps the sharing sheet's desktop section in step with the live session.
 *
 * Only the latest refresh may change the section. Each refresh cancels the
 * one before it, and a decision is shown only while the session it was taken
 * on is still the current one; otherwise the refresh starts over on the
 * session that replaced it. A disconnect or a session change that overtakes a
 * refresh suspended in its decision therefore always wins.
 *
 * A decision that fails (the key cannot be loaded, for one) is passed to
 * [failed] under the same rule instead of escaping the refresh's scope;
 * cancellation is never reported.
 *
 * Call [refresh] and [cancel] on [scope]'s thread (the main thread for the
 * sheet).
 *
 * @param currentSession the session a share would go out on now, or null
 *   when the section must be hidden
 * @param decide what the gate allows on that session
 * @param show applies a decision; null hides the section
 * @param failed reports a decision that failed; nothing may be sent
 */
class DesktopSectionRefresh(
    private val scope: CoroutineScope,
    private val currentSession: () -> ShareSession?,
    private val decide: suspend (ShareSession) -> DesktopShareDecision,
    private val show: (DesktopShareDecision?) -> Unit,
    private val failed: (Exception) -> Unit
) {
    private var running: Job? = null

    /** Re-reads the session and decides again, replacing any refresh still running. */
    fun refresh() {
        cancel()
        val session = currentSession()
        if (session == null) {
            show(null)
            return
        }
        running = scope.launch {
            val decision = try {
                Result.success(decide(session))
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Result.failure(e)
            }
            if (!isActive) return@launch
            if (!session.sameAs(currentSession())) {
                refresh()
                return@launch
            }
            decision.fold(onSuccess = { show(it) }, onFailure = { failed(it as Exception) })
        }
    }

    /** Stops any refresh still running; it shows nothing. */
    fun cancel() {
        running?.cancel()
        running = null
    }
}
