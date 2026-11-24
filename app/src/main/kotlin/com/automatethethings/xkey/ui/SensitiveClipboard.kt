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
package com.automatethethings.xkey.ui

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import java.util.UUID

/**
 * Puts a secret (a password, an OATH code) on the clipboard and takes it off
 * again [CLEAR_AFTER_MS] later.
 *
 * - The time is counted on [clock], which keeps counting while the device
 *   sleeps: a copy left on the clipboard through a deep sleep is due as soon
 *   as the device wakes. The handler timer only wakes the check; whether a
 *   copy is due is always decided by [clock].
 * - The clip is marked sensitive ([ClipDescription.EXTRA_IS_SENSITIVE], API
 *   33+), so the system clipboard preview does not show it.
 * - Each clip carries a random token in its description's extras. When the
 *   time is up the clip is cleared only if the clipboard still holds that
 *   token: a clip someone else set in between, or a later copy of ours, is
 *   left alone. Only the description is read back, never the secret text.
 * - Android 10 and later hide the clipboard from an app without window
 *   focus. An unreadable clipboard is never cleared: the clear stays pending
 *   until the app can read the clipboard again ([retryPendingClears], called by
 *   [ClipboardFocusRetry] when any window of the app gains focus) and finds its own token there.
 * - [clearIfOwned] is the only place the clipboard is cleared.
 *
 * Main thread only: copies, the change listener, the timer and the retry
 * all run there.
 */
internal object SensitiveClipboard {

    /** How long a copied secret stays on the clipboard. */
    const val CLEAR_AFTER_MS = 45_000L

    /** Description extra holding the token that marks a clip this app set. */
    const val EXTRA_CLIP_TOKEN = "com.automatethethings.xkey.extra.CLIP_TOKEN"

    private val mainHandler by lazy { Handler(Looper.getMainLooper()) }

    /** The deadline clock; counts time asleep. Replaced in tests. */
    internal var clock: MonotonicClock = MonotonicClock.SYSTEM

    /** A copy whose clip is to be cleared once [clock] reaches [dueAt] (milliseconds, time asleep included). */
    private class PendingClear(val token: String, val dueAt: Long)

    /** Copies not yet cleared or given up; at most the latest copy, since a new copy replaces the clip. */
    private val pending = mutableListOf<PendingClear>()

    /** A plain-text clip of [text] marked sensitive and tagged with [token]. */
    fun clip(label: String, text: String, token: String = newToken()): ClipData =
        ClipData.newPlainText(label, text).apply {
            description.extras = PersistableBundle().apply {
                putString(EXTRA_CLIP_TOKEN, token)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                }
            }
        }

    /** Copy [text] to [clipboard] and clear it after [clearAfterMs] once it is provably still ours. */
    fun copy(
        clipboard: ClipboardManager,
        label: String,
        text: String,
        clearAfterMs: Long = CLEAR_AFTER_MS,
        handler: Handler = mainHandler
    ) {
        val token = newToken()
        val entry = PendingClear(token, clock.nowMillis() + clearAfterMs)
        val listener = ClipboardManager.OnPrimaryClipChangedListener {
            val seen = tokenReader(clipboard)
            if (seen is TokenRead.Readable && seen.token != token) pending.remove(entry)
        }
        clipboard.setPrimaryClip(clip(label, text, token))
        // This clip replaced any earlier copy of ours: those can never match again.
        pending.clear()
        pending.add(entry)
        clipboard.addPrimaryClipChangedListener(listener)
        handler.postDelayed({
            clipboard.removePrimaryClipChangedListener(listener)
            if (entry in pending && entry.dueAt <= clock.nowMillis()) clearIfOwned(clipboard, entry)
        }, clearAfterMs)
    }

    /**
     * Clear the copies whose time is up and whose clip the clipboard still
     * holds. Called only by [ClipboardFocusRetry], when any window of the app
     * gains focus: from Android 10 on that is when the app can read the
     * clipboard again.
     */
    fun retryPendingClears(clipboard: ClipboardManager) {
        val now = clock.nowMillis()
        pending.filter { it.dueAt <= now }.forEach { entry ->
            if (entry in pending) clearIfOwned(clipboard, entry)
        }
    }

    /**
     * The one ownership check and the only clear: a readable clipboard holding
     * [entry]'s token is cleared; a readable clipboard holding anything else
     * ends [entry] without clearing; an unreadable one keeps [entry] pending
     * and clears nothing. Returns whether the clipboard was cleared.
     */
    private fun clearIfOwned(clipboard: ClipboardManager, entry: PendingClear): Boolean =
        when (val current = tokenReader(clipboard)) {
            is TokenRead.Readable -> {
                pending.remove(entry)
                if (current.token == entry.token) {
                    clipboard.clearPrimaryClip()
                    true
                } else {
                    false
                }
            }
            TokenRead.Unreadable -> false
        }

    /** Reads the token of the clip on the clipboard; replaced in tests. */
    internal var tokenReader: (ClipboardManager) -> TokenRead = ::readToken

    private fun newToken(): String = UUID.randomUUID().toString()

    internal sealed interface TokenRead {
        /** The clipboard could be read; [token] is null for a clip that is not ours or no clip. */
        data class Readable(val token: String?) : TokenRead
        data object Unreadable : TokenRead
    }

    internal fun readToken(clipboard: ClipboardManager): TokenRead {
        val description = try {
            clipboard.primaryClipDescription
        } catch (e: SecurityException) {
            null
        }
        return when {
            description != null -> TokenRead.Readable(description.extras?.getString(EXTRA_CLIP_TOKEN))
            // Before Android 10 null means an empty clipboard; from 10 on an
            // empty clipboard and a hidden one both read as null.
            Build.VERSION.SDK_INT < Build.VERSION_CODES.Q -> TokenRead.Readable(null)
            else -> TokenRead.Unreadable
        }
    }
}
