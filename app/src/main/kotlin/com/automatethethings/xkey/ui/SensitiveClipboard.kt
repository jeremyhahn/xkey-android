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
 * - The clip is marked sensitive ([ClipDescription.EXTRA_IS_SENSITIVE], API
 *   33+), so the system clipboard preview does not show it.
 * - Each clip carries a random token in its description's extras. When the
 *   time is up the clip is cleared only if the clipboard still holds that
 *   token: a clip someone else set in between, or a later copy of ours, is
 *   left alone. Only the description is read back, never the secret text.
 * - Android 10 and later hide the clipboard from an app that is not in the
 *   foreground. If the description cannot be read then, the clip is cleared
 *   unless a change by someone else was seen while it could be read.
 */
internal object SensitiveClipboard {

    /** How long a copied secret stays on the clipboard. */
    const val CLEAR_AFTER_MS = 45_000L

    /** Description extra holding the token that marks a clip this app set. */
    const val EXTRA_CLIP_TOKEN = "com.automatethethings.xkey.extra.CLIP_TOKEN"

    private val mainHandler by lazy { Handler(Looper.getMainLooper()) }

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

    /** Copy [text] to [clipboard] and clear it after [clearAfterMs] if it is still ours. */
    fun copy(
        clipboard: ClipboardManager,
        label: String,
        text: String,
        clearAfterMs: Long = CLEAR_AFTER_MS,
        handler: Handler = mainHandler
    ) {
        val token = newToken()
        var replaced = false
        val listener = ClipboardManager.OnPrimaryClipChangedListener {
            val seen = readToken(clipboard)
            if (seen is TokenRead.Readable && seen.token != token) replaced = true
        }
        clipboard.setPrimaryClip(clip(label, text, token))
        clipboard.addPrimaryClipChangedListener(listener)
        handler.postDelayed({
            clipboard.removePrimaryClipChangedListener(listener)
            val current = readToken(clipboard)
            val ours = when (current) {
                is TokenRead.Readable -> current.token == token
                TokenRead.Unreadable -> !replaced
            }
            if (ours) clipboard.clearPrimaryClip()
        }, clearAfterMs)
    }

    private fun newToken(): String = UUID.randomUUID().toString()

    private sealed interface TokenRead {
        /** The clipboard could be read; [token] is null for a clip that is not ours or no clip. */
        data class Readable(val token: String?) : TokenRead
        data object Unreadable : TokenRead
    }

    private fun readToken(clipboard: ClipboardManager): TokenRead {
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
