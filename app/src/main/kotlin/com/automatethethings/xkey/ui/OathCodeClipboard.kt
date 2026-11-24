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
import android.content.Context
import com.automatethethings.xkey.oath.OathRepository

/**
 * The one way the app puts an OATH code on the clipboard: the list row tap,
 * the long-press Copy and the details screen's Copy all come here.
 *
 * - The clip is marked sensitive ([ClipDescription.EXTRA_IS_SENSITIVE], API
 *   33+), so the system clipboard preview does not show the code, and it is
 *   cleared after [SensitiveClipboard.CLEAR_AFTER_MS] unless something else
 *   has been copied since ([SensitiveClipboard]).
 * - Every copy resolves the code when it runs, through one function
 *   ([OathRepository.generateCode] in the app): TOTP at the current time,
 *   HOTP at the stored counter, which it claims and advances once (and
 *   records the use), so the next copy gives a fresh code. No caller passes a
 *   code it captured earlier, so a menu or a screen left open across a TOTP
 *   period never copies an expired code.
 *
 * The caller shows the confirmation (a Snackbar in the list, a Toast on the
 * details screen) or, when [copy] throws, one generic "code unavailable"
 * message, never the exception text.
 *
 * @param codeNow Generates the credential's code at the moment of the call;
 *   throws, before any HOTP claim, when no code can be computed.
 */
class OathCodeClipboard(
    private val clipboard: ClipboardManager,
    private val codeNow: suspend (oathId: String) -> String
) {

    /**
     * Copy the code of the credential [oathId] as it is now. Returns the code
     * copied; throws (and copies nothing) when no code can be computed.
     */
    suspend fun copy(oathId: String): String {
        val code = codeNow(oathId)
        SensitiveClipboard.copy(clipboard, CLIP_LABEL, code)
        return code
    }

    companion object {
        /** Clip label; the code itself is never part of it. */
        const val CLIP_LABEL = "OTP code"

        /** The clipboard of [context] with codes from [repository]. */
        fun create(context: Context, repository: OathRepository): OathCodeClipboard =
            OathCodeClipboard(
                context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager,
                repository::generateCode
            )

        /** A plain-text clip of [code] marked sensitive where the platform supports it. */
        fun sensitiveClip(code: String): ClipData = SensitiveClipboard.clip(CLIP_LABEL, code)
    }
}
