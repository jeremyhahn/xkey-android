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
import com.automatethethings.xkey.oath.OathCredentialEntity
import com.automatethethings.xkey.oath.OathRepository

/**
 * The one way the app puts an OATH code on the clipboard: the list row tap,
 * the long-press Copy and the details screen's Copy all come here.
 *
 * - The clip is marked sensitive ([ClipDescription.EXTRA_IS_SENSITIVE], API
 *   33+), so the system clipboard preview does not show the code, and it is
 *   cleared after [SensitiveClipboard.CLEAR_AFTER_MS] unless something else
 *   has been copied since ([SensitiveClipboard]).
 * - TOTP copies the code on screen and leaves the credential untouched.
 * - HOTP copies the code at the stored counter and advances the counter
 *   ([OathRepository.generateCode] also records the use), so the next copy
 *   gives a fresh code and the list moves on to the next counter's code.
 *
 * The caller shows the confirmation (a Snackbar in the list, a Toast on the
 * details screen).
 *
 * @param nextHotpCode Generates an HOTP code at the stored counter and
 *   advances it; [OathRepository.generateCode] in the app.
 */
class OathCodeClipboard(
    private val clipboard: ClipboardManager,
    private val nextHotpCode: suspend (oathId: String) -> String
) {

    /**
     * Copy the code of [credential]. [shownCode] is the TOTP code on screen;
     * an HOTP code is always generated afresh. Returns the code copied.
     */
    suspend fun copy(credential: OathCredentialEntity, shownCode: String): String {
        val code = if (credential.oathType == HOTP) nextHotpCode(credential.oathId) else shownCode
        SensitiveClipboard.copy(clipboard, CLIP_LABEL, code)
        return code
    }

    companion object {
        private const val HOTP = "HOTP"

        /** Clip label; the code itself is never part of it. */
        const val CLIP_LABEL = "OTP code"

        /** The clipboard of [context] with HOTP codes from [repository]. */
        fun create(context: Context, repository: OathRepository): OathCodeClipboard =
            OathCodeClipboard(
                context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager,
                repository::generateCode
            )

        /** A plain-text clip of [code] marked sensitive where the platform supports it. */
        fun sensitiveClip(code: String): ClipData = SensitiveClipboard.clip(CLIP_LABEL, code)
    }
}
