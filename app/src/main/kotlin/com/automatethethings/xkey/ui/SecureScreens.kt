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

import android.app.Dialog
import android.view.Window
import android.view.WindowManager

/**
 * Keeps a screen that shows or takes a secret (a password, a PIN) out of
 * screenshots, screen recordings, casting and the recents thumbnail.
 *
 * A dialog is a window of its own and does not inherit its activity's
 * FLAG_SECURE, so every dialog such a screen opens goes through [show].
 */
internal object SecureScreens {

    /** Mark [window] FLAG_SECURE. */
    fun protect(window: Window?) {
        window?.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }

    /** Mark [dialog]'s window FLAG_SECURE, then show it. */
    fun <D : Dialog> show(dialog: D): D {
        protect(dialog.window)
        dialog.show()
        return dialog
    }
}
