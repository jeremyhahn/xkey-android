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

import com.automatethethings.xkey.R
import com.automatethethings.xkey.remote.DesktopShareDecision
import org.junit.Assert.assertEquals
import org.junit.Test

/** Every gate decision has its own status line on the sharing sheet. */
class KeySharingDesktopStatusTest {

    @Test
    fun `each decision maps to a distinct status string`() {
        val lines = DesktopShareDecision.values().map { KeySharingBottomSheet.desktopStatusFor(it) }
        assertEquals(DesktopShareDecision.values().size, lines.toSet().size)
    }

    @Test
    fun `a symmetric key without a wrap path says why`() {
        assertEquals(
            R.string.sharing_desktop_no_wrap_path,
            KeySharingBottomSheet.desktopStatusFor(DesktopShareDecision.SYMMETRIC_NO_WRAP_PATH)
        )
        assertEquals(
            R.string.sharing_desktop_ready,
            KeySharingBottomSheet.desktopStatusFor(DesktopShareDecision.PUBLIC_KEY)
        )
    }
}
