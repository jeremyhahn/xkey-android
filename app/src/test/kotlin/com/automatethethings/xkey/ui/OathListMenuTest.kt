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
import com.automatethethings.xkey.ui.OathListMenu.Action
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class OathListMenuTest {

    @Test
    fun `without a desktop the menu is copy, delete, details`() {
        val menu = OathListMenu(emptyList())

        assertEquals(listOf(Action.COPY, Action.DELETE, Action.DETAILS), menu.entries)
        assertEquals(
            listOf(R.string.oath_context_copy, R.string.oath_context_delete, R.string.oath_context_details),
            menu.labels
        )
    }

    @Test
    fun `desktop entries follow the row entries in the order given`() {
        val menu = OathListMenu(
            listOf(OathDesktopActions.Entry.COPY, OathDesktopActions.Entry.DESKTOP_CODE)
        )

        assertEquals(
            listOf(Action.COPY, Action.DELETE, Action.DETAILS, Action.COPY_TO_DESKTOP, Action.DESKTOP_CODE),
            menu.entries
        )
    }

    @Test
    fun `only the desktop entries offered are appended`() {
        val menu = OathListMenu(listOf(OathDesktopActions.Entry.DESKTOP_CODE))

        assertEquals(listOf(Action.COPY, Action.DELETE, Action.DETAILS, Action.DESKTOP_CODE), menu.entries)
        assertEquals(R.string.oath_context_desktop_code, menu.labels[3])
    }

    @Test
    fun `each index maps to its action`() {
        val menu = OathListMenu(
            listOf(OathDesktopActions.Entry.COPY, OathDesktopActions.Entry.DESKTOP_CODE)
        )

        assertEquals(Action.COPY, menu.actionAt(0))
        assertEquals(Action.DELETE, menu.actionAt(1))
        assertEquals(Action.DETAILS, menu.actionAt(2))
        assertEquals(Action.COPY_TO_DESKTOP, menu.actionAt(3))
        assertEquals(Action.DESKTOP_CODE, menu.actionAt(4))
    }

    @Test
    fun `an index outside the menu maps to nothing`() {
        val menu = OathListMenu(emptyList())

        assertNull(menu.actionAt(3))
        assertNull(menu.actionAt(-1))
    }
}
