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

import androidx.annotation.StringRes
import com.automatethethings.xkey.R

/**
 * The long-press menu of an OATH list row: Copy, Delete and Details, then
 * the desktop entries the connected desktop offers (none when no desktop is
 * connected). The dialog shows [labels] in [entries] order and maps the
 * picked index back with [actionAt].
 */
class OathListMenu(desktopEntries: List<OathDesktopActions.Entry>) {

    /** One menu entry and the string resource it is labelled with. */
    enum class Action(@StringRes val label: Int) {
        COPY(R.string.oath_context_copy),
        DELETE(R.string.oath_context_delete),
        DETAILS(R.string.oath_context_details),
        COPY_TO_DESKTOP(R.string.oath_context_copy_to_desktop),
        DESKTOP_CODE(R.string.oath_context_desktop_code)
    }

    val entries: List<Action> = listOf(Action.COPY, Action.DELETE, Action.DETAILS) +
        desktopEntries.map { entry ->
            when (entry) {
                OathDesktopActions.Entry.COPY -> Action.COPY_TO_DESKTOP
                OathDesktopActions.Entry.DESKTOP_CODE -> Action.DESKTOP_CODE
            }
        }

    /** Label resources in display order. */
    val labels: List<Int> get() = entries.map { it.label }

    /** The action at the picked [index], or null for an index outside the menu. */
    fun actionAt(index: Int): Action? = entries.getOrNull(index)
}
