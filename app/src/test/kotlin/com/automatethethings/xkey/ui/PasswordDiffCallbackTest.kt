/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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

import com.automatethethings.xkey.password.PasswordRecord
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [PasswordAdapter.PasswordDiffCallback]'s identity and content rules.
 *
 * The callback is plain comparison logic, so it is asserted directly; the
 * notifications the adapter emits from it are covered by the instrumented
 * `PasswordAdapterDiffTest`, which needs a Looper.
 */
class PasswordDiffCallbackTest {

    @Test
    fun itemsAreIdentifiedByTheirPasswordId() {
        val callback = PasswordAdapter.PasswordDiffCallback()
        val original = record("a", title = "GitHub")
        val renamed = original.copy(title = "GitHub (work)")

        assertTrue(callback.areItemsTheSame(original, renamed))
        assertFalse(callback.areItemsTheSame(original, record("b", title = "GitHub")))
    }

    @Test
    fun contentsCoverEverythingTheRowRenders() {
        val callback = PasswordAdapter.PasswordDiffCallback()
        val original = record("a", title = "GitHub", username = "jhahn", url = "github.com")

        assertTrue(callback.areContentsTheSame(original, original.copy()))
        assertFalse(callback.areContentsTheSame(original, original.copy(title = "GitLab")))
        assertFalse(callback.areContentsTheSame(original, original.copy(username = "other")))
        assertFalse(callback.areContentsTheSame(original, original.copy(url = "gitlab.com")))
        assertFalse(callback.areContentsTheSame(original, original.copy(name = "renamed")))
    }

    /**
     * The password value is never rendered in the list, so changing it must not
     * redraw the row — that would be a needless re-bind of a secret-bearing item.
     */
    @Test
    fun changingOnlyTheSecret_isNotAContentChange() {
        val callback = PasswordAdapter.PasswordDiffCallback()
        val original = record("a", title = "GitHub")

        assertTrue(callback.areContentsTheSame(original, original.copy(password = "rotated")))
    }

    private fun record(
        id: String,
        title: String? = "Title $id",
        username: String? = null,
        url: String? = null
    ) = PasswordRecord(
        passwordId = "pwd-$id",
        name = "name-$id",
        title = title,
        username = username,
        password = "secret-$id",
        url = url
    )
}
