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

import androidx.recyclerview.widget.RecyclerView
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.automatethethings.xkey.password.PasswordRecord
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Collections

/**
 * Covers [PasswordAdapter]'s move from `notifyDataSetChanged()` to
 * `ListAdapter` + `DiffUtil`.
 *
 * `notifyDataSetChanged()` tells RecyclerView that *everything* changed, so the
 * whole list is rebound with no move/insert/remove animation and every row loses
 * its transient state. Every sibling adapter (`OathAdapter`, `PasskeyAdapter`)
 * already diffs; this one did not.
 *
 * The observable difference is the notification the adapter emits, so that is
 * what is asserted here rather than anything about pixels: a one-row append must
 * arrive as an insert of one row, and resubmitting an equal list must say nothing
 * at all.
 *
 * No host activity is launched: the adapter's list handling is exercised
 * directly, and building rows needs no `Context` until a view holder is created.
 * `AsyncListDiffer` requires a Looper and dispatches on the main thread, hence an
 * instrumented test and `runOnMainSync`.
 */
@RunWith(AndroidJUnit4::class)
class PasswordAdapterDiffTest {

    private lateinit var adapter: PasswordAdapter
    private lateinit var events: MutableList<String>

    @Before
    fun setUp() {
        events = Collections.synchronizedList(mutableListOf())
        onMain {
            adapter = PasswordAdapter { }
            adapter.registerAdapterDataObserver(object : RecyclerView.AdapterDataObserver() {
                override fun onChanged() {
                    events.add("changed")
                }

                override fun onItemRangeInserted(positionStart: Int, itemCount: Int) {
                    events.add("inserted:$positionStart:$itemCount")
                }

                override fun onItemRangeRemoved(positionStart: Int, itemCount: Int) {
                    events.add("removed:$positionStart:$itemCount")
                }

                override fun onItemRangeChanged(positionStart: Int, itemCount: Int) {
                    events.add("rangeChanged:$positionStart:$itemCount")
                }

                override fun onItemRangeMoved(fromPosition: Int, toPosition: Int, itemCount: Int) {
                    events.add("moved:$fromPosition:$toPosition:$itemCount")
                }
            })
        }
    }

    // ---------------------------------------------------------------
    // Notifications
    // ---------------------------------------------------------------

    @Test
    fun appendingARow_reportsAnInsertRatherThanARebuild() {
        submitAndAwait(listOf(record("a"), record("b")))
        events.clear()

        submitAndAwait(listOf(record("a"), record("b"), record("c")))

        assertEquals(listOf("inserted:2:1"), events.toList())
        assertFalse(
            "A diffed list must never fall back to notifyDataSetChanged",
            events.contains("changed")
        )
    }

    @Test
    fun removingARow_reportsARemoval() {
        submitAndAwait(listOf(record("a"), record("b"), record("c")))
        events.clear()

        submitAndAwait(listOf(record("a"), record("c")))

        assertEquals(listOf("removed:1:1"), events.toList())
    }

    /**
     * A reload that produced the same rows used to redraw the whole list. It must
     * now be silent.
     *
     * The equal list is followed by a real change and only that change is awaited:
     * `AsyncListDiffer` applies submissions in order, so once the append has been
     * dispatched the equal submission has demonstrably been processed too.
     */
    @Test
    fun resubmittingAnEqualList_notifiesNothing() {
        val items = listOf(record("a"), record("b"))
        submitAndAwait(items)
        events.clear()

        onMain { adapter.submit(items.map { it.copy() }) }
        submitAndAwait(items + record("c"))

        assertEquals(listOf("inserted:2:1"), events.toList())
    }

    // ---------------------------------------------------------------
    // Diff callback semantics
    // ---------------------------------------------------------------

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
        val original = record("a", title = "GitHub", username = "user-01", url = "github.com")

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

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun submitAndAwait(items: List<PasswordRecord>) {
        onMain { adapter.submit(items) }
        awaitCondition("The submitted list should be applied") {
            adapter.itemCount == items.size
        }
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

    private fun onMain(block: () -> Unit) {
        InstrumentationRegistry.getInstrumentation().runOnMainSync(block)
    }
}
