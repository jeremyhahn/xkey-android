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

import android.app.Activity
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Assert.fail

/**
 * View-tree helpers shared by the instrumented UI tests.
 *
 * Most xKey screens build their UI programmatically, so there are no XML ids to
 * match on and much of the content lives below the fold inside a scroll
 * container (where Espresso's `isDisplayed()` would fail). These helpers walk
 * the real view hierarchy on the main thread instead, and offer polling
 * variants for content that a Room `Flow` or a coroutine populates
 * asynchronously after launch.
 *
 * Rules of thumb:
 * - `...InTree` matchers ignore visibility; use them for "does this view exist".
 * - `...Shown` matchers require every ancestor to be VISIBLE; use them to tell
 *   an empty state apart from a populated list (both exist in the tree).
 */

/** Default time to wait for asynchronously-populated content. */
const val UI_AWAIT_TIMEOUT_MS = 5_000L

private const val POLL_INTERVAL_MS = 50L

// ---------------------------------------------------------------------------
// Tree search
// ---------------------------------------------------------------------------

/**
 * Returns the first [TextView] in [root] whose text contains [text], or null.
 * Visibility is ignored.
 */
fun findTextViewContaining(root: View?, text: String): TextView? =
    searchForText(root, text, requireVisible = false)

/**
 * Returns the first [TextView] in [root] whose text contains [text] and whose
 * whole ancestor chain is [View.VISIBLE], or null.
 */
fun findShownTextViewContaining(root: View?, text: String): TextView? =
    searchForText(root, text, requireVisible = true)

/**
 * Returns the first visible [TextView] in [root] whose text is exactly [text].
 *
 * Use this for numeric content such as summary counts, where a "contains" match
 * would happily hit any date or identifier that embeds the same digit.
 */
fun findShownTextViewWithExactText(root: View?, text: String): TextView? =
    searchForExactText(root, text)

private fun searchForExactText(view: View?, text: String): TextView? {
    if (view == null || view.visibility != View.VISIBLE) return null
    if (view is TextView && view.text?.toString() == text) return view
    if (view is ViewGroup) {
        for (i in 0 until view.childCount) {
            searchForExactText(view.getChildAt(i), text)?.let { return it }
        }
    }
    return null
}

private fun searchForText(view: View?, text: String, requireVisible: Boolean): TextView? {
    if (view == null) return null
    if (requireVisible && view.visibility != View.VISIBLE) return null
    if (view is TextView && view.text?.toString()?.contains(text) == true) return view
    if (view is ViewGroup) {
        for (i in 0 until view.childCount) {
            searchForText(view.getChildAt(i), text, requireVisible)?.let { return it }
        }
    }
    return null
}

/** Returns the first [RecyclerView] found in [root], or null. */
fun findFirstRecyclerView(root: View?): RecyclerView? {
    if (root == null) return null
    if (root is RecyclerView) return root
    if (root is ViewGroup) {
        for (i in 0 until root.childCount) {
            findFirstRecyclerView(root.getChildAt(i))?.let { return it }
        }
    }
    return null
}

// ---------------------------------------------------------------------------
// Activity-scoped assertions
// ---------------------------------------------------------------------------

/** Runs [block] on the activity and returns its value. */
fun <A : Activity, T> withActivity(scenario: ActivityScenario<A>, block: (A) -> T): T {
    var result: T? = null
    scenario.onActivity { result = block(it) }
    @Suppress("UNCHECKED_CAST")
    return result as T
}

/**
 * Polls [predicate] against the activity until it returns true or [timeoutMs]
 * elapses. Returns whether the predicate was ever satisfied.
 */
fun <A : Activity> awaitActivity(
    scenario: ActivityScenario<A>,
    timeoutMs: Long = UI_AWAIT_TIMEOUT_MS,
    predicate: (A) -> Boolean
): Boolean {
    InstrumentationRegistry.getInstrumentation().waitForIdleSync()
    val deadline = System.currentTimeMillis() + timeoutMs
    while (System.currentTimeMillis() < deadline) {
        // A screen may finish itself while being polled (detail screens close
        // when their row disappears); treat that as "not satisfied yet" rather
        // than letting ActivityScenario's destroyed-state error escape.
        val satisfied = runCatching { withActivity(scenario) { predicate(it) } }.getOrDefault(false)
        if (satisfied) return true
        Thread.sleep(POLL_INTERVAL_MS)
    }
    return false
}

/** Polls until a [TextView] containing [text] exists in the activity's tree. */
fun <A : Activity> awaitTextInTree(
    scenario: ActivityScenario<A>,
    text: String,
    timeoutMs: Long = UI_AWAIT_TIMEOUT_MS
): Boolean = awaitActivity(scenario, timeoutMs) {
    findTextViewContaining(it.window.decorView, text) != null
}

/** Polls until a *visible* [TextView] containing [text] exists. */
fun <A : Activity> awaitShownTextInTree(
    scenario: ActivityScenario<A>,
    text: String,
    timeoutMs: Long = UI_AWAIT_TIMEOUT_MS
): Boolean = awaitActivity(scenario, timeoutMs) {
    findShownTextViewContaining(it.window.decorView, text) != null
}

/** Asserts that a [TextView] containing [text] appears within the timeout. */
fun <A : Activity> assertTextInTree(scenario: ActivityScenario<A>, text: String) {
    assertTrue(
        "Expected a TextView containing '$text' in the activity's view tree",
        awaitTextInTree(scenario, text)
    )
}

/** Asserts that a *visible* [TextView] containing [text] appears. */
fun <A : Activity> assertShownTextInTree(scenario: ActivityScenario<A>, text: String) {
    assertTrue(
        "Expected a visible TextView containing '$text' in the activity's view tree",
        awaitShownTextInTree(scenario, text)
    )
}

/** Asserts that a *visible* [TextView] whose text is exactly [text] appears. */
fun <A : Activity> assertExactTextShown(scenario: ActivityScenario<A>, text: String) {
    assertTrue(
        "Expected a visible TextView reading exactly '$text'",
        awaitActivity(scenario) {
            findShownTextViewWithExactText(it.window.decorView, text) != null
        }
    )
}

/**
 * Asserts that no [TextView] containing [text] remains in the tree.
 *
 * Polls rather than checking once: RecyclerView item animators keep removed rows
 * attached for the duration of their remove animation, so an immediate check
 * would race the list update.
 */
fun <A : Activity> assertTextNotInTree(
    scenario: ActivityScenario<A>,
    text: String,
    timeoutMs: Long = UI_AWAIT_TIMEOUT_MS
) {
    assertTrue(
        "Did not expect a TextView containing '$text' in the activity's view tree",
        awaitActivity(scenario, timeoutMs) {
            findTextViewContaining(it.window.decorView, text) == null
        }
    )
}

// ---------------------------------------------------------------------------
// Interaction
// ---------------------------------------------------------------------------

/**
 * Clicks the view carrying [text], or its nearest clickable ancestor.
 *
 * Programmatic cards wrap a non-clickable [TextView] inside a clickable row, and
 * rows are frequently scrolled out of view, so this performs the click directly
 * on the main thread rather than injecting motion events.
 */
fun <A : Activity> clickTextInTree(scenario: ActivityScenario<A>, text: String) {
    scenario.onActivity { activity ->
        val target: View? = findTextViewContaining(activity.window.decorView, text)
        if (target == null) {
            fail("No view containing '$text' to click")
            return@onActivity
        }
        var candidate: View? = target
        while (candidate != null && !candidate.isClickable) {
            candidate = candidate.parent as? View
        }
        (candidate ?: target).performClick()
    }
    InstrumentationRegistry.getInstrumentation().waitForIdleSync()
}

/**
 * Clicks the first visible, clickable [TextView] whose text is exactly [text].
 *
 * Filter chips and floating action buttons share their label with badges and
 * dialog titles elsewhere on screen; requiring an exact match on a view that is
 * itself clickable pins the click to the control rather than to a decoration.
 */
fun <A : Activity> clickClickableWithExactText(scenario: ActivityScenario<A>, text: String) {
    scenario.onActivity { activity ->
        val target = findClickableWithExactText(activity.window.decorView, text)
        if (target == null) {
            fail("No clickable view reading exactly '$text'")
            return@onActivity
        }
        target.performClick()
    }
    InstrumentationRegistry.getInstrumentation().waitForIdleSync()
}

private fun findClickableWithExactText(view: View?, text: String): View? {
    if (view == null || view.visibility != View.VISIBLE) return null
    if (view is TextView && view.isClickable && view.text?.toString() == text) return view
    if (view is ViewGroup) {
        for (i in 0 until view.childCount) {
            findClickableWithExactText(view.getChildAt(i), text)?.let { return it }
        }
    }
    return null
}

/**
 * Asserts that [text] appears on a bound row of the first [RecyclerView].
 *
 * Scoping the search to the list matters whenever the same label also decorates
 * a filter chip or summary badge elsewhere on the screen.
 */
fun <A : Activity> assertTextInList(scenario: ActivityScenario<A>, text: String) {
    assertTrue(
        "Expected '$text' on a row of the list",
        awaitActivity(scenario) {
            val recycler = findFirstRecyclerView(it.window.decorView)
            recycler != null && findShownTextViewContaining(recycler, text) != null
        }
    )
}

/** Returns the item count of the first [RecyclerView] in the activity. */
fun <A : Activity> recyclerItemCount(scenario: ActivityScenario<A>): Int =
    withActivity(scenario) {
        findFirstRecyclerView(it.window.decorView)?.adapter?.itemCount ?: -1
    }

/** Polls until the first [RecyclerView] reports at least [count] items. */
fun <A : Activity> awaitRecyclerItemCount(
    scenario: ActivityScenario<A>,
    count: Int,
    timeoutMs: Long = UI_AWAIT_TIMEOUT_MS
): Boolean = awaitActivity(scenario, timeoutMs) {
    (findFirstRecyclerView(it.window.decorView)?.adapter?.itemCount ?: -1) >= count
}

/** Polls until the first [RecyclerView] reports exactly [count] items. */
fun <A : Activity> awaitExactRecyclerItemCount(
    scenario: ActivityScenario<A>,
    count: Int,
    timeoutMs: Long = UI_AWAIT_TIMEOUT_MS
): Boolean = awaitActivity(scenario, timeoutMs) {
    (findFirstRecyclerView(it.window.decorView)?.adapter?.itemCount ?: -1) == count
}

/**
 * Long-clicks the item view bound at [position] in the first [RecyclerView].
 *
 * Scrolls the item into view first so its view holder exists, then invokes the
 * row's listener directly (espresso-contrib is not a dependency here).
 */
fun <A : Activity> longClickRecyclerItem(scenario: ActivityScenario<A>, position: Int) {
    scenario.onActivity { activity ->
        findFirstRecyclerView(activity.window.decorView)?.scrollToPosition(position)
    }
    InstrumentationRegistry.getInstrumentation().waitForIdleSync()
    scenario.onActivity { activity ->
        val recycler = findFirstRecyclerView(activity.window.decorView)
        if (recycler == null) {
            fail("No RecyclerView in the activity")
            return@onActivity
        }
        val holder = recycler.findViewHolderForAdapterPosition(position)
        if (holder == null) {
            fail("No view holder bound at position $position")
            return@onActivity
        }
        holder.itemView.performLongClick()
    }
    InstrumentationRegistry.getInstrumentation().waitForIdleSync()
}

/**
 * Asserts that [text] appears on a list-backed screen, scrolling the first
 * [RecyclerView] through its positions until it does.
 *
 * A RecyclerView binds only the rows on screen, so a row further down is not
 * merely invisible — it is not in the view tree at all. Any assertion about a
 * row that other suites' leftover data can push down the list has to scroll,
 * or it fails for a reason that has nothing to do with the screen under test.
 */
fun <A : Activity> assertShownTextInList(scenario: ActivityScenario<A>, text: String) {
    if (awaitShownTextInTree(scenario, text, LIST_SCAN_SETTLE_MS)) return

    val itemCount = withActivity(scenario) {
        findFirstRecyclerView(it.window.decorView)?.adapter?.itemCount ?: 0
    }
    for (position in 0 until itemCount) {
        withActivity(scenario) {
            findFirstRecyclerView(it.window.decorView)?.scrollToPosition(position)
        }
        if (awaitShownTextInTree(scenario, text, LIST_SCAN_SETTLE_MS)) return
    }

    fail(
        "Expected a visible TextView containing '$text' somewhere in the list " +
            "(scanned $itemCount rows)"
    )
}

/**
 * Per-position wait while scanning a list. Short, because the row either binds
 * on the next layout pass or is not at that position at all.
 */
private const val LIST_SCAN_SETTLE_MS = 300L
