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
import androidx.core.widget.NestedScrollView
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.UiController
import androidx.test.espresso.ViewAction
import androidx.test.espresso.action.ViewActions.scrollTo
import androidx.test.espresso.matcher.ViewMatchers.Visibility
import androidx.test.espresso.matcher.ViewMatchers.isAssignableFrom
import androidx.test.espresso.matcher.ViewMatchers.withEffectiveVisibility
import androidx.test.platform.app.InstrumentationRegistry
import org.hamcrest.Description
import org.hamcrest.Matcher
import org.hamcrest.Matchers.allOf
import org.hamcrest.TypeSafeMatcher
import org.junit.Assert.assertTrue

/**
 * Shared helpers for the programmatic-UI instrumented tests in this package.
 *
 * Most xKey screens build their views in code, so there are no XML ids to match
 * on and no Espresso idling resource behind the coroutine/Room loads that
 * populate them. These helpers provide the three primitives every suite needs:
 *
 * - [scrollToView]: an Espresso scroll action that also works inside a
 *   [NestedScrollView] (the stock `scrollTo()` only handles `ScrollView`).
 * - [awaitText] / [awaitCondition]: deterministic polling for asynchronously
 *   rendered content instead of arbitrary sleeps.
 * - [nthMatch] / [findTextView] / [switchForLabel]: matchers for view trees
 *   that have no ids and frequently repeat the same text.
 */

/** Default budget for the polling helpers. */
private const val AWAIT_TIMEOUT_MS = 5_000L

/** Poll interval for the polling helpers. */
private const val AWAIT_POLL_MS = 50L

/**
 * Scrolls to a view that may live inside a [NestedScrollView].
 *
 * Espresso's [scrollTo] only declares support for `ScrollView`, so this first
 * attempts the standard action and falls back to walking up to the enclosing
 * [NestedScrollView] and requesting focus for the target child.
 */
fun scrollToView(): ViewAction = object : ViewAction {

    override fun getConstraints(): Matcher<View> = allOf(
        withEffectiveVisibility(Visibility.VISIBLE),
        isAssignableFrom(View::class.java)
    )

    override fun getDescription(): String = "scroll NestedScrollView to view"

    override fun perform(uiController: UiController, view: View) {
        try {
            scrollTo().perform(uiController, view)
            return
        } catch (_: Exception) {
            // Not a plain ScrollView; fall through to the NestedScrollView path.
        }

        var parent = view.parent
        while (parent != null) {
            if (parent is NestedScrollView) {
                parent.requestChildFocus(view, view)
                uiController.loopMainThreadUntilIdle()
                return
            }
            parent = parent.parent
        }
    }
}

/**
 * Recursively finds the first [TextView] in [view]'s subtree whose text
 * contains [text], or null when there is none.
 */
fun findTextView(view: View?, text: String): TextView? {
    if (view == null) return null
    if (view is TextView && view.text?.toString()?.contains(text) == true) return view
    if (view is ViewGroup) {
        for (i in 0 until view.childCount) {
            val result = findTextView(view.getChildAt(i), text)
            if (result != null) return result
        }
    }
    return null
}

/**
 * Recursively finds the first *visible* [TextView] in [view]'s subtree whose
 * text contains [text], or null when there is none.
 *
 * Presence in the tree is not the same as being on screen. When a list empties
 * out, these screens set `recyclerView.visibility = GONE`; a GONE ViewGroup
 * never lays out again, so its already-bound rows remain attached as children
 * indefinitely. [View.isShown] is the correct test for "the user can see this",
 * and it stays true for rows merely scrolled out of view.
 */
fun findShownTextView(view: View?, text: String): TextView? {
    if (view == null || view.visibility != View.VISIBLE) return null
    if (view is TextView && view.text?.toString()?.contains(text) == true && view.isShown) {
        return view
    }
    if (view is ViewGroup) {
        for (i in 0 until view.childCount) {
            val result = findShownTextView(view.getChildAt(i), text)
            if (result != null) return result
        }
    }
    return null
}

/**
 * Recursively collects every view in [view]'s subtree that satisfies
 * [predicate], in depth-first order.
 */
fun collectViews(view: View?, predicate: (View) -> Boolean): List<View> {
    val found = mutableListOf<View>()
    fun walk(current: View?) {
        if (current == null) return
        if (predicate(current)) found.add(current)
        if (current is ViewGroup) {
            for (i in 0 until current.childCount) walk(current.getChildAt(i))
        }
    }
    walk(view)
    return found
}

/**
 * Polls [scenario]'s view hierarchy until a [TextView] containing [text]
 * appears, failing the test when [timeoutMs] elapses first.
 *
 * Screens populated from a coroutine-backed Room query are not covered by
 * Espresso's idling, so assertions on their content need an explicit wait.
 */
fun <A : Activity> awaitText(
    scenario: ActivityScenario<A>,
    text: String,
    timeoutMs: Long = AWAIT_TIMEOUT_MS
) {
    assertTrue(
        "Expected a view containing '$text' within ${timeoutMs}ms",
        pollForText(scenario, text, timeoutMs)
    )
}

/**
 * Polls [scenario]'s view hierarchy asserting that no *visible* [TextView]
 * containing [text] remains within [timeoutMs].
 *
 * Visibility, not mere presence, is the assertion these callers want: a row
 * that has been filtered or deleted away stays attached to a RecyclerView that
 * the activity has just set to GONE (a GONE parent never lays out again), so a
 * presence-only check can never succeed even though nothing is on screen. See
 * [findShownTextView].
 */
fun <A : Activity> awaitTextAbsent(
    scenario: ActivityScenario<A>,
    text: String,
    timeoutMs: Long = AWAIT_TIMEOUT_MS
) {
    val deadline = System.currentTimeMillis() + timeoutMs
    var visible = true
    while (visible && System.currentTimeMillis() < deadline) {
        visible = hasShownText(scenario, text)
        if (visible) Thread.sleep(AWAIT_POLL_MS)
    }
    assertTrue("Expected no visible view containing '$text' within ${timeoutMs}ms", !visible)
}

/** Returns true when a [TextView] containing [text] shows up before [timeoutMs]. */
fun <A : Activity> pollForText(
    scenario: ActivityScenario<A>,
    text: String,
    timeoutMs: Long = AWAIT_TIMEOUT_MS
): Boolean {
    val deadline = System.currentTimeMillis() + timeoutMs
    while (System.currentTimeMillis() < deadline) {
        if (hasText(scenario, text)) return true
        Thread.sleep(AWAIT_POLL_MS)
    }
    return false
}

private fun <A : Activity> hasText(scenario: ActivityScenario<A>, text: String): Boolean =
    inspect(scenario) { decor -> findTextView(decor, text) != null }

private fun <A : Activity> hasShownText(scenario: ActivityScenario<A>, text: String): Boolean =
    inspect(scenario) { decor -> findShownTextView(decor, text) != null }

private fun <A : Activity> inspect(
    scenario: ActivityScenario<A>,
    check: (View) -> Boolean
): Boolean {
    if (scenario.state == Lifecycle.State.DESTROYED) return false
    var result = false
    scenario.onActivity { activity ->
        result = check(activity.window.decorView)
    }
    return result
}

/**
 * Polls [condition] until it holds, failing with [message] after [timeoutMs].
 */
fun awaitCondition(
    message: String,
    timeoutMs: Long = AWAIT_TIMEOUT_MS,
    condition: () -> Boolean
) = awaitCondition(timeoutMs, { message }, condition)

/**
 * Polls [condition] until it holds, failing after [timeoutMs] with the message
 * [describe] produces.
 *
 * The lazy form exists so a diagnostic can be expensive — dumping table
 * contents, say — without paying for it on the passing path. A string built
 * eagerly at the call site runs on every poll attempt and can perturb the very
 * timing the wait is there to absorb.
 */
fun awaitCondition(
    timeoutMs: Long = AWAIT_TIMEOUT_MS,
    describe: () -> String,
    condition: () -> Boolean
) {
    val deadline = System.currentTimeMillis() + timeoutMs
    while (System.currentTimeMillis() < deadline) {
        if (condition()) return
        Thread.sleep(AWAIT_POLL_MS)
    }
    assertTrue(describe(), condition())
}

/**
 * Matches only the view at [index] (0-based, depth-first) among those matching
 * [matcher].
 *
 * Espresso throws `AmbiguousViewMatcherException` when a matcher hits more than
 * one view, which the app's repeated labels and unlabelled dialog fields do
 * constantly.
 *
 * The counter advances during the hierarchy traversal, so each returned matcher
 * is good for exactly ONE traversal: give every `onView` its own call, and give
 * that interaction a single action or check (`perform(a, b)` and chained
 * `check(...).check(...)` each traverse again and would find nothing).
 */
fun nthMatch(matcher: Matcher<View>, index: Int): Matcher<View> = object : TypeSafeMatcher<View>() {

    private var seen = 0

    override fun matchesSafely(view: View): Boolean {
        if (!matcher.matches(view)) return false
        return seen++ == index
    }

    override fun describeTo(description: Description) {
        description.appendText("view #$index matching ")
        matcher.describeTo(description)
    }
}

/**
 * Finds the toggle rendered alongside the label [label] in a programmatic
 * settings row.
 *
 * Setting rows are built as `[text column][switch]`, so the switch is located
 * by walking up from the label to the row and back down to the first view of
 * type [switchType].
 *
 * @return the toggle, or null when the label or the toggle is not present.
 */
fun <T : View> switchForLabel(root: View, label: String, switchType: Class<T>): T? {
    val labelView = collectViews(root) { it is TextView && it.text?.toString() == label }
        .firstOrNull() ?: return null

    // Walk up from the label, looking only at each ancestor's DIRECT children.
    // Searching the whole subtree returns the first switch anywhere under that
    // ancestor, which — once the walk reaches a section container holding
    // several rows — is some other row's switch. That silently pointed the
    // Settings tests at the wrong control: they toggled it, saw it flip, and
    // then found nothing persisted for the setting they meant.
    var candidate: View = labelView
    while (true) {
        val parent = candidate.parent as? ViewGroup ?: return null
        for (i in 0 until parent.childCount) {
            val child = parent.getChildAt(i)
            if (switchType.isInstance(child)) {
                @Suppress("UNCHECKED_CAST")
                return child as T
            }
        }
        candidate = parent
    }
}

/** Blocks until the instrumentation main loop is idle. */
fun waitForIdle() {
    InstrumentationRegistry.getInstrumentation().waitForIdleSync()
}
