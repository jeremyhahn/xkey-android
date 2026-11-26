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
import android.content.ClipboardManager
import android.content.Context
import android.view.View
import android.widget.ArrayAdapter
import android.widget.AutoCompleteTextView
import android.widget.EditText
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.NoMatchingRootException
import androidx.test.espresso.UiController
import androidx.test.espresso.ViewAction
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.doesNotExist
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isAssignableFrom
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.isRoot
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.platform.app.InstrumentationRegistry
import org.hamcrest.Matcher
import org.junit.Assert.assertTrue

/**
 * Helpers for driving the app's programmatically-built dialogs, and for reading
 * back what a dialog action put on the clipboard.
 *
 * The dialogs on these screens ([AddOathDialog], the password add dialog, the
 * OATH context menus) build their fields in code: no ids, hints carried on a
 * `TextInputLayout` rather than on the editable view, and often more fields and
 * rows than fit on screen. That rules out both `withHint`/`withId` matching and
 * the stock text actions, which refuse to touch a view scrolled out of the
 * dialog's viewport.
 *
 * Everything here therefore addresses fields *positionally* — depth-first order
 * of the dialog window's own view tree, which is the order the dialog added them
 * — and mutates them on the main thread rather than by injecting events, so a
 * field below the fold behaves exactly like one above it.
 *
 * The dialog window is reached with `onView(isRoot()).inRoot(isDialog())`, which
 * resolves to the decor view of the topmost dialog. Reading an exposed
 * dropdown's options ([dropdownOptions]) matters as much as setting them: a
 * choice control that renders no options at all is a bug this project has
 * already shipped once.
 *
 * Members live on an object so these names cannot clash with helpers other
 * suites add to this package.
 */
internal object DialogFlowSupport {

    /** Runs [block] against the topmost dialog's root view on the main thread. */
    private fun onDialogRoot(description: String, block: (View) -> Unit) {
        onView(isRoot()).inRoot(isDialog()).perform(object : ViewAction {
            override fun getConstraints(): Matcher<View> = isAssignableFrom(View::class.java)

            override fun getDescription(): String = description

            override fun perform(uiController: UiController, view: View) {
                block(view)
                uiController.loopMainThreadUntilIdle()
            }
        })
    }

    /**
     * Clicks the topmost dialog's button [buttonId] on the main thread.
     *
     * Espresso's `click()` injects a real tap, which is dropped whenever the
     * soft keyboard is still animating out over the button — `closeSoftKeyboard()`
     * asks the IME to hide but does not wait for the window to go away. The tap
     * is then swallowed by the departing IME window, the action reports success
     * and the dialog simply stays up. Invoking the button's listener directly
     * still runs every line of production code behind the button; only the
     * hit-testing is skipped, and that is covered by the suites that click a
     * dialog button without typing first.
     *
     * The button is waited for, up to [timeoutMs], rather than looked up once:
     * the dialog may still be on its way, or a departing sheet may still be the
     * topmost dialog window (see [awaitDialogRoot]).
     */
    fun clickButton(buttonId: Int, timeoutMs: Long = PROMPT_TIMEOUT_MS) {
        awaitDialogRoot(
            "click dialog button ${Integer.toHexString(buttonId)}",
            timeoutMs,
            ready = { root -> root.findViewById<View>(buttonId)?.isShown == true },
            describeFailure = { "The topmost dialog has no button $buttonId" }
        ) { root ->
            root.findViewById<View>(buttonId).performClick()
        }
    }

    /**
     * Runs [block] against the topmost dialog's root once [ready] holds for it.
     *
     * Opening a dialog from a bottom sheet or from another dialog leaves the
     * departing window on screen while it animates out, and the departing window
     * can still be the one `isDialog()` resolves to. Picking it fails the very
     * step that follows ("no button", a field that is not there). Polling until
     * the root is the one the caller means waits for the previous root to go.
     * [block] runs at most once; its failures are not retried.
     */
    private fun awaitDialogRoot(
        description: String,
        timeoutMs: Long,
        ready: (View) -> Boolean,
        describeFailure: () -> String,
        block: (View) -> Unit
    ) {
        var ran = false
        awaitCondition(timeoutMs, describeFailure) {
            val attempt = runCatching {
                onDialogRoot(description) { root ->
                    if (ready(root)) {
                        ran = true
                        block(root)
                    }
                }
            }
            if (ran) attempt.getOrThrow()
            ran
        }
    }

    /**
     * Waits until a view matching [matcher] is displayed in a dialog window.
     *
     * Use it after any step that replaces one dialog or sheet with another and
     * before touching the new one: `inRoot(isDialog())` keeps resolving to the
     * departing window until it is gone, so a first look can miss a view that
     * is on its way.
     */
    fun awaitInDialog(matcher: Matcher<View>, timeoutMs: Long = PROMPT_TIMEOUT_MS) {
        awaitCondition(timeoutMs, { "No dialog showed a view $matcher" }) {
            runCatching {
                onView(matcher).inRoot(isDialog()).check(matches(isDisplayed()))
            }.isSuccess
        }
    }

    /**
     * Taps the view matching [matcher] in a dialog window once it is there.
     *
     * A confirmation dialog opened from a bottom sheet, a menu or a row tap
     * arrives after the call that opened it returns; a first look can still
     * resolve the departing window. The tap is retried only while the view
     * cannot be found or is not yet tappable, so it lands once.
     */
    fun clickInDialog(matcher: Matcher<View>, timeoutMs: Long = PROMPT_TIMEOUT_MS) {
        awaitCondition(timeoutMs, { "No dialog offered a view $matcher to tap" }) {
            runCatching {
                onView(matcher).inRoot(isDialog()).perform(click())
            }.isSuccess
        }
    }

    /** [clickInDialog] for the dialog view whose text is the string [textResId]. */
    fun clickInDialog(textResId: Int, timeoutMs: Long = PROMPT_TIMEOUT_MS) {
        clickInDialog(withText(textResId), timeoutMs)
    }

    /**
     * Picks the option labelled [optionResId] from the bottom sheet (or option
     * dialog) on screen, then waits for what the option opens.
     *
     * With [next] given, waits until a dialog shows a view matching it, which
     * also means the sheet has given way. Without one (an option that opens
     * nothing, or hands off to another activity), waits until no dialog
     * window shows the option's label any more, so the caller never acts on the sheet's
     * window while it is still animating out.
     */
    fun chooseFromSheet(
        optionResId: Int,
        next: Matcher<View>? = null,
        timeoutMs: Long = PROMPT_TIMEOUT_MS
    ) {
        val label = InstrumentationRegistry.getInstrumentation().targetContext.getString(optionResId)
        clickInDialog(withText(label), timeoutMs)
        if (next != null) {
            awaitInDialog(next, timeoutMs)
        } else {
            awaitCondition(timeoutMs, { "The sheet offering '$label' never closed" }) {
                val check = runCatching {
                    onView(withText(label)).inRoot(isDialog()).check(doesNotExist())
                }
                // No dialog window left at all is the sheet having closed too.
                check.isSuccess || check.exceptionOrNull() is NoMatchingRootException
            }
        }
    }

    /** Returns every [EditText] in the topmost dialog, in the order it was added. */
    private fun fields(root: View): List<EditText> =
        collectViews(root) { it is EditText }.map { it as EditText }

    /**
     * Replaces the text of the dialog's [index]-th editable field.
     *
     * Note that an [AutoCompleteTextView] is itself an [EditText], so exposed
     * dropdowns occupy positions in the same sequence as plain text fields.
     */
    fun setText(index: Int, text: String) {
        onDialogRoot("set dialog field #$index to '$text'") { root ->
            val fields = fields(root)
            require(index < fields.size) {
                "Dialog has ${fields.size} editable fields; no field at index $index"
            }
            fields[index].setText(text)
        }
    }

    /**
     * Selects [value] on the dialog's [index]-th field, which must be an exposed
     * dropdown.
     *
     * Uses `setText(value, false)` exactly as the production code does: passing
     * `true` would re-open the dropdown and refilter the adapter.
     */
    fun setDropdown(index: Int, value: String) {
        onDialogRoot("select '$value' on dialog dropdown #$index") { root ->
            val field = fields(root)[index]
            require(field is AutoCompleteTextView) {
                "Field $index is a ${field.javaClass.simpleName}, not a dropdown"
            }
            field.setText(value, false)
        }
    }

    /** Returns the current text of every editable field in the topmost dialog. */
    fun fieldTexts(): List<String> {
        val texts = mutableListOf<String>()
        onDialogRoot("read every dialog field") { root ->
            fields(root).mapTo(texts) { it.text?.toString().orEmpty() }
        }
        return texts
    }

    /**
     * Returns the text of every [TextView] in the topmost dialog.
     *
     * Dialogs that render a tall column of detail rows put most of those rows
     * below the fold, where Espresso's `isDisplayed()` refuses to match them even
     * though they are attached and correct. Reading the whole window and
     * asserting over the result tests the content rather than the viewport.
     */
    fun texts(): List<String> {
        val texts = mutableListOf<String>()
        onDialogRoot("read every dialog label") { root ->
            collectViews(root) { it is TextView }
                .mapTo(texts) { (it as TextView).text?.toString().orEmpty() }
        }
        return texts
    }

    /** Asserts the topmost dialog renders a label whose text is exactly [text]. */
    fun assertShowsExactly(text: String) {
        val texts = texts()
        assertTrue(
            "Expected a dialog label reading exactly '$text', found $texts",
            texts.any { it == text }
        )
    }

    /** Asserts the topmost dialog renders a label containing [text]. */
    fun assertContains(text: String) {
        val texts = texts()
        assertTrue(
            "Expected a dialog label containing '$text', found $texts",
            texts.any { it.contains(text) }
        )
    }

    /** Asserts no label in the topmost dialog contains [text]. */
    fun assertDoesNotContain(text: String) {
        val texts = texts()
        assertTrue(
            "Did not expect a dialog label containing '$text', found $texts",
            texts.none { it.contains(text) }
        )
    }

    /**
     * Returns the options offered by the dialog's [index]-th field, which must be
     * an exposed dropdown backed by an [ArrayAdapter].
     */
    fun dropdownOptions(index: Int): List<String> {
        val options = mutableListOf<String>()
        onDialogRoot("read the options of dialog dropdown #$index") { root ->
            val field = fields(root)[index] as AutoCompleteTextView

            @Suppress("UNCHECKED_CAST")
            val adapter = field.adapter as ArrayAdapter<String>
            for (position in 0 until adapter.count) {
                options.add(adapter.getItem(position).orEmpty())
            }
        }
        return options
    }

    /**
     * Returns the text currently on the system clipboard, or null when it is
     * empty.
     *
     * Read through the activity: from Android 10 onwards only the focused
     * foreground app may read the clipboard, so the instrumentation process
     * cannot ask on its own behalf.
     */
    fun <A : Activity> clipboardText(scenario: ActivityScenario<A>): String? =
        withActivity(scenario) { activity ->
            val clipboard =
                activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.primaryClip
                ?.takeIf { it.itemCount > 0 }
                ?.getItemAt(0)
                ?.coerceToText(activity)
                ?.toString()
        }
}
