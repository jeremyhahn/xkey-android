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
import androidx.test.espresso.UiController
import androidx.test.espresso.ViewAction
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isAssignableFrom
import androidx.test.espresso.matcher.ViewMatchers.isRoot
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
     */
    fun clickButton(buttonId: Int) {
        onDialogRoot("click dialog button ${Integer.toHexString(buttonId)}") { root ->
            val button = root.findViewById<View>(buttonId)
                ?: throw AssertionError("The topmost dialog has no button $buttonId")
            button.performClick()
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
