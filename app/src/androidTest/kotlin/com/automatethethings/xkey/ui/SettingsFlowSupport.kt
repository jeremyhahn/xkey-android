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

import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.CompoundButton
import android.widget.EditText
import android.widget.RadioButton
import android.widget.Spinner
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import com.google.android.material.materialswitch.MaterialSwitch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue

/**
 * Helpers for driving [SettingsActivity]'s programmatic settings tree.
 *
 * `buildSettingsUI()` constructs every card in code and hides the XML-declared
 * ones, so nothing on this screen has a usable id. Controls are therefore
 * located by the text the screen actually renders, and driven with
 * [View.performClick] on the main thread rather than by injecting taps: most of
 * the screen sits far below the fold, and several containers are `GONE` until a
 * toggle reveals them.
 *
 * Everything lives on an object so these names can never clash with the
 * package's existing top-level helpers ([switchForLabel], [collectViews],
 * [awaitCondition], …), which this file uses rather than reimplements.
 */
internal object SettingsFlowSupport {

    /**
     * `SettingsActivity.isInitializing` guards every listener on the screen:
     * while it is true a toggle changes the widget but writes nothing. It flips
     * to false on the last line of `loadSettings()`, and nothing the activity
     * exposes publicly reports that moment, so the tests read the field.
     *
     * Without this wait a test races the initial DataStore load and silently
     * asserts against a click the activity deliberately ignored.
     */
    private val initializingField by lazy {
        SettingsActivity::class.java
            .getDeclaredField("isInitializing")
            .apply { isAccessible = true }
    }

    /** Blocks until `loadSettings()` has finished applying persisted values. */
    fun awaitInitialized(scenario: ActivityScenario<SettingsActivity>) {
        // Resolve the field up front so a rename surfaces as a NoSuchFieldException
        // rather than as awaitActivity quietly swallowing the reflection error.
        val field = initializingField
        val settled = awaitActivity(scenario) { !field.getBoolean(it) }
        assertTrue(
            "SettingsActivity should finish loadSettings() before a test drives it",
            settled
        )
        waitForIdle()
    }

    // -----------------------------------------------------------------------
    // Locating controls
    // -----------------------------------------------------------------------

    /**
     * The toggle of a `createSettingRowWithSwitch` row titled [label].
     *
     * The row is `[text column][switch]`, so the switch is a sibling of the
     * title's column rather than a child of it.
     */
    fun rowSwitch(root: View, label: String): MaterialSwitch? =
        switchForLabel(root, label, MaterialSwitch::class.java)

    /**
     * A [MaterialSwitch] that carries [text] itself.
     *
     * The Media Signing section labels its switches through `text` instead of a
     * separate title view, so [rowSwitch] would walk up to the shared container
     * and return whichever switch comes first.
     */
    fun ownTextSwitch(root: View, text: String): MaterialSwitch? =
        collectViews(root) { it is MaterialSwitch && it.text?.toString() == text }
            .firstOrNull() as MaterialSwitch?

    /** The bootstrap method checkbox labelled [text] (e.g. "DANE"). */
    fun methodCheckBox(root: View, text: String): CheckBox? =
        collectViews(root) { it is CheckBox && it.text?.toString() == text }
            .firstOrNull() as CheckBox?

    /**
     * The radio option whose label starts with [text].
     *
     * Not an exact match: a radio button carries its title on the first line and
     * its description on a second, so the rendered label is
     * "<title>\n<description>". The title alone is what identifies the option.
     */
    fun radioOption(root: View, text: String): RadioButton? =
        collectViews(root) { view ->
            view is RadioButton &&
                view.text?.toString()?.substringBefore('\n') == text
        }.firstOrNull() as RadioButton?

    /** The button reading exactly [text]. */
    fun button(root: View, text: String): Button? =
        collectViews(root) { it is Button && it.text?.toString() == text }
            .firstOrNull() as Button?

    /**
     * The [EditText] identified by [hint].
     *
     * The rendered hint is "<label> (<example>)", so a caller passing either the
     * label or the example placeholder finds the field. Several bootstrap fields
     * share one example, which is why the label is the reliable key.
     */
    fun editTextWithHint(root: View, hint: String): EditText? =
        collectViews(root) { view ->
            view is EditText && view.hint?.toString()?.contains(hint) == true
        }
            .firstOrNull() as EditText?

    /**
     * The first [EditText] inside the container that also holds the label
     * [label].
     *
     * Three bootstrap fields and the CA server URL field all share the hint
     * "https://ca.example.com", so a hint match alone is ambiguous; the
     * surrounding subsection label is what tells them apart.
     */
    fun editTextNearLabel(root: View, label: String): EditText? {
        val labelView = collectViews(root) { it is TextView && it.text?.toString() == label }
            .firstOrNull() ?: return null
        val container = labelView.parent as? ViewGroup ?: return null
        return collectViews(container) { it is EditText }.firstOrNull() as EditText?
    }

    /**
     * Every [EditText] in the method section whose checkbox reads [methodName],
     * in the order the section adds them.
     */
    fun methodSectionEditTexts(root: View, methodName: String): List<EditText> {
        val checkbox = methodCheckBox(root, methodName) ?: return emptyList()
        val section = checkbox.parent as? ViewGroup ?: return emptyList()
        return collectViews(section) { it is EditText }.map { it as EditText }
    }

    /** The [Spinner] whose adapter offers [item]. */
    fun spinnerWithItem(root: View, item: String): Spinner? =
        collectViews(root) { view ->
            val adapter = (view as? Spinner)?.adapter ?: return@collectViews false
            (0 until adapter.count).any { adapter.getItem(it)?.toString() == item }
        }.firstOrNull() as Spinner?

    // -----------------------------------------------------------------------
    // Driving controls
    // -----------------------------------------------------------------------

    /**
     * Drives the toggle found by [locate] to [desired], clicking only on a real
     * state change so the listener is not fired for a no-op.
     */
    fun setToggle(
        scenario: ActivityScenario<SettingsActivity>,
        desired: Boolean,
        describe: String,
        locate: (View) -> CompoundButton?
    ) {
        scenario.onActivity { activity ->
            val toggle = locate(activity.window.decorView)
            assertNotNull("Expected the $describe toggle to be built", toggle)
            // Every listener on this screen is a no-op while isInitializing is
            // true, so a click landing then writes nothing and the failure
            // surfaces much later as "the setting was not persisted".
            assertFalse(
                "SettingsActivity is still initializing; the $describe click would be discarded",
                initializingField.getBoolean(activity)
            )
            // The caller seeds the opposite value first, so a toggle already
            // reading `desired` means the seed never reached the screen and the
            // click — and therefore the listener and the write — never happens.
            assertEquals(
                "The $describe toggle should start at ${!desired} so the click has an effect",
                !desired,
                toggle!!.isChecked
            )
            toggle.performClick()
            // A toggle helper that cannot confirm its own effect turns "the
            // listener never wrote anything" into a misleading assertion about
            // persistence much later in the test.
            assertEquals(
                "The $describe toggle should now read $desired",
                desired,
                toggle.isChecked
            )
        }
        waitForIdle()
    }

    /** Clicks the view found by [locate] on the main thread. */
    fun clickView(
        scenario: ActivityScenario<SettingsActivity>,
        describe: String,
        locate: (View) -> View?
    ) {
        scenario.onActivity { activity ->
            val view = locate(activity.window.decorView)
            assertNotNull("Expected $describe to be built", view)
            view!!.performClick()
        }
        waitForIdle()
    }

    /**
     * Selects [targetItem] on the spinner identified by [anchorItem].
     *
     * `Spinner.setSelection` only notifies its listener during the next layout
     * pass, so the spinner has to be inside a container the screen is currently
     * showing — every caller reveals it first.
     */
    fun selectSpinnerItem(
        scenario: ActivityScenario<SettingsActivity>,
        anchorItem: String,
        targetItem: String
    ) {
        scenario.onActivity { activity ->
            val spinner = spinnerWithItem(activity.window.decorView, anchorItem)
            assertNotNull("Expected a spinner offering '$anchorItem'", spinner)
            val adapter = spinner!!.adapter
            val index = (0 until adapter.count)
                .firstOrNull { adapter.getItem(it)?.toString() == targetItem } ?: -1
            assertTrue("Spinner should offer '$targetItem'", index >= 0)
            spinner.setSelection(index)
        }
        waitForIdle()
    }

    /**
     * Writes [value] into the field found by [locate] and then moves focus away.
     *
     * The bootstrap and CA-subject fields persist from an
     * `OnFocusChangeListener`, which only runs on a real focus transition, so
     * the field has to take focus before it can lose it.
     */
    fun setFieldAndBlur(
        scenario: ActivityScenario<SettingsActivity>,
        describe: String,
        value: String,
        locate: (View) -> EditText?
    ) {
        scenario.onActivity { activity ->
            val edit = locate(activity.window.decorView)
            assertNotNull("Expected the $describe field to be built", edit)
            assertTrue("The $describe field should be able to take focus", edit!!.requestFocus())
            edit.setText(value)
        }
        waitForIdle()
        scenario.onActivity { activity ->
            locate(activity.window.decorView)?.clearFocus()
        }
        waitForIdle()
    }

    // -----------------------------------------------------------------------
    // Reading the screen
    // -----------------------------------------------------------------------

    /** True when a [TextView] containing [text] is visible right now. */
    fun shows(scenario: ActivityScenario<SettingsActivity>, text: String): Boolean =
        withActivity(scenario) {
            findShownTextViewContaining(it.window.decorView, text) != null
        }

    /** Polls until [text] is visible, failing with a readable message. */
    fun assertEventuallyShows(scenario: ActivityScenario<SettingsActivity>, text: String) {
        assertTrue(
            "Expected '$text' to become visible on the settings screen",
            awaitActivity(scenario) {
                findShownTextViewContaining(it.window.decorView, text) != null
            }
        )
    }

    /** Polls until [text] is no longer visible. */
    fun assertEventuallyHides(scenario: ActivityScenario<SettingsActivity>, text: String) {
        assertTrue(
            "Expected '$text' to stop being visible on the settings screen",
            awaitActivity(scenario) {
                findShownTextViewContaining(it.window.decorView, text) == null
            }
        )
    }

    /**
     * True when the bootstrap method [methodName] itself is on screen.
     *
     * Deliberately keyed on the method's checkbox rather than on its name as
     * text: the always-visible auto-bootstrap row is described as "Automatically
     * try methods in order: DANE, Noise, SPKI, Direct", so a substring search for
     * a method name matches whether the method list is expanded or not.
     */
    fun methodShown(
        scenario: ActivityScenario<SettingsActivity>,
        methodName: String
    ): Boolean = withActivity(scenario) {
        methodCheckBox(it.window.decorView, methodName)?.isShown == true
    }

    /** Polls until the bootstrap method [methodName] is on screen. */
    fun assertEventuallyMethodShown(
        scenario: ActivityScenario<SettingsActivity>,
        methodName: String
    ) {
        assertTrue(
            "Expected the $methodName bootstrap method to become visible",
            awaitActivity(scenario) {
                methodCheckBox(it.window.decorView, methodName)?.isShown == true
            }
        )
    }

    /**
     * True when the config container of the bootstrap method [methodName] is on
     * screen, judged from its first field.
     *
     * The container holds only unlabelled [EditText]s, so there is no text to
     * assert on; `isShown` is the honest test that the expand actually happened.
     */
    fun methodConfigShown(
        scenario: ActivityScenario<SettingsActivity>,
        methodName: String
    ): Boolean = withActivity(scenario) {
        methodSectionEditTexts(it.window.decorView, methodName).firstOrNull()?.isShown == true
    }

    /** Polls until the config container of [methodName] matches [expected]. */
    fun assertMethodConfigShown(
        scenario: ActivityScenario<SettingsActivity>,
        methodName: String,
        expected: Boolean
    ) {
        assertTrue(
            "Expected the $methodName config container to be " +
                (if (expected) "expanded" else "collapsed"),
            awaitActivity(scenario) {
                val shown = methodSectionEditTexts(it.window.decorView, methodName)
                    .firstOrNull()?.isShown == true
                shown == expected
            }
        )
    }
}
