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

import android.content.DialogInterface
import android.os.Bundle
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.TextView
import androidx.annotation.StringRes
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ble.XKeyGattService
import com.google.android.material.snackbar.SnackbarContentLayout
import io.mockk.mockk
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.robolectric.Robolectric
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.shadows.ShadowDialog
import java.time.Duration

/**
 * Hosts [DesktopBackupDialogs] in a themed activity for Robolectric tests.
 *
 * The dialogs reach the service only through their `() -> XKeyGattService?`
 * lambda; here it reads [service], which starts out returning the mockk
 * [gatt] and can be set to return null (no desktop connected) at any point.
 * The real service is never bound or started.
 *
 * Dialogs are found through [ShadowDialog.getLatestDialog] and Snackbars by
 * walking the activity's views, so the tests assert on what is shown, not on
 * how the dialogs show it.
 */
class DesktopBackupDialogsTestHost {

    /** The activity the dialogs are built on: Material themed, a plain root. */
    class HostActivity : AppCompatActivity() {
        lateinit var root: FrameLayout

        override fun onCreate(savedInstanceState: Bundle?) {
            setTheme(R.style.Theme_xKey)
            super.onCreate(savedInstanceState)
            root = FrameLayout(this)
            setContentView(root)
        }
    }

    /** The service the dialogs see while [service] returns it. */
    val gatt: XKeyGattService = mockk()

    /** What the dialogs' service lambda returns, read on every call. */
    var service: () -> XKeyGattService? = { gatt }

    private val controller: ActivityController<HostActivity> =
        Robolectric.buildActivity(HostActivity::class.java).setup()

    val activity: HostActivity get() = controller.get()

    val dialogs = DesktopBackupDialogs(activity, activity.root) { service() }

    /** Runs what is due on the main looper without moving the clock. */
    fun idle() {
        shadowOf(Looper.getMainLooper()).idle()
    }

    /**
     * Moves the clock a second so Snackbar and dialog animations finish and a
     * queued Snackbar replaces a dismissed one. A long Snackbar (2.75 s) is
     * still shown afterwards.
     */
    fun settle() {
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(1))
    }

    fun close() {
        controller.pause().stop().destroy()
    }

    fun string(@StringRes res: Int, vararg args: Any): String = activity.getString(res, *args)

    // ---------------------------------------------------------------- dialogs

    /** The latest dialog created, shown or not, or null when none was. */
    fun latestDialog(): AlertDialog? = ShadowDialog.getLatestDialog() as AlertDialog?

    /** The latest dialog, asserted to be showing. */
    fun shownDialog(): AlertDialog {
        val dialog = latestDialog()
        assertNotNull("no dialog was shown", dialog)
        assertTrue("the latest dialog must be showing", dialog!!.isShowing)
        return dialog
    }

    /** Whether a dialog is showing now. */
    fun anyDialogShowing(): Boolean = latestDialog()?.isShowing == true

    /** The password fields of [dialog], in layout order. */
    fun fields(dialog: AlertDialog): List<EditText> = viewsOf(dialog.window!!.decorView)

    /** The store toggles of [dialog], in layout order. */
    fun toggles(dialog: AlertDialog): List<CheckBox> = viewsOf(dialog.window!!.decorView)

    /** Every text [dialog] shows outside its fields: title, message, buttons, items. */
    fun texts(dialog: AlertDialog): List<String> =
        viewsOf<TextView>(dialog.window!!.decorView)
            .filter { it !is EditText && it.visibility == View.VISIBLE }
            .map { it.text.toString() }

    /** The dialog's message, or null when it has none. */
    fun message(dialog: AlertDialog): String? =
        dialog.findViewById<TextView>(android.R.id.message)?.text?.toString()

    /** The rows of a list dialog such as the entry menu. */
    fun menuItems(dialog: AlertDialog): List<String> {
        val adapter = dialog.listView.adapter
        return (0 until adapter.count).map { adapter.getItem(it).toString() }
    }

    /** Taps row [which] of a list dialog. */
    fun pickMenuItem(dialog: AlertDialog, which: Int) {
        val list = dialog.listView
        val row = list.adapter.getView(which, null, list)
        list.performItemClick(row, which, list.adapter.getItemId(which))
        idle()
    }

    fun clickPositive(dialog: AlertDialog) {
        dialog.getButton(DialogInterface.BUTTON_POSITIVE).performClick()
        idle()
    }

    fun clickNegative(dialog: AlertDialog) {
        dialog.getButton(DialogInterface.BUTTON_NEGATIVE).performClick()
        idle()
    }

    fun pressBack(dialog: AlertDialog) {
        dialog.onBackPressedDispatcher.onBackPressed()
        idle()
    }

    /** Opens the entry menu and picks create (0) or restore (1). */
    fun open(which: Int) {
        dialogs.show()
        idle()
        pickMenuItem(shownDialog(), which)
    }

    /**
     * Records every state [field]'s text passes through from now on, so a test
     * can see the characters overwritten before the field is cleared.
     */
    fun watch(field: EditText): List<String> {
        val seen = mutableListOf<String>()
        field.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
            override fun afterTextChanged(s: Editable?) {
                seen += s.toString()
            }
        })
        return seen
    }

    // -------------------------------------------------------------- snackbars

    /** The Snackbars attached to the activity now, oldest first. */
    fun snackbars(): List<SnackbarContentLayout> = viewsOf(activity.window.decorView)

    /** The text of the newest Snackbar shown, or null when none is. */
    fun snackbarText(): String? = snackbars().lastOrNull()?.messageView?.text?.toString()

    /** The texts of every Snackbar attached now. */
    fun snackbarTexts(): List<String> = snackbars().map { it.messageView.text.toString() }

    /** The newest Snackbar's action button, or null when it offers none. */
    fun snackbarAction(): Button? =
        snackbars().lastOrNull()?.actionView?.takeIf { it.visibility == View.VISIBLE }

    private inline fun <reified T : View> viewsOf(root: View): List<T> =
        collect(root, T::class.java, mutableListOf())

    private fun <T : View> collect(view: View, type: Class<T>, found: MutableList<T>): List<T> {
        if (type.isInstance(view)) found += type.cast(view)!!
        if (view is ViewGroup) for (i in 0 until view.childCount) collect(view.getChildAt(i), type, found)
        return found
    }
}
