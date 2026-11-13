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
import android.text.InputType
import android.util.Log
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import androidx.annotation.StringRes
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ble.XKeyGattService
import com.automatethethings.xkey.remote.RemoteBackupClient
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

/**
 * The phone-initiated desktop backup and restore flow, reached from the
 * Manage tab like Sync with Desktop.
 *
 * Create asks for the backup password twice and which stores to include;
 * restore picks the latest stored backup, lists the desktop's backups
 * (`remote.listBackups`) and says whether the desktop holds it, then asks for
 * its password once. The
 * password is read from its field into a [CharArray] only when it is sent,
 * the fields are wiped, and [XKeyGattService] zeroes the array once the
 * request is done. The fields keep no saved state, offer nothing to autofill
 * and ask the keyboard not to learn from them.
 */
class DesktopBackupDialogs(
    private val activity: AppCompatActivity,
    private val root: View,
    private val service: () -> XKeyGattService?
) {

    /** Offers create or restore, or explains that no desktop is connected. */
    fun show() {
        if (service() == null) {
            Snackbar.make(root, R.string.sync_not_connected, Snackbar.LENGTH_LONG).show()
            return
        }
        MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.desktop_backup_title)
            .setItems(
                arrayOf(
                    activity.getString(R.string.desktop_backup_action_create),
                    activity.getString(R.string.desktop_backup_action_restore)
                )
            ) { _, which -> if (which == 0) showCreate() else pickLatestAndRestore() }
            .setNegativeButton(R.string.button_cancel, null)
            .show()
    }

    private fun showCreate() {
        val password = passwordField(R.string.desktop_backup_password)
        val confirm = passwordField(R.string.desktop_backup_password_confirm)
        val trustStore = toggle(R.string.desktop_backup_include_trust_store)
        val oath = toggle(R.string.desktop_backup_include_oath)
        val passwords = toggle(R.string.desktop_backup_include_passwords)
        val form = column(password, confirm, trustStore, oath, passwords)

        val dialog = MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.desktop_backup_create_title)
            .setView(ScrollView(activity).apply { addView(form) })
            .setPositiveButton(R.string.desktop_backup_create_button, null)
            .setNegativeButton(R.string.button_cancel, null)
            .create()
        dialog.setOnDismissListener { wipe(password); wipe(confirm) }
        dialog.setOnShowListener {
            dialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener {
                val include = RemoteBackupClient.Include(
                    trustStore = trustStore.isChecked,
                    oath = oath.isChecked,
                    passwords = passwords.isChecked
                )
                val problem = DesktopBackupForm.checkCreate(password.text, confirm.text, include)
                if (problem != null) {
                    (if (password.text.isEmpty()) password else confirm).error = activity.getString(problem)
                    return@setOnClickListener
                }
                val secret = take(password)
                dialog.dismiss()
                runWithNotice(R.string.desktop_backup_in_progress, onRetry = null) { gatt ->
                    val result = gatt.createDesktopBackup(secret, include)
                    Snackbar.make(
                        root,
                        activity.getString(R.string.desktop_backup_complete, result.backupId, result.itemCount),
                        Snackbar.LENGTH_LONG
                    ).show()
                }
            }
        }
        dialog.show()
    }

    /**
     * Looks up the latest stored backup, lists the desktop's backups, and
     * asks for its password. A storage failure during the lookup shows an
     * error instead of crashing the app; a listing failure is said in the
     * restore dialog and does not block the restore.
     */
    private fun pickLatestAndRestore() {
        val gatt = service()
        if (gatt == null) {
            Snackbar.make(root, R.string.sync_not_connected, Snackbar.LENGTH_LONG).show()
            return
        }
        activity.lifecycleScope.launch {
            when (val latest = DesktopBackupForm.findLatest(gatt::latestStoredBackupId)) {
                is DesktopBackupForm.LatestBackup.Found -> {
                    val listing = DesktopBackupForm.listDesktop(gatt::listDesktopBackups)
                    if (listing is DesktopBackupForm.DesktopListing.Failed) {
                        Log.w(TAG, "Could not list the desktop's backups", listing.error)
                    }
                    showRestore(latest.backupId, DesktopBackupForm.listingNote(listing, latest.backupId))
                }
                DesktopBackupForm.LatestBackup.None ->
                    Snackbar.make(root, R.string.desktop_backup_none_stored, Snackbar.LENGTH_LONG).show()
                is DesktopBackupForm.LatestBackup.Failed -> {
                    Log.w(TAG, "Could not read the stored backups", latest.error)
                    Snackbar.make(root, latest.message, Snackbar.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun showRestore(backupId: String, note: DesktopBackupForm.ListingNote) {
        val password = passwordField(R.string.desktop_backup_password)
        val message = activity.getString(R.string.desktop_backup_restore_message, backupId) +
            "\n\n" + activity.getString(note.message, note.count)
        val dialog = MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.desktop_backup_restore_title)
            .setMessage(message)
            .setView(column(password))
            .setPositiveButton(R.string.desktop_backup_restore_button, null)
            .setNegativeButton(R.string.button_cancel, null)
            .create()
        dialog.setOnDismissListener { wipe(password) }
        dialog.setOnShowListener {
            dialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener {
                val problem = DesktopBackupForm.checkRestore(password.text)
                if (problem != null) {
                    password.error = activity.getString(problem)
                    return@setOnClickListener
                }
                val secret = take(password)
                dialog.dismiss()
                runWithNotice(R.string.desktop_backup_restore_in_progress, onRetry = { showRestore(backupId, note) }) { gatt ->
                    showRestoreResult(gatt.restoreDesktopBackup(backupId, secret))
                }
            }
        }
        dialog.show()
    }

    private fun showRestoreResult(result: RemoteBackupClient.RestoreResult) {
        val lines = mutableListOf<String>()
        for (item in result.items) {
            val label = DesktopBackupForm.itemLabel(item.item)?.let(activity::getString) ?: item.item
            lines += activity.getString(
                R.string.desktop_backup_restore_item, label, item.restored, item.quarantined, item.skipped
            )
            item.errors.forEach { lines += activity.getString(R.string.desktop_backup_restore_item_error, it) }
        }
        if (result.items.isEmpty() && result.restored.isNotEmpty()) {
            val labels = result.restored.map { name ->
                DesktopBackupForm.itemLabel(name)?.let(activity::getString) ?: name
            }
            lines += activity.getString(R.string.desktop_backup_restored_list, labels.joinToString())
        }
        result.message?.let { lines += it }
        MaterialAlertDialogBuilder(activity)
            .setTitle(
                if (result.success) R.string.desktop_backup_restore_complete
                else R.string.desktop_backup_restore_partial
            )
            .setMessage(lines.joinToString("\n"))
            .setPositiveButton(R.string.button_ok, null)
            .show()
    }

    /**
     * Shows the progress notice [progress] while [block] runs, then dismisses
     * it on every exit: success, a typed failure, or cancellation when the
     * activity goes away. A failure [DesktopBackupForm.canRetry] allows offers
     * [onRetry].
     */
    private fun runWithNotice(
        @StringRes progress: Int,
        onRetry: (() -> Unit)?,
        block: suspend (XKeyGattService) -> Unit
    ) {
        val notice = Snackbar.make(root, progress, Snackbar.LENGTH_INDEFINITE)
        notice.show()
        activity.lifecycleScope.launch {
            try {
                val gatt = service() ?: throw IllegalStateException(activity.getString(R.string.sync_not_connected))
                block(gatt)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                val res = DesktopBackupForm.errorMessage(e)
                val text = if (res == R.string.desktop_backup_failed) {
                    activity.getString(res, e.message ?: e.javaClass.simpleName)
                } else {
                    activity.getString(res)
                }
                val failure = Snackbar.make(root, text, Snackbar.LENGTH_LONG)
                if (onRetry != null && DesktopBackupForm.canRetry(e)) {
                    failure.setAction(R.string.desktop_backup_retry) { onRetry() }
                }
                failure.show()
            } finally {
                notice.dismiss()
            }
        }
    }

    /** A password field: no autofill, no keyboard learning, no saved state. */
    private fun passwordField(@StringRes hint: Int): EditText = EditText(activity).apply {
        setHint(hint)
        inputType = InputType.TYPE_CLASS_TEXT or
            InputType.TYPE_TEXT_VARIATION_PASSWORD or
            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        imeOptions = imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
        isSaveEnabled = false
    }

    private fun toggle(@StringRes label: Int): CheckBox = CheckBox(activity).apply {
        setText(label)
        isChecked = true
    }

    private fun column(vararg views: View): LinearLayout = LinearLayout(activity).apply {
        orientation = LinearLayout.VERTICAL
        val hPad = UIHelpers.dpToPxInt(activity, 24)
        val vPad = UIHelpers.dpToPxInt(activity, 8)
        setPadding(hPad, vPad, hPad, vPad)
        views.forEach(::addView)
    }

    /** Copies the field's characters into a new array and wipes the field. */
    private fun take(field: EditText): CharArray {
        val text = field.text
        val chars = CharArray(text.length)
        for (i in chars.indices) chars[i] = text[i]
        wipe(field)
        return chars
    }

    /**
     * Overwrites the field's characters in place before clearing it, so the
     * editor's buffer does not keep the password. Best effort: the platform
     * gives no stronger guarantee for an [EditText].
     */
    private fun wipe(field: EditText) {
        val text = field.text
        if (text.isEmpty()) return
        text.replace(0, text.length, " ".repeat(text.length))
        text.clear()
    }

    private companion object {
        const val TAG = "DesktopBackupDialogs"
    }
}
