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
import com.automatethethings.xkey.remote.RemoteBackupClient
import com.automatethethings.xkey.remote.RemoteBackupException
import kotlinx.coroutines.CancellationException

/**
 * The decisions behind the desktop backup and restore dialogs, kept free of
 * views so they run on the JVM: form checks, the message for each typed
 * failure, the outcome of the latest-backup lookup, and the label for each
 * restored item.
 *
 * The checks read the password fields as [CharSequence]s and never make a
 * [String] of them.
 */
object DesktopBackupForm {

    /**
     * The problem with a create form, as a string resource, or null when it
     * may be sent: the password is non-empty, the confirmation matches it and
     * at least one store is selected.
     */
    @StringRes
    fun checkCreate(password: CharSequence, confirm: CharSequence, include: RemoteBackupClient.Include): Int? =
        when {
            password.isEmpty() -> R.string.desktop_backup_error_password_empty
            !sameChars(password, confirm) -> R.string.desktop_backup_error_password_mismatch
            !include.any -> R.string.desktop_backup_error_nothing_selected
            else -> null
        }

    /** The problem with a restore form, as a string resource, or null when it may be sent. */
    @StringRes
    fun checkRestore(password: CharSequence): Int? =
        if (password.isEmpty()) R.string.desktop_backup_error_password_empty else null

    /**
     * The message for a failed backup or restore. [R.string.desktop_backup_failed]
     * takes the exception's message as its argument; every other message has none.
     */
    @StringRes
    fun errorMessage(e: Throwable): Int = when (e) {
        is RemoteBackupException.EmptyPassword -> R.string.desktop_backup_error_password_empty
        is RemoteBackupException.NothingSelected -> R.string.desktop_backup_error_nothing_selected
        is RemoteBackupException.InvalidParams -> R.string.desktop_backup_error_bad_request
        is RemoteBackupException.CreationFailed -> R.string.desktop_backup_error_create_failed
        is RemoteBackupException.WrongPasswordOrDamaged -> R.string.desktop_backup_error_wrong_password
        is RemoteBackupException.NotConfigured -> R.string.desktop_backup_error_not_configured
        is RemoteBackupException.ApprovalRequired -> R.string.desktop_backup_error_approval_required
        is RemoteBackupException.TimedOut -> R.string.desktop_backup_error_timed_out
        else -> R.string.desktop_backup_failed
    }

    /** What looking up the latest stored backup found. */
    sealed interface LatestBackup {
        /** The latest stored backup is [backupId]. */
        data class Found(val backupId: String) : LatestBackup

        /** No backup is stored on this phone. */
        data object None : LatestBackup

        /** The stored backups could not be read; [message] is the string to show. */
        data class Failed(val error: Exception, @StringRes val message: Int) : LatestBackup
    }

    /**
     * Runs [lookup] for the latest stored backup id and turns a storage
     * failure (an `IOException` from reading or migrating a record, a keystore
     * failure, or any other [Exception]) into [LatestBackup.Failed] instead of
     * throwing it. Cancellation still propagates.
     */
    suspend fun findLatest(lookup: suspend () -> String?): LatestBackup =
        try {
            lookup()?.let { LatestBackup.Found(it) } ?: LatestBackup.None
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            LatestBackup.Failed(e, R.string.desktop_backup_error_read_stored)
        }

    /** Whether the user should be offered to retype the password after [e]. */
    fun canRetry(e: Throwable): Boolean = e is RemoteBackupException.WrongPasswordOrDamaged

    /** The display label for a restore item name, or null for a name the phone does not know. */
    @StringRes
    fun itemLabel(item: String): Int? = when (item) {
        "trust_store" -> R.string.desktop_backup_item_trust_store
        "oath" -> R.string.desktop_backup_item_oath
        "passwords" -> R.string.desktop_backup_item_passwords
        "ca" -> R.string.desktop_backup_item_ca
        else -> null
    }

    private fun sameChars(a: CharSequence, b: CharSequence): Boolean {
        if (a.length != b.length) return false
        var diff = 0
        for (i in 0 until a.length) diff = diff or (a[i].code xor b[i].code)
        return diff == 0
    }
}
