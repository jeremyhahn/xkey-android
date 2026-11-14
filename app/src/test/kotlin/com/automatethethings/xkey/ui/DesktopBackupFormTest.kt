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

import com.automatethethings.xkey.R
import com.automatethethings.xkey.remote.RemoteBackupClient
import com.automatethethings.xkey.remote.RemoteBackupException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/** JVM tests for [DesktopBackupForm], the view-free half of the desktop backup dialogs. */
class DesktopBackupFormTest {

    private val oathOnly = RemoteBackupClient.Include(oath = true)

    @Test
    fun `create refuses an empty password`() {
        assertEquals(R.string.desktop_backup_error_password_empty, DesktopBackupForm.checkCreate("", "", oathOnly))
    }

    @Test
    fun `create refuses a confirmation that does not match`() {
        assertEquals(
            R.string.desktop_backup_error_password_mismatch,
            DesktopBackupForm.checkCreate("secret", "secreT", oathOnly)
        )
        assertEquals(
            R.string.desktop_backup_error_password_mismatch,
            DesktopBackupForm.checkCreate("secret", "secret!", oathOnly)
        )
    }

    @Test
    fun `create refuses a backup with nothing selected`() {
        assertEquals(
            R.string.desktop_backup_error_nothing_selected,
            DesktopBackupForm.checkCreate("secret", "secret", RemoteBackupClient.Include())
        )
    }

    @Test
    fun `create accepts a matching non-empty password with a store selected`() {
        assertNull(DesktopBackupForm.checkCreate("secret", "secret", oathOnly))
        assertNull(
            DesktopBackupForm.checkCreate("s", "s", RemoteBackupClient.Include(trustStore = true))
        )
        assertNull(
            DesktopBackupForm.checkCreate("s", "s", RemoteBackupClient.Include(passwords = true))
        )
    }

    @Test
    fun `restore refuses only an empty password`() {
        assertEquals(R.string.desktop_backup_error_password_empty, DesktopBackupForm.checkRestore(""))
        assertNull(DesktopBackupForm.checkRestore("x"))
    }

    @Test
    fun `each typed failure has its own message`() {
        val cases = mapOf(
            RemoteBackupException.EmptyPassword() to R.string.desktop_backup_error_password_empty,
            RemoteBackupException.NothingSelected() to R.string.desktop_backup_error_nothing_selected,
            RemoteBackupException.InvalidParams("m") to R.string.desktop_backup_error_bad_request,
            RemoteBackupException.CreationFailed("m") to R.string.desktop_backup_error_create_failed,
            RemoteBackupException.WrongPasswordOrDamaged("m") to R.string.desktop_backup_error_wrong_password,
            RemoteBackupException.NotConfigured("m") to R.string.desktop_backup_error_not_configured,
            RemoteBackupException.ApprovalRequired("m") to R.string.desktop_backup_error_approval_required,
            RemoteBackupException.TimedOut("remote.createBackup") to R.string.desktop_backup_error_timed_out,
            RemoteBackupException.Other(-32603, "m") to R.string.desktop_backup_failed,
            RemoteBackupException.MalformedReply("m") to R.string.desktop_backup_failed,
            IllegalStateException("not connected") to R.string.desktop_backup_failed
        )
        for ((e, res) in cases) {
            assertEquals(e::class.simpleName, res, DesktopBackupForm.errorMessage(e))
        }
    }

    @Test
    fun `only a wrong password or damaged backup offers a retry`() {
        assertTrue(DesktopBackupForm.canRetry(RemoteBackupException.WrongPasswordOrDamaged("m")))
        assertFalse(DesktopBackupForm.canRetry(RemoteBackupException.InvalidParams("m")))
        assertFalse(DesktopBackupForm.canRetry(RemoteBackupException.CreationFailed("m")))
        assertFalse(DesktopBackupForm.canRetry(IllegalStateException()))
    }

    @Test
    fun `a latest-backup lookup that fails on storage reports an error instead of throwing`() = runTest {
        val diskFull = IOException("No space left on device")
        val latest = DesktopBackupForm.findLatest { throw diskFull }
        assertTrue(latest is DesktopBackupForm.LatestBackup.Failed)
        latest as DesktopBackupForm.LatestBackup.Failed
        assertSame(diskFull, latest.error)
        assertEquals(R.string.desktop_backup_error_read_stored, latest.message)
    }

    @Test
    fun `a latest-backup lookup reports the stored id or none`() = runTest {
        assertEquals(DesktopBackupForm.LatestBackup.Found("b-7"), DesktopBackupForm.findLatest { "b-7" })
        assertEquals(DesktopBackupForm.LatestBackup.None, DesktopBackupForm.findLatest { null })
    }

    @Test
    fun `a cancelled latest-backup lookup still propagates the cancellation`() = runTest {
        val cancelled = CancellationException("activity destroyed")
        val thrown = runCatching { DesktopBackupForm.findLatest { throw cancelled } }.exceptionOrNull()
        assertSame(cancelled, thrown)
    }

    @Test
    fun `known restore item names have labels and unknown ones fall through`() {
        assertEquals(R.string.desktop_backup_item_trust_store, DesktopBackupForm.itemLabel("trust_store"))
        assertEquals(R.string.desktop_backup_item_oath, DesktopBackupForm.itemLabel("oath"))
        assertEquals(R.string.desktop_backup_item_passwords, DesktopBackupForm.itemLabel("passwords"))
        assertEquals(R.string.desktop_backup_item_ca, DesktopBackupForm.itemLabel("ca"))
        assertNull(DesktopBackupForm.itemLabel("fido2"))
    }

    // --- Listing the desktop's backups before a restore ---------------------

    private fun info(id: String) = RemoteBackupClient.BackupInfo(id, "2026-11-01T10:00:00Z", null, 10L)

    @Test
    fun `a desktop listing reports the backups it found`() = runTest {
        val listing = DesktopBackupForm.listDesktop { listOf(info("a"), info("b")) }
        assertEquals(DesktopBackupForm.DesktopListing.Listed(listOf(info("a"), info("b"))), listing)
    }

    @Test
    fun `a failed desktop listing is reported, not thrown`() = runTest {
        val failure = RemoteBackupException.NotConfigured("no backup dir")
        val listing = DesktopBackupForm.listDesktop { throw failure }
        assertEquals(DesktopBackupForm.DesktopListing.Failed(failure), listing)
    }

    @Test
    fun `a cancelled desktop listing still propagates the cancellation`() = runTest {
        val cancelled = CancellationException("activity destroyed")
        val thrown = runCatching { DesktopBackupForm.listDesktop { throw cancelled } }.exceptionOrNull()
        assertSame(cancelled, thrown)
    }

    @Test
    fun `the listing note says whether the desktop holds the chosen backup`() {
        val listed = DesktopBackupForm.DesktopListing.Listed(listOf(info("a"), info("phone-7")))
        assertEquals(
            DesktopBackupForm.ListingNote(R.string.desktop_backup_listed_match, 2),
            DesktopBackupForm.listingNote(listed, "phone-7")
        )
        assertEquals(
            DesktopBackupForm.ListingNote(R.string.desktop_backup_listed, 2),
            DesktopBackupForm.listingNote(listed, "phone-8")
        )
        assertEquals(
            DesktopBackupForm.ListingNote(R.string.desktop_backup_listed, 0),
            DesktopBackupForm.listingNote(DesktopBackupForm.DesktopListing.Listed(emptyList()), "phone-8")
        )
        assertEquals(
            DesktopBackupForm.ListingNote(R.string.desktop_backup_list_failed, 0),
            DesktopBackupForm.listingNote(DesktopBackupForm.DesktopListing.Failed(IOException("down")), "phone-8")
        )
    }
}
