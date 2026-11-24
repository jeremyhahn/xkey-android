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

import android.app.Application
import androidx.appcompat.app.AlertDialog
import com.automatethethings.xkey.R
import com.automatethethings.xkey.remote.RemoteBackupClient
import com.automatethethings.xkey.remote.RemoteBackupException
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.slot
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.IOException

/**
 * Robolectric tests for the restore half of [DesktopBackupDialogs]: the
 * latest-backup lookup, the listing note in the restore dialog, the call it
 * sends, the per-store result, the error and retry notices and the clearing
 * of the password field. The lookup, listing and note decisions themselves
 * are covered by [DesktopBackupFormTest]; these test what the dialogs add.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class DesktopBackupDialogsRestoreTest {

    private lateinit var host: DesktopBackupDialogsTestHost

    @Before
    fun setUp() {
        host = DesktopBackupDialogsTestHost()
    }

    @After
    fun tearDown() {
        host.close()
        unmockkAll()
    }

    // ---------------------------------------------------------------- lookup

    @Test
    fun `with no stored backup restore says so and opens no dialog`() {
        stored(null)

        host.open(RESTORE)
        host.settle()

        assertEquals(listOf(host.string(R.string.desktop_backup_none_stored)), host.snackbarTexts())
        assertFalse(host.anyDialogShowing())
        coVerify(exactly = 0) { host.gatt.listDesktopBackups() }
    }

    @Test
    fun `a lookup that fails shows the stored-backups error and opens no dialog`() {
        coEvery { host.gatt.latestStoredBackupId() } throws IOException("record unreadable")

        host.open(RESTORE)
        host.settle()

        assertEquals(listOf(host.string(R.string.desktop_backup_error_read_stored)), host.snackbarTexts())
        assertFalse(host.anyDialogShowing())
        coVerify(exactly = 0) { host.gatt.listDesktopBackups() }
    }

    @Test
    fun `the restore dialog names the backup and says the desktop holds it`() {
        stored("b-1")
        listed("b-0", "b-1")

        val dialog = openRestore()

        assertTrue(host.texts(dialog).contains(host.string(R.string.desktop_backup_restore_title)))
        assertEquals(
            host.string(R.string.desktop_backup_restore_message, "b-1") + "\n\n" +
                host.string(R.string.desktop_backup_listed_match, 2),
            host.message(dialog)
        )
        assertEquals(1, host.fields(dialog).size)
        assertEquals(host.string(R.string.desktop_backup_password), host.fields(dialog)[0].hint.toString())
    }

    @Test
    fun `the restore dialog says when the desktop does not hold the backup`() {
        stored("b-1")
        listed("b-0")

        val dialog = openRestore()

        assertEquals(
            host.string(R.string.desktop_backup_restore_message, "b-1") + "\n\n" +
                host.string(R.string.desktop_backup_listed, 1),
            host.message(dialog)
        )
    }

    @Test
    fun `a listing that fails is said in the dialog and the restore still opens`() {
        stored("b-1")
        coEvery { host.gatt.listDesktopBackups() } throws IllegalStateException("No desktop connected")

        val dialog = openRestore()

        assertEquals(
            host.string(R.string.desktop_backup_restore_message, "b-1") + "\n\n" +
                host.string(R.string.desktop_backup_list_failed, 0),
            host.message(dialog)
        )
        assertNull("a listing failure shows no notice", host.snackbarText())
    }

    // ------------------------------------------------------------------ send

    @Test
    fun `an empty password is flagged on the field and nothing is sent`() {
        storedAndListed()
        val dialog = openRestore()

        host.clickPositive(dialog)

        assertEquals(
            host.string(R.string.desktop_backup_error_password_empty),
            host.fields(dialog)[0].error?.toString()
        )
        assertTrue(dialog.isShowing)
        assertNull(host.snackbarText())
        coVerify(exactly = 0) { host.gatt.restoreDesktopBackup(any(), any()) }
    }

    @Test
    fun `a valid password is sent once with the stored backup id`() {
        storedAndListed()
        val sent = slot<CharArray>()
        var typed: CharArray? = null
        coEvery { host.gatt.restoreDesktopBackup(any(), capture(sent)) } coAnswers {
            typed = sent.captured.copyOf()
            result(success = true)
        }
        val dialog = openRestore()
        host.fields(dialog)[0].setText("restore pass")

        host.clickPositive(dialog)

        assertArrayEquals("restore pass".toCharArray(), typed)
        coVerify(exactly = 1) { host.gatt.restoreDesktopBackup("b-1", any()) }
        assertFalse(dialog.isShowing)
    }

    // --------------------------------------------------------------- results

    @Test
    fun `a complete result lists each store with its counts and errors and the message`() {
        val dialog = restoreWith(
            result(
                success = true,
                items = listOf(
                    RemoteBackupClient.RestoreItem("trust_store", 3, 1, 0, emptyList()),
                    RemoteBackupClient.RestoreItem("oath", 2, 0, 1, listOf("entry 4 unreadable"))
                ),
                message = "All done"
            )
        )

        assertTrue(host.texts(dialog).contains(host.string(R.string.desktop_backup_restore_complete)))
        assertFalse(host.texts(dialog).contains(host.string(R.string.desktop_backup_restore_partial)))
        assertEquals(
            listOf(
                item(host.string(R.string.desktop_backup_item_trust_store), 3, 1, 0),
                item(host.string(R.string.desktop_backup_item_oath), 2, 0, 1),
                host.string(R.string.desktop_backup_restore_item_error, "entry 4 unreadable"),
                "All done"
            ).joinToString("\n"),
            host.message(dialog)
        )
    }

    @Test
    fun `a failed result shows the partial title`() {
        val dialog = restoreWith(
            result(
                success = false,
                items = listOf(RemoteBackupClient.RestoreItem("passwords", 0, 0, 5, listOf("locked")))
            )
        )

        assertTrue(host.texts(dialog).contains(host.string(R.string.desktop_backup_restore_partial)))
        assertFalse(host.texts(dialog).contains(host.string(R.string.desktop_backup_restore_complete)))
        assertEquals(
            listOf(
                item(host.string(R.string.desktop_backup_item_passwords), 0, 0, 5),
                host.string(R.string.desktop_backup_restore_item_error, "locked")
            ).joinToString("\n"),
            host.message(dialog)
        )
    }

    @Test
    fun `with no items the restored names are listed, unknown names raw`() {
        val dialog = restoreWith(result(success = true, restored = listOf("passwords", "ca", "notes")))

        assertEquals(
            host.string(
                R.string.desktop_backup_restored_list,
                listOf(
                    host.string(R.string.desktop_backup_item_passwords),
                    host.string(R.string.desktop_backup_item_ca),
                    "notes"
                ).joinToString()
            ),
            host.message(dialog)
        )
    }

    @Test
    fun `an item the phone does not know is shown by its raw name`() {
        val dialog = restoreWith(
            result(
                success = true,
                items = listOf(RemoteBackupClient.RestoreItem("notes", 1, 0, 0, emptyList())),
                restored = listOf("notes")
            )
        )

        assertEquals(item("notes", 1, 0, 0), host.message(dialog))
    }

    // ---------------------------------------------------------------- errors

    @Test
    fun `a wrong password offers a retry that reopens the restore with an empty field`() {
        storedAndListed()
        coEvery { host.gatt.restoreDesktopBackup(any(), any()) } throws
            RemoteBackupException.WrongPasswordOrDamaged("cannot decrypt")
        val first = openRestore()
        host.fields(first)[0].setText("wrong pass")
        host.clickPositive(first)
        host.settle()

        assertEquals(listOf(host.string(R.string.desktop_backup_error_wrong_password)), host.snackbarTexts())
        val retry = host.snackbarAction()
        assertNotNull("a wrong password must offer a retry", retry)
        assertEquals(host.string(R.string.desktop_backup_retry), retry!!.text.toString())

        retry.performClick()
        host.idle()

        val again = host.shownDialog()
        assertNotSame(first, again)
        assertEquals("", host.fields(again)[0].text.toString())
        assertEquals(
            host.string(R.string.desktop_backup_restore_message, "b-1") + "\n\n" +
                host.string(R.string.desktop_backup_listed_match, 1),
            host.message(again)
        )
    }

    @Test
    fun `a timeout shows its text and no retry`() {
        storedAndListed()
        coEvery { host.gatt.restoreDesktopBackup(any(), any()) } throws
            RemoteBackupException.TimedOut("remote.restoreBackup")

        send("pass")

        assertEquals(listOf(host.string(R.string.desktop_backup_error_timed_out)), host.snackbarTexts())
        assertNull(host.snackbarAction())
    }

    @Test
    fun `a plain failure shows the generic text and no retry`() {
        storedAndListed()
        coEvery { host.gatt.restoreDesktopBackup(any(), any()) } throws IOException("link lost")

        send("pass")

        assertEquals(listOf(host.string(R.string.desktop_backup_failed, "link lost")), host.snackbarTexts())
        assertNull(host.snackbarAction())
    }

    // ------------------------------------------------------ password clearing

    @Test
    fun `after send the field is overwritten, then cleared`() {
        storedAndListed()
        coEvery { host.gatt.restoreDesktopBackup(any(), any()) } returns result(success = true)
        val dialog = openRestore()
        val field = host.fields(dialog)[0]
        field.setText("hunter22")
        val seen = host.watch(field)

        host.clickPositive(dialog)

        assertEquals("", field.text.toString())
        assertEquals(listOf(" ".repeat(8), ""), seen)
    }

    @Test
    fun `cancel empties the field and sends nothing`() {
        storedAndListed()
        val dialog = openRestore()
        val field = host.fields(dialog)[0]
        field.setText("hunter22")
        val seen = host.watch(field)

        host.clickNegative(dialog)

        assertFalse(dialog.isShowing)
        assertEquals("", field.text.toString())
        assertEquals(listOf(" ".repeat(8), ""), seen)
        coVerify(exactly = 0) { host.gatt.restoreDesktopBackup(any(), any()) }
    }

    @Test
    fun `back empties the field and sends nothing`() {
        storedAndListed()
        val dialog = openRestore()
        val field = host.fields(dialog)[0]
        field.setText("hunter22")
        val seen = host.watch(field)

        host.pressBack(dialog)

        assertFalse(dialog.isShowing)
        assertEquals("", field.text.toString())
        assertEquals(listOf(" ".repeat(8), ""), seen)
        coVerify(exactly = 0) { host.gatt.restoreDesktopBackup(any(), any()) }
    }

    @Test
    fun `the password array sent is zeroed once the call returns`() {
        storedAndListed()
        val sent = slot<CharArray>()
        coEvery { host.gatt.restoreDesktopBackup(any(), capture(sent)) } returns result(success = true)

        send("hunter22")

        assertTrue("the dialogs must zero the copy they made", sent.captured.all { it == '\u0000' })
    }

    @Test
    fun `the password array sent is zeroed when the call throws`() {
        storedAndListed()
        val sent = slot<CharArray>()
        coEvery { host.gatt.restoreDesktopBackup(any(), capture(sent)) } throws
            RemoteBackupException.WrongPasswordOrDamaged("cannot decrypt")

        send("hunter22")

        assertEquals(8, sent.captured.size)
        assertTrue("the dialogs must zero the copy they made", sent.captured.all { it == '\u0000' })
    }

    @Test
    fun `a desktop gone by the send shows not connected and copies no password`() {
        storedAndListed()
        val dialog = openRestore()
        val field = host.fields(dialog)[0]
        field.setText("hunter22")
        host.service = { null }

        host.clickPositive(dialog)
        host.settle()

        assertEquals(listOf(host.string(R.string.sync_not_connected)), host.snackbarTexts())
        assertNull("not connected offers no retry", host.snackbarAction())
        assertFalse(dialog.isShowing)
        assertEquals("", field.text.toString())
        coVerify(exactly = 0) { host.gatt.restoreDesktopBackup(any(), any()) }
    }

    @Test
    fun `a bound service with no desktop by the send shows not connected and copies no password`() {
        storedAndListed()
        val dialog = openRestore()
        val field = host.fields(dialog)[0]
        field.setText("hunter22")
        host.desktop = null

        host.clickPositive(dialog)
        host.settle()

        assertEquals(listOf(host.string(R.string.sync_not_connected)), host.snackbarTexts())
        assertNull("not connected offers no retry", host.snackbarAction())
        assertFalse(dialog.isShowing)
        assertEquals("", field.text.toString())
        coVerify(exactly = 0) { host.gatt.restoreDesktopBackup(any(), any()) }
    }

    @Test
    fun `a bound service with no desktop at the pick says so and opens no dialog`() {
        storedAndListed()
        host.dialogs.show()
        host.idle()
        val menu = host.shownDialog()
        host.desktop = null

        host.pickMenuItem(menu, RESTORE)
        host.settle()

        assertEquals(listOf(host.string(R.string.sync_not_connected)), host.snackbarTexts())
        assertFalse(host.anyDialogShowing())
        coVerify(exactly = 0) { host.gatt.latestStoredBackupId() }
    }

    // --------------------------------------------------------------- helpers

    private fun stored(id: String?) {
        coEvery { host.gatt.latestStoredBackupId() } returns id
    }

    private fun listed(vararg ids: String) {
        coEvery { host.gatt.listDesktopBackups() } returns
            ids.map { RemoteBackupClient.BackupInfo(it, "2026-01-01T00:00:00Z", null, 1024L) }
    }

    private fun storedAndListed() {
        stored("b-1")
        listed("b-1")
    }

    private fun openRestore(): AlertDialog {
        host.open(RESTORE)
        return host.shownDialog()
    }

    /** Opens restore of `b-1`, types [password] and sends it. */
    private fun send(password: String) {
        val dialog = openRestore()
        host.fields(dialog)[0].setText(password)
        host.clickPositive(dialog)
        host.settle()
    }

    /** Restores `b-1` to [result] and returns the result dialog. */
    private fun restoreWith(result: RemoteBackupClient.RestoreResult): AlertDialog {
        storedAndListed()
        coEvery { host.gatt.restoreDesktopBackup(any(), any()) } returns result
        val dialog = openRestore()
        host.fields(dialog)[0].setText("pass")
        host.clickPositive(dialog)
        val shown = host.shownDialog()
        assertNotSame("the result must open its own dialog", dialog, shown)
        return shown
    }

    private fun item(label: String, restored: Int, quarantined: Int, skipped: Int) =
        host.string(R.string.desktop_backup_restore_item, label, restored, quarantined, skipped)

    private fun result(
        success: Boolean,
        items: List<RemoteBackupClient.RestoreItem> = emptyList(),
        restored: List<String> = emptyList(),
        message: String? = null
    ) = RemoteBackupClient.RestoreResult(success, restored, message, items)

    private companion object {
        const val RESTORE = 1
    }
}
