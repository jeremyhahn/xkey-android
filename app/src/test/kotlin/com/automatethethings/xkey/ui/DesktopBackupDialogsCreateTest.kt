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
import io.mockk.confirmVerified
import io.mockk.slot
import io.mockk.unmockkAll
import kotlinx.coroutines.CompletableDeferred
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.IOException

/**
 * Robolectric tests for the create half of [DesktopBackupDialogs]: the entry
 * menu, the create form's checks, the call it sends, the notices it shows and
 * the clearing of both password fields. The form checks themselves are
 * covered by [DesktopBackupFormTest]; these test what the dialogs add.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class DesktopBackupDialogsCreateTest {

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

    // ------------------------------------------------------------ entry menu

    @Test
    fun `with no desktop connected show says so and opens no dialog`() {
        host.service = { null }

        host.dialogs.show()
        host.idle()

        assertEquals(host.string(R.string.sync_not_connected), host.snackbarText())
        assertNull("no dialog may open without a desktop", host.latestDialog())
    }

    @Test
    fun `entry menu offers create and restore and cancel closes it`() {
        host.dialogs.show()
        host.idle()
        val menu = host.shownDialog()

        assertTrue(host.texts(menu).contains(host.string(R.string.desktop_backup_title)))
        assertEquals(
            listOf(
                host.string(R.string.desktop_backup_action_create),
                host.string(R.string.desktop_backup_action_restore)
            ),
            host.menuItems(menu)
        )

        host.clickNegative(menu)

        assertFalse(menu.isShowing)
        assertNull(host.snackbarText())
        confirmVerified(host.gatt)
    }

    @Test
    fun `create asks for the password twice and offers three stores, all ticked`() {
        val dialog = openCreate()

        assertTrue(host.texts(dialog).contains(host.string(R.string.desktop_backup_create_title)))
        val fields = host.fields(dialog)
        assertEquals(2, fields.size)
        assertEquals(host.string(R.string.desktop_backup_password), fields[0].hint.toString())
        assertEquals(host.string(R.string.desktop_backup_password_confirm), fields[1].hint.toString())
        val toggles = host.toggles(dialog)
        assertEquals(
            listOf(
                host.string(R.string.desktop_backup_include_trust_store),
                host.string(R.string.desktop_backup_include_oath),
                host.string(R.string.desktop_backup_include_passwords)
            ),
            toggles.map { it.text.toString() }
        )
        assertTrue(toggles.all { it.isChecked })
    }

    // ----------------------------------------------------------- form checks

    @Test
    fun `an empty password is flagged on the password field and nothing is sent`() {
        val dialog = openCreate()

        host.clickPositive(dialog)

        val (password, confirm) = host.fields(dialog)
        assertEquals(host.string(R.string.desktop_backup_error_password_empty), password.error?.toString())
        assertNull(confirm.error)
        assertTrue("the form stays open to be corrected", dialog.isShowing)
        assertNull(host.snackbarText())
        coVerify(exactly = 0) { host.gatt.createDesktopBackup(any(), any()) }
    }

    @Test
    fun `a mismatched confirmation is flagged on the confirmation field and nothing is sent`() {
        val dialog = openCreate()
        fill(dialog, "first pass", "other pass")

        host.clickPositive(dialog)

        val (password, confirm) = host.fields(dialog)
        assertNull(password.error)
        assertEquals(host.string(R.string.desktop_backup_error_password_mismatch), confirm.error?.toString())
        assertTrue(dialog.isShowing)
        coVerify(exactly = 0) { host.gatt.createDesktopBackup(any(), any()) }
    }

    @Test
    fun `every store unticked shows the nothing-selected error once and nothing is sent`() {
        val dialog = openCreate()
        fill(dialog, "same pass")
        host.toggles(dialog).forEach { it.isChecked = false }

        host.clickPositive(dialog)

        val errors = (host.fields(dialog) + host.toggles(dialog)).mapNotNull { it.error?.toString() }
        assertEquals(listOf(host.string(R.string.desktop_backup_error_nothing_selected)), errors)
        assertTrue(dialog.isShowing)
        coVerify(exactly = 0) { host.gatt.createDesktopBackup(any(), any()) }
    }

    // ------------------------------------------------------------------ send

    @Test
    fun `a valid form sends the typed password and the ticked stores once`() {
        val sent = slot<CharArray>()
        val include = slot<RemoteBackupClient.Include>()
        var typed: CharArray? = null
        coEvery { host.gatt.createDesktopBackup(capture(sent), capture(include)) } coAnswers {
            typed = sent.captured.copyOf()
            result()
        }
        val dialog = openCreate()
        fill(dialog, "s3cret pass")
        host.toggles(dialog)[1].isChecked = false

        host.clickPositive(dialog)
        host.settle()

        assertArrayEquals("s3cret pass".toCharArray(), typed)
        assertEquals(
            RemoteBackupClient.Include(trustStore = true, oath = false, passwords = true),
            include.captured
        )
        coVerify(exactly = 1) { host.gatt.createDesktopBackup(any(), any()) }
        assertFalse(dialog.isShowing)
        assertEquals(listOf(host.string(R.string.desktop_backup_complete, "b-7", 3)), host.snackbarTexts())
    }

    @Test
    fun `the in-progress notice shows while the call is open, then the complete notice`() {
        val gate = CompletableDeferred<RemoteBackupClient.CreateResult>()
        coEvery { host.gatt.createDesktopBackup(any(), any()) } coAnswers { gate.await() }
        val dialog = openCreate()
        fill(dialog, "pass")

        host.clickPositive(dialog)

        assertEquals(host.string(R.string.desktop_backup_in_progress), host.snackbarText())
        assertFalse(dialog.isShowing)

        gate.complete(result(id = "b-9", count = 12))
        host.idle()
        host.settle()

        assertEquals(listOf(host.string(R.string.desktop_backup_complete, "b-9", 12)), host.snackbarTexts())
    }

    // ---------------------------------------------------------------- errors

    @Test
    fun `a desktop error shows its own text and create offers no retry`() {
        coEvery { host.gatt.createDesktopBackup(any(), any()) } throws
            RemoteBackupException.WrongPasswordOrDamaged("cannot decrypt")

        send("pass")

        assertEquals(listOf(host.string(R.string.desktop_backup_error_wrong_password)), host.snackbarTexts())
        assertNull("create never offers a retry", host.snackbarAction())
    }

    @Test
    fun `a timeout shows the timed-out text with no retry`() {
        coEvery { host.gatt.createDesktopBackup(any(), any()) } throws
            RemoteBackupException.TimedOut("remote.createBackup")

        send("pass")

        assertEquals(listOf(host.string(R.string.desktop_backup_error_timed_out)), host.snackbarTexts())
        assertNull(host.snackbarAction())
    }

    @Test
    fun `a plain failure shows the generic text with its message`() {
        coEvery { host.gatt.createDesktopBackup(any(), any()) } throws IOException("link lost")

        send("pass")

        assertEquals(listOf(host.string(R.string.desktop_backup_failed, "link lost")), host.snackbarTexts())
        assertNull(host.snackbarAction())
    }

    @Test
    fun `a failure without a message names its type`() {
        coEvery { host.gatt.createDesktopBackup(any(), any()) } throws IllegalStateException()

        send("pass")

        assertEquals(
            listOf(host.string(R.string.desktop_backup_failed, "IllegalStateException")),
            host.snackbarTexts()
        )
    }

    // ------------------------------------------------------ password clearing

    @Test
    fun `after send both fields are overwritten, then cleared`() {
        coEvery { host.gatt.createDesktopBackup(any(), any()) } returns result()
        val dialog = openCreate()
        fill(dialog, "hunter22")
        val (password, confirm) = host.fields(dialog)
        val passwordSeen = host.watch(password)
        val confirmSeen = host.watch(confirm)

        host.clickPositive(dialog)
        host.settle()

        assertEquals("", password.text.toString())
        assertEquals("", confirm.text.toString())
        assertEquals(listOf(" ".repeat(8), ""), passwordSeen)
        assertEquals(listOf(" ".repeat(8), ""), confirmSeen)
    }

    @Test
    fun `cancel empties both fields and sends nothing`() {
        val dialog = openCreate()
        fill(dialog, "hunter22", "hunter2")
        val (password, confirm) = host.fields(dialog)
        val passwordSeen = host.watch(password)
        val confirmSeen = host.watch(confirm)

        host.clickNegative(dialog)

        assertFalse(dialog.isShowing)
        assertEquals("", password.text.toString())
        assertEquals("", confirm.text.toString())
        assertEquals(listOf(" ".repeat(8), ""), passwordSeen)
        assertEquals(listOf(" ".repeat(7), ""), confirmSeen)
        coVerify(exactly = 0) { host.gatt.createDesktopBackup(any(), any()) }
    }

    @Test
    fun `back empties both fields and sends nothing`() {
        val dialog = openCreate()
        fill(dialog, "hunter22")
        val (password, confirm) = host.fields(dialog)

        host.pressBack(dialog)

        assertFalse(dialog.isShowing)
        assertEquals("", password.text.toString())
        assertEquals("", confirm.text.toString())
        coVerify(exactly = 0) { host.gatt.createDesktopBackup(any(), any()) }
    }

    @Test
    fun `the password array sent is zeroed once the call returns`() {
        val sent = slot<CharArray>()
        coEvery { host.gatt.createDesktopBackup(capture(sent), any()) } returns result()

        send("hunter22")

        assertTrue("the dialogs must zero the copy they made", sent.captured.all { it == '\u0000' })
    }

    @Test
    fun `the password array sent is zeroed when the call throws`() {
        val sent = slot<CharArray>()
        coEvery { host.gatt.createDesktopBackup(capture(sent), any()) } throws IOException("link lost")

        send("hunter22")

        assertEquals(8, sent.captured.size)
        assertTrue("the dialogs must zero the copy they made", sent.captured.all { it == '\u0000' })
    }

    // --------------------------------------------------------------- helpers

    private fun openCreate(): AlertDialog {
        host.open(0)
        return host.shownDialog()
    }

    private fun fill(dialog: AlertDialog, password: String, confirm: String = password) {
        val fields = host.fields(dialog)
        fields[0].setText(password)
        fields[1].setText(confirm)
    }

    /** Opens create, types [password] in both fields and sends it. */
    private fun send(password: String) {
        val dialog = openCreate()
        fill(dialog, password)
        host.clickPositive(dialog)
        host.settle()
    }

    private fun result(id: String = "b-7", count: Int = 3) =
        RemoteBackupClient.CreateResult(ByteArray(0), id, count)
}
