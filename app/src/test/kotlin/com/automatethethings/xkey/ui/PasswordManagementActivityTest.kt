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
import android.app.Dialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.DialogInterface
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.recyclerview.widget.RecyclerView
import com.automatethethings.xkey.R
import com.automatethethings.xkey.crypto.KeystoreAeadCipher
import com.automatethethings.xkey.password.PasswordDao
import com.automatethethings.xkey.password.PasswordEntity
import com.automatethethings.xkey.password.PasswordRepository
import com.automatethethings.xkey.password.fixtureSecret
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowDialog
import java.time.Duration
import javax.crypto.AEADBadTagException

/**
 * The password screen keeps its secrets off screenshots, recordings, casts
 * and the recents thumbnail: its window and every dialog it opens are
 * FLAG_SECURE.
 *
 * The Keystore cipher is stubbed with a reversible transform (a marker byte
 * in front of the plaintext); ciphertext without the marker fails to decrypt
 * as a corrupt entry would.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class PasswordManagementActivityTest {

    private lateinit var dao: PasswordDao
    private lateinit var cipher: KeystoreAeadCipher
    private val marker: Byte = 0x7f

    private companion object {
        const val NAME_FIELD = 0
        const val PASSWORD_FIELD = 2
    }

    @Before
    fun setUp() {
        dao = mockk(relaxed = true)
        cipher = mockk()
        every { cipher.encrypt(any()) } answers { byteArrayOf(marker) + firstArg<ByteArray>() }
        every { cipher.decrypt(any()) } answers {
            val sealed = firstArg<ByteArray>()
            if (sealed.isEmpty() || sealed[0] != marker) throw AEADBadTagException("corrupt")
            sealed.copyOfRange(1, sealed.size)
        }
        PasswordManagementActivity.repositoryForTest = PasswordRepository(dao, cipher)
    }

    @After
    fun tearDown() {
        PasswordManagementActivity.repositoryForTest = null
        unmockkAll()
    }

    @Test
    fun `the password screen window is FLAG_SECURE`() {
        val activity = launch()

        assertSecure(activity.window.attributes.flags)
    }

    @Test
    fun `the detail dialog window is FLAG_SECURE`() {
        stored(entity("pw-good", "Good", sealed(fixtureSecret(1))))
        val activity = launch()

        clickRow(activity, 0)

        val dialog = ShadowDialog.getLatestDialog()
        assertNotNull("detail dialog shown", dialog)
        assertSecure(dialog.window!!.attributes.flags)
    }

    @Test
    fun `the add dialog window is FLAG_SECURE`() {
        val activity = launch()

        val dialog = openAddDialog(activity)

        assertSecure(dialog.window!!.attributes.flags)
    }

    @Test
    fun `the list shows every entry and decrypts none of them`() {
        stored(
            entity("pw-bad", "Alpha", byteArrayOf(0x00, 0x01)),
            entity("pw-good", "Beta", sealed(fixtureSecret(2)))
        )
        val activity = launch()

        assertEquals(2, recycler(activity).adapter!!.itemCount)
        verify(exactly = 0) { cipher.decrypt(any()) }
    }

    @Test
    fun `an entry that cannot be decrypted opens an error and the others still open`() {
        stored(
            entity("pw-bad", "Alpha", byteArrayOf(0x00, 0x01)),
            entity("pw-good", "Beta", sealed(fixtureSecret(2)))
        )
        val activity = launch()

        clickRow(activity, 0)
        assertEquals(
            activity.getString(R.string.password_unreadable),
            dialogMessage(ShadowDialog.getLatestDialog())
        )

        clickRow(activity, 1)
        assertTrue(
            "the good entry's detail shows its password",
            dialogMessage(ShadowDialog.getLatestDialog()).contains(fixtureSecret(2))
        )
    }

    @Test
    fun `saving without a name keeps the add dialog open with a name error and the typed password`() {
        val activity = launch()
        val dialog = openAddDialog(activity) as AlertDialog
        val fields = editTexts(dialog.window!!.decorView)
        val typed = fixtureSecret(3)
        fields[PASSWORD_FIELD].setText(typed)

        dialog.getButton(DialogInterface.BUTTON_POSITIVE).performClick()
        idle()

        assertTrue("add dialog still showing", dialog.isShowing)
        assertEquals(
            activity.getString(R.string.password_name_required),
            fields[NAME_FIELD].error?.toString()
        )
        assertEquals(typed, fields[PASSWORD_FIELD].text.toString())
    }

    @Test
    fun `saving without a password keeps the add dialog open with a password error and the typed name`() {
        val activity = launch()
        val dialog = openAddDialog(activity) as AlertDialog
        val fields = editTexts(dialog.window!!.decorView)
        fields[NAME_FIELD].setText("Example")

        dialog.getButton(DialogInterface.BUTTON_POSITIVE).performClick()
        idle()

        assertTrue("add dialog still showing", dialog.isShowing)
        assertEquals(
            activity.getString(R.string.password_password_required),
            fields[PASSWORD_FIELD].error?.toString()
        )
        assertEquals("Example", fields[NAME_FIELD].text.toString())
    }

    @Test
    fun `a copied password is cleared from the clipboard after 45 seconds`() {
        stored(entity("pw-good", "Good", sealed(fixtureSecret(4))))
        val activity = launch()
        val clipboard = clipboard(activity)

        copyFromDetail(activity, 0)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(44))
        assertEquals(fixtureSecret(4), clipText(clipboard))

        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(1))
        assertTrue("clipboard still holds the password", clipText(clipboard).isNullOrEmpty())
    }

    @Test
    fun `a clip set by someone else after a password copy is not cleared`() {
        stored(entity("pw-good", "Good", sealed(fixtureSecret(4))))
        val activity = launch()
        val clipboard = clipboard(activity)

        copyFromDetail(activity, 0)
        clipboard.setPrimaryClip(ClipData.newPlainText("note", "shopping list"))
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(45))

        assertEquals("shopping list", clipText(clipboard))
    }

    // -------------------------------------------------------------------------
    // Fixtures

    private fun clipboard(activity: PasswordManagementActivity): ClipboardManager =
        activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

    private fun clipText(clipboard: ClipboardManager): String? =
        clipboard.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString()

    /** Opens row [position]'s detail dialog and taps Copy. */
    private fun copyFromDetail(activity: PasswordManagementActivity, position: Int) {
        clickRow(activity, position)
        val dialog = ShadowDialog.getLatestDialog() as AlertDialog
        dialog.getButton(DialogInterface.BUTTON_POSITIVE).performClick()
        idle()
    }

    /** The add dialog's fields in order: name, username, password, URL, notes. */
    private fun editTexts(root: View): List<EditText> {
        val found = mutableListOf<EditText>()
        fun walk(view: View) {
            if (view is EditText) found += view
            if (view is ViewGroup) for (i in 0 until view.childCount) walk(view.getChildAt(i))
        }
        walk(root)
        assertEquals("add dialog fields", 5, found.size)
        return found
    }

    private fun dialogMessage(dialog: Dialog): String =
        dialog.findViewById<TextView>(android.R.id.message).text.toString()
    // -------------------------------------------------------------------------

    private fun assertSecure(flags: Int) {
        assertTrue("FLAG_SECURE not set", flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
    }

    private fun sealed(plaintext: String): ByteArray =
        byteArrayOf(marker) + plaintext.toByteArray(Charsets.UTF_8)

    private fun entity(passwordId: String, name: String, ciphertext: ByteArray) = PasswordEntity(
        passwordId = passwordId,
        name = name,
        title = name,
        username = "user@example.com",
        passwordEncrypted = ciphertext,
        createdAt = 1_000L,
        updatedAt = 2_000L
    )

    private fun stored(vararg entities: PasswordEntity) {
        coEvery { dao.getAll() } returns entities.toList()
        entities.forEach { e -> coEvery { dao.getByPasswordId(e.passwordId) } returns e }
    }

    private fun launch(): PasswordManagementActivity {
        val activity = Robolectric.buildActivity(PasswordManagementActivity::class.java).setup().get()
        idle()
        return activity
    }

    private fun idle() = shadowOf(Looper.getMainLooper()).idle()

    private fun recycler(activity: PasswordManagementActivity): RecyclerView {
        val recycler = find(activity.window.decorView) { it is RecyclerView } as RecyclerView
        recycler.measure(
            View.MeasureSpec.makeMeasureSpec(1080, View.MeasureSpec.EXACTLY),
            View.MeasureSpec.makeMeasureSpec(1920, View.MeasureSpec.EXACTLY)
        )
        recycler.layout(0, 0, 1080, 1920)
        return recycler
    }

    private fun clickRow(activity: PasswordManagementActivity, position: Int) {
        val holder = recycler(activity).findViewHolderForAdapterPosition(position)
        assertNotNull("row $position laid out", holder)
        holder!!.itemView.performClick()
        idle()
    }

    private fun openAddDialog(activity: PasswordManagementActivity): Dialog {
        find(activity.window.decorView) { it is ExtendedFloatingActionButton }!!.performClick()
        idle()
        val dialog = ShadowDialog.getLatestDialog()
        assertNotNull("add dialog shown", dialog)
        return dialog
    }

    private fun find(root: View, match: (View) -> Boolean): View? {
        if (match(root)) return root
        if (root is ViewGroup) {
            for (i in 0 until root.childCount) {
                find(root.getChildAt(i), match)?.let { return it }
            }
        }
        return null
    }
}
