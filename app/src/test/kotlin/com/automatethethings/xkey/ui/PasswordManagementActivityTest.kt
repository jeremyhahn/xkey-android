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
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import androidx.recyclerview.widget.RecyclerView
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
import org.junit.After
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

    // -------------------------------------------------------------------------
    // Fixtures
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
