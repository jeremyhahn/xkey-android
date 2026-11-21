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

import android.app.AlertDialog
import android.app.Application
import android.content.DialogInterface
import android.os.Looper
import android.text.Spanned
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.auth.PromptOwnership
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowAlertDialog

/**
 * The account-choice mode of [TransparentBiometricActivity], driven through
 * [BiometricActivityLauncher.requestAccountChoice]: one list of the accounts
 * in the order given, as plain text, with the RP as subtitle. A tap answers
 * its index; Cancel, back and a withdrawn request answer nothing.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class)
class TransparentBiometricActivityAccountChoiceTest {

    private lateinit var app: Application
    private lateinit var launcher: BiometricActivityLauncher

    private val accounts = listOf("Alice (alice)", "<b>Bob</b> (bob)", "Carol &amp; co (carol)")

    @Before
    fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        app = RuntimeEnvironment.getApplication()
        ShadowAlertDialog.reset()
        launcher = BiometricActivityLauncher(app).also { it.register() }
    }

    @After
    fun tearDown() {
        launcher.unregister()
        assertEquals("every choice let go of its queue entry", 0, PromptOwnership.process.entries)
        Dispatchers.resetMain()
    }

    /** Delivers what the activity broadcast, and resumes whoever it settled. */
    private fun TestScope.settle() {
        shadowOf(Looper.getMainLooper()).idle()
        runCurrent()
    }

    /** Asks for a choice and opens the activity the launcher started for it. */
    private fun TestScope.choose(
        showOnLockScreen: Boolean = false
    ): Pair<Deferred<Int?>, ActivityController<TransparentBiometricActivity>> {
        val answer = async {
            launcher.requestAccountChoice(
                title = "Choose an account",
                subtitle = "example.com",
                accounts = accounts,
                showOnLockScreen = showOnLockScreen
            )
        }
        runCurrent()
        val started = shadowOf(app).nextStartedActivity
        assertNotNull("the list was started", started)
        assertEquals(TransparentBiometricActivity::class.java.name, started.component?.className)
        val controller = Robolectric.buildActivity(TransparentBiometricActivity::class.java, started).setup()
        shadowOf(Looper.getMainLooper()).idle()
        return answer to controller
    }

    private fun list(): AlertDialog {
        val dialog = ShadowAlertDialog.getLatestAlertDialog()
        assertNotNull("the account list is up", dialog)
        assertTrue(dialog!!.isShowing)
        return dialog
    }

    private fun texts(view: View): List<CharSequence> = when (view) {
        is TextView -> listOf(view.text)
        is ViewGroup -> (0 until view.childCount).flatMap { texts(view.getChildAt(it)) }
        else -> emptyList()
    }

    @Test
    fun `the list shows every account in order as plain text with the RP as subtitle`() = runTest {
        val (answer, _) = choose()
        val dialog = list()

        val items = shadowOf(dialog).items.toList()
        assertEquals(accounts, items.map { it.toString() })
        assertFalse("account names are never markup", items.any { it is Spanned })
        val header = texts(dialog.window!!.decorView).map { it.toString() }
        assertTrue("title in $header", "Choose an account" in header)
        assertTrue("RP as subtitle in $header", "example.com" in header)
        assertFalse("no biometric prompt for the list", answer.isCompleted)

        list().getButton(DialogInterface.BUTTON_NEGATIVE).performClick()
        settle()
    }

    @Test
    fun `a tap on an account answers its index`() = runTest {
        val (answer, controller) = choose()

        shadowOf(list()).clickOnItem(2)
        settle()

        assertEquals(2, answer.await())
        assertTrue(controller.get().isFinishing)
    }

    @Test
    fun `Cancel answers no account`() = runTest {
        val (answer, controller) = choose()

        list().getButton(DialogInterface.BUTTON_NEGATIVE).performClick()
        settle()

        assertNull(answer.await())
        assertTrue(controller.get().isFinishing)
    }

    @Test
    fun `back on the list answers no account`() = runTest {
        val (answer, controller) = choose()

        list().onBackPressed()
        settle()

        assertNull(answer.await())
        assertTrue(controller.get().isFinishing)
    }

    @Test
    fun `back on the activity answers no account`() = runTest {
        val (answer, controller) = choose()

        controller.get().onBackPressedDispatcher.onBackPressed()
        settle()

        assertNull(answer.await())
        assertTrue(controller.get().isFinishing)
    }

    @Test
    fun `on a locked phone the list shows over the lock screen`() = runTest {
        val (answer, controller) = choose(showOnLockScreen = true)

        assertTrue(shadowOf(controller.get()).showWhenLocked)
        assertTrue(shadowOf(controller.get()).turnScreenOn)

        list().getButton(DialogInterface.BUTTON_NEGATIVE).performClick()
        settle()
        assertNull(answer.await())
    }

    @Test
    fun `a cancelled caller takes the list down`() = runTest {
        val (answer, controller) = choose()
        val dialog = list()

        answer.cancel()
        settle()

        assertTrue(controller.get().isFinishing)
        assertFalse(dialog.isShowing)
    }
}
