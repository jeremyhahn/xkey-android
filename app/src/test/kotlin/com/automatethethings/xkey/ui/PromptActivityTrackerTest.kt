/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.ui

import android.app.Application
import android.content.DialogInterface
import android.os.Bundle
import android.os.Looper
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.FragmentActivity
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ble.XKeyGattService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
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
import org.robolectric.shadows.ShadowDialog
import java.io.File

/**
 * The pairing confirmation and every biometric prompt need an activity to
 * host them. Before #320 only MainActivity registered itself, and each
 * MainActivity instance cleared the service's reference in its own
 * onPause/onDestroy, whether or not it was the instance held. A second
 * instance destroyed after the first one resumed left the service with no
 * activity while the app was in front, and the desktop's pairing was refused
 * without a prompt.
 *
 * These tests drive the lifecycle orders that did that, a non-Main screen in
 * front, and the headless refusal that must survive the fix.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class)
class PromptActivityTrackerTest {

    private lateinit var app: Application
    private val controllers = mutableListOf<ActivityController<out FragmentActivity>>()

    @Before
    fun setUp() {
        app = RuntimeEnvironment.getApplication()
        PromptActivityTracker.reset()
        app.registerActivityLifecycleCallbacks(PromptActivityTracker)
    }

    @After
    fun tearDown() {
        controllers.forEach { runCatching { it.pause().stop().destroy() } }
        app.unregisterActivityLifecycleCallbacks(PromptActivityTracker)
        PromptActivityTracker.reset()
    }

    // -----------------------------------------------------------------
    // The tracker
    // -----------------------------------------------------------------

    @Test
    fun theResumedActivityIsTheHost() {
        val main = launch(HostActivity::class.java)

        assertSame(main.get(), PromptActivityTracker.current())
    }

    /** The order #320 hit: the old instance goes away after the new one resumed. */
    @Test
    fun anOldInstanceGoingAwayAfterTheNewOneResumedLeavesTheNewHost() {
        val old = launch(HostActivity::class.java)
        val new = launch(HostActivity::class.java)

        old.pause().stop().destroy()

        assertSame(new.get(), PromptActivityTracker.current())
    }

    @Test
    fun aRecreatedActivityIsTheHost() {
        val first = launch(HostActivity::class.java)

        first.recreate()

        val host = PromptActivityTracker.current()
        assertNotNull("a recreated activity must host prompts", host)
        assertSame(first.get(), host)
    }

    @Test
    fun aSecondaryScreenInFrontIsTheHost() {
        val main = launch(HostActivity::class.java)
        main.pause()
        val other = launch(OtherScreenActivity::class.java)
        main.stop()

        assertSame(other.get(), PromptActivityTracker.current())
    }

    @Test
    fun returningToTheFirstScreenMakesItTheHostAgain() {
        val main = launch(HostActivity::class.java)
        main.pause()
        val other = launch(OtherScreenActivity::class.java)
        main.stop()

        other.pause()
        main.restart().resume()
        other.stop().destroy()

        assertSame(main.get(), PromptActivityTracker.current())
    }

    @Test
    fun aPausedActivityIsNoHost() {
        val main = launch(HostActivity::class.java)

        main.pause()

        assertNull(PromptActivityTracker.current())
    }

    @Test
    fun aFinishingActivityIsNoHost() {
        val main = launch(HostActivity::class.java)

        main.get().finish()

        assertNull(PromptActivityTracker.current())
    }

    // -----------------------------------------------------------------
    // The pairing confirmation, through the service
    // -----------------------------------------------------------------

    @Test
    fun thePairingConfirmationIsShownOnTheResumedActivity() {
        val old = launch(HostActivity::class.java)
        val new = launch(HostActivity::class.java)
        old.pause().stop().destroy()

        val answer = askToPair()

        val dialog = shownDialog()
        dialog.getButton(DialogInterface.BUTTON_POSITIVE).performClick()
        idle()
        assertTrue("the user's approval must reach the caller", completed(answer))
        assertSame(new.get(), PromptActivityTracker.current())
    }

    @Test
    fun aSecondaryScreenHostsThePairingConfirmation() {
        val main = launch(HostActivity::class.java)
        main.pause()
        launch(OtherScreenActivity::class.java)
        main.stop()

        val answer = askToPair()

        val dialog = shownDialog()
        dialog.getButton(DialogInterface.BUTTON_NEGATIVE).performClick()
        idle()
        assertFalse("the user's refusal must reach the caller", completed(answer))
    }

    /**
     * A short-lived host (a biometric screen that finishes itself once its
     * prompt is answered) taking the pairing dialog down with its window must
     * not leave the caller waiting: on the stream path that wait holds the
     * only connection. The host going away is a refusal.
     */
    @Test
    fun aPairingWhoseHostIsDestroyedIsRefusedAndItsDialogGoesAway() {
        val host = launch(HostActivity::class.java)

        val answer = askToPair()
        val dialog = shownDialog()
        host.get().finish()
        host.pause().stop().destroy()
        idle()

        assertFalse("a prompt whose host went away is a refusal", completed(answer))
        assertFalse("the prompt must not outlive its host", dialog.isShowing)
    }

    @Test
    fun withNoResumedActivityThePairingIsRefused() {
        val main = launch(HostActivity::class.java)
        main.pause().stop()

        val service = Robolectric.buildService(XKeyGattService::class.java).get()
        val approved = runBlocking { service.onPairingConfirmationRequired("Headless Laptop", "abcd1234") }

        assertFalse("nothing may be approved while there is no one to ask", approved)
        assertNull("no dialog may be raised without a resumed activity", ShadowDialog.getLatestDialog())
    }

    // -----------------------------------------------------------------
    // No lookup bypasses the tracker
    // -----------------------------------------------------------------

    /**
     * A per-screen reference is what broke #320: a lookup that reads its own
     * field, set by one activity and cleared by another, fails here.
     */
    @Test
    fun everyPromptLookupGoesThroughThePromptHost() {
        val sources = mainSources()
        val bypasses = mutableListOf<String>()
        for (file in sources) {
            val text = file.readText()
            val name = file.name
            if (text.contains("No activity available") && !text.contains("promptHost")) {
                bypasses += "$name: a prompt lookup that does not ask promptHost"
            }
            if (name != "PromptActivityTracker.kt" && text.contains("WeakReference<FragmentActivity>")) {
                bypasses += "$name: its own activity reference"
            }
            text.lineSequence()
                .filter { SET_ACTIVITY_CALL.containsMatchIn(it) && !it.contains("fun setActivity(") }
                .forEach { bypasses += "$name: calls setActivity: ${it.trim()}" }
        }
        assertEquals("prompt lookups that bypass the tracker", emptyList<String>(), bypasses)

        val application = sources.single { it.name == "XKeyApplication.kt" }.readText()
        assertTrue(
            "the application must register the tracker",
            application.contains("registerActivityLifecycleCallbacks(PromptActivityTracker)")
        )
    }

    /**
     * A dialog answer awaited by hand settles only on its buttons, and a host
     * destroyed under it leaves the caller waiting forever. Every such wait
     * goes through the one host-bound choke point.
     */
    @Test
    fun everyDialogAnswerWaitIsBoundToItsHost() {
        val bypasses = mainSources()
            .filter { it.name != "HostBoundDialog.kt" }
            .filter {
                val text = it.readText()
                text.contains("suspendCancellableCoroutine") && text.contains("AlertDialog")
            }
            .map { "${it.name}: awaits a dialog answer outside awaitHostedAnswer" }
        assertEquals("dialog waits not bound to their host", emptyList<String>(), bypasses)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun <T : FragmentActivity> launch(type: Class<T>): ActivityController<T> =
        Robolectric.buildActivity(type).setup().also { controllers += it }

    @OptIn(ExperimentalCoroutinesApi::class)
    private fun askToPair(): Deferred<Boolean> {
        val service = Robolectric.buildService(XKeyGattService::class.java).get()
        // Unconfined runs the call on this thread up to its switch to the main
        // dispatcher; idling the main looper then raises the dialog.
        val answer = CoroutineScope(Dispatchers.Unconfined).async {
            service.onPairingConfirmationRequired("Test Laptop", "abcd1234")
        }
        idle()
        return answer
    }

    private fun shownDialog(): AlertDialog {
        val dialog = ShadowDialog.getLatestDialog()
        assertNotNull("the pairing prompt never appeared", dialog)
        assertTrue("the pairing prompt must be showing", dialog.isShowing)
        return dialog as AlertDialog
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    private fun completed(answer: Deferred<Boolean>): Boolean {
        assertTrue("the prompt's answer never reached the caller", answer.isCompleted)
        return answer.getCompleted()
    }

    private fun idle() = shadowOf(Looper.getMainLooper()).idle()

    private fun mainSources(): List<File> {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        return root.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
    }

    /** A screen with the app theme, which the Material dialog needs. */
    open class HostActivity : FragmentActivity() {
        override fun onCreate(savedInstanceState: Bundle?) {
            setTheme(R.style.Theme_xKey)
            super.onCreate(savedInstanceState)
        }
    }

    /** Any screen other than the first, such as OATH or Settings. */
    class OtherScreenActivity : HostActivity()

    private companion object {
        val SET_ACTIVITY_CALL = Regex("""\bsetActivity\(""")
    }
}
