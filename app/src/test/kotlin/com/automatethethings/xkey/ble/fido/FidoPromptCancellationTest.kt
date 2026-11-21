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

package com.automatethethings.xkey.ble.fido

import android.app.Application
import android.content.Intent
import android.os.Looper
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.auth.PromptOwnership
import com.automatethethings.xkey.testing.ReleaseMocks
import com.automatethethings.xkey.ui.TransparentBiometricActivity
import io.mockk.every
import io.mockk.just
import io.mockk.mockkObject
import io.mockk.runs
import io.mockk.unmockkAll
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.ExecutorCoroutineDispatcher
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors

/**
 * A BLE ceremony cancelled (CTAP CANCEL or the client disconnecting, which
 * both cancel the session's job) with its prompt on screen, through the real
 * launcher and [TransparentBiometricActivity]. The session runs off the main
 * thread, as BLE sessions do, so the prompt's dismissal has to reach the main
 * thread before the screen is handed to the next approval.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class)
class FidoPromptCancellationTest {

    /** Drops what MockK recorded here, so it does not outlive the test. */
    @get:Rule
    val releaseMocks = ReleaseMocks()

    private lateinit var app: Application
    private lateinit var launcher: BiometricActivityLauncher
    private lateinit var session: ExecutorCoroutineDispatcher
    private lateinit var scope: CoroutineScope

    /** The prompt on screen when the next request launched, as it was then. */
    private val shownAtNextLaunch = ConcurrentLinkedQueue<Pair<String, Boolean>>()
    private var onScreen: ActivityController<TransparentBiometricActivity>? = null

    /** Records, as each request launches, whether the prompt on screen has gone. */
    private inner class RecordingLockScreen : FidoLockScreen {
        override val locked = true
        override fun post(operationType: String, rpId: String, key: String, prompt: Intent, onTimeout: () -> Unit) {
            onScreen?.let { shownAtNextLaunch += rpId to it.get().isFinishing }
        }
        override fun cancel(key: String) {}
    }

    @Before
    fun setUp() {
        app = RuntimeEnvironment.getApplication()
        mockkObject(AuditLogger)
        every { AuditLogger.logBiometricSuccess(any()) } just runs
        every { AuditLogger.logBiometricFailure(any(), any()) } just runs
        launcher = BiometricActivityLauncher(app).also { it.register() }
        session = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
        scope = CoroutineScope(SupervisorJob() + session)
    }

    @After
    fun tearDown() {
        scope.cancel()
        launcher.unregister()
        idleUntil { PromptOwnership.process.entries == 0 }
        session.close()
        unmockkAll()
    }

    /** Runs the main looper, as Android would, until [done] or a bounded wait passes. */
    private fun idleUntil(done: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + 5_000
        while (!done()) {
            if (System.currentTimeMillis() > deadline) return false
            shadowOf(Looper.getMainLooper()).idle()
            Thread.sleep(5)
        }
        shadowOf(Looper.getMainLooper()).idle()
        return true
    }

    private fun nextStart(): Intent {
        var started: Intent? = null
        assertTrue("a prompt was started", idleUntil { shadowOf(app).nextStartedActivity?.also { started = it } != null })
        assertEquals(TransparentBiometricActivity::class.java.name, started!!.component?.className)
        return started!!
    }

    private fun open(prompt: Intent): ActivityController<TransparentBiometricActivity> =
        Robolectric.buildActivity(TransparentBiometricActivity::class.java, prompt).setup()
            .also { onScreen = it }

    private fun verify(rpId: String, registering: Boolean): Deferred<UserCheck> = scope.async {
        BiometricFidoUserPrompt(app, RecordingLockScreen()) { launcher }.verify(rpId, registering)
    }

    private fun cancelledShownPromptIsDismissedBeforeTheNext(registering: Boolean) {
        val first = verify("first.example", registering)
        val firstScreen = open(nextStart())
        val second = verify("second.example", registering)
        assertTrue("the second request waits its turn", idleUntil { PromptOwnership.process.entries == 2 })
        assertNull("only one prompt is started", shadowOf(app).nextStartedActivity)

        // CTAP CANCEL and a disconnect both cancel the session's job.
        first.cancel()

        val secondStart = nextStart()
        assertEquals(
            "the cancelled prompt was gone before the next one launched",
            listOf("second.example" to true),
            shownAtNextLaunch.toList()
        )
        assertTrue("the cancelled prompt goes away", firstScreen.get().isFinishing)
        assertTrue(idleUntil { first.isCompleted })
        assertTrue(runCatching { first.getCompleted() }.exceptionOrNull() is CancellationException)

        open(secondStart).get().promptCallback!!.onAuthenticationSucceeded(io.mockk.mockk(relaxed = true))
        assertTrue(idleUntil { second.isCompleted })
        assertEquals(UserCheck.VERIFIED, second.getCompleted())
    }

    @Test
    fun `a registration cancelled with its prompt up dismisses it before the next approval launches`() =
        cancelledShownPromptIsDismissedBeforeTheNext(registering = true)

    @Test
    fun `an assertion cancelled with its prompt up dismisses it before the next approval launches`() =
        cancelledShownPromptIsDismissedBeforeTheNext(registering = false)

    @Test
    fun `a cancelled prompt answers nothing`() {
        val first = verify("first.example", registering = false)
        val screen = open(nextStart())
        first.cancel()
        assertTrue(idleUntil { first.isCompleted })
        assertTrue("the cancelled prompt goes away", screen.get().isFinishing)
        assertNotNull(screen.get().promptCallback)
        assertEquals(
            "no result is broadcast for a withdrawn prompt",
            0,
            shadowOf(app).broadcastIntents.count { it.action == TransparentBiometricActivity.ACTION_BIOMETRIC_RESULT }
        )
    }
}
