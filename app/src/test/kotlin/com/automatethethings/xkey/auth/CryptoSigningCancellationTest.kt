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

package com.automatethethings.xkey.auth

import androidx.biometric.BiometricPrompt
import com.automatethethings.xkey.auth.BiometricActivityLauncher.CryptoSigningResult
import com.automatethethings.xkey.ui.CryptoSigningController
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64
import java.util.concurrent.Executor

/**
 * A cancelled signing request takes its prompt down, and a touch that lands
 * anyway signs nothing.
 *
 * This drives the real [PendingCryptoSignatures], the real cancellation
 * registry and the real [CryptoSigningController] the activity runs on. Only
 * the activity's Android edges are stand-ins: the biometric prompt, the main
 * thread, `finish()`, and the result broadcast, which here completes the
 * launcher's pending request exactly as its receiver does.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CryptoSigningCancellationTest {

    /** Its own line of prompts, so no other test's request can hold the screen. */
    private val pending = PendingCryptoSignatures(prompts = SigningPromptQueue())

    /** The activities launched, by request id. */
    private val activities = LinkedHashMap<String, FakeActivity>()

    // -----------------------------------------------------------------
    // A cancelled request
    // -----------------------------------------------------------------

    @Test
    fun cancellingTheRequestCancelsItsPromptAndFinishesWithoutAResult() = runTest {
        val waiting = async { pending.await(::launchActivity) }
        runCurrent()
        val activity = activities.values.single()

        waiting.cancel()
        runCurrent()
        activity.mainThread.drain()

        assertTrue(waiting.isCancelled)
        assertEquals("the prompt is cancelled", 1, activity.prompt.cancellations)
        assertTrue("the activity finishes", activity.finished)
        assertNull("nothing is delivered", activity.delivered)
    }

    /** The user's touch racing the revocation: the key is never used. */
    @Test
    fun aSuccessAfterTheCancelSignsAndDeliversNothing() = runTest {
        val waiting = async { pending.await(::launchActivity) }
        runCurrent()
        val activity = activities.values.single()
        waiting.cancel()
        runCurrent()

        // The success callback can run before the posted cancel does.
        activity.authenticate()
        activity.mainThread.drain()

        assertEquals("the key is not used", 0, activity.signings)
        assertNull("nothing is delivered", activity.delivered)
        assertTrue(activity.finished)
    }

    /** A cancel landing while the key signs drops the signature. */
    @Test
    fun aCancelWhileSigningDropsTheSignature() = runTest {
        val waiting = async { pending.await(::launchActivity) }
        runCurrent()
        val activity = activities.values.single()
        activity.duringSigning = { waiting.cancel() }

        activity.authenticate()
        runCurrent()
        activity.mainThread.drain()

        assertEquals(1, activity.signings)
        assertNull("the signature is dropped", activity.delivered)
        assertTrue(waiting.isCancelled)
    }

    /** An error after the cancel is not delivered either. */
    @Test
    fun anErrorAfterTheCancelDeliversNothing() = runTest {
        val waiting = async { pending.await(::launchActivity) }
        runCurrent()
        val activity = activities.values.single()
        waiting.cancel()
        runCurrent()

        activity.controller.fail(ERROR_CODE, "Authentication error")
        activity.mainThread.drain()

        assertNull(activity.delivered)
    }

    /** Cancelled before the activity came up: it finishes without prompting. */
    @Test
    fun aCancelBeforeTheActivityComesUpMeansNoPrompt() = runTest {
        var launchedId: String? = null
        val waiting = async { pending.await { launchedId = it } }
        runCurrent()

        waiting.cancel()
        runCurrent()
        val activity = FakeActivity(launchedId!!)

        assertFalse("the activity must not prompt", activity.controller.start())
        assertTrue(activity.finished)
        activity.authenticate()
        assertEquals(0, activity.signings)
        assertNull(activity.delivered)
    }

    // -----------------------------------------------------------------
    // Cancellation is per request
    // -----------------------------------------------------------------

    @Test
    fun cancellingTheRequestOnScreenBringsUpTheNextAndLeavesItAlone() = runTest {
        val first = async { pending.await(::launchActivity) }
        val second = async { pending.await(::launchActivity) }
        runCurrent()
        val firstActivity = activities.values.single()

        first.cancel()
        runCurrent()
        firstActivity.mainThread.drain()
        val secondActivity = activities.values.last()
        secondActivity.mainThread.drain()

        assertEquals("the next request comes up", 2, activities.size)
        assertEquals(1, firstActivity.prompt.cancellations)
        assertEquals("the other prompt stays up", 0, secondActivity.prompt.cancellations)
        assertFalse(secondActivity.finished)

        secondActivity.authenticate()
        runCurrent()

        assertEquals(CryptoSigningResult.Success(SIGNATURE_BASE64), second.await())
    }

    /** Unregistering the launcher cancels every request; one still waiting never comes up. */
    @Test
    fun cancelAllCancelsEveryPrompt() = runTest {
        val first = async { pending.await(::launchActivity) }
        val second = async { pending.await(::launchActivity) }
        runCurrent()

        pending.cancelAll()
        runCurrent()
        activities.values.forEach { it.mainThread.drain() }

        assertTrue(first.isCancelled)
        assertTrue(second.isCancelled)
        val activity = activities.values.single()
        assertEquals(1, activity.prompt.cancellations)
        assertTrue(activity.finished)
    }

    // -----------------------------------------------------------------
    // Overlapping requests take turns
    // -----------------------------------------------------------------

    /** Two requests at once: one prompt at a time, and both are answered. */
    @Test
    fun twoOverlappingRequestsBothSettleOneAfterTheOther() = runTest {
        val first = async { pending.await(::launchActivity) }
        val second = async { pending.await(::launchActivity) }
        runCurrent()

        assertEquals("one prompt at a time", 1, activities.size)
        val firstActivity = activities.values.single()
        firstActivity.authenticate()
        runCurrent()

        assertEquals(CryptoSigningResult.Success(SIGNATURE_BASE64), first.await())
        assertEquals("the second comes up once the first settles", 2, activities.size)
        val secondActivity = activities.values.last()
        assertFalse(secondActivity.finished)

        secondActivity.controller.fail(ERROR_CODE, "Authentication error")
        runCurrent()

        assertEquals(CryptoSigningResult.Error(ERROR_CODE, "Authentication error"), second.await())
        assertEquals("neither prompt was displaced", 0, firstActivity.prompt.cancellations)
        assertEquals(0, secondActivity.prompt.cancellations)
    }

    /** A request cancelled while it waits for its turn is withdrawn, never shown. */
    @Test
    fun aRequestCancelledWhileItWaitsIsNeverShown() = runTest {
        val first = async { pending.await(::launchActivity) }
        var secondShown = false
        val second = async { pending.await { secondShown = true } }
        runCurrent()

        second.cancel()
        runCurrent()
        val firstActivity = activities.values.single()
        firstActivity.mainThread.drain()

        assertTrue(second.isCancelled)
        assertEquals("the request on screen is left alone", 0, firstActivity.prompt.cancellations)
        assertFalse(firstActivity.finished)

        firstActivity.authenticate()
        runCurrent()
        assertEquals(CryptoSigningResult.Success(SIGNATURE_BASE64), first.await())
        assertFalse("the withdrawn request must never come up", secondShown)

        // The line is not stalled behind the withdrawn request.
        val third = async { pending.await(::launchActivity) }
        runCurrent()
        assertEquals(2, activities.size)
        activities.values.last().authenticate()
        runCurrent()
        assertEquals(CryptoSigningResult.Success(SIGNATURE_BASE64), third.await())
    }

    /** A prompt that cannot be launched settles its request, and the next comes up. */
    @Test
    fun aLaunchThatFailsSettlesItsRequestAndTheNextComesUp() = runTest {
        val first = async { pending.await(::launchActivity) }
        val second = async {
            runCatching { pending.await { throw IllegalStateException("the activity cannot start") } }
        }
        val third = async { pending.await(::launchActivity) }
        runCurrent()

        activities.values.single().authenticate()
        runCurrent()

        assertEquals(CryptoSigningResult.Success(SIGNATURE_BASE64), first.await())
        assertTrue(second.await().exceptionOrNull() is IllegalStateException)
        assertEquals("the third comes up after the failed launch", 2, activities.size)
        activities.values.last().authenticate()
        runCurrent()
        assertEquals(CryptoSigningResult.Success(SIGNATURE_BASE64), third.await())
    }

    // -----------------------------------------------------------------
    // The activity goes away
    // -----------------------------------------------------------------

    /** Swiped away or finished by the system while prompting: refused, and the next comes up. */
    @Test
    fun anActivityGoneForGoodRefusesItsRequestOnce() = runTest {
        val first = async { pending.await(::launchActivity) }
        val second = async { pending.await(::launchActivity) }
        runCurrent()
        val firstActivity = activities.values.single()

        firstActivity.controller.release(recreating = false)
        // The dismissed prompt then reports its own cancel; it is not delivered again.
        firstActivity.controller.fail(ERROR_CODE, "Authentication cancelled")
        runCurrent()

        assertEquals(
            CryptoSigningResult.Error(BiometricPrompt.ERROR_USER_CANCELED, "The signing prompt was closed"),
            first.await()
        )
        assertEquals("the prompt is dismissed", 1, firstActivity.prompt.cancellations)
        assertEquals(2, activities.size)
        activities.values.last().authenticate()
        runCurrent()
        assertEquals(CryptoSigningResult.Success(SIGNATURE_BASE64), second.await())
    }

    /** Recreated for a configuration change: the new instance answers the request. */
    @Test
    fun aRecreatedActivityTakesTheRequestOver() = runTest {
        val waiting = async { pending.await(::launchActivity) }
        runCurrent()
        val old = activities.values.single()

        old.controller.release(recreating = true)
        old.controller.fail(ERROR_CODE, "Authentication cancelled")
        val recreated = FakeActivity(old.controller.requestId)
        assertTrue(recreated.controller.start())
        assertTrue(recreated.controller.attach(recreated.prompt))
        runCurrent()

        assertTrue("nothing settled the request yet", waiting.isActive)
        assertNull(old.delivered)
        recreated.authenticate()
        runCurrent()
        assertEquals(CryptoSigningResult.Success(SIGNATURE_BASE64), waiting.await())
    }

    /** An activity that already answered, or was cancelled, delivers nothing more when it goes. */
    @Test
    fun releasingASettledOrCancelledRequestDeliversNothing() = runTest {
        val answered = async { pending.await(::launchActivity) }
        runCurrent()
        val answeredActivity = activities.values.single()
        answeredActivity.controller.fail(ERROR_CODE, "Authentication error")
        runCurrent()
        answeredActivity.controller.release(recreating = false)
        assertEquals(CryptoSigningResult.Error(ERROR_CODE, "Authentication error"), answered.await())
        assertEquals(1, answeredActivity.deliveries)

        val cancelled = async { pending.await(::launchActivity) }
        runCurrent()
        val cancelledActivity = activities.values.last()
        cancelled.cancel()
        runCurrent()
        cancelledActivity.controller.release(recreating = false)
        cancelledActivity.mainThread.drain()
        assertNull(cancelledActivity.delivered)
    }

    // -----------------------------------------------------------------
    // An uncancelled request
    // -----------------------------------------------------------------

    @Test
    fun anAuthenticatedRequestReturnsItsSignature() = runTest {
        val waiting = async { pending.await(::launchActivity) }
        runCurrent()
        val activity = activities.values.single()

        activity.authenticate()
        runCurrent()

        assertEquals(CryptoSigningResult.Success(SIGNATURE_BASE64), waiting.await())
        assertEquals(1, activity.signings)
        assertEquals(0, activity.prompt.cancellations)
        assertTrue(activity.finished)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /** What `requestCryptoSignature` starts: the activity, up and prompting. */
    private fun launchActivity(requestId: String) {
        val activity = FakeActivity(requestId)
        activities[requestId] = activity
        check(activity.controller.start()) { "a live request must prompt" }
        check(activity.controller.attach(activity.prompt)) { "a live request shows its prompt" }
    }

    private class FakePrompt : CryptoSigningController.Prompt {
        var cancellations = 0
        override fun cancelAuthentication() {
            cancellations++
        }
    }

    /** The main thread: work posted to it runs when the test drains it. */
    private class MainThread : Executor {
        private val queue = ArrayDeque<Runnable>()
        override fun execute(command: Runnable) {
            queue.addLast(command)
        }
        fun drain() {
            while (queue.isNotEmpty()) queue.removeFirst().run()
        }
    }

    /** `CryptoSigningActivity` without Android: its controller, prompt and result. */
    private inner class FakeActivity(requestId: String) {
        val mainThread = MainThread()
        val prompt = FakePrompt()
        var finished = false
        var delivered: CryptoSigningResult? = null
        var deliveries = 0
        var signings = 0
        var duringSigning: () -> Unit = {}

        val controller = CryptoSigningController(
            requestId = requestId,
            mainExecutor = mainThread,
            deliverSuccess = { deliver(requestId, CryptoSigningResult.Success(it)) },
            deliverError = { code, message -> deliver(requestId, CryptoSigningResult.Error(code, message)) },
            finish = { finished = true },
        )

        /** `onAuthenticationSucceeded`: sign with the unlocked key. */
        fun authenticate() = controller.succeed {
            signings++
            duringSigning()
            SIGNATURE
        }

        /** The result broadcast, received by the launcher. */
        private fun deliver(requestId: String, result: CryptoSigningResult) {
            delivered = result
            deliveries++
            pending.complete(requestId.toLong(), result)
        }
    }

    private companion object {
        const val ERROR_CODE = 7
        val SIGNATURE = ByteArray(64) { it.toByte() }
        val SIGNATURE_BASE64: String = Base64.getEncoder().encodeToString(SIGNATURE)
    }
}
