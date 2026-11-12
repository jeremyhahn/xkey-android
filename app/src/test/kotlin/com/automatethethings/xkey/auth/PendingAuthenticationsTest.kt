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
package com.automatethethings.xkey.auth

import androidx.biometric.BiometricPrompt
import com.automatethethings.xkey.auth.BiometricActivityLauncher.BiometricResult
import com.automatethethings.xkey.ui.TransparentBiometricActivity
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every approval prompt is one request the launcher owns, and the id it hands
 * to whatever shows the prompt (its own activity launch, or the lock-screen
 * notification's full-screen intent) is the id the result broadcast must
 * carry to reach the waiting caller.
 *
 * There is one screen, and the prompt activity shows one request: requests
 * take turns on it, the next launched only once the one before it settles,
 * and a request still waiting for its turn when its deadline passes settles
 * with a timeout instead of waiting forever.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PendingAuthenticationsTest {

    /** The screen these requests take turns on; each test gets its own. */
    private val screen = SigningPromptQueue()

    private val pending = PendingAuthentications(screen)

    /** The ids handed to the prompts, in launch order. */
    private val launched = mutableListOf<String>()

    @Test
    fun anApprovalCarryingTheLaunchedIdCompletesTheRequest() = runTest {
        val waiting = async { pending.await { launched += it } }
        runCurrent()

        assertTrue(pending.complete(launched.single(), BiometricResult.Success))
        runCurrent()

        assertEquals(BiometricResult.Success, waiting.await())
    }

    @Test
    fun aCancelCarryingTheLaunchedIdCompletesTheRequestWithTheCancel() = runTest {
        val waiting = async { pending.await { launched += it } }
        runCurrent()

        val cancel = BiometricResult.Error(BiometricPrompt.ERROR_USER_CANCELED, "cancelled")
        assertTrue(pending.complete(launched.single(), cancel))

        assertEquals(cancel, waiting.await())
    }

    @Test
    fun aResultForAnIdTheLauncherNeverIssuedCompletesNothing() = runTest {
        val waiting = async { pending.await { launched += it } }
        runCurrent()

        assertFalse(pending.complete("set-key-policy-178", BiometricResult.Success))
        assertFalse(pending.complete("", BiometricResult.Success))
        assertFalse(waiting.isCompleted)

        assertTrue(pending.complete(launched.single(), BiometricResult.Success))
        waiting.await()
    }

    @Test
    fun twoLaunchersNeverIssueTheSameId() = runTest {
        val other = PendingAuthentications(SigningPromptQueue())
        val first = async { pending.await { launched += it } }
        val second = async { other.await { launched += it } }
        runCurrent()

        assertNotEquals(launched[0], launched[1])
        // Each launcher answers only the request it issued.
        assertFalse(other.complete(launched[0], BiometricResult.Success))
        assertTrue(pending.complete(launched[0], BiometricResult.Success))
        assertTrue(other.complete(launched[1], BiometricResult.Success))
        first.await()
        second.await()
    }

    @Test
    fun aCancelledCallerWithdrawsItsRequest() = runTest {
        val waiting = async { pending.await { launched += it } }
        runCurrent()

        waiting.cancel()
        runCurrent()

        assertTrue(waiting.isCancelled)
        assertFalse(pending.complete(launched.single(), BiometricResult.Success))
    }

    @Test
    fun aPromptThatCannotLaunchFailsTheRequestAndLeavesNothingPending() = runTest {
        val failure = IllegalStateException("no activity")
        val waiting = async {
            runCatching { pending.await { launched += it; throw failure } }
        }
        runCurrent()

        // Compared by type and message: coroutines may hand back a copy
        // carrying the recovered stack trace.
        val thrown = waiting.await().exceptionOrNull()
        assertEquals(IllegalStateException::class, thrown?.let { it::class })
        assertEquals(failure.message, thrown?.message)
        assertFalse(pending.complete(launched.single(), BiometricResult.Success))
    }

    @Test
    fun aRequestArrivingWhileAnotherPromptsIsLaunchedOnlyAfterItSettles() = runTest {
        val first = async { pending.await { launched += it } }
        val second = async { pending.await { launched += it } }
        runCurrent()

        assertEquals("one prompt on screen", 1, launched.size)
        assertTrue(pending.complete(launched[0], BiometricResult.Success))
        runCurrent()
        assertEquals(BiometricResult.Success, first.await())

        assertEquals("the next comes up once the first settles", 2, launched.size)
        assertNotEquals(launched[0], launched[1])
        assertTrue(pending.complete(launched[1], BiometricResult.Success))
        assertEquals(BiometricResult.Success, second.await())
    }

    @Test
    fun aCancelAnswersOnlyTheRequestOnScreenAndBringsUpTheNext() = runTest {
        val first = async { pending.await { launched += it } }
        val second = async { pending.await { launched += it } }
        val third = async { pending.await { launched += it } }
        runCurrent()

        val cancel = BiometricResult.Error(BiometricPrompt.ERROR_USER_CANCELED, "cancelled")
        assertTrue(pending.complete(launched[0], cancel))
        runCurrent()
        assertEquals(cancel, first.await())
        assertEquals(2, launched.size)

        assertTrue(pending.complete(launched[1], BiometricResult.Success))
        runCurrent()
        assertEquals(BiometricResult.Success, second.await())

        assertTrue(pending.complete(launched[2], cancel))
        assertEquals(cancel, third.await())
    }

    @Test
    fun aQueuedRequestPastItsDeadlineTimesOutUnseenAndLeavesTheScreenAlone() = runTest {
        val onScreen = async { pending.await { launched += it } }
        val queued = async { pending.await(queueDeadlineMillis = 1_000L) { launched += it } }
        runCurrent()

        advanceTimeBy(1_001L)
        runCurrent()

        val timedOut = queued.await()
        assertTrue("a queued request settles", timedOut is BiometricResult.Error)
        assertEquals(BiometricPrompt.ERROR_TIMEOUT, (timedOut as BiometricResult.Error).code)
        assertEquals("it never prompts", 1, launched.size)
        assertTrue("the request on screen keeps waiting", onScreen.isActive)

        assertTrue(pending.complete(launched[0], BiometricResult.Success))
        assertEquals(BiometricResult.Success, onScreen.await())
        assertEquals(1, launched.size)
    }

    @Test
    fun theDefaultQueueDeadlineIsFiniteAndOutlastsThePromptsOwnTimeout() {
        assertTrue(PendingAuthentications.QUEUE_DEADLINE_MILLIS in 30_001L..300_000L)
    }

    @Test
    fun theActiveDeadlineOutlastsTheNotificationAndFallsInsideTheQueueDeadline() {
        assertTrue(PendingAuthentications.ACTIVE_DEADLINE_MILLIS in 30_001L until UNSEEN_MILLIS)
        assertTrue(UNSEEN_MILLIS < PendingAuthentications.QUEUE_DEADLINE_MILLIS)
    }

    @Test
    fun aCallerCancelledWhileQueuedNeverPromptsAndKeepsItsPlaceForNobody() = runTest {
        val first = async { pending.await { launched += it } }
        val withdrawn = async { pending.await { launched += it } }
        val third = async { pending.await { launched += it } }
        runCurrent()

        withdrawn.cancel()
        runCurrent()
        assertTrue(pending.complete(launched[0], BiometricResult.Success))
        runCurrent()
        first.await()

        assertEquals("the withdrawn request is skipped", 2, launched.size)
        assertTrue(pending.complete(launched[1], BiometricResult.Success))
        third.await()
    }

    @Test
    fun aRequestWithdrawnOnScreenHandsTheScreenOn() = runTest {
        val first = async { pending.await { launched += it } }
        val second = async { pending.await { launched += it } }
        runCurrent()

        first.cancel()
        runCurrent()

        assertEquals(2, launched.size)
        assertFalse(pending.complete(launched[0], BiometricResult.Success))
        assertTrue(pending.complete(launched[1], BiometricResult.Success))
        second.await()
    }

    @Test
    fun twoLaunchersOnOneScreenTakeTurns() = runTest {
        val other = PendingAuthentications(screen)
        val first = async { pending.await { launched += it } }
        val second = async { other.await { launched += it } }
        runCurrent()

        assertEquals(1, launched.size)
        assertTrue(pending.complete(launched[0], BiometricResult.Success))
        runCurrent()
        first.await()
        assertTrue(other.complete(launched[1], BiometricResult.Success))
        second.await()
    }

    @Test
    fun aPromptThatCannotLaunchHandsTheScreenOn() = runTest {
        val failing = async {
            runCatching { pending.await { launched += it; throw IllegalStateException("no activity") } }
        }
        val next = async { pending.await { launched += it } }
        runCurrent()

        assertNull(failing.await().getOrNull())
        assertEquals(2, launched.size)
        assertTrue(pending.complete(launched[1], BiometricResult.Success))
        next.await()
    }

    @Test
    fun onlyANewerRequestDisplacesThePromptOnScreen() {
        assertTrue(TransparentBiometricActivity.isNewer("8", "7"))
        assertFalse("a repeat delivery keeps its prompt", TransparentBiometricActivity.isNewer("7", "7"))
        assertFalse("a late older delivery is dropped", TransparentBiometricActivity.isNewer("6", "7"))
        assertFalse(TransparentBiometricActivity.isNewer("set-key-policy", "7"))
        assertTrue(
            "a launcher request displaces a wake-only prompt that answers none",
            TransparentBiometricActivity.isNewer("8", "verifyUser-3")
        )
        assertFalse(TransparentBiometricActivity.isNewer("verifyUser-9", "verifyUser-3"))
    }

    @Test
    fun aLaunchedRequestWhosePromptNeverComesUpTimesOutAndHandsTheScreenOn() = runTest {
        // Android blocked the start and nothing else (no notification, no
        // expiry callback) will ever answer it.
        val unseen = PendingAuthentications(screen, expirePrompt = { true })
        val blocked = async { unseen.await { launched += it } }
        val next = async { unseen.await { launched += it } }
        runCurrent()
        assertEquals(1, launched.size)

        advanceTimeBy(UNSEEN_MILLIS)
        runCurrent()

        assertTrue("the unseen request settles on its own", blocked.isCompleted)
        val timedOut = blocked.await()
        assertEquals(BiometricPrompt.ERROR_TIMEOUT, (timedOut as BiometricResult.Error).code)
        assertEquals("the next request gets the screen", 2, launched.size)
        assertTrue(unseen.complete(launched[1], BiometricResult.Success))
        assertEquals(BiometricResult.Success, next.await())
    }

    @Test
    fun aLaunchedRequestWhosePromptIsUpKeepsWaitingPastTheDeadline() = runTest {
        val answering = PendingAuthentications(screen, expirePrompt = { false })
        val onScreen = async { answering.await { launched += it } }
        runCurrent()

        advanceTimeBy(UNSEEN_MILLIS)
        runCurrent()

        assertTrue("the owner is answering it", onScreen.isActive)
        assertTrue(answering.complete(launched.single(), BiometricResult.Success))
        assertEquals(BiometricResult.Success, onScreen.await())
    }

    @Test
    fun cancelAllCancelsEveryWaitingCaller() = runTest {
        val first = async { pending.await { launched += it } }
        val second = async { pending.await { launched += it } }
        runCurrent()

        pending.cancelAll()
        runCurrent()

        assertTrue(first.isCancelled)
        assertTrue("a request waiting for its turn is cancelled too", second.isCancelled)
        assertEquals("and never prompts", 1, launched.size)
    }

    private companion object {
        /** Past any launched request's own deadline, inside a queued one's. */
        const val UNSEEN_MILLIS = 90_000L
    }
}
