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

import com.automatethethings.xkey.auth.BiometricActivityLauncher.BiometricResult
import com.automatethethings.xkey.auth.PromptOwnership.Event
import com.automatethethings.xkey.auth.PromptOwnership.Kind
import com.automatethethings.xkey.auth.PromptOwnership.Outcome
import com.automatethethings.xkey.auth.PromptOwnership.Refusal
import com.automatethethings.xkey.auth.PromptOwnership.State
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every approval owns exactly one entry in the one prompt queue, from enqueue
 * to settle, and once it has settled nothing that names it -- a second
 * settle, a late activity result, notification tap or expiry, its deadline --
 * changes anything.
 */
class PromptOwnershipTest {

    private val refused = mutableListOf<Refusal>()
    private val owner = PromptOwnership(report = { refused += it })

    /** Keys in the order their approvals became ACTIVE. */
    private val activated = mutableListOf<String>()

    private fun enqueue(key: String, kind: Kind = Kind.GENERIC, connection: String? = null) =
        owner.enqueue(key, kind, connection) { activated += key }

    @Test
    fun everyKindHoldsOneEntryWhileQueuedOrActiveAndNoneAfterSettled() {
        val kinds = Kind.values()
        kinds.forEach { enqueue("k-$it", it) }

        assertEquals(kinds.size, owner.entries)
        assertEquals(State.ACTIVE, owner.state("k-${kinds.first()}"))
        kinds.drop(1).forEach { assertEquals(State.QUEUED, owner.state("k-$it")) }
        kinds.forEach { assertTrue(owner.holds("k-$it")) }

        for ((settledSoFar, kind) in kinds.withIndex()) {
            assertTrue(owner.settle("k-$kind", Outcome.APPROVED, Event.ACTIVITY_RESULT))
            assertEquals(State.SETTLED, owner.state("k-$kind"))
            assertFalse(owner.holds("k-$kind"))
            assertEquals(kinds.size - settledSoFar - 1, owner.entries)
        }
        assertEquals(kinds.map { "k-$it" }, activated)
        assertNull(owner.activeKey)
        assertTrue(refused.isEmpty())
    }

    @Test
    fun aCancelAllBetweenTheNextTurnAndItsCallerResumingCancelsItUnlaunchedAndFreesTheQueue() = runTest {
        val requests = PendingAuthentications(owner, expirePrompt = { true })
        val launched = mutableListOf<String>()
        val first = async { requests.await { launched += it } }
        val second = async { requests.await { launched += it } }
        runCurrent()
        assertEquals(1, launched.size)

        // Settling the first makes the second ACTIVE and completes its turn
        // at once; its coroutine is only dispatched, not yet resumed.
        assertTrue(requests.complete(launched.single(), BiometricResult.Success))
        assertEquals(State.ACTIVE, owner.state(NotificationKeys.approval(launchedNext(launched.single()))))
        requests.cancelAll()
        runCurrent()

        assertEquals(BiometricResult.Success, first.await())
        assertTrue("the request whose turn had come is cancelled", second.isCancelled)
        assertEquals("and never launches", 1, launched.size)
        assertEquals("it holds no entry", 0, owner.entries)
        assertNull(owner.activeKey)

        val next = async { requests.await { launched += it } }
        runCurrent()
        assertEquals("the queue is free for the next request", 2, launched.size)
        assertTrue(requests.complete(launched[1], BiometricResult.Success))
        assertEquals(BiometricResult.Success, next.await())
    }

    /** The id allocated after [id]: ids grow by one within a process. */
    private fun launchedNext(id: String) = (id.toLong() + 1).toString()

    @Test
    fun aQueuedApprovalSettledByItsOwnerReleasesItsEntryUnshown() {
        enqueue("a")
        enqueue("b")

        assertTrue(owner.settle("b", Outcome.EXPIRED))
        assertEquals(1, owner.entries)
        assertTrue(owner.settle("a", Outcome.DENIED, Event.ACTIVITY_RESULT))

        assertEquals(listOf("a"), activated)
        assertEquals(0, owner.entries)
    }

    @Test
    fun aSecondSettleIsRefusedAndChangesNothing() {
        enqueue("a")
        enqueue("b")
        assertTrue(owner.settle("a", Outcome.APPROVED, Event.ACTIVITY_RESULT))

        assertFalse(owner.settle("a", Outcome.DENIED))

        assertEquals(State.SETTLED, owner.state("a"))
        assertEquals("b", owner.activeKey)
        assertEquals(1, owner.entries)
        assertEquals(listOf(Refusal("a", null, State.SETTLED)), refused)
    }

    @Test
    fun lateIntentsForASettledApprovalAreEachRefusedAndChangeNothing() {
        enqueue("a")
        enqueue("b")
        assertTrue(owner.settle("a", Outcome.APPROVED, Event.ACTIVITY_RESULT))

        assertFalse(owner.settle("a", Outcome.DENIED, Event.ACTIVITY_RESULT))
        assertFalse(owner.accept("a", Event.NOTIFICATION_TAP))
        assertFalse(owner.settle("a", Outcome.EXPIRED, Event.NOTIFICATION_EXPIRY))
        assertFalse(owner.settle("a", Outcome.FAILED, Event.DEADLINE))

        assertEquals(State.SETTLED, owner.state("a"))
        assertEquals("b", owner.activeKey)
        assertEquals(listOf("a", "b"), activated)
        assertEquals(1, owner.entries)
        assertEquals(
            listOf(Event.ACTIVITY_RESULT, Event.NOTIFICATION_TAP, Event.NOTIFICATION_EXPIRY, Event.DEADLINE)
                .map { Refusal("a", it, State.SETTLED) },
            refused
        )
    }

    @Test
    fun intentsForAQueuedOrUnknownApprovalAreRefused() {
        enqueue("a")
        enqueue("b")

        assertFalse(owner.accept("b", Event.NOTIFICATION_TAP))
        assertFalse(owner.settle("b", Outcome.APPROVED, Event.ACTIVITY_RESULT))
        assertFalse(owner.accept("never", Event.NOTIFICATION_EXPIRY))

        assertEquals(State.QUEUED, owner.state("b"))
        assertEquals(2, owner.entries)
        assertEquals(
            listOf(
                Refusal("b", Event.NOTIFICATION_TAP, State.QUEUED),
                Refusal("b", Event.ACTIVITY_RESULT, State.QUEUED),
                Refusal("never", Event.NOTIFICATION_EXPIRY, null),
            ),
            refused
        )
    }

    @Test
    fun anActiveApprovalWhoseDeadlineFiresSettlesFailedAndTheNextBecomesActive() {
        enqueue("keygen", Kind.KEY_GENERATION)
        enqueue("share", Kind.SHARING_APPROVAL)

        assertTrue(owner.accept("keygen", Event.DEADLINE))
        assertTrue(owner.expire("keygen", Event.DEADLINE))

        assertEquals(Outcome.FAILED, owner.outcome("keygen"))
        assertEquals(State.ACTIVE, owner.state("share"))
        assertEquals(listOf("keygen", "share"), activated)
    }

    @Test
    fun aNotificationExpirySettlesExpired() {
        enqueue("sig", Kind.CRYPTO_SIGNING)

        assertTrue(owner.expire("sig", Event.NOTIFICATION_EXPIRY))

        assertEquals(Outcome.EXPIRED, owner.outcome("sig"))
        assertEquals(0, owner.entries)
    }

    @Test
    fun twoApprovalsOnDifferentConnectionsAreNeverActiveAtOnce() {
        enqueue("one", Kind.SHARING_APPROVAL, connection = "conn-1")
        enqueue("two", Kind.CRYPTO_SIGNING, connection = "conn-2")

        assertEquals(State.ACTIVE, owner.state("one"))
        assertEquals(State.QUEUED, owner.state("two"))
        assertEquals(listOf("one"), activated)

        assertTrue(owner.end("one"))
        assertEquals(Outcome.WITHDRAWN, owner.outcome("one"))
        assertEquals(State.ACTIVE, owner.state("two"))
        assertEquals(listOf("one", "two"), activated)
    }

    @Test
    fun endIsTheOwnersOwnExitAndSettlesNothingTwice() {
        enqueue("a")
        assertTrue(owner.settle("a", Outcome.APPROVED, Event.ACTIVITY_RESULT))

        assertFalse(owner.end("a"))

        assertEquals(Outcome.APPROVED, owner.outcome("a"))
        assertTrue(refused.isEmpty())
    }

    @Test
    fun beforeNextLearnsWhetherTheApprovalWasActiveAndRunsBeforeTheNextActivates() {
        enqueue("a")
        enqueue("b")
        val seen = mutableListOf<String>()

        owner.end("b") { wasActive -> seen += "b:$wasActive" }
        enqueue("c")
        owner.end("a") { wasActive -> seen += "a:$wasActive:${activated.toList()}" }

        assertEquals(listOf("b:false", "a:true:[a]"), seen)
        assertEquals(listOf("a", "c"), activated)
    }

    @Test(expected = IllegalStateException::class)
    fun aKeyIsEnqueuedOnce() {
        enqueue("a")
        owner.settle("a", Outcome.APPROVED, Event.ACTIVITY_RESULT)
        enqueue("a")
    }

    // -----------------------------------------------------------------
    // turn: prompts raised outside a launcher (wake-only notifications)
    // -----------------------------------------------------------------

    @Test
    fun aTurnRunsItsPromptOnlyOnceTheActiveApprovalSettles() = runTest {
        enqueue("approval-1")
        val raised = mutableListOf<String>()

        val wake = async { owner.turn("wake-verifyUser-1") { raised += "wake-verifyUser-1"; "signed" } }
        runCurrent()

        assertEquals(emptyList<String>(), raised)
        assertEquals(State.QUEUED, owner.state("wake-verifyUser-1"))

        owner.settle("approval-1", Outcome.APPROVED)
        assertEquals("signed", wake.await())
        assertEquals(listOf("wake-verifyUser-1"), raised)
        assertEquals(State.SETTLED, owner.state("wake-verifyUser-1"))
        assertEquals(0, owner.entries)
    }

    @Test
    fun aTurnHoldsTheScreenWhileItsPromptIsUp() = runTest {
        val turn = async {
            owner.turn("wake-sign-1") {
                assertEquals(State.ACTIVE, owner.state("wake-sign-1"))
                enqueue("approval-2")
                assertEquals(State.QUEUED, owner.state("approval-2"))
            }
        }
        turn.await()

        assertEquals(State.ACTIVE, owner.state("approval-2"))
        assertEquals(listOf("approval-2"), activated)
    }

    @Test
    fun aTurnWhoseDeadlinePassesRaisesNothingAndLeavesTheQueue() = runTest {
        enqueue("approval-1")
        var raised = false

        val result = owner.turn("wake-sign-2", queueDeadlineMillis = 1_000L) { raised = true }

        assertNull(result)
        assertFalse(raised)
        assertEquals(Outcome.EXPIRED, owner.outcome("wake-sign-2"))
        assertEquals(1, owner.entries)
    }

    @Test
    fun aFailingOrCancelledTurnHandsTheScreenOn() = runTest {
        val failed = runCatching { owner.turn("wake-sign-3") { error("prompt failed") } }
        assertTrue(failed.isFailure)
        assertEquals(Outcome.FAILED, owner.outcome("wake-sign-3"))

        enqueue("approval-1")
        val queued = async { owner.turn("wake-sign-4") { } }
        runCurrent()
        queued.cancel()
        runCurrent()

        assertEquals(Outcome.WITHDRAWN, owner.outcome("wake-sign-4"))
        assertEquals(1, owner.entries)
    }
}
