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

import com.automatethethings.xkey.auth.PromptOwnership.Event
import com.automatethethings.xkey.auth.PromptOwnership.Kind
import com.automatethethings.xkey.auth.PromptOwnership.Outcome
import com.automatethethings.xkey.auth.PromptOwnership.Refusal
import com.automatethethings.xkey.auth.PromptOwnership.State
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
}
