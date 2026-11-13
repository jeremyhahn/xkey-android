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

import android.content.Intent
import android.util.Log
import androidx.annotation.VisibleForTesting
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * The owner of the one prompt queue: every approval, of either prompt family,
 * holds exactly one entry in it from [enqueue] to its settle, and the entry is
 * released exactly once, when it settles.
 *
 * There is one screen and the system shows one biometric authentication at a
 * time, so one approval is ACTIVE at a time, whatever its connection; the rest
 * are QUEUED in arrival order. An approval goes
 *
 * - QUEUED to ACTIVE when its turn comes ([enqueue]'s `onActive` then
 *   launches its prompt or notification);
 * - QUEUED to SETTLED expired when its turn has not come within the queue
 *   deadline every [enqueue] arms ([enqueue]'s `onQueueExpired` then takes
 *   its caller's cancel path, and `onActive` never runs);
 * - QUEUED or ACTIVE to SETTLED by its owner ([settle] with no event:
 *   the queue deadline, a launch failure; [end]: a withdrawal);
 * - ACTIVE to SETTLED by an intent naming it ([settle] with its [Event]: the
 *   activity result, the deadline, the notification's expiry).
 *
 * An intent for a key that is not ACTIVE, and a second settle, are refused,
 * reported, and change nothing. Keys are the notification keys
 * ([NotificationKeys.approval], [NotificationKeys.signature]), unique across
 * both families.
 *
 * Callbacks (`onActive`, `onQueueExpired`, `beforeNext`) run outside the lock.
 *
 * @param report learns every refusal
 */
internal class PromptOwnership(
    private val report: (Refusal) -> Unit = {},
) {
    enum class State { QUEUED, ACTIVE, SETTLED }

    /** What an approval asks for; the queue treats every kind alike. */
    enum class Kind { GENERIC, CRYPTO_SIGNING, KEY_GENERATION, SHARING_APPROVAL }

    enum class Outcome { APPROVED, DENIED, FAILED, EXPIRED, WITHDRAWN }

    /** An intent that names an approval from outside its owner; only an ACTIVE one accepts it. */
    enum class Event { ACTIVITY_RESULT, NOTIFICATION_TAP, NOTIFICATION_EXPIRY, DEADLINE }

    /** [event] (null for an owner's settle) refused for [key], which was in [state] (null: unknown). */
    data class Refusal(val key: String, val event: Event?, val state: State?)

    private class Entry(
        val key: String,
        val kind: Kind,
        val connection: String?,
        val onQueueExpired: () -> Unit,
        val onActive: () -> Unit,
    ) {
        /** The queue deadline's clock while QUEUED; cancelled once it is ACTIVE or settled. */
        @Volatile
        var deadline: Job? = null
    }

    /** QUEUED and ACTIVE entries, in arrival order. */
    private val open = LinkedHashMap<String, Entry>()
    private var active: Entry? = null

    /** Settled keys, newest last, bounded: a key forgotten here is unknown, and refused alike. */
    private val settled = LinkedHashMap<String, Outcome>()

    /** Entries held: QUEUED and ACTIVE approvals. */
    val entries: Int @Synchronized get() = open.size

    val activeKey: String? @Synchronized get() = active?.key

    /**
     * Takes one entry for [key], ACTIVE now when nothing is, otherwise QUEUED
     * behind the entries ahead of it. [onActive] runs once, when it becomes
     * ACTIVE, and never for an approval settled while QUEUED.
     *
     * Every entry waits at most [queueDeadlineMillis] for its turn, timed on
     * [clock] (the caller's scope or dispatcher, so a test's virtual time
     * runs it): one still QUEUED then settles [Outcome.EXPIRED], raises
     * nothing, and [onQueueExpired] runs once, its caller's cancel path. A
     * turn that comes as the deadline passes goes one way only: ACTIVE, or
     * expired and handed straight on. Neither the clock nor the expiry path
     * has a default, so no caller can enqueue without them.
     *
     * @throws IllegalStateException if [key] was enqueued before
     */
    fun enqueue(
        key: String,
        kind: Kind = Kind.GENERIC,
        connection: String? = null,
        clock: CoroutineScope,
        queueDeadlineMillis: Long = PendingAuthentications.QUEUE_DEADLINE_MILLIS,
        onQueueExpired: () -> Unit,
        onActive: () -> Unit,
    ) {
        val entry = Entry(key, kind, connection, onQueueExpired, onActive)
        val activeNow = synchronized(this) {
            check(key !in open && key !in settled) { "Approval $key already owns a queue entry" }
            open[key] = entry
            if (active == null) {
                active = entry
                true
            } else {
                false
            }
        }
        if (activeNow) {
            entry.onActive()
            return
        }
        val deadline = clock.launch {
            delay(queueDeadlineMillis)
            expireQueued(entry)
        }
        // Its turn may have come (or it settled) before the clock was set.
        val stillQueued = synchronized(this) {
            (open[key] === entry && active !== entry).also { if (it) entry.deadline = deadline }
        }
        if (!stillQueued) deadline.cancel()
    }

    /** Settles [entry] expired if it is still QUEUED, then takes its caller's cancel path. */
    private fun expireQueued(entry: Entry) {
        synchronized(this) {
            if (open[entry.key] !== entry || active === entry) return
            open.remove(entry.key)
            settledLocked(entry.key, Outcome.EXPIRED)
            entry.deadline = null
        }
        entry.onQueueExpired()
    }

    /**
     * Holds an entry for [key] across [prompt], for a prompt no launcher
     * request owns: an activity-bound `BiometricPrompt`, `local.verifyUser`'s
     * prompt, and the wake-only notification each posts. [prompt] runs only
     * once [key] is ACTIVE, so it raises nothing while another approval holds
     * the screen; its key is a [NotificationKeys.wakeOnly] key, which
     * `TransparentBiometricActivity` shows a prompt for only while ACTIVE.
     *
     * However [prompt] ends (returns, throws, is cancelled) the entry settles
     * and the screen goes to the next. A turn that has not come within
     * [queueDeadlineMillis] settles expired, runs nothing and returns null.
     */
    suspend fun <T> turn(
        key: String,
        kind: Kind = Kind.GENERIC,
        queueDeadlineMillis: Long = PendingAuthentications.QUEUE_DEADLINE_MILLIS,
        prompt: suspend () -> T,
    ): T? = coroutineScope {
        val turnCame = CompletableDeferred<Boolean>()
        enqueue(
            key,
            kind,
            clock = this,
            queueDeadlineMillis = queueDeadlineMillis,
            onQueueExpired = { turnCame.complete(false) },
        ) { turnCame.complete(true) }
        var outcome = Outcome.WITHDRAWN
        var expired = false
        try {
            if (!turnCame.await()) {
                // Settled expired by the queue deadline already.
                expired = true
                null
            } else {
                outcome = Outcome.FAILED
                prompt().also { outcome = Outcome.APPROVED }
            }
        } catch (e: CancellationException) {
            outcome = Outcome.WITHDRAWN
            throw e
        } finally {
            if (!expired) settle(key, outcome)
        }
    }

    @Synchronized
    fun state(key: String): State? = stateLocked(key)

    /** How [key] settled; null while it is open or unknown. */
    @Synchronized
    fun outcome(key: String): Outcome? = settled[key]

    /** Whether [key] holds a queue entry. */
    @Synchronized
    fun holds(key: String): Boolean = key in open

    /** True when [key] is ACTIVE, so [event] may act on it; otherwise refused and reported. */
    fun accept(key: String, event: Event): Boolean {
        val refusal = synchronized(this) {
            if (active?.key == key) return true
            Refusal(key, event, stateLocked(key))
        }
        report(refusal)
        return false
    }

    /**
     * Settles [key] with [outcome] and releases its entry; if it was ACTIVE,
     * the next QUEUED approval becomes ACTIVE, after [beforeNext]. With an
     * [event] it must be ACTIVE; without one (its owner's own settle) QUEUED
     * or ACTIVE. False, reported, and nothing changed otherwise.
     */
    fun settle(
        key: String,
        outcome: Outcome,
        event: Event? = null,
        beforeNext: (wasActive: Boolean) -> Unit = {},
    ): Boolean {
        val refusal = synchronized(this) {
            val legal = if (event == null) key in open else active?.key == key
            if (legal) null else Refusal(key, event, stateLocked(key))
        }
        if (refusal != null) {
            report(refusal)
            return false
        }
        return release(key, outcome, beforeNext)
    }

    /**
     * Settles ACTIVE [key] by its [event], [Event.DEADLINE] as failed and
     * [Event.NOTIFICATION_EXPIRY] as expired; refused like [settle].
     */
    fun expire(key: String, event: Event): Boolean =
        settle(key, if (event == Event.DEADLINE) Outcome.FAILED else Outcome.EXPIRED, event)

    /**
     * The owner's own exit: settles [key] as withdrawn if it still holds its
     * entry. False, and nothing reported, when it has settled already.
     */
    fun end(key: String, beforeNext: (wasActive: Boolean) -> Unit = {}): Boolean =
        release(key, Outcome.WITHDRAWN, beforeNext)

    /** Releases [key]'s entry exactly once; false when it holds none. */
    private fun release(key: String, outcome: Outcome, beforeNext: (wasActive: Boolean) -> Unit): Boolean {
        val wasActive: Boolean
        val next: Entry?
        val stopped: List<Job>
        synchronized(this) {
            val entry = open.remove(key) ?: return false
            settledLocked(key, outcome)
            wasActive = active === entry
            next = if (wasActive) open.values.firstOrNull() else null
            if (wasActive) active = next
            stopped = listOfNotNull(entry.deadline, next?.deadline)
            entry.deadline = null
            next?.deadline = null
        }
        // Off the queue: neither clock may expire it now.
        stopped.forEach { it.cancel() }
        beforeNext(wasActive)
        next?.onActive()
        return true
    }

    private fun settledLocked(key: String, outcome: Outcome) {
        settled[key] = outcome
        while (settled.size > MAX_SETTLED) settled.remove(settled.keys.first())
    }

    /** Forgets the settled keys, as a freshly started process has none; open entries stay. */
    @VisibleForTesting
    @Synchronized
    fun forgetSettled() = settled.clear()

    private fun stateLocked(key: String): State? = when {
        active?.key == key -> State.ACTIVE
        key in open -> State.QUEUED
        key in settled -> State.SETTLED
        else -> null
    }

    companion object {
        /** Settled keys remembered; an older one is unknown, refused all the same. */
        private const val MAX_SETTLED = 256

        /** The one screen every launcher in the process prompts on. */
        val process = PromptOwnership(report = { refusal ->
            // A JVM test without Android's logger still runs the process owner.
            runCatching { Log.w("PromptOwnership", "Refused $refusal") }
        })

        /** The queue key an activity started from outside the app (a Credential Manager pending intent) enqueues under. */
        const val EXTRA_PROMPT_KEY = "com.automatethethings.xkey.auth.PROMPT_KEY"

        /**
         * Marks [intent], for an activity the system starts later, with a fresh
         * [NotificationKeys.wakeOnly] key for [operation]. The activity takes
         * its queue entry under that key ([promptKey]) and prompts only on
         * its turn, never over an ACTIVE approval.
         */
        fun queued(intent: Intent, operation: String): Intent =
            intent.putExtra(EXTRA_PROMPT_KEY, NotificationKeys.wakeOnly(operation))

        /**
         * The key [intent] was [queued] under, or a fresh one for [operation]
         * when it carries none or its key already took an entry (a relaunch).
         */
        fun promptKey(intent: Intent?, operation: String): String =
            intent?.getStringExtra(EXTRA_PROMPT_KEY)
                ?.takeIf { process.state(it) == null && process.outcome(it) == null }
                ?: NotificationKeys.wakeOnly(operation)
    }
}
