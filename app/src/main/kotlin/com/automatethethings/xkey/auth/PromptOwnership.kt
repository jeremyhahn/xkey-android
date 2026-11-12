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

import android.util.Log
import androidx.annotation.VisibleForTesting

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
 * Callbacks (`onActive`, `beforeNext`) run outside the lock.
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

    private class Entry(val key: String, val kind: Kind, val connection: String?, val onActive: () -> Unit)

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
     * @throws IllegalStateException if [key] was enqueued before
     */
    fun enqueue(key: String, kind: Kind = Kind.GENERIC, connection: String? = null, onActive: () -> Unit) {
        val entry = Entry(key, kind, connection, onActive)
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
        if (activeNow) entry.onActive()
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
        synchronized(this) {
            val entry = open.remove(key) ?: return false
            settled[key] = outcome
            while (settled.size > MAX_SETTLED) settled.remove(settled.keys.first())
            wasActive = active === entry
            next = if (wasActive) open.values.firstOrNull() else null
            if (wasActive) active = next
        }
        beforeNext(wasActive)
        next?.onActive()
        return true
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
    }
}
