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
package com.automatethethings.xkey.pin

import android.content.ContentResolver
import android.os.SystemClock
import android.provider.Settings
import java.io.File

/**
 * The time base of the failed-attempt lockout.
 *
 * A lockout is measured on [elapsedRealtime], which the user cannot set, and
 * tied to the boot it was measured in by [bootId]. The wall clock
 * ([currentTimeMillis]) only renders the informational `lockoutUntil`
 * deadline; it never decides whether a secret is locked.
 */
interface LockoutClock {

    /** Milliseconds since boot, deep sleep included (`SystemClock.elapsedRealtime`). */
    fun elapsedRealtime(): Long

    /** An identifier that changes on every boot, or null when none is readable. */
    fun bootId(): String?

    /** Wall-clock epoch milliseconds, for display only. */
    fun currentTimeMillis(): Long
}

/**
 * The device's [LockoutClock]: `SystemClock.elapsedRealtime` and the boot
 * identifier from `Settings.Global.BOOT_COUNT` when a [contentResolver] is
 * given, else the kernel's per-boot `boot_id`.
 *
 * A boot identifier that cannot be read is null; two nulls compare equal, and
 * the lockout then still treats an [elapsedRealtime] that went backwards as a
 * new boot.
 */
class SystemLockoutClock(private val contentResolver: ContentResolver? = null) : LockoutClock {

    override fun elapsedRealtime(): Long = SystemClock.elapsedRealtime()

    override fun currentTimeMillis(): Long = System.currentTimeMillis()

    override fun bootId(): String? = bootCount()?.let { "boot-count:$it" } ?: kernelBootId

    private fun bootCount(): Int? = contentResolver?.let { resolver ->
        runCatching { Settings.Global.getInt(resolver, Settings.Global.BOOT_COUNT) }.getOrNull()
    }

    private companion object {
        /** Constant for the life of the process, which cannot outlive its boot. */
        val kernelBootId: String? by lazy {
            runCatching { File("/proc/sys/kernel/random/boot_id").readText().trim() }
                .getOrNull()
                ?.takeIf { it.isNotEmpty() }
                ?.let { "boot-id:$it" }
        }
    }
}

/**
 * One secret's persisted lockout state.
 *
 * @property failedAttempts Consecutive failures; only a success or a reset clears it.
 * @property remainingMs Lockout time left as of the anchor (0 = none).
 * @property anchorElapsedMs [LockoutClock.elapsedRealtime] when [remainingMs]
 *   was measured, or [PinLockout.UNANCHORED] when it was not measured on this
 *   clock (state migrated from the old epoch deadline).
 * @property anchorBootId [LockoutClock.bootId] of the boot [anchorElapsedMs] belongs to.
 */
data class LockoutState(
    val failedAttempts: Int = 0,
    val remainingMs: Long = 0,
    val anchorElapsedMs: Long = PinLockout.UNANCHORED,
    val anchorBootId: String? = null
)

/**
 * The phone's one failed-attempt lockout rule, shared by every secret it
 * rate-limits: the SO and User PINs ([PinManager]) and the password vault's
 * passphrase ([com.automatethethings.xkey.password.PasswordVault]).
 *
 * - Once a failure brings the consecutive count to `maxAttempts`, that
 *   failure locks for `lockoutDurationSeconds`. With backoff each further
 *   failure doubles the previous lockout, capped at [MAX_LOCKOUT_MS] (or the
 *   base duration when that is longer); without backoff each locks for the
 *   base duration.
 * - With [Policy.permanentBlock], the count reaching [PERMANENT_BLOCK_ATTEMPTS]
 *   (or `maxAttempts`, when that is higher) blocks the secret until it is
 *   reset; no time ends it.
 * - The lockout runs on a monotonic clock ([LockoutClock]): on the boot that
 *   measured it, the time left is the stored remainder less the elapsed
 *   realtime since; on any other boot the stored remainder is resumed whole
 *   and re-anchored. Changing the wall clock neither ends nor extends it.
 */
object PinLockout {

    /** Consecutive failures that block a secret for good when the policy allows. */
    const val PERMANENT_BLOCK_ATTEMPTS = 15

    /** The longest a backed-off lockout grows to: 24 hours. */
    const val MAX_LOCKOUT_MS = 24L * 60 * 60 * 1000

    /** [LockoutState.anchorElapsedMs] of a remainder not measured on the monotonic clock. */
    const val UNANCHORED = -1L

    /**
     * The thresholds a secret is held to.
     *
     * @property maxAttempts Consecutive failures that start the first lockout.
     * @property lockoutDurationSeconds The first lockout's length.
     * @property backoff Whether each later lockout doubles.
     * @property permanentBlock Whether [PERMANENT_BLOCK_ATTEMPTS] blocks for good.
     */
    data class Policy(
        val maxAttempts: Int,
        val lockoutDurationSeconds: Int,
        val backoff: Boolean,
        val permanentBlock: Boolean
    )

    /** The count at which [policy] blocks for good, or null when it never does. */
    fun permanentBlockAt(policy: Policy): Int? =
        if (policy.permanentBlock) maxOf(PERMANENT_BLOCK_ATTEMPTS, policy.maxAttempts) else null

    /** Whether [failedAttempts] blocks the secret for good under [policy]. */
    fun isPermanent(failedAttempts: Int, policy: Policy): Boolean =
        permanentBlockAt(policy)?.let { failedAttempts >= it } ?: false

    /**
     * The lockout a failure that brings the count to [failedAttempts] starts,
     * in milliseconds, or 0 when the count is still under the limit.
     */
    fun lockoutDurationMs(failedAttempts: Int, policy: Policy): Long {
        if (failedAttempts < policy.maxAttempts) return 0L
        val base = policy.lockoutDurationSeconds.coerceAtLeast(0) * 1000L
        if (!policy.backoff) return base
        val cap = maxOf(MAX_LOCKOUT_MS, base)
        var duration = base
        repeat(failedAttempts - policy.maxAttempts) {
            duration = if (duration >= cap / 2) cap else duration * 2
        }
        return duration.coerceAtMost(cap)
    }

    /**
     * The state after one more failure on [state]: a lockout it starts is
     * anchored now on [clock]; a failure under the limit only counts.
     */
    fun recordFailure(state: LockoutState, policy: Policy, clock: LockoutClock): LockoutState {
        val failed = state.failedAttempts + 1
        val duration = lockoutDurationMs(failed, policy)
        if (duration <= 0) return LockoutState(failedAttempts = failed)
        return LockoutState(
            failedAttempts = failed,
            remainingMs = duration,
            anchorElapsedMs = clock.elapsedRealtime(),
            anchorBootId = clock.bootId()
        )
    }

    /** The timed lockout left on [state] now, in milliseconds (0 = not locked). */
    fun remainingMs(state: LockoutState, clock: LockoutClock): Long {
        if (state.remainingMs <= 0) return 0L
        val now = clock.elapsedRealtime()
        val sameBoot = state.anchorElapsedMs != UNANCHORED &&
            state.anchorBootId == clock.bootId() &&
            now >= state.anchorElapsedMs
        if (!sameBoot) return state.remainingMs
        return (state.remainingMs - (now - state.anchorElapsedMs)).coerceAtLeast(0L)
    }

    /** Whether [state] refuses an attempt now: blocked for good, or a timed lockout left. */
    fun isLocked(state: LockoutState, policy: Policy, clock: LockoutClock): Boolean =
        isPermanent(state.failedAttempts, policy) || remainingMs(state, clock) > 0

    /**
     * [state] re-measured now: the time left anchored to the current boot and
     * realtime, so a later boot resumes from here and not from an older anchor.
     */
    fun reanchor(state: LockoutState, clock: LockoutClock): LockoutState =
        state.copy(
            remainingMs = remainingMs(state, clock),
            anchorElapsedMs = clock.elapsedRealtime(),
            anchorBootId = clock.bootId()
        )

    /**
     * The state stored by the old rule, an epoch-millisecond deadline: the
     * time left by the wall clock once, unanchored so it is resumed whole and
     * then runs on the monotonic clock.
     */
    fun migrateLegacy(failedAttempts: Int, legacyLockedUntil: Long, wallNow: Long): LockoutState =
        LockoutState(
            failedAttempts = failedAttempts,
            remainingMs = (legacyLockedUntil - wallNow).coerceAtLeast(0L),
            anchorElapsedMs = UNANCHORED,
            anchorBootId = null
        )

    /**
     * The state a secret is held to, from its stored fields: the monotonic
     * state when one is stored, else the old epoch deadline migrated.
     */
    fun fromStored(
        failedAttempts: Int,
        remainingMs: Long,
        anchorElapsedMs: Long,
        anchorBootId: String?,
        legacyLockedUntil: Long,
        wallNow: Long
    ): LockoutState =
        if (remainingMs <= 0 && legacyLockedUntil > wallNow) {
            migrateLegacy(failedAttempts, legacyLockedUntil, wallNow)
        } else {
            LockoutState(failedAttempts, remainingMs, anchorElapsedMs, anchorBootId)
        }

    /**
     * The informational epoch deadline of [state] for display and the wire:
     * [Long.MAX_VALUE] when blocked for good, 0 when not locked.
     */
    fun displayDeadline(state: LockoutState, policy: Policy, clock: LockoutClock): Long {
        if (isPermanent(state.failedAttempts, policy)) return Long.MAX_VALUE
        val remaining = remainingMs(state, clock)
        return if (remaining > 0) clock.currentTimeMillis() + remaining else 0L
    }
}
