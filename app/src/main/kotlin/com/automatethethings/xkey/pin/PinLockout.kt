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

/**
 * The phone's one failed-attempt lockout rule, shared by every secret it
 * rate-limits: the SO and User PINs ([PinManager]) and the password vault's
 * passphrase ([com.automatethethings.xkey.password.PasswordVault]).
 *
 * Once a failure brings the consecutive count to `maxAttempts`, that failure
 * and every further one lock for `lockoutDurationSeconds` from the moment it
 * happened. Only a success clears the count. Times are epoch milliseconds, the
 * form the counters are persisted in, so a lockout survives a restart.
 */
object PinLockout {

    /**
     * The epoch milliseconds a failure that brings the count to
     * [failedAttempts] locks until, or 0 when it is still under the limit.
     */
    fun lockedUntil(failedAttempts: Int, maxAttempts: Int, lockoutDurationSeconds: Int, now: Long): Long =
        if (failedAttempts >= maxAttempts) now + (lockoutDurationSeconds * 1000L) else 0L

    /** Whether a lockout ending at [lockedUntil] still holds at [now]. */
    fun isLocked(lockedUntil: Long, now: Long): Boolean = lockedUntil > now
}
