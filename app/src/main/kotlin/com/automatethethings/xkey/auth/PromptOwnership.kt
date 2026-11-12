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

/** The owner of the one prompt queue's entries. Stub: the transitions land next. */
internal class PromptOwnership(
    private val report: (Refusal) -> Unit = {},
) {
    enum class State { QUEUED, ACTIVE, SETTLED }

    enum class Kind { GENERIC, CRYPTO_SIGNING, KEY_GENERATION, SHARING_APPROVAL }

    enum class Outcome { APPROVED, DENIED, FAILED, EXPIRED, WITHDRAWN }

    enum class Event { ACTIVITY_RESULT, NOTIFICATION_TAP, NOTIFICATION_EXPIRY, DEADLINE }

    data class Refusal(val key: String, val event: Event?, val state: State?)

    val entries: Int get() = 0

    val activeKey: String? get() = null

    fun enqueue(key: String, kind: Kind = Kind.GENERIC, connection: String? = null, onActive: () -> Unit) {}

    fun state(key: String): State? = null

    fun outcome(key: String): Outcome? = null

    fun holds(key: String): Boolean = false

    fun accept(key: String, event: Event): Boolean = false

    fun settle(
        key: String,
        outcome: Outcome,
        event: Event? = null,
        beforeNext: (wasActive: Boolean) -> Unit = {},
    ): Boolean = false

    fun expire(key: String, event: Event): Boolean = false

    fun end(key: String, beforeNext: (wasActive: Boolean) -> Unit = {}): Boolean = false
}
