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
package com.automatethethings.xkey.remote

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The one way to schedule cleanup (key erasure, session teardown) into a
 * scope that may be cancelled: once this returns, [block] runs to completion.
 *
 * A default-start launch whose body is [NonCancellable] is not enough: a
 * scope cancelled before the coroutine is dispatched never runs its body at
 * all. This one starts [CoroutineStart.ATOMIC], so the body begins even when
 * the scope is already cancelled, and its whole body is [NonCancellable], so
 * no cancellation stops it part way.
 *
 * @return the cleanup job, for callers that wait on it
 */
fun CoroutineScope.launchCleanup(block: suspend CoroutineScope.() -> Unit): Job =
    launch(start = CoroutineStart.ATOMIC) { withContext(NonCancellable, block) }
