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

package com.automatethethings.xkey.audit

import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/**
 * The one path for a stored write and its audit entry. Both run under
 * [NonCancellable]: a cancellation cannot land between a committed write and
 * its audit, so a caller whose scope is cancelled while the write runs (an
 * activity finishing, for example) still leaves the audit row. A write that
 * throws is not audited and the exception reaches the caller; a pending
 * cancellation is seen at the caller's next suspension point.
 *
 * @param write The database write; its result is passed to [audit].
 * @param audit Appends the audit entry for the committed write.
 * @return The result of [write].
 */
internal suspend fun <T> auditedWrite(
    write: suspend () -> T,
    audit: (T) -> Unit
): T = withContext(NonCancellable) {
    val result = write()
    audit(result)
    result
}
