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

package com.automatethethings.xkey.tcp

import com.automatethethings.xkey.transport.DesktopPeer
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout

/**
 * Closes [desktop] and waits for the server to finish with it (#64): the
 * connection's last log comes before the server is back to listening, so no
 * connection is mid-serve, still logging, when the test unmocks `Log`.
 */
internal suspend fun TcpHsmServer.closeAndAwaitListening(desktop: DesktopPeer, timeoutMs: Long = 10_000L) {
    desktop.close()
    withTimeout(timeoutMs) { state.first { it is TcpHsmState.Listening } }
}
