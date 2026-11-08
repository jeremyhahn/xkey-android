/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
package com.automatethethings.xkey.tcp

import org.junit.Assert.assertEquals
import org.junit.Test

/** The loopback port [TcpHsmServer] listens on by default. */
class TcpHsmServerDefaultPortTest {

    /**
     * The port must stay 8444: go-xkms hard-codes
     * `pairing.DefaultTCPAddress = "localhost:8444"`, and the documented
     * workflow is `adb forward tcp:8444 tcp:8444`.
     */
    @Test
    fun theDefaultPortMatchesTheGoXkmsContract() {
        assertEquals(8444, TcpHsmServer.DEFAULT_PORT)
    }
}
