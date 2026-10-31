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
package com.automatethethings.xkey.oath

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * RFC 4226 HOTP vectors for [OathEngine]. TOTP, digit, algorithm and
 * period behaviour is covered by [OathEngineRfcVectorTest].
 *
 * HOTP test vectors are taken from RFC 4226 Appendix D, using the ASCII
 * encoding of "12345678901234567890" as the shared secret with SHA1 and
 * 6-digit codes.
 */
class OathEngineTest {

    /** RFC 4226 test secret: ASCII bytes of "12345678901234567890". */
    private val rfcSecret = "12345678901234567890".toByteArray(Charsets.US_ASCII)

    /** RFC 4226 Appendix D expected HOTP values for counters 0-9. */
    private val rfcExpectedCodes = listOf(
        "755224", "287082", "359152", "969429", "338314",
        "254676", "287922", "162583", "399871", "520489"
    )

    // -------------------------------------------------------------------------
    // HOTP Tests
    // -------------------------------------------------------------------------

    @Test
    fun `HOTP all 10 RFC 4226 test vectors verified`() {
        for (counter in 0L..9L) {
            val code = OathEngine.generateHotpCode(rfcSecret, counter = counter, algorithm = "SHA1", digits = 6)
            assertEquals(
                "RFC 4226 mismatch at counter $counter",
                rfcExpectedCodes[counter.toInt()],
                code
            )
        }
    }
}
