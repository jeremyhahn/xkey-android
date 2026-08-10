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
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * Tests for [OathEngine] HOTP (RFC 4226) and TOTP (RFC 6238) generation.
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
    fun `HOTP counter 0 matches RFC 4226 vector`() {
        val code = OathEngine.generateHotpCode(rfcSecret, counter = 0L, algorithm = "SHA1", digits = 6)
        assertEquals("755224", code)
    }

    @Test
    fun `HOTP counter 1 matches RFC 4226 vector`() {
        val code = OathEngine.generateHotpCode(rfcSecret, counter = 1L, algorithm = "SHA1", digits = 6)
        assertEquals("287082", code)
    }

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

    @Test
    fun `HOTP 8-digit code produces 8-character string`() {
        val code = OathEngine.generateHotpCode(rfcSecret, counter = 0L, algorithm = "SHA1", digits = 8)
        assertEquals(8, code.length)
    }

    @Test
    fun `HOTP leading zeros preserved for all digit lengths`() {
        // Generate many codes and verify length is always exactly equal to digits.
        // Leading zeros must be preserved via padStart, so no code should be shorter.
        for (counter in 0L..99L) {
            for (digits in listOf(6, 7, 8)) {
                val code = OathEngine.generateHotpCode(rfcSecret, counter = counter, algorithm = "SHA1", digits = digits)
                assertEquals(
                    "Code length mismatch at counter=$counter, digits=$digits",
                    digits,
                    code.length
                )
            }
        }
    }

    @Test
    fun `HOTP SHA256 algorithm produces valid code`() {
        val code = OathEngine.generateHotpCode(rfcSecret, counter = 0L, algorithm = "SHA256", digits = 6)
        assertEquals(6, code.length)
    }

    @Test
    fun `HOTP SHA512 algorithm produces valid code`() {
        val code = OathEngine.generateHotpCode(rfcSecret, counter = 0L, algorithm = "SHA512", digits = 6)
        assertEquals(6, code.length)
    }

    // -------------------------------------------------------------------------
    // TOTP Tests
    // -------------------------------------------------------------------------

    @Test
    fun `TOTP deterministic output for fixed time`() {
        val code1 = OathEngine.generateTotpCode(rfcSecret, algorithm = "SHA1", digits = 6, periodSeconds = 30, timeMs = 59000L)
        val code2 = OathEngine.generateTotpCode(rfcSecret, algorithm = "SHA1", digits = 6, periodSeconds = 30, timeMs = 59000L)
        assertEquals(code1, code2)
    }

    @Test
    fun `TOTP same time window produces same code`() {
        // Both timestamps fall within the same 30-second window (T=3: 90s-119s)
        val code1 = OathEngine.generateTotpCode(rfcSecret, algorithm = "SHA1", digits = 6, periodSeconds = 30, timeMs = 90_000L)
        val code2 = OathEngine.generateTotpCode(rfcSecret, algorithm = "SHA1", digits = 6, periodSeconds = 30, timeMs = 119_000L)
        assertEquals(code1, code2)
    }

    @Test
    fun `TOTP different time windows produce different codes`() {
        // T=0 window (0s-29s) vs T=1 window (30s-59s)
        val code1 = OathEngine.generateTotpCode(rfcSecret, algorithm = "SHA1", digits = 6, periodSeconds = 30, timeMs = 0L)
        val code2 = OathEngine.generateTotpCode(rfcSecret, algorithm = "SHA1", digits = 6, periodSeconds = 30, timeMs = 30_000L)
        assertNotEquals(code1, code2)
    }

    @Test
    fun `TOTP custom period of 60 seconds works`() {
        // With 60-second period, timeMs=0 and timeMs=59000 should be in the same window (T=0)
        val code1 = OathEngine.generateTotpCode(rfcSecret, algorithm = "SHA1", digits = 6, periodSeconds = 60, timeMs = 0L)
        val code2 = OathEngine.generateTotpCode(rfcSecret, algorithm = "SHA1", digits = 6, periodSeconds = 60, timeMs = 59_000L)
        assertEquals(code1, code2)

        // timeMs=60000 should be in the next window (T=1)
        val code3 = OathEngine.generateTotpCode(rfcSecret, algorithm = "SHA1", digits = 6, periodSeconds = 60, timeMs = 60_000L)
        assertNotEquals(code1, code3)
    }

    // -------------------------------------------------------------------------
    // Error Cases
    // -------------------------------------------------------------------------

    @Test(expected = IllegalArgumentException::class)
    fun `HOTP invalid algorithm throws IllegalArgumentException`() {
        OathEngine.generateHotpCode(rfcSecret, counter = 0L, algorithm = "MD5", digits = 6)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `HOTP invalid digits throws IllegalArgumentException`() {
        OathEngine.generateHotpCode(rfcSecret, counter = 0L, algorithm = "SHA1", digits = 5)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `TOTP non-positive period throws IllegalArgumentException`() {
        OathEngine.generateTotpCode(rfcSecret, algorithm = "SHA1", digits = 6, periodSeconds = 0, timeMs = 1000L)
    }
}
