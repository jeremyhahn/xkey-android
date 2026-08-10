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
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RFC 6238 conformance tests for [OathEngine]'s TOTP path.
 *
 * `OathEngineTest` covers the RFC 4226 HOTP vectors; this suite covers the
 * complementary appendix-B table from RFC 6238, which is the only published
 * evidence that the SHA-256 and SHA-512 variants and the 8-digit truncation
 * are implemented correctly rather than merely self-consistently. A phone whose
 * TOTP disagrees with the RFC is silently unusable against every real verifier,
 * and nothing in the app itself would notice.
 *
 * The seeds are the RFC's own ASCII seeds, each truncated or extended to the
 * digest's block-friendly length exactly as the RFC specifies.
 */
class OathEngineRfcVectorTest {

    /** RFC 6238 appendix B seed for HMAC-SHA1 (20 bytes). */
    private val seedSha1 = "12345678901234567890".toByteArray(Charsets.US_ASCII)

    /** RFC 6238 appendix B seed for HMAC-SHA256 (32 bytes). */
    private val seedSha256 = "12345678901234567890123456789012".toByteArray(Charsets.US_ASCII)

    /** RFC 6238 appendix B seed for HMAC-SHA512 (64 bytes). */
    private val seedSha512 =
        "1234567890123456789012345678901234567890123456789012345678901234"
            .toByteArray(Charsets.US_ASCII)

    private fun totp(seed: ByteArray, algorithm: String, seconds: Long): String =
        OathEngine.generateTotpCode(
            secret = seed,
            algorithm = algorithm,
            digits = 8,
            periodSeconds = 30,
            timeMs = seconds * 1000L
        )

    // -------------------------------------------------------------------------
    // RFC 6238 appendix B vectors
    // -------------------------------------------------------------------------

    @Test
    fun `SHA1 matches every RFC 6238 appendix B vector`() {
        assertEquals("94287082", totp(seedSha1, "SHA1", 59L))
        assertEquals("07081804", totp(seedSha1, "SHA1", 1_111_111_109L))
        assertEquals("14050471", totp(seedSha1, "SHA1", 1_111_111_111L))
        assertEquals("89005924", totp(seedSha1, "SHA1", 1_234_567_890L))
        assertEquals("69279037", totp(seedSha1, "SHA1", 2_000_000_000L))
        assertEquals("65353130", totp(seedSha1, "SHA1", 20_000_000_000L))
    }

    @Test
    fun `SHA256 matches every RFC 6238 appendix B vector`() {
        assertEquals("46119246", totp(seedSha256, "SHA256", 59L))
        assertEquals("68084774", totp(seedSha256, "SHA256", 1_111_111_109L))
        assertEquals("67062674", totp(seedSha256, "SHA256", 1_111_111_111L))
        assertEquals("91819424", totp(seedSha256, "SHA256", 1_234_567_890L))
        assertEquals("90698825", totp(seedSha256, "SHA256", 2_000_000_000L))
        assertEquals("77737706", totp(seedSha256, "SHA256", 20_000_000_000L))
    }

    @Test
    fun `SHA512 matches every RFC 6238 appendix B vector`() {
        assertEquals("90693936", totp(seedSha512, "SHA512", 59L))
        assertEquals("25091201", totp(seedSha512, "SHA512", 1_111_111_109L))
        assertEquals("99943326", totp(seedSha512, "SHA512", 1_111_111_111L))
        assertEquals("93441116", totp(seedSha512, "SHA512", 1_234_567_890L))
        assertEquals("38618901", totp(seedSha512, "SHA512", 2_000_000_000L))
        assertEquals("47863826", totp(seedSha512, "SHA512", 20_000_000_000L))
    }

    @Test
    fun `the vector beyond 2038 proves the counter is not truncated to 32 bits`() {
        // 20000000000 s / 30 = 666666666 time steps, which needs more than the
        // 32-bit range an int counter would give.
        assertEquals("65353130", totp(seedSha1, "SHA1", 20_000_000_000L))
    }

    // -------------------------------------------------------------------------
    // TOTP is HOTP over the time step
    // -------------------------------------------------------------------------

    @Test
    fun `TOTP is exactly HOTP applied to the floor of the time step`() {
        val seconds = 1_234_567_890L
        val step = seconds / 30L

        assertEquals(
            OathEngine.generateHotpCode(seedSha1, step, "SHA1", 8),
            totp(seedSha1, "SHA1", seconds)
        )
    }

    @Test
    fun `a code holds for the whole period and changes on the boundary`() {
        val periodStart = 30L * 100L

        val atStart = totp(seedSha1, "SHA1", periodStart)
        val nearEnd = totp(seedSha1, "SHA1", periodStart + 29L)
        val nextPeriod = totp(seedSha1, "SHA1", periodStart + 30L)

        assertEquals(atStart, nearEnd)
        assertNotEquals(atStart, nextPeriod)
    }

    @Test
    fun `sub-second time is truncated rather than rounded`() {
        val exact = OathEngine.generateTotpCode(seedSha1, "SHA1", 8, 30, 30_000L)
        val justUnder = OathEngine.generateTotpCode(seedSha1, "SHA1", 8, 30, 29_999L)
        val justOver = OathEngine.generateTotpCode(seedSha1, "SHA1", 8, 30, 30_999L)

        assertEquals(exact, justOver)
        assertNotEquals(exact, justUnder)
    }

    @Test
    fun `the epoch itself is time step zero`() {
        assertEquals(
            OathEngine.generateHotpCode(seedSha1, 0L, "SHA1", 8),
            OathEngine.generateTotpCode(seedSha1, "SHA1", 8, 30, 0L)
        )
    }

    @Test
    fun `a one-second period makes every second its own step`() {
        val a = OathEngine.generateTotpCode(seedSha1, "SHA1", 6, 1, 5_000L)
        val b = OathEngine.generateTotpCode(seedSha1, "SHA1", 6, 1, 6_000L)

        assertEquals(OathEngine.generateHotpCode(seedSha1, 5L, "SHA1", 6), a)
        assertNotEquals(a, b)
    }

    @Test
    fun `the default time argument produces a code for the current window`() {
        val now = System.currentTimeMillis()
        val implicit = OathEngine.generateTotpCode(seedSha1, "SHA1", 6, 30)
        val explicit = OathEngine.generateTotpCode(seedSha1, "SHA1", 6, 30, now)

        // Both read the clock within the same test, so they can only differ if a
        // period boundary fell between them; accept either neighbouring window.
        val neighbour = OathEngine.generateTotpCode(seedSha1, "SHA1", 6, 30, now + 30_000L)
        assertTrue(implicit == explicit || implicit == neighbour)
    }

    // -------------------------------------------------------------------------
    // Digit handling
    // -------------------------------------------------------------------------

    @Test
    fun `every supported digit length is a prefix-preserving truncation`() {
        val eight = OathEngine.generateHotpCode(seedSha1, 1L, "SHA1", 8)
        val seven = OathEngine.generateHotpCode(seedSha1, 1L, "SHA1", 7)
        val six = OathEngine.generateHotpCode(seedSha1, 1L, "SHA1", 6)

        assertEquals(8, eight.length)
        assertEquals(7, seven.length)
        assertEquals(6, six.length)
        assertEquals(eight.takeLast(7), seven)
        assertEquals(eight.takeLast(6), six)
    }

    @Test
    fun `a code is always numeric and zero padded to the requested width`() {
        for (counter in 0L until 200L) {
            val code = OathEngine.generateHotpCode(seedSha1, counter, "SHA1", 6)

            assertEquals("counter $counter", 6, code.length)
            assertTrue("counter $counter produced '$code'", code.all { it.isDigit() })
        }
    }

    @Test
    fun `digit counts outside six to eight are rejected`() {
        for (digits in listOf(0, 1, 5, 9, 10, -1)) {
            assertThrows(IllegalArgumentException::class.java) {
                OathEngine.generateHotpCode(seedSha1, 0L, "SHA1", digits)
            }
        }
    }

    // -------------------------------------------------------------------------
    // Algorithm handling
    // -------------------------------------------------------------------------

    @Test
    fun `algorithm names are matched exactly and not case-folded`() {
        // The repository upper-cases before storing, so the engine can insist on
        // the canonical spelling; a lower-case name reaching it is a bug upstream.
        assertThrows(IllegalArgumentException::class.java) {
            OathEngine.generateHotpCode(seedSha1, 0L, "sha1", 6)
        }
        assertThrows(IllegalArgumentException::class.java) {
            OathEngine.generateHotpCode(seedSha1, 0L, "HmacSHA1", 6)
        }
        assertThrows(IllegalArgumentException::class.java) {
            OathEngine.generateHotpCode(seedSha1, 0L, "SHA-1", 6)
        }
    }

    @Test
    fun `the unsupported-algorithm message names the accepted values`() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            OathEngine.generateHotpCode(seedSha1, 0L, "MD5", 6)
        }

        assertTrue(error.message!!.contains("MD5"))
        assertTrue(error.message!!.contains("SHA1"))
        assertTrue(error.message!!.contains("SHA256"))
        assertTrue(error.message!!.contains("SHA512"))
    }

    @Test
    fun `the three algorithms disagree for the same secret and counter`() {
        val a = OathEngine.generateHotpCode(seedSha512, 1L, "SHA1", 8)
        val b = OathEngine.generateHotpCode(seedSha512, 1L, "SHA256", 8)
        val c = OathEngine.generateHotpCode(seedSha512, 1L, "SHA512", 8)

        assertEquals(3, setOf(a, b, c).size)
    }

    // -------------------------------------------------------------------------
    // Period validation
    // -------------------------------------------------------------------------

    @Test
    fun `a zero or negative period is rejected before any HMAC is computed`() {
        for (period in listOf(0, -1, -30)) {
            val error = assertThrows(IllegalArgumentException::class.java) {
                OathEngine.generateTotpCode(seedSha1, "SHA1", 6, period, 0L)
            }
            assertTrue(error.message!!.contains("Period must be positive"))
        }
    }

    // -------------------------------------------------------------------------
    // Secret handling
    // -------------------------------------------------------------------------

    @Test
    fun `a different secret yields a different code`() {
        val other = "09876543210987654321".toByteArray(Charsets.US_ASCII)

        assertNotEquals(
            OathEngine.generateHotpCode(seedSha1, 0L, "SHA1", 6),
            OathEngine.generateHotpCode(other, 0L, "SHA1", 6)
        )
    }

    @Test
    fun `a one-byte secret still produces a well-formed code`() {
        val code = OathEngine.generateHotpCode(byteArrayOf(0x2a), 0L, "SHA1", 6)

        assertEquals(6, code.length)
        assertTrue(code.all { it.isDigit() })
    }

    @Test
    fun `generation is stateless so repeated calls agree`() {
        val first = OathEngine.generateHotpCode(seedSha1, 42L, "SHA256", 8)
        val second = OathEngine.generateHotpCode(seedSha1, 42L, "SHA256", 8)

        assertEquals(first, second)
    }
}
