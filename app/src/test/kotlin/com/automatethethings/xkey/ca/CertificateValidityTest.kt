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
package com.automatethethings.xkey.ca

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

class CertificateValidityTest {

    private val day = 24L * 60 * 60 * 1000

    // 2026-11-12T00:00:00Z, fixed: no clock.
    private val now = Date(1_794_441_600_000L)

    private fun daysFromNow(days: Long) = Date(now.time + days * day)

    @Test
    fun `issuer with years left gives now plus the profile days`() {
        val validity = validityFor(now, 365, daysFromNow(-10), daysFromNow(3650))

        assertEquals(now, validity.notBefore)
        assertEquals(daysFromNow(365), validity.notAfter)
    }

    @Test
    fun `issuer with 30 days left clamps a 365-day profile to the issuer notAfter`() {
        val issuerNotAfter = daysFromNow(30)
        val validity = validityFor(now, 365, daysFromNow(-10), issuerNotAfter)

        assertEquals(now, validity.notBefore)
        assertEquals(issuerNotAfter, validity.notAfter)
    }

    @Test
    fun `SubordinateCA default under an issuer with 2 years left is clamped`() {
        val issuerNotAfter = daysFromNow(730)
        val profile = CertificateProfile.SubordinateCA()
        val validity = validityFor(now, profile.validityDays, daysFromNow(-10), issuerNotAfter)

        assertEquals(issuerNotAfter, validity.notAfter)
    }

    @Test
    fun `requested end date past the issuer notAfter is clamped`() {
        val issuerNotAfter = daysFromNow(400)
        val validity = validityUntil(now, daysFromNow(1826), daysFromNow(-10), issuerNotAfter)

        assertEquals(now, validity.notBefore)
        assertEquals(issuerNotAfter, validity.notAfter)
    }

    @Test
    fun `expired issuer is refused naming its notAfter`() {
        val issuerNotAfter = daysFromNow(-1)
        val e = assertThrows(IllegalStateException::class.java) {
            validityFor(now, 365, daysFromNow(-400), issuerNotAfter)
        }
        assertTrue(e.message!!.contains(issuerNotAfter.toInstant().toString()))
    }

    @Test
    fun `issuer not yet valid is refused naming its notBefore`() {
        val issuerNotBefore = daysFromNow(1)
        val e = assertThrows(IllegalStateException::class.java) {
            validityFor(now, 365, issuerNotBefore, daysFromNow(3650))
        }
        assertTrue(e.message!!.contains(issuerNotBefore.toInstant().toString()))
    }

    @Test
    fun `expired issuer refuses an end-date request too`() {
        assertThrows(IllegalStateException::class.java) {
            validityUntil(now, daysFromNow(365), daysFromNow(-400), daysFromNow(-1))
        }
    }

    @Test
    fun `zero validity days is refused`() {
        assertThrows(IllegalArgumentException::class.java) {
            validityFor(now, 0, daysFromNow(-10), daysFromNow(3650))
        }
    }

    @Test
    fun `negative validity days is refused`() {
        assertThrows(IllegalArgumentException::class.java) {
            validityFor(now, -1, daysFromNow(-10), daysFromNow(3650))
        }
    }
}
