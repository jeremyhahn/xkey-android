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
package com.automatethethings.xkey.ca

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The classification a refused enrollment is filed under.
 *
 * The enrollment ceremony has never run against real hardware, so the record a
 * refusal leaves is the only diagnostic there will be the first time it does.
 * What that record has to answer is which of two very different things
 * happened: a device that answered the credential challenge with the wrong
 * secret does not hold the keys it presented — an attack or a broken device —
 * while a device that never answered at all is an interoperability problem to
 * chase. Both used to be free text, and free text cannot be filtered on.
 *
 * The case names are therefore pinned here as literals rather than derived from
 * the enum-like structure: they are written into the audit log and into stored
 * refusal records, and a rename that quietly reclassifies rows already written
 * is exactly what these assertions exist to catch.
 */
class EnrollmentRefusalTest {

    private val all: List<EnrollmentRefusal> = listOf(
        EnrollmentRefusal.MalformedPackage("d"),
        EnrollmentRefusal.UntrustedEndorsement("d"),
        EnrollmentRefusal.ActivationMismatch("d"),
        EnrollmentRefusal.ActivationUnsupported("d"),
        EnrollmentRefusal.QuoteInvalid("d")
    )

    // -------------------------------------------------------------------------
    // The names that reach the audit log
    // -------------------------------------------------------------------------

    @Test
    fun `each case carries the name it is filed under`() {
        assertEquals("malformed-package", EnrollmentRefusal.MalformedPackage("d").auditName)
        assertEquals("untrusted-endorsement", EnrollmentRefusal.UntrustedEndorsement("d").auditName)
        assertEquals("activation-mismatch", EnrollmentRefusal.ActivationMismatch("d").auditName)
        assertEquals(
            "activation-unsupported",
            EnrollmentRefusal.ActivationUnsupported("d").auditName
        )
        assertEquals("quote-invalid", EnrollmentRefusal.QuoteInvalid("d").auditName)
    }

    @Test
    fun `no two cases share a name`() {
        assertEquals(all.size, all.map { it.auditName }.toSet().size)
    }

    /**
     * The distinction the whole exercise turns on: a wrong answer and no answer
     * must not be filed under one name.
     */
    @Test
    fun `a wrong activation secret is not the same case as an unanswered challenge`() {
        val mismatch = EnrollmentRefusal.ActivationMismatch("returned a different secret")
        val unsupported = EnrollmentRefusal.ActivationUnsupported("could not build a challenge")

        assertNotEquals(mismatch.auditName, unsupported.auditName)
        assertNotEquals(mismatch as Any, unsupported as Any)
    }

    // -------------------------------------------------------------------------
    // Reading a stored record back
    // -------------------------------------------------------------------------

    @Test
    fun `every case round trips through its name`() {
        all.forEach { refusal ->
            assertEquals(refusal, EnrollmentRefusal.of(refusal.auditName, refusal.detail))
        }
    }

    @Test
    fun `a name this build does not know reads back as nothing`() {
        assertNull(EnrollmentRefusal.of("something-a-newer-build-wrote", "d"))
        assertNull(EnrollmentRefusal.of("", "d"))
        // Not the class name, and not a near miss on the real one.
        assertNull(EnrollmentRefusal.of("MalformedPackage", "d"))
        assertNull(EnrollmentRefusal.of("malformed_package", "d"))
    }

    // -------------------------------------------------------------------------
    // The human-readable half
    // -------------------------------------------------------------------------

    @Test
    fun `the detail is kept verbatim`() {
        val detail = "EK certificate carries a EC key; credential activation needs an RSA " +
            "endorsement key"
        val refusal: EnrollmentRefusal = EnrollmentRefusal.ActivationUnsupported(detail)

        assertEquals(detail, refusal.detail)
        assertEquals(detail, EnrollmentRefusal.of(refusal.auditName, refusal.detail)?.detail)
    }

    @Test
    fun `two refusals of the same case differ by their detail`() {
        assertNotEquals(
            EnrollmentRefusal.QuoteInvalid("quote carries no PCR values"),
            EnrollmentRefusal.QuoteInvalid("quote omits PCRs [7]")
        )
    }

    @Test
    fun `an empty detail is still a refusal`() {
        val refusal = EnrollmentRefusal.MalformedPackage("")

        assertEquals("", refusal.detail)
        assertEquals(refusal, EnrollmentRefusal.of(refusal.auditName, ""))
    }

    @Test
    fun `the name is stable across instances of the same case`() {
        assertTrue(
            all.all { refusal ->
                EnrollmentRefusal.of(refusal.auditName, "other detail")?.auditName ==
                    refusal.auditName
            }
        )
    }
}
