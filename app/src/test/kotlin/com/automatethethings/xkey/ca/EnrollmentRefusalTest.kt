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
}
