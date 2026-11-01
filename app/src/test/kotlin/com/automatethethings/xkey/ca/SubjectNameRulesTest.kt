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

import org.bouncycastle.asn1.ASN1String
import org.bouncycastle.asn1.DERUTF8String
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * The X.500 name rules the enrollment paths have relied on since Bouncy Castle 1.85.
 *
 * BCStyle refuses, when a name is built from strings, a common name longer than
 * 64 characters (RFC 5280 ub-common-name) and a country that is not exactly two
 * characters. Three inputs reach that check: the desktop's pairing device name
 * becomes the IAK/IDevID common name, falling back to its Noise key in hex
 * (GattServer.enrollmentSubject); the desktop's enrollment `subject` is parsed
 * with X500Name(String) (Handler, local enrollment request); and the CA subject
 * comes from Settings. Decoding DER skips the check, so certificates already
 * stored with an over-length name must keep loading.
 */
class SubjectNameRulesTest {

    private fun commonName(name: X500Name): String =
        (name.getRDNs(BCStyle.CN).first().first.value as ASN1String).string

    @Test
    fun `a common name of 64 characters is accepted and one of 65 refused`() {
        assertEquals(64, commonName(X500Name("CN=${"d".repeat(64)}, O=xKey")).length)

        assertThrows(IllegalArgumentException::class.java) {
            X500Name("CN=${"d".repeat(65)}, O=xKey")
        }
        assertThrows(IllegalArgumentException::class.java) {
            X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, "d".repeat(65))
        }
    }

    @Test
    fun `a CA subject country must be two characters`() {
        val name = CASubject(cn = "Acme Root", country = "US").toX500Name("unused")
        assertEquals("Acme Root", commonName(name))

        assertThrows(IllegalArgumentException::class.java) {
            CASubject(cn = "Acme Root", country = "USA").toX500Name("unused")
        }
    }

    @Test
    fun `a stored name with an over-length common name still decodes`() {
        val longCn = "d".repeat(80)
        val der = X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.CN, DERUTF8String(longCn))
            .build()
            .encoded

        assertEquals(longCn, commonName(X500Name.getInstance(der)))
    }
}
