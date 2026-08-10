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
package com.automatethethings.xkey.credential

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [RelyingPartyOrigin].
 *
 * The rule under test is WebAuthn Level 3's: an RP ID is usable for a ceremony
 * only when it equals the origin's effective domain or is a registrable domain
 * suffix of it. The failures matter more than the successes here — every case
 * that returns false is one where xKey would otherwise have signed a response
 * binding an origin it does not own.
 */
class RelyingPartyOriginTest {

    // -----------------------------------------------------------------
    // Accepted relationships
    // -----------------------------------------------------------------

    @Test
    fun exactHostMatchIsAccepted() {
        assertTrue(RelyingPartyOrigin.isRpIdValidForOrigin("example.com", "https://example.com"))
    }

    @Test
    fun registrableSuffixIsAccepted() {
        assertTrue(
            RelyingPartyOrigin.isRpIdValidForOrigin("example.com", "https://login.example.com")
        )
        assertTrue(
            RelyingPartyOrigin.isRpIdValidForOrigin("example.com", "https://a.b.example.com")
        )
    }

    @Test
    fun portAndPathAreIgnored() {
        assertTrue(
            RelyingPartyOrigin.isRpIdValidForOrigin("example.com", "https://example.com:8443")
        )
        assertTrue(
            RelyingPartyOrigin.isRpIdValidForOrigin("example.com", "https://example.com/authn")
        )
    }

    @Test
    fun comparisonIsCaseInsensitiveAndIgnoresTheRootLabel() {
        assertTrue(RelyingPartyOrigin.isRpIdValidForOrigin("Example.COM", "https://EXAMPLE.com"))
        assertTrue(RelyingPartyOrigin.isRpIdValidForOrigin("example.com.", "https://example.com"))
    }

    /** The spec carves out plain-http localhost as a secure context. */
    @Test
    fun httpLocalhostIsAccepted() {
        assertTrue(RelyingPartyOrigin.isRpIdValidForOrigin("localhost", "http://localhost"))
        assertTrue(RelyingPartyOrigin.isRpIdValidForOrigin("localhost", "http://localhost:8080"))
    }

    // -----------------------------------------------------------------
    // Rejected relationships
    // -----------------------------------------------------------------

    @Test
    fun anUnrelatedRelyingPartyIsRejected() {
        assertFalse(
            RelyingPartyOrigin.isRpIdValidForOrigin("attacker.test", "https://example.com")
        )
    }

    /**
     * The direction matters: a parent RP ID may cover a subdomain origin, never
     * the reverse.
     */
    @Test
    fun aSubdomainRelyingPartyDoesNotCoverItsParentOrigin() {
        assertFalse(
            RelyingPartyOrigin.isRpIdValidForOrigin("login.example.com", "https://example.com")
        )
    }

    /** "notexample.com" ends with "example.com" as a string but not as a domain. */
    @Test
    fun aSuffixThatIsNotALabelBoundaryIsRejected() {
        assertFalse(
            RelyingPartyOrigin.isRpIdValidForOrigin("example.com", "https://notexample.com")
        )
    }

    @Test
    fun plainHttpOriginsOtherThanLocalhostAreRejected() {
        assertFalse(RelyingPartyOrigin.isRpIdValidForOrigin("example.com", "http://example.com"))
    }

    @Test
    fun nonWebOriginsAreRejected() {
        assertFalse(
            RelyingPartyOrigin.isRpIdValidForOrigin("example.com", "android:apk-key-hash:abc")
        )
        assertFalse(RelyingPartyOrigin.isRpIdValidForOrigin("example.com", "example.com"))
    }

    @Test
    fun ipv6LiteralOriginsAreRejected() {
        assertFalse(RelyingPartyOrigin.isRpIdValidForOrigin("::1", "https://[::1]:8443"))
    }

    @Test
    fun blankInputsAreRejected() {
        assertFalse(RelyingPartyOrigin.isRpIdValidForOrigin("", "https://example.com"))
        assertFalse(RelyingPartyOrigin.isRpIdValidForOrigin("example.com", ""))
        assertFalse(RelyingPartyOrigin.isRpIdValidForOrigin("example.com", "https://"))
    }
}
