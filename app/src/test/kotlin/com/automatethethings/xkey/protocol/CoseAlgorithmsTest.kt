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
package com.automatethethings.xkey.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Unit tests for [CoseAlgorithms].
 *
 * `local.generateKey` and `local.sign` receive `algorithm` from go-xkms as a
 * *name string* ("ES256", "AES-256", "HMAC-SHA256") while the legacy/base
 * methods send the raw COSE integer. [CoseAlgorithms.fromName] is the single
 * point where both forms are reconciled, so every accepted spelling, the alias
 * table, the numeric-string escape hatch and the rejection path are pinned here.
 *
 * The identifiers themselves are IANA COSE registry values and must never
 * change; [CoseAlgorithms.getAlgorithmName] is the inverse mapping used when
 * echoing an algorithm back on the wire, so the two are also checked for
 * consistency.
 */
class CoseAlgorithmsTest {

    /** Every (constant, canonical name) pair supported by the mapping. */
    private val canonicalPairs = listOf(
        CoseAlgorithms.ES256 to "ES256",
        CoseAlgorithms.ES384 to "ES384",
        CoseAlgorithms.ES512 to "ES512",
        CoseAlgorithms.EDDSA to "EdDSA",
        CoseAlgorithms.RS256 to "RS256",
        CoseAlgorithms.RS384 to "RS384",
        CoseAlgorithms.RS512 to "RS512",
        CoseAlgorithms.A128GCM to "AES-128",
        CoseAlgorithms.A192GCM to "AES-192",
        CoseAlgorithms.A256GCM to "AES-256",
        CoseAlgorithms.HMAC_256 to "HMAC-SHA256",
        CoseAlgorithms.HMAC_384 to "HMAC-SHA384",
        CoseAlgorithms.HMAC_512 to "HMAC-SHA512"
    )

    // -------------------------------------------------------------------------
    // COSE identifier values (IANA registry - must not drift)
    // -------------------------------------------------------------------------

    @Test
    fun `signature algorithm identifiers match the IANA COSE registry`() {
        assertEquals(-7, CoseAlgorithms.ES256)
        assertEquals(-35, CoseAlgorithms.ES384)
        assertEquals(-36, CoseAlgorithms.ES512)
        assertEquals(-8, CoseAlgorithms.EDDSA)
        assertEquals(-257, CoseAlgorithms.RS256)
        assertEquals(-258, CoseAlgorithms.RS384)
        assertEquals(-259, CoseAlgorithms.RS512)
    }

    @Test
    fun `symmetric algorithm identifiers match the IANA COSE registry`() {
        assertEquals(1, CoseAlgorithms.A128GCM)
        assertEquals(2, CoseAlgorithms.A192GCM)
        assertEquals(3, CoseAlgorithms.A256GCM)
        assertEquals(5, CoseAlgorithms.HMAC_256)
        assertEquals(6, CoseAlgorithms.HMAC_384)
        assertEquals(7, CoseAlgorithms.HMAC_512)
    }

    // -------------------------------------------------------------------------
    // getAlgorithmName
    // -------------------------------------------------------------------------

    @Test
    fun `getAlgorithmName returns the canonical name for every supported algorithm`() {
        canonicalPairs.forEach { (id, name) ->
            assertEquals("name for COSE id $id", name, CoseAlgorithms.getAlgorithmName(id))
        }
    }

    @Test
    fun `getAlgorithmName throws INVALID_ALGORITHM for an unknown identifier`() {
        val e = assertProtocolException { CoseAlgorithms.getAlgorithmName(-999) }

        assertEquals(ErrorCodes.INVALID_ALGORITHM, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("-999"))
    }

    // -------------------------------------------------------------------------
    // fromName - canonical names
    // -------------------------------------------------------------------------

    @Test
    fun `fromName resolves every canonical algorithm name`() {
        canonicalPairs.forEach { (id, name) ->
            assertEquals("fromName(\"$name\")", id, CoseAlgorithms.fromName(name))
        }
    }

    @Test
    fun `fromName is case insensitive`() {
        assertEquals(CoseAlgorithms.ES256, CoseAlgorithms.fromName("es256"))
        assertEquals(CoseAlgorithms.RS512, CoseAlgorithms.fromName("rs512"))
        assertEquals(CoseAlgorithms.EDDSA, CoseAlgorithms.fromName("eddsa"))
        assertEquals(CoseAlgorithms.A256GCM, CoseAlgorithms.fromName("aes-256"))
    }

    @Test
    fun `fromName trims surrounding whitespace`() {
        assertEquals(CoseAlgorithms.ES384, CoseAlgorithms.fromName("  ES384  "))
        assertEquals(CoseAlgorithms.HMAC_256, CoseAlgorithms.fromName("\tHMAC-SHA256\n"))
    }

    @Test
    fun `fromName normalizes underscores to hyphens`() {
        assertEquals(CoseAlgorithms.A128GCM, CoseAlgorithms.fromName("AES_128"))
        assertEquals(CoseAlgorithms.HMAC_512, CoseAlgorithms.fromName("HMAC_SHA512"))
    }

    // -------------------------------------------------------------------------
    // fromName - aliases
    // -------------------------------------------------------------------------

    @Test
    fun `fromName accepts the AES aliases with and without a hyphen and the COSE spelling`() {
        listOf("AES-128", "AES128", "A128GCM").forEach {
            assertEquals("alias $it", CoseAlgorithms.A128GCM, CoseAlgorithms.fromName(it))
        }
        listOf("AES-192", "AES192", "A192GCM").forEach {
            assertEquals("alias $it", CoseAlgorithms.A192GCM, CoseAlgorithms.fromName(it))
        }
        listOf("AES-256", "AES256", "A256GCM").forEach {
            assertEquals("alias $it", CoseAlgorithms.A256GCM, CoseAlgorithms.fromName(it))
        }
    }

    @Test
    fun `fromName accepts the HMAC aliases including the JOSE HS spellings`() {
        listOf("HMAC-SHA256", "HMAC256", "HS256").forEach {
            assertEquals("alias $it", CoseAlgorithms.HMAC_256, CoseAlgorithms.fromName(it))
        }
        listOf("HMAC-SHA384", "HMAC384", "HS384").forEach {
            assertEquals("alias $it", CoseAlgorithms.HMAC_384, CoseAlgorithms.fromName(it))
        }
        listOf("HMAC-SHA512", "HMAC512", "HS512").forEach {
            assertEquals("alias $it", CoseAlgorithms.HMAC_512, CoseAlgorithms.fromName(it))
        }
    }

    // -------------------------------------------------------------------------
    // fromName - numeric strings (legacy/base callers)
    // -------------------------------------------------------------------------

    @Test
    fun `fromName passes through a negative numeric string unchanged`() {
        assertEquals(CoseAlgorithms.ES256, CoseAlgorithms.fromName("-7"))
        assertEquals(CoseAlgorithms.RS256, CoseAlgorithms.fromName("-257"))
    }

    @Test
    fun `fromName passes through an unrecognized numeric string without validating it`() {
        // Numeric input is taken verbatim: validation is the caller's job.
        assertEquals(4242, CoseAlgorithms.fromName("4242"))
    }

    // -------------------------------------------------------------------------
    // fromName - rejection
    // -------------------------------------------------------------------------

    @Test
    fun `fromName throws INVALID_ALGORITHM for an unknown name`() {
        val e = assertProtocolException { CoseAlgorithms.fromName("RSA-PSS") }

        assertEquals(ErrorCodes.INVALID_ALGORITHM, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("RSA-PSS"))
    }

    @Test
    fun `fromName throws INVALID_ALGORITHM for an empty string`() {
        assertEquals(
            ErrorCodes.INVALID_ALGORITHM,
            assertProtocolException { CoseAlgorithms.fromName("") }.errorCode
        )
    }

    @Test
    fun `fromName throws INVALID_ALGORITHM for a value that is only partially numeric`() {
        assertEquals(
            ErrorCodes.INVALID_ALGORITHM,
            assertProtocolException { CoseAlgorithms.fromName("-7x") }.errorCode
        )
    }

    // -------------------------------------------------------------------------
    // isSupported
    // -------------------------------------------------------------------------

    @Test
    fun `isSupported accepts the key generation algorithms of the base protocol`() {
        assertTrue(CoseAlgorithms.isSupported(CoseAlgorithms.ES256))
        assertTrue(CoseAlgorithms.isSupported(CoseAlgorithms.ES384))
        assertTrue(CoseAlgorithms.isSupported(CoseAlgorithms.ES512))
        assertTrue(CoseAlgorithms.isSupported(CoseAlgorithms.RS256))
    }

    @Test
    fun `isSupported rejects algorithms the Android Keystore cannot generate for FIDO2`() {
        assertFalse(CoseAlgorithms.isSupported(CoseAlgorithms.EDDSA))
        assertFalse(CoseAlgorithms.isSupported(CoseAlgorithms.RS384))
        assertFalse(CoseAlgorithms.isSupported(CoseAlgorithms.RS512))
        assertFalse(CoseAlgorithms.isSupported(CoseAlgorithms.A256GCM))
        assertFalse(CoseAlgorithms.isSupported(CoseAlgorithms.HMAC_256))
        assertFalse(CoseAlgorithms.isSupported(0))
    }

    // -------------------------------------------------------------------------
    // getKeySizeBits
    // -------------------------------------------------------------------------

    @Test
    fun `getKeySizeBits returns the curve or modulus size for asymmetric algorithms`() {
        assertEquals(256, CoseAlgorithms.getKeySizeBits(CoseAlgorithms.ES256))
        assertEquals(384, CoseAlgorithms.getKeySizeBits(CoseAlgorithms.ES384))
        assertEquals(521, CoseAlgorithms.getKeySizeBits(CoseAlgorithms.ES512))
        assertEquals(2048, CoseAlgorithms.getKeySizeBits(CoseAlgorithms.RS256))
        assertEquals(3072, CoseAlgorithms.getKeySizeBits(CoseAlgorithms.RS384))
        assertEquals(4096, CoseAlgorithms.getKeySizeBits(CoseAlgorithms.RS512))
    }

    @Test
    fun `getKeySizeBits returns 521 not 512 for ES512 because P-521 is the curve`() {
        assertEquals(521, CoseAlgorithms.getKeySizeBits(CoseAlgorithms.ES512))
    }

    @Test
    fun `getKeySizeBits throws INVALID_ALGORITHM for symmetric and unknown algorithms`() {
        listOf(CoseAlgorithms.A256GCM, CoseAlgorithms.HMAC_256, CoseAlgorithms.EDDSA, -999).forEach {
            assertEquals(
                "getKeySizeBits($it)",
                ErrorCodes.INVALID_ALGORITHM,
                assertProtocolException { CoseAlgorithms.getKeySizeBits(it) }.errorCode
            )
        }
    }

    // -------------------------------------------------------------------------
    // getCurveName
    // -------------------------------------------------------------------------

    @Test
    fun `getCurveName returns the NIST curve for each EC algorithm`() {
        assertEquals("secp256r1", CoseAlgorithms.getCurveName(CoseAlgorithms.ES256))
        assertEquals("secp384r1", CoseAlgorithms.getCurveName(CoseAlgorithms.ES384))
        assertEquals("secp521r1", CoseAlgorithms.getCurveName(CoseAlgorithms.ES512))
    }

    @Test
    fun `getCurveName throws INVALID_ALGORITHM for non-EC algorithms`() {
        listOf(CoseAlgorithms.RS256, CoseAlgorithms.EDDSA, CoseAlgorithms.A256GCM, 0).forEach {
            assertEquals(
                "getCurveName($it)",
                ErrorCodes.INVALID_ALGORITHM,
                assertProtocolException { CoseAlgorithms.getCurveName(it) }.errorCode
            )
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private fun assertProtocolException(block: () -> Unit): ProtocolException {
        try {
            block()
        } catch (e: ProtocolException) {
            return e
        }
        fail("Expected ProtocolException")
        throw IllegalStateException("unreachable")
    }
}
