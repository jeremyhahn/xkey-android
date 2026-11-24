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

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test

/**
 * `keySizeBits` on `local.generateKey`: an RSA request takes its modulus
 * from it, and a size the phone cannot make is INVALID_PARAMS, never a key
 * of another size.
 */
class LocalGenerateKeySizeTest {

    private fun params(algorithm: String, keySizeBits: Any? = null) = JSONObject()
        .put("keyId", "k")
        .put("algorithm", algorithm)
        .apply { keySizeBits?.let { put("keySizeBits", it) } }

    private fun assertRefused(algorithm: String, keySizeBits: Any) {
        try {
            LocalGenerateKeyParams.fromJson(params(algorithm, keySizeBits))
            fail("$algorithm with keySizeBits $keySizeBits must be refused")
        } catch (e: ProtocolException) {
            assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        }
    }

    @Test
    fun `an RS256 request with keySizeBits 4096 asks for a 4096-bit key`() {
        val parsed = LocalGenerateKeyParams.fromJson(params("RS256", 4096))
        assertEquals(4096, parsed.keySizeBits)
        assertEquals(4096, parsed.resolvedKeySizeBits())
    }

    @Test
    fun `every RSA size the Keystore makes is accepted with every RSA hash`() {
        for (algorithm in listOf("RS256", "RS384", "RS512")) {
            for (bits in listOf(2048, 3072, 4096)) {
                assertEquals(bits, LocalGenerateKeyParams.fromJson(params(algorithm, bits)).resolvedKeySizeBits())
            }
        }
    }

    @Test
    fun `without keySizeBits the size follows the algorithm`() {
        val parsed = LocalGenerateKeyParams.fromJson(params("RS384"))
        assertNull(parsed.keySizeBits)
        assertEquals(3072, parsed.resolvedKeySizeBits())
        assertEquals(256, LocalGenerateKeyParams.fromJson(params("ES256")).resolvedKeySizeBits())
        assertEquals(192, LocalGenerateKeyParams.fromJson(params("AES-192")).resolvedKeySizeBits())
        assertEquals(384, LocalGenerateKeyParams.fromJson(params("HMAC-SHA384")).resolvedKeySizeBits())
    }

    @Test
    fun `keySizeBits 0 is no size`() {
        assertNull(LocalGenerateKeyParams.fromJson(params("RS256", 0)).keySizeBits)
    }

    @Test
    fun `an RSA size the Keystore cannot make is INVALID_PARAMS`() {
        assertRefused("RS256", 1024)
        assertRefused("RS256", 8192)
        assertRefused("RS512", 2047)
        assertRefused("RS256", "big")
    }

    @Test
    fun `a size that is not the algorithm's own is INVALID_PARAMS`() {
        assertRefused("ES256", 384)
        assertRefused("ES384", 2048)
        assertRefused("AES-128", 256)
        assertRefused("HMAC-SHA256", 512)
    }

    @Test
    fun `the algorithm's own size is accepted`() {
        assertEquals(521, LocalGenerateKeyParams.fromJson(params("ES512", 521)).resolvedKeySizeBits())
        assertEquals(256, LocalGenerateKeyParams.fromJson(params("AES-256", 256)).resolvedKeySizeBits())
    }
}
