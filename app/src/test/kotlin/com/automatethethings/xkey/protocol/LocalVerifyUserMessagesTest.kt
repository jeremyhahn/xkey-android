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

package com.automatethethings.xkey.protocol

import java.util.Base64
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * The `local.verifyUser` wire messages (owner ruling 167): the request carries
 * only a version and a 32-byte nonce, and anything else is INVALID_PARAMS.
 */
class LocalVerifyUserMessagesTest {

    @Test
    fun `params round-trip through JSON`() {
        val params = LocalVerifyUserParams(protocolVersion = 2, nonce = nonceOf(32))

        val parsed = LocalVerifyUserParams.fromJson(JSONObject(params.toJson().toString()))

        assertEquals(params, parsed)
        assertArrayEquals(ByteArray(32) { it.toByte() }, parsed.getNonceBytes())
    }

    @Test
    fun `params carry no purpose and no binding`() {
        val json = LocalVerifyUserParams(protocolVersion = 2, nonce = nonceOf(32)).toJson()

        assertEquals(setOf("protocolVersion", "nonce"), json.keys().asSequence().toSet())
    }

    @Test
    fun `result round-trips through JSON`() {
        val result = LocalVerifyUserResult(
            protocolVersion = 2,
            certificateChain = listOf("bGVhZg==", "aW50ZXJtZWRpYXRl", "cm9vdA=="),
            signature = "c2lnbmF0dXJl",
            signatureAlgorithm = "ES256"
        )

        val json = result.toJson()

        assertEquals(
            setOf("protocolVersion", "certificateChain", "signature", "signatureAlgorithm"),
            json.keys().asSequence().toSet()
        )
        assertEquals(result, LocalVerifyUserResult.fromJson(JSONObject(json.toString())))
    }

    @Test
    fun `version 3 is invalid params`() {
        assertInvalidParams(JSONObject().put("protocolVersion", 3).put("nonce", nonceOf(32)))
    }

    @Test
    fun `a missing version is invalid params`() {
        assertInvalidParams(JSONObject().put("nonce", nonceOf(32)))
    }

    @Test
    fun `a 33-byte nonce is invalid params`() {
        assertInvalidParams(JSONObject().put("protocolVersion", 2).put("nonce", nonceOf(33)))
    }

    @Test
    fun `a missing nonce is invalid params`() {
        assertInvalidParams(JSONObject().put("protocolVersion", 2))
    }

    @Test
    fun `a nonce that is not base64 is invalid params`() {
        assertInvalidParams(JSONObject().put("protocolVersion", 2).put("nonce", "not base64!"))
    }

    private fun assertInvalidParams(params: JSONObject) {
        val e = assertThrows(ProtocolException::class.java) {
            LocalVerifyUserParams.fromJson(params)
        }
        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
    }

    private fun nonceOf(size: Int): String =
        Base64.getEncoder().encodeToString(ByteArray(size) { it.toByte() })
}
