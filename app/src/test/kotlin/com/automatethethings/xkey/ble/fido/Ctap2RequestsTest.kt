/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
package com.automatethethings.xkey.ble.fido

import com.automatethethings.xkey.crypto.CborEncoder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * [Ctap2Requests] called directly: every refusal answers its exact CTAP2
 * status, one test per field so a regression names it, and the accepted
 * shapes carry what the commands read.
 */
class Ctap2RequestsTest {

    private val hash = ByteArray(32) { (it + 1).toByte() }
    private val rp = mapOf("id" to "example.com")
    private val user = mapOf("id" to byteArrayOf(1, 2, 3))
    private val es256 = mapOf("alg" to -7, "type" to "public-key")

    /** Marks a field the request leaves out. */
    private val absent = Any()

    private fun params(base: Map<Any, Any?>, changes: Array<out Pair<Any, Any?>>): Map<Any, Any?> {
        val m = LinkedHashMap(base)
        for ((key, value) in changes) if (value === absent) m.remove(key) else m[key] = value
        return m
    }

    private fun mc(vararg changes: Pair<Any, Any?>): MakeCredentialRequest = Ctap2Requests.makeCredential(
        byteArrayOf(Ctap2.CMD_MAKE_CREDENTIAL.toByte()) +
            CborEncoder.encode(params(mapOf(1 to hash, 2 to rp, 3 to user, 4 to listOf(es256)), changes))
    )

    private fun ga(vararg changes: Pair<Any, Any?>): GetAssertionRequest = Ctap2Requests.getAssertion(
        byteArrayOf(Ctap2.CMD_GET_ASSERTION.toByte()) +
            CborEncoder.encode(params(mapOf(1 to "example.com", 2 to hash), changes))
    )

    private fun descriptor(vararg changes: Pair<Any, Any?>): Map<Any, Any?> =
        params(mapOf("id" to byteArrayOf(9, 9), "type" to "public-key"), changes)

    private fun refused(expected: Int, request: () -> Any) {
        try {
            request()
            fail("accepted; expected status 0x%02X".format(expected))
        } catch (e: Ctap2RequestException) {
            assertEquals("status", expected, e.status)
        }
    }

    // --- framing shared by both commands ---

    @Test
    fun `a request shorter than two bytes is a missing parameter`() {
        for (request in listOf(ByteArray(0), byteArrayOf(Ctap2.CMD_MAKE_CREDENTIAL.toByte()))) {
            refused(Ctap2.ERR_MISSING_PARAMETER) { Ctap2Requests.makeCredential(request) }
            refused(Ctap2.ERR_MISSING_PARAMETER) { Ctap2Requests.getAssertion(request) }
        }
    }

    @Test
    fun `a body that is not CBOR is invalid CBOR`() {
        // A break byte with no indefinite item open, and a map header with no entries after it.
        for (body in listOf(byteArrayOf(0xFF.toByte()), byteArrayOf(0xA1.toByte()), byteArrayOf(0xA0.toByte(), 0x00))) {
            refused(Ctap2.ERR_INVALID_CBOR) { Ctap2Requests.makeCredential(byteArrayOf(1) + body) }
            refused(Ctap2.ERR_INVALID_CBOR) { Ctap2Requests.getAssertion(byteArrayOf(2) + body) }
        }
    }

    @Test
    fun `a top-level value that is not a map is an unexpected type`() {
        for (value in listOf<Any?>(listOf(1), "x", 1, hash, true, null)) {
            val body = CborEncoder.encode(value)
            refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { Ctap2Requests.makeCredential(byteArrayOf(1) + body) }
            refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { Ctap2Requests.getAssertion(byteArrayOf(2) + body) }
        }
    }

    // --- makeCredential: required fields ---

    @Test
    fun `makeCredential without clientDataHash is a missing parameter`() =
        refused(Ctap2.ERR_MISSING_PARAMETER) { mc(1 to absent) }

    @Test
    fun `makeCredential without rp is a missing parameter`() =
        refused(Ctap2.ERR_MISSING_PARAMETER) { mc(2 to absent) }

    @Test
    fun `makeCredential without user is a missing parameter`() =
        refused(Ctap2.ERR_MISSING_PARAMETER) { mc(3 to absent) }

    @Test
    fun `makeCredential without pubKeyCredParams is a missing parameter`() =
        refused(Ctap2.ERR_MISSING_PARAMETER) { mc(4 to absent) }

    @Test
    fun `makeCredential with an empty map is a missing parameter`() =
        refused(Ctap2.ERR_MISSING_PARAMETER) {
            Ctap2Requests.makeCredential(byteArrayOf(1) + CborEncoder.encode(emptyMap<Any, Any?>()))
        }

    @Test
    fun `an rp without id is a missing parameter`() =
        refused(Ctap2.ERR_MISSING_PARAMETER) { mc(2 to mapOf("name" to "Example")) }

    @Test
    fun `a user without id is a missing parameter`() =
        refused(Ctap2.ERR_MISSING_PARAMETER) { mc(3 to mapOf("name" to "alice")) }

    // --- makeCredential: wrong types ---

    @Test
    fun `a makeCredential clientDataHash that is not bytes is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(1 to "0".repeat(32)) }

    @Test
    fun `an rp that is not a map is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(2 to "example.com") }

    @Test
    fun `an rp id that is not text is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(2 to mapOf("id" to "example.com".toByteArray())) }

    @Test
    fun `an rp name that is not text is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(2 to mapOf("id" to "example.com", "name" to 1)) }

    @Test
    fun `an rp icon that is not text is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(2 to mapOf("id" to "example.com", "icon" to listOf("x"))) }

    @Test
    fun `a user that is not a map is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(3 to listOf(byteArrayOf(1))) }

    @Test
    fun `a user id that is not bytes is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(3 to mapOf("id" to "alice")) }

    @Test
    fun `a user name that is not text is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(3 to mapOf("id" to byteArrayOf(1), "name" to byteArrayOf(1))) }

    @Test
    fun `a user displayName that is not text is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(3 to mapOf("id" to byteArrayOf(1), "displayName" to true)) }

    @Test
    fun `a user icon that is not text is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(3 to mapOf("id" to byteArrayOf(1), "icon" to 7)) }

    @Test
    fun `pubKeyCredParams that is not an array is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(4 to es256) }

    @Test
    fun `an excludeList that is not an array is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(5 to descriptor()) }

    @Test
    fun `makeCredential extensions that are not a map are an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(6 to listOf("credProtect")) }

    @Test
    fun `makeCredential options that are not a map are an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(7 to listOf("rk")) }

    @Test
    fun `a makeCredential pinUvAuthProtocol that is not an unsigned integer is an unexpected type`() {
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(9 to -1) }
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(9 to "1") }
    }

    @Test
    fun `an enterpriseAttestation that is not an unsigned integer is an unexpected type`() {
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(10 to -2) }
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(10 to true) }
    }

    @Test
    fun `a required makeCredential field present as CBOR null is an unexpected type, not a missing one`() {
        for (key in 1..4) refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(key to null) }
    }

    @Test
    fun `an optional makeCredential field present as CBOR null is an unexpected type, not an absent one`() {
        for (key in listOf(5, 6, 7, 9, 10)) refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(key to null) }
    }

    // --- makeCredential: lengths ---

    @Test
    fun `a makeCredential clientDataHash that is not 32 bytes is an invalid length`() {
        for (size in listOf(0, 31, 33, 64)) refused(Ctap2.ERR_INVALID_LENGTH) { mc(1 to ByteArray(size)) }
    }

    @Test
    fun `an empty rp id is an invalid length`() =
        refused(Ctap2.ERR_INVALID_LENGTH) { mc(2 to mapOf("id" to "")) }

    @Test
    fun `an empty user id is an invalid length`() =
        refused(Ctap2.ERR_INVALID_LENGTH) { mc(3 to mapOf("id" to ByteArray(0))) }

    @Test
    fun `a user id longer than 64 bytes is an invalid length and 64 bytes is accepted`() {
        refused(Ctap2.ERR_INVALID_LENGTH) { mc(3 to mapOf("id" to ByteArray(Ctap2Requests.MAX_USER_HANDLE + 1))) }
        assertEquals(64, mc(3 to mapOf("id" to ByteArray(Ctap2Requests.MAX_USER_HANDLE))).userHandle.size)
    }

    // --- makeCredential: pubKeyCredParams entries ---

    @Test
    fun `a pubKeyCredParams entry that is not a map is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(4 to listOf(es256, "public-key")) }

    @Test
    fun `a pubKeyCredParams entry without type is a missing parameter`() =
        refused(Ctap2.ERR_MISSING_PARAMETER) { mc(4 to listOf(es256, mapOf("alg" to -7))) }

    @Test
    fun `a pubKeyCredParams type that is not text is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(4 to listOf(es256, mapOf("alg" to -7, "type" to 1))) }

    @Test
    fun `a pubKeyCredParams entry without alg is a missing parameter`() =
        refused(Ctap2.ERR_MISSING_PARAMETER) { mc(4 to listOf(es256, mapOf("type" to "public-key"))) }

    @Test
    fun `a pubKeyCredParams alg that is not an integer is an unexpected type`() {
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(4 to listOf(es256, mapOf("alg" to "ES256", "type" to "public-key"))) }
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(4 to listOf(es256, mapOf("alg" to byteArrayOf(-7), "type" to "public-key"))) }
    }

    @Test
    fun `pubKeyCredParams with no public-key ES256 entry is an unsupported algorithm`() {
        refused(Ctap2.ERR_UNSUPPORTED_ALGORITHM) { mc(4 to emptyList<Any>()) }
        refused(Ctap2.ERR_UNSUPPORTED_ALGORITHM) { mc(4 to listOf(mapOf("alg" to -8, "type" to "public-key"))) }
        refused(Ctap2.ERR_UNSUPPORTED_ALGORITHM) { mc(4 to listOf(mapOf("alg" to -7, "type" to "other"))) }
    }

    // --- makeCredential: excludeList descriptors ---

    @Test
    fun `an excludeList descriptor that is not a map is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(5 to listOf(descriptor(), byteArrayOf(9, 9))) }

    @Test
    fun `an excludeList descriptor without id is a missing parameter`() =
        refused(Ctap2.ERR_MISSING_PARAMETER) { mc(5 to listOf(descriptor("id" to absent))) }

    @Test
    fun `an excludeList descriptor without type is a missing parameter`() =
        refused(Ctap2.ERR_MISSING_PARAMETER) { mc(5 to listOf(descriptor("type" to absent))) }

    @Test
    fun `an excludeList descriptor id that is not bytes is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(5 to listOf(descriptor("id" to "9999"))) }

    @Test
    fun `an excludeList descriptor type that is not text is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(5 to listOf(descriptor("type" to 0))) }

    @Test
    fun `an excludeList descriptor id out of the WebAuthn range is an invalid length`() {
        refused(Ctap2.ERR_INVALID_LENGTH) { mc(5 to listOf(descriptor("id" to ByteArray(0)))) }
        refused(Ctap2.ERR_INVALID_LENGTH) { mc(5 to listOf(descriptor("id" to ByteArray(Ctap2Requests.MAX_CREDENTIAL_ID + 1)))) }
    }

    @Test
    fun `an excludeList descriptor of another type is still checked in full`() {
        refused(Ctap2.ERR_MISSING_PARAMETER) { mc(5 to listOf(descriptor("type" to "other", "id" to absent))) }
        refused(Ctap2.ERR_INVALID_LENGTH) { mc(5 to listOf(descriptor("type" to "other", "id" to ByteArray(0)))) }
    }

    @Test
    fun `excludeList transports that are not an array of text are an unexpected type`() {
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(5 to listOf(descriptor("transports" to "ble"))) }
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(5 to listOf(descriptor("transports" to listOf("ble", 1)))) }
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(5 to listOf(descriptor("transports" to null))) }
    }

    // --- makeCredential: options, pinUvAuthParam, extensions ---

    @Test
    fun `a makeCredential option that is not a boolean is an unexpected type`() {
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(7 to mapOf("rk" to 1)) }
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(7 to mapOf("uv" to "true")) }
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(7 to mapOf("unknown" to null)) }
    }

    @Test
    fun `a makeCredential option key that is not text is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(7 to mapOf(1 to true)) }

    @Test
    fun `makeCredential with up false is an invalid option`() =
        refused(Ctap2.ERR_INVALID_OPTION) { mc(7 to mapOf("up" to false)) }

    @Test
    fun `a makeCredential pinUvAuthParam is refused, as there is no clientPin`() {
        refused(Ctap2.ERR_PIN_AUTH_INVALID) { mc(8 to ByteArray(16), 9 to 1) }
        refused(Ctap2.ERR_PIN_AUTH_INVALID) { mc(8 to ByteArray(0)) }
    }

    @Test
    fun `a makeCredential extension key that is not text is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { mc(6 to mapOf(1 to true)) }

    // --- makeCredential: accepted shapes ---

    @Test
    fun `a minimal makeCredential is accepted with no optional field`() {
        val request = mc()
        assertArrayEquals(hash, request.clientDataHash)
        assertEquals("example.com", request.rpId)
        assertNull(request.rpName)
        assertArrayEquals(byteArrayOf(1, 2, 3), request.userHandle)
        assertNull(request.userName)
        assertNull(request.userDisplayName)
        assertNull(request.excludeList)
        assertTrue(request.options.isEmpty())
    }

    @Test
    fun `a makeCredential with every optional field is accepted`() {
        val request = mc(
            2 to mapOf("id" to "example.com", "name" to "Example", "icon" to "https://example.com/i.png"),
            3 to mapOf("id" to byteArrayOf(1), "name" to "alice", "displayName" to "Alice", "icon" to "i"),
            4 to listOf(mapOf("alg" to -8, "type" to "public-key"), es256),
            5 to listOf(descriptor("transports" to listOf("ble", "usb")), descriptor("id" to byteArrayOf(7), "type" to "other")),
            6 to mapOf("credProtect" to 2, "hmac-secret" to true),
            7 to mapOf("rk" to true, "uv" to false, "up" to true),
            9 to 1,
            10 to 2
        )
        assertEquals("Example", request.rpName)
        assertEquals("alice", request.userName)
        assertEquals("Alice", request.userDisplayName)
        // The descriptor of another type is checked and names no credential.
        assertEquals(1, request.excludeList!!.size)
        assertArrayEquals(byteArrayOf(9, 9), request.excludeList!!.single())
        assertEquals(mapOf("rk" to true, "uv" to false, "up" to true), request.options)
    }

    @Test
    fun `empty optional makeCredential containers mean the same as absent ones`() {
        val request = mc(5 to emptyList<Any>(), 6 to emptyMap<Any, Any>(), 7 to emptyMap<Any, Any>())
        assertNull(request.excludeList)
        assertTrue(request.options.isEmpty())
        assertNull(mc(5 to listOf(descriptor("type" to "other"))).excludeList)
    }

    @Test
    fun `unknown makeCredential keys and members are ignored`() {
        val request = mc(
            2 to mapOf("id" to "example.com", "extra" to listOf(1)),
            3 to mapOf("id" to byteArrayOf(1), "extra" to mapOf(1 to 2)),
            5 to listOf(descriptor("extra" to 1)),
            7 to mapOf("unknown" to true),
            11 to "unknown",
            "text-key" to 1
        )
        assertEquals("example.com", request.rpId)
        assertEquals(mapOf("unknown" to true), request.options)
    }

    // --- getAssertion: required fields and types ---

    @Test
    fun `getAssertion without rpId is a missing parameter`() =
        refused(Ctap2.ERR_MISSING_PARAMETER) { ga(1 to absent) }

    @Test
    fun `getAssertion without clientDataHash is a missing parameter`() =
        refused(Ctap2.ERR_MISSING_PARAMETER) { ga(2 to absent) }

    @Test
    fun `a getAssertion rpId that is not text is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { ga(1 to "example.com".toByteArray()) }

    @Test
    fun `an empty getAssertion rpId is an invalid length`() =
        refused(Ctap2.ERR_INVALID_LENGTH) { ga(1 to "") }

    @Test
    fun `a getAssertion clientDataHash that is not bytes is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { ga(2 to listOf(1, 2)) }

    @Test
    fun `a getAssertion clientDataHash that is not 32 bytes is an invalid length`() {
        for (size in listOf(0, 31, 33)) refused(Ctap2.ERR_INVALID_LENGTH) { ga(2 to ByteArray(size)) }
    }

    @Test
    fun `an allowList that is not an array is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { ga(3 to descriptor()) }

    @Test
    fun `getAssertion extensions that are not a map are an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { ga(4 to "hmac-secret") }

    @Test
    fun `getAssertion options that are not a map are an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { ga(5 to true) }

    @Test
    fun `a getAssertion pinUvAuthProtocol that is not an unsigned integer is an unexpected type`() {
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { ga(7 to -1) }
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { ga(7 to byteArrayOf(1)) }
    }

    @Test
    fun `a getAssertion field present as CBOR null is an unexpected type`() {
        for (key in listOf(1, 2, 3, 4, 5, 7)) refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { ga(key to null) }
    }

    // --- getAssertion: allowList descriptors ---

    @Test
    fun `an allowList descriptor that is not a map is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { ga(3 to listOf(descriptor(), "public-key")) }

    @Test
    fun `an allowList descriptor without id is a missing parameter`() =
        refused(Ctap2.ERR_MISSING_PARAMETER) { ga(3 to listOf(descriptor("id" to absent))) }

    @Test
    fun `an allowList descriptor without type is a missing parameter`() =
        refused(Ctap2.ERR_MISSING_PARAMETER) { ga(3 to listOf(descriptor("type" to absent))) }

    @Test
    fun `an allowList descriptor id that is not bytes is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { ga(3 to listOf(descriptor("id" to 99))) }

    @Test
    fun `an allowList descriptor id out of the WebAuthn range is an invalid length`() {
        refused(Ctap2.ERR_INVALID_LENGTH) { ga(3 to listOf(descriptor("id" to ByteArray(0)))) }
        refused(Ctap2.ERR_INVALID_LENGTH) { ga(3 to listOf(descriptor("id" to ByteArray(Ctap2Requests.MAX_CREDENTIAL_ID + 1)))) }
    }

    @Test
    fun `allowList transports that are not an array of text are an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { ga(3 to listOf(descriptor("transports" to mapOf("ble" to true)))) }

    // --- getAssertion: options, pinUvAuthParam, extensions ---

    @Test
    fun `a getAssertion option that is not a boolean is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { ga(5 to mapOf("uv" to 0)) }

    @Test
    fun `a getAssertion option key that is not text is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { ga(5 to mapOf(2 to true)) }

    @Test
    fun `getAssertion with up false is an unsupported option`() =
        refused(Ctap2.ERR_UNSUPPORTED_OPTION) { ga(5 to mapOf("up" to false)) }

    @Test
    fun `a getAssertion pinUvAuthParam is refused, as there is no clientPin`() =
        refused(Ctap2.ERR_PIN_AUTH_INVALID) { ga(6 to ByteArray(16), 7 to 1) }

    @Test
    fun `a getAssertion extension key that is not text is an unexpected type`() =
        refused(Ctap2.ERR_CBOR_UNEXPECTED_TYPE) { ga(4 to mapOf(-1 to "x")) }

    // --- getAssertion: accepted shapes ---

    @Test
    fun `a minimal getAssertion is a discovery request with no options`() {
        val request = ga()
        assertEquals("example.com", request.rpId)
        assertArrayEquals(hash, request.clientDataHash)
        assertNull(request.allowList)
        assertTrue(request.options.isEmpty())
    }

    @Test
    fun `an empty allowList is discovery`() = assertNull(ga(3 to emptyList<Any>()).allowList)

    @Test
    fun `an allowList of another type only is empty, never discovery`() {
        val allowList = ga(3 to listOf(descriptor("type" to "other"))).allowList
        assertTrue(allowList != null && allowList.isEmpty())
    }

    @Test
    fun `a getAssertion with every optional field is accepted`() {
        val request = ga(
            3 to listOf(descriptor("transports" to listOf("ble")), descriptor("id" to ByteArray(Ctap2Requests.MAX_CREDENTIAL_ID))),
            4 to mapOf("hmac-secret" to mapOf(1 to 2)),
            5 to mapOf("up" to true, "uv" to true),
            7 to 1
        )
        assertEquals(2, request.allowList!!.size)
        assertArrayEquals(byteArrayOf(9, 9), request.allowList!![0])
        assertEquals(Ctap2Requests.MAX_CREDENTIAL_ID, request.allowList!![1].size)
        assertEquals(mapOf("up" to true, "uv" to true), request.options)
    }

    @Test
    fun `unknown getAssertion keys and options are ignored`() {
        val request = ga(5 to mapOf("unknown" to false), 8 to listOf(1), "text-key" to true)
        assertNull(request.allowList)
        assertEquals(mapOf("unknown" to false), request.options)
    }
}
